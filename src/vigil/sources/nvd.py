"""NVD 2.0 — CVE metadata and any-source CVSS.

Endpoint: services.nvd.nist.gov/rest/json/cves/2.0. Anonymous rate limit is
5 req / 30s; the optional NVD API key (file: secrets/nvd-api-key) bumps it
to 50 req / 30s. The key is a NIST data-access token, not an LLM billing key.

Post-2026-04-15 NVD shift: most CVEs lack NVD-validated CVSS. This module
reads CVSS from any provider (NVD / CNA / ADP) across v3.1 / v4.0 containers
and never drops an item just because it has no score.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone

from .. import _paths
from .._http import get

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _api_key() -> str | None:
    if key := os.environ.get("NVD_API_KEY"):
        return key.strip() or None
    key_file = _paths.secrets_dir() / "nvd-api-key"
    if key_file.exists():
        return key_file.read_text().strip() or None
    return None


def _iso(dt: datetime) -> str:
    # NVD 2.0 expects ISO 8601 with millisecond precision, no trailing Z.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_window(start: datetime, end: datetime, *, mode: str = "pub",
                 api_key: str | None = None) -> list[dict]:
    """mode = 'pub' (publication date) or 'mod' (last-modified date)."""
    if mode not in ("pub", "mod"):
        raise ValueError(f"unknown mode: {mode}")
    headers = {"apiKey": api_key} if api_key else {}
    out: list[dict] = []
    start_index = 0
    while True:
        params: dict[str, object] = {
            "resultsPerPage": 2000,
            "startIndex": start_index,
        }
        if mode == "pub":
            params["pubStartDate"] = _iso(start)
            params["pubEndDate"] = _iso(end)
        else:
            params["lastModStartDate"] = _iso(start)
            params["lastModEndDate"] = _iso(end)
        r = get(NVD_URL, timeout=60.0, params=params, headers=headers)
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        out.extend(vulns)
        total = data.get("totalResults", 0)
        per_page = data.get("resultsPerPage", 0) or len(vulns)
        start_index += per_page
        if start_index >= total or not vulns or per_page == 0:
            break
        # Stay under NVD rate limit: 5 req/30s anonymous, 50 req/30s keyed.
        time.sleep(0.7 if api_key else 6.0)
    return out


def fetch_last_24h(now: datetime | None = None) -> list[dict]:
    """Returns unique CVEs published OR last-modified in the last 24h."""
    if now is None:
        now = datetime.now(timezone.utc)
    start = now - timedelta(hours=24)
    key = _api_key()
    pub = fetch_window(start, now, mode="pub", api_key=key)
    if not key:
        time.sleep(6.0)
    mod = fetch_window(start, now, mode="mod", api_key=key)
    merged: dict[str, dict] = {}
    for item in pub + mod:
        cid = (item.get("cve") or {}).get("id")
        if cid and cid not in merged:
            merged[cid] = item
    return list(merged.values())


def _source_label(source: str, mtype: str) -> str:
    s = (source or "").lower()
    if "nist.gov" in s:
        return "NVD"
    if mtype == "Primary":
        return f"CNA ({source})" if source else "CNA"
    return f"3rd-party ({source})" if source else "3rd-party"


def extract_cvss(cve_item: dict) -> dict | None:
    """Return highest-rank available CVSS with source label, or None.

    Prefers newer version, then Primary over Secondary, then higher score.
    Reads from cvssMetricV40, V31, V30, V2 across any provider.
    """
    metrics = (cve_item.get("cve") or {}).get("metrics", {})
    candidates = []
    for key, ver_rank, ver_label in (
        ("cvssMetricV40", 4, "4.0"),
        ("cvssMetricV31", 3, "3.1"),
        ("cvssMetricV30", 2, "3.0"),
        ("cvssMetricV2", 1, "2.0"),
    ):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            score = data.get("baseScore")
            if score is None:
                continue
            source = m.get("source", "")
            mtype = m.get("type", "")
            candidates.append({
                "score": float(score),
                "ver_rank": ver_rank,
                "version": ver_label,
                "severity": data.get("baseSeverity"),
                "source": source,
                "type": mtype,
                "label": _source_label(source, mtype),
            })
    if not candidates:
        return None
    candidates.sort(
        key=lambda c: (c["ver_rank"], c["type"] == "Primary", c["score"]),
        reverse=True,
    )
    top = candidates[0]
    return {
        "score": top["score"],
        "version": top["version"],
        "severity": top["severity"],
        "source": top["source"],
        "label": top["label"],
    }


def extract_vendor_product(cve_item: dict) -> tuple[str, str]:
    """Pull (vendor, product) from the first vulnerable CPE in configurations.

    CPE 2.3 format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
    Returns ('', '') if no parseable CPE — Codex's rationale plus the
    description still give the reader context.
    """
    cve = cve_item.get("cve") or {}
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) >= 5 and parts[0] == "cpe" and parts[1] == "2.3":
                    vendor = parts[3].replace("_", " ")
                    product = parts[4].replace("_", " ")
                    if vendor or product:
                        return vendor, product
    return "", ""


def extract_summary(cve_item: dict) -> dict:
    cve = cve_item.get("cve") or {}
    cid = cve.get("id")
    descs = cve.get("descriptions") or []
    en = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
    if len(en) > 400:
        en = en[:397] + "..."
    cwe: list[str] = []
    for w in cve.get("weaknesses") or []:
        for d in w.get("description") or []:
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwe:
                cwe.append(v)
    vendor, product = extract_vendor_product(cve_item)
    return {
        "cve": cid,
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "description": en,
        "cwe": cwe,
        "cvss": extract_cvss(cve_item),
        "vendor": vendor,
        "product": product,
    }
