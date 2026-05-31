"""vigil entry point — run once, exit.

Pipeline:
  fetch (KEV/EPSS/NVD/RSS)
    -> gate + cap
    -> Codex selection + rationale JSON
    -> merge with Python's structured records into a brief object
    -> render markdown + HTML
    -> post to #vigil + email operator
    -> append to runs.jsonl

Each delivery leg is independent. main returns 1 only when both fail,
which triggers run.sh's notify path.
"""
from __future__ import annotations

import json
import os
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from . import _paths, brief, deliver, post, render
from . import prompt as prompt_mod
from .sources import atomic_write, epss, kev, nvd, rss


def _config_path() -> Path:
    if cfg := os.environ.get("VIGIL_CONFIG"):
        return Path(cfg).expanduser()
    return Path(__file__).resolve().parents[2] / "config.toml"


def _load_config() -> dict:
    with open(_config_path(), "rb") as f:
        return tomllib.load(f)


def _release_sha() -> str:
    """Best-effort short SHA of the running release dir.

    For prod releases under ~/work/agents/vigil/releases/<sha>/, the dir
    name IS the sha. For dev runs, it's the worktree name; fine for run_id.
    """
    return Path(__file__).resolve().parents[2].name


def _candidate_cves(nvd_items: list[dict],
                    epss_scores: dict[str, dict],
                    cfg: dict) -> list[dict]:
    """Apply inclusion rules to the NVD set (KEV-listed are surfaced separately).

    A CVE enters if any of:
      - EPSS >= epss_high, or percentile >= epss_top_decile
      - CVSS from any source >= cvss_high
    """
    t = cfg["thresholds"]
    out = []
    for item in nvd_items:
        summary = nvd.extract_summary(item)
        cve_id = summary["cve"]
        if not cve_id:
            continue
        e = epss_scores.get(cve_id)
        cvss = summary.get("cvss")
        include = False
        if e and (
            e["epss"] >= t["epss_high"]
            or e["percentile"] >= t["epss_top_decile"]
        ):
            include = True
        if cvss and cvss["score"] >= t["cvss_high"]:
            include = True
        if include:
            summary["epss"] = e
            out.append(summary)
    out.sort(
        key=lambda c: (
            (c.get("epss") or {}).get("epss", 0.0),
            (c.get("cvss") or {}).get("score", 0.0),
        ),
        reverse=True,
    )
    return out


def _diversity_cap(candidates: list[dict], kev_ids: set[str], cfg: dict) -> list[dict]:
    """A3: per-CNA cap applied between gating and the global cve cap.

    KEV-listed (cve_id in kev_ids) and high-EPSS items are exempt. Other
    candidates are grouped by CVSS source label; any group named in
    cfg[diversity_caps] is truncated to that cap, keeping the highest-EPSS
    then -CVSS within each group. Final list is ordered EPSS desc then CVSS
    desc so the downstream global cap still picks the most actionable.
    """
    diversity_caps = cfg.get("diversity_caps") or {}
    if not diversity_caps:
        return candidates
    epss_high = cfg["thresholds"]["epss_high"]

    def _rank(c: dict) -> tuple[float, float]:
        return (
            (c.get("epss") or {}).get("epss", 0.0),
            (c.get("cvss") or {}).get("score", 0.0),
        )

    exempt: list[dict] = []
    by_source: dict[str, list[dict]] = {}
    for c in candidates:
        cid = c.get("cve")
        epss = (c.get("epss") or {}).get("epss", 0.0)
        if cid in kev_ids or epss >= epss_high:
            exempt.append(c)
            continue
        label = (c.get("cvss") or {}).get("label", "")
        by_source.setdefault(label, []).append(c)

    capped: list[dict] = list(exempt)
    for label, group in by_source.items():
        cap = diversity_caps.get(label)
        if cap is None:
            capped.extend(group)
            continue
        group.sort(key=_rank, reverse=True)
        capped.extend(group[: int(cap)])

    capped.sort(key=_rank, reverse=True)
    return capped


def _collapse_kernel(records: list[dict], cfg: dict) -> list[dict]:
    """A4: collapse kernel-CNA + low-EPSS + non-KEV items into one summary.

    Operates on the cves section's records (kernel items shouldn't be in
    act_now/rising — those exempt high-EPSS/KEV already). When 2+ items
    qualify, replace them with a single summary record carrying their
    cve_ids and a canned rationale. Below threshold, returns input unchanged.
    """
    kc_cfg = cfg.get("kernel_collapse") or {}
    threshold = int(kc_cfg.get("threshold", 0))
    low_epss = float(kc_cfg.get("low_epss", 0.10))
    if threshold <= 0:
        return records

    kernel_recs: list[dict] = []
    other_recs: list[dict] = []
    for r in records:
        is_kernel = r.get("cvss_source") == "Linux kernel"
        is_low = (r.get("epss") or 0.0) < low_epss
        is_not_kev = not r.get("kev")
        if is_kernel and is_low and is_not_kev:
            kernel_recs.append(r)
        else:
            other_recs.append(r)

    if len(kernel_recs) < threshold:
        return records

    cve_ids = [r["cve_id"] for r in kernel_recs]
    summary = {
        "type": "kernel_summary",
        "cve_ids": cve_ids,
        "count": len(cve_ids),
        "rationale": (
            f"{len(cve_ids)} Linux kernel CVEs this cycle "
            f"(high CVSS, EPSS near zero, none KEV-listed)."
        ),
    }
    return other_recs + [summary]


def _build_record(cve_id: str, *,
                  kev_by_id: dict, cand_by_id: dict, mover_by_id: dict,
                  epss_curr: dict, with_rise: bool = False) -> dict | None:
    """Build a uniform brief record for a cve_id by gathering everything we know.

    The same record shape is used as input to the rationale prompt AND as the
    rendered brief item (after rationale is attached). Returns None if cve_id
    isn't in any pool (should not happen with Python-owned section assignment).
    """
    k = kev_by_id.get(cve_id)
    c = cand_by_id.get(cve_id)
    m = mover_by_id.get(cve_id)
    if not any((k, c, m)):
        return None
    rec: dict = {
        "cve_id": cve_id,
        "cvss": None,
        "cvss_source": None,
        "epss": None,
        "vendor": "",
        "product": "",
        "description": "",
        "cwe": [],
        "rationale": "",
        "kev": k is not None,
        "due_date": None,
    }
    if k:
        rec["vendor"] = k.get("vendorProject", "")
        rec["product"] = k.get("product", "")
        rec["due_date"] = k.get("dueDate")
        rec["description"] = (
            k.get("shortDescription", "") or k.get("vulnerabilityName", "")
        )
    if c:
        if c.get("cvss"):
            rec["cvss"] = c["cvss"]["score"]
            rec["cvss_source"] = c["cvss"].get("label", "?")
        if not rec["vendor"]:
            rec["vendor"] = c.get("vendor", "")
        if not rec["product"]:
            rec["product"] = c.get("product", "")
        if not rec["description"]:
            rec["description"] = c.get("description", "")
        rec["cwe"] = c.get("cwe") or []
        if c.get("epss"):
            rec["epss"] = c["epss"]["epss"]
    if rec["epss"] is None:
        score = epss_curr.get(cve_id)
        if score:
            rec["epss"] = score["epss"]
    if with_rise and m:
        if rec["epss"] is None:
            rec["epss"] = m.get("epss_curr")
        rec["epss_prev"] = m.get("epss_prev")
        rec["epss_delta"] = m.get("delta")
    return rec


def _assign_sections(*, kev_by_id: dict, cand_by_id: dict, mover_by_id: dict,
                     thresholds: dict) -> tuple[set, set, list]:
    """A1: Python-deterministic section membership.

    act_now = newly KEV-listed UNION {candidates with EPSS >= epss_high AND CVSS >= cvss_high}
    rising  = EPSS movers (minus anything already in act_now)
    cves    = remaining candidates not in act_now or rising
    """
    act_now_ids: set[str] = set(kev_by_id.keys())
    for cid, c in cand_by_id.items():
        if cid in act_now_ids:
            continue
        cvss = (c.get("cvss") or {}).get("score")
        epss = (c.get("epss") or {}).get("epss")
        if (cvss is not None and cvss >= thresholds["cvss_high"]
                and epss is not None and epss >= thresholds["epss_high"]):
            act_now_ids.add(cid)
    rising_ids = set(mover_by_id.keys()) - act_now_ids
    cves_ids = [
        cid for cid in cand_by_id
        if cid not in act_now_ids and cid not in rising_ids
    ]
    return act_now_ids, rising_ids, cves_ids


def _order_key(r: dict) -> tuple[float, float]:
    """Deterministic section ordering: EPSS desc, then CVSS desc."""
    return (r.get("epss") or 0.0, r.get("cvss") or 0.0)


def main(argv: list[str] | None = None) -> int:
    cfg = _load_config()
    data_dir = _paths.data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    # Fetch
    kev_new, kev_first = kev.get_new_kev_entries(data_dir)
    epss_curr, epss_moves, epss_first = epss.get_epss_state(
        data_dir,
        delta_threshold=cfg["thresholds"]["epss_delta"],
        top_decile=cfg["thresholds"]["epss_top_decile"],
    )
    nvd_items = nvd.fetch_last_24h()
    news, feed_counts, source_errors = rss.get_new_items(data_dir, cfg["feeds"]["rss"])
    for url, err in source_errors.items():
        print(f"SOURCE WARN: {url} -> {err}", file=sys.stderr)

    # Gate
    candidates = _candidate_cves(nvd_items, epss_curr, cfg)

    # A3: per-source diversity cap (between gating and the global cap).
    # KEV-listed exemption uses the full kev_new (not the capped subset) so
    # an exempt CVE isn't accidentally suppressed when KEV's own cap kicks in.
    kev_new_ids = {k.get("cveID") for k in kev_new if k.get("cveID")}
    candidates = _diversity_cap(candidates, kev_new_ids, cfg)

    # Final caps
    caps = cfg["caps"]
    kev_capped = kev_new[: caps["kev"]]
    cands_capped = candidates[: caps["cve"]]
    moves_capped = epss_moves[: caps["cve"]]
    news_capped = news[: caps["news"]]
    first_run = kev_first or epss_first

    # Lookup tables (used for both section assignment and record building)
    kev_by_id = {k["cveID"]: k for k in kev_capped if k.get("cveID")}
    cand_by_id = {c["cve"]: c for c in cands_capped if c.get("cve")}
    mover_by_id = {m["cve"]: m for m in moves_capped if m.get("cve")}

    # A1: Python decides section membership (Codex never moves items across sections)
    act_now_ids, rising_ids, cves_ids = _assign_sections(
        kev_by_id=kev_by_id, cand_by_id=cand_by_id, mover_by_id=mover_by_id,
        thresholds=cfg["thresholds"],
    )

    def _section_records(ids, *, with_rise: bool = False) -> list[dict]:
        out = [
            _build_record(cid, kev_by_id=kev_by_id, cand_by_id=cand_by_id,
                          mover_by_id=mover_by_id, epss_curr=epss_curr,
                          with_rise=with_rise)
            for cid in ids
        ]
        out = [r for r in out if r is not None]
        out.sort(key=_order_key, reverse=True)
        return out

    act_now_records = _section_records(act_now_ids)
    rising_records  = _section_records(rising_ids, with_rise=True)
    cves_records    = _section_records(cves_ids)

    # A4: collapse the kernel-CNA bucket in cves (it would otherwise flood the
    # brief with a wall of 9.8-CVSS / 0.00-EPSS items per spec example).
    cves_records = _collapse_kernel(cves_records, cfg)

    # Codex: rationale only (no selection)
    prompt_text = prompt_mod.build_brief_prompt(
        act_now_records=act_now_records,
        rising_records=rising_records,
        cves_records=cves_records,
        news=news_capped,
        first_run=first_run,
    )
    rationale_text = brief.run_codex(prompt_text)
    rationale = brief.parse_rationale_json(rationale_text)

    # Attach rationale by cve_id (cross-section index — Codex putting a rationale
    # in the "wrong" section still attaches to the right item via cve_id match)
    rationale_by_id: dict[str, str] = {}
    for section in ("act_now", "rising", "cves"):
        for entry in rationale.get(section, []) or []:
            cid = entry.get("cve_id")
            if cid:
                rationale_by_id[cid] = entry.get("rationale", "")
    news_relevance: dict[str, str] = {}
    for entry in rationale.get("news", []) or []:
        url = entry.get("url")
        if url:
            news_relevance[url] = entry.get("relevance", "")
    for rec in act_now_records + rising_records + cves_records:
        rec["rationale"] = rationale_by_id.get(rec["cve_id"], "")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_id = f"{_release_sha()}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"

    brief_obj = {
        "date": today,
        "run_id": run_id,
        "notes": rationale.get("notes"),
        "act_now": act_now_records,
        "rising":  rising_records,
        "cves":    cves_records,
        "news": [
            {
                "title":     n.get("title", "?"),
                "source":    n.get("feed", ""),
                "url":       n.get("link") or "",
                "relevance": news_relevance.get(n.get("link") or "", ""),
            }
            for n in news_capped if n.get("link")
        ],
    }

    # Render
    channel_md = render.render_markdown(brief_obj)
    email_html = render.render_html(brief_obj)
    email_text = channel_md  # plain leg = markdown (TTS-friendly per spec)

    sys.stdout.write(channel_md)
    if not channel_md.endswith("\n"):
        sys.stdout.write("\n")

    # Deliver — legs independent
    subject = f"vigil: daily cyber brief {today}"
    delivery_errors: list[str] = []
    try:
        post.post(channel_md)
    except Exception as e:
        delivery_errors.append(f"post: {e!r}")
    try:
        deliver.send_brief(subject=subject, text_body=email_text, html_body=email_html)
    except Exception as e:
        delivery_errors.append(f"deliver: {e!r}")
    for err in delivery_errors:
        level = "ERROR" if len(delivery_errors) == 2 else "WARN"
        print(f"DELIVERY {level}: {err}", file=sys.stderr)

    # Persist context for the listener (Feature 2). Always written, even on
    # delivery failure — context is the day's pool, not delivery state. The
    # uncapped lists are what the listener consults when the operator asks
    # about an item that didn't make the capped brief.
    context_obj = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "date": today,
        "run_id": run_id,
        "first_run": first_run,
        "brief": brief_obj,
        "uncapped": {
            "kev_new":     kev_new,
            "epss_movers": epss_moves,
            "candidates":  candidates,
            "news":        news,
        },
        "feeds": feed_counts,
        "source_errors": source_errors,
    }
    context_json = json.dumps(context_obj, separators=(",", ":"))
    atomic_write(data_dir / f"context-{today}.json", context_json)
    atomic_write(data_dir / "context-today.json", context_json)

    # Log
    run_log = _paths.logs_dir() / "runs.jsonl"
    run_log.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "first_run": first_run,
        "counts": {
            "kev_new": len(kev_new),
            "kev_capped": len(kev_capped),
            "epss_movers": len(epss_moves),
            "nvd_items": len(nvd_items),
            "cve_candidates": len(candidates),
            "news": len(news),
            "feeds": feed_counts,
        },
        "delivery_errors": delivery_errors,
        "source_errors": source_errors,
        "brief": brief_obj,
    }
    with open(run_log, "a") as f:
        f.write(json.dumps(record) + "\n")

    return 1 if len(delivery_errors) == 2 else 0


if __name__ == "__main__":
    sys.exit(main())
