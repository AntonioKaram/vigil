"""EPSS (FIRST) — daily exploitation-probability scores.

Source: epss.cyentia.com daily CSV (gzipped). No key. Two jobs:
  1. Lookup EPSS for a given CVE — the post-2026-04-15 NVD shift means most
     CVEs lack an NVD-validated CVSS, so EPSS replaces the severity gate.
  2. Compute overnight EPSS delta against data/epss-prev.json — sharp rises
     often precede a KEV listing, so this is our early warning.
"""
from __future__ import annotations

import csv
import gzip
import json
from pathlib import Path

from . import atomic_write
from .._http import get

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


def fetch() -> dict[str, dict[str, float]]:
    """Returns {cve_id: {"epss": float, "percentile": float}}."""
    r = get(EPSS_URL, timeout=60.0)
    raw = gzip.decompress(r.content).decode("utf-8")
    lines = raw.splitlines()
    # Skip leading metadata comments (#model_version: ..., #score_date: ...)
    while lines and lines[0].startswith("#"):
        lines.pop(0)
    reader = csv.DictReader(lines)
    out: dict[str, dict[str, float]] = {}
    for row in reader:
        cve = (row.get("cve") or "").strip()
        if not cve:
            continue
        try:
            out[cve] = {
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
        except (KeyError, ValueError):
            continue
    return out


def movers(prev: dict[str, dict] | None, curr: dict[str, dict], *,
           delta_threshold: float = 0.10,
           top_decile: float = 0.90) -> list[dict]:
    """CVEs whose EPSS rose significantly overnight.

    Significant = absolute delta >= delta_threshold, OR crossing into the top
    decile overnight (percentile went from <top_decile to >=top_decile).
    """
    if not prev:
        return []
    out = []
    for cve, c in curr.items():
        p = prev.get(cve)
        if not p:
            continue
        delta = c["epss"] - p["epss"]
        crossed = c["percentile"] >= top_decile and p["percentile"] < top_decile
        if delta >= delta_threshold or crossed:
            out.append({
                "cve": cve,
                "epss_prev": p["epss"],
                "epss_curr": c["epss"],
                "delta": delta,
                "percentile": c["percentile"],
            })
    out.sort(key=lambda x: x["delta"], reverse=True)
    return out


def get_epss_state(data_dir: Path, *,
                   delta_threshold: float = 0.10,
                   top_decile: float = 0.90,
                   ) -> tuple[dict[str, dict], list[dict], bool]:
    """Returns (current_scores, movers, first_run)."""
    curr = fetch()
    prev_path = data_dir / "epss-prev.json"
    first_run = not prev_path.exists()
    prev = None if first_run else json.loads(prev_path.read_text())
    moves = movers(prev, curr,
                   delta_threshold=delta_threshold,
                   top_decile=top_decile)
    atomic_write(prev_path, json.dumps(curr, separators=(",", ":")))
    return curr, moves, first_run
