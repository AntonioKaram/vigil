"""CISA KEV — confirmed exploited-in-the-wild catalog.

Single public JSON, no key. Diff today's catalog against yesterday's snapshot
and surface only newly added entries. KEV membership is always-include in the
brief, regardless of EPSS or CVSS.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import atomic_write
from .._http import get

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def fetch() -> dict:
    return get(KEV_URL, timeout=30.0).json()


def _index(catalog: dict) -> dict[str, dict]:
    return {v["cveID"]: v for v in catalog.get("vulnerabilities", [])}


def diff_new(prev: dict | None, curr: dict) -> list[dict]:
    if prev is None:
        return []
    prev_ids = set(_index(prev).keys())
    curr_idx = _index(curr)
    return [curr_idx[cid] for cid in curr_idx if cid not in prev_ids]


def get_new_kev_entries(data_dir: Path) -> tuple[list[dict], bool]:
    """Returns (new_entries, first_run). Snapshots today's catalog for tomorrow."""
    curr = fetch()
    prev_path = data_dir / "kev-prev.json"
    first_run = not prev_path.exists()
    prev = None if first_run else json.loads(prev_path.read_text())
    new = diff_new(prev, curr)
    atomic_write(prev_path, json.dumps(curr, separators=(",", ":")))
    return new, first_run
