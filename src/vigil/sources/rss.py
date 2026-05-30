"""RSS — 4 feeds by default (Krebs, BleepingComputer, The Hacker News, SANS ISC).

Dedupes against data/seen.json using each item's GUID (or link as fallback).
Returns only items in the last 24h that haven't been seen.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser

from . import atomic_write

feedparser.USER_AGENT = "vigil/0.1 (cyber-signal brief; read-only)"


def _to_dt(struct_time) -> datetime | None:
    if not struct_time:
        return None
    return datetime.fromtimestamp(time.mktime(struct_time), tz=timezone.utc)


def fetch_feed(url: str) -> list[dict]:
    parsed = feedparser.parse(url)
    feed_title = ""
    if hasattr(parsed, "feed") and parsed.feed:
        feed_title = parsed.feed.get("title", "") or ""
    feed_title = feed_title or url
    out = []
    for e in parsed.entries:
        published = _to_dt(e.get("published_parsed") or e.get("updated_parsed"))
        out.append({
            "feed": feed_title,
            "title": e.get("title", "(untitled)"),
            "link": e.get("link", ""),
            "guid": e.get("id") or e.get("link") or e.get("title", ""),
            "published": published.isoformat() if published else None,
            "summary": (e.get("summary") or "")[:500],
        })
    return out


def get_new_items(data_dir: Path, urls: list[str], *,
                  window_hours: int = 24,
                  now: datetime | None = None,
                  ) -> tuple[list[dict], dict[str, int]]:
    """Returns (new_items_in_window, per-feed total item counts)."""
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)
    seen_path = data_dir / "seen.json"
    seen: set[str] = set()
    if seen_path.exists():
        seen = set(json.loads(seen_path.read_text()))
    new_items: list[dict] = []
    new_seen = set(seen)
    counts: dict[str, int] = {}
    for url in urls:
        items = fetch_feed(url)
        counts[url] = len(items)
        for item in items:
            guid = item["guid"]
            if not guid or guid in seen:
                continue
            pub_iso = item["published"]
            if pub_iso:
                try:
                    pub_dt = datetime.fromisoformat(pub_iso)
                except ValueError:
                    pub_dt = None
                if pub_dt and pub_dt < cutoff:
                    # Out-of-window but newly seen: mark seen so we don't
                    # reconsider it tomorrow.
                    new_seen.add(guid)
                    continue
            new_items.append(item)
            new_seen.add(guid)
    atomic_write(seen_path, json.dumps(sorted(new_seen)))
    return new_items, counts
