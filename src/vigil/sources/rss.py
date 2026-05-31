"""RSS — 4 feeds by default (Krebs, BleepingComputer, The Hacker News, SANS ISC).

Pipeline (v1.2 A2 rewrite):
  1. Fetch each feed; capture parse errors per-source.
  2. Window-first filter: keep items with tz-aware UTC pubdate >= now-24h.
     Items without a parseable pubdate are excluded — we can't verify
     they're in window and we'd rather drop a possibly-fresh item than
     pollute the brief with possibly-ancient ones.
  3. Dedupe against seen.json.
  4. Update seen.json with every in-window guid + prune entries older
     than the horizon (default 7 days) so seen stays bounded and items
     can re-enter the brief if they get re-published later.

seen.json format change: was `[guid, ...]`, now `{guid: pub_iso_or_null}`.
The list format is auto-migrated on load; migrated entries are timestamped
"now" so they age out within the horizon instead of masking forever.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser

from . import atomic_write

feedparser.USER_AGENT = "vigil/0.1 (cyber-signal brief; read-only)"

SEEN_HORIZON_DAYS = 7


def _to_dt(struct_time) -> datetime | None:
    if not struct_time:
        return None
    return datetime.fromtimestamp(time.mktime(struct_time), tz=timezone.utc)


def _parse_iso_utc(s: str | None) -> datetime | None:
    """Parse ISO 8601 to a tz-aware UTC datetime. None on failure.

    Naive inputs are defensively treated as UTC — fetch_feed always emits
    tz-aware ISO so this is belt-and-braces against a single stray naive
    comparison reintroducing the A2 bug.
    """
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def fetch_feed(url: str) -> tuple[list[dict], str | None]:
    """Returns (items, err). feedparser doesn't raise on dead feeds —
    .bozo + .bozo_exception signal parse trouble. We surface the message
    so __main__ can put it in runs.jsonl[source_errors].
    """
    parsed = feedparser.parse(url)
    err: str | None = None
    if parsed.bozo and not parsed.entries:
        err = str(getattr(parsed, "bozo_exception", "")) or "bozo"

    feed_title = ""
    if hasattr(parsed, "feed") and parsed.feed:
        feed_title = parsed.feed.get("title", "") or ""
    feed_title = feed_title or url

    out: list[dict] = []
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
    return out, err


def _in_window(item: dict, cutoff: datetime) -> bool:
    pub_dt = _parse_iso_utc(item.get("published"))
    if pub_dt is None:
        return False
    return pub_dt >= cutoff


def _load_seen(path: Path) -> dict[str, str | None]:
    """Load seen.json. Auto-migrates the legacy list format to dict.

    Migrated entries get a "now" timestamp so they age out within the
    horizon rather than masking matching guids forever.
    """
    if not path.exists():
        return {}
    raw = json.loads(path.read_text())
    if isinstance(raw, list):
        now_iso = datetime.now(timezone.utc).isoformat()
        return {g: now_iso for g in raw}
    if isinstance(raw, dict):
        return raw
    return {}


def _prune_seen(seen: dict[str, str | None],
                horizon_cutoff: datetime) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for guid, pub_iso in seen.items():
        pub_dt = _parse_iso_utc(pub_iso)
        if pub_dt is None:
            # No parseable timestamp — keep, but a future-cycle update
            # will refresh pub_iso once the item is re-sighted with a date.
            out[guid] = pub_iso
            continue
        if pub_dt >= horizon_cutoff:
            out[guid] = pub_iso
    return out


def get_new_items(data_dir: Path, urls: list[str], *,
                  window_hours: int = 24,
                  horizon_days: int = SEEN_HORIZON_DAYS,
                  now: datetime | None = None,
                  ) -> tuple[list[dict], dict[str, int], dict[str, str]]:
    """Returns (new_items, per-feed counts, per-source errors).

    Stages: fetch + capture errors → window-filter → dedupe → update + prune seen.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)
    horizon_cutoff = now - timedelta(days=horizon_days)

    seen_path = data_dir / "seen.json"
    seen = _load_seen(seen_path)

    all_items: list[dict] = []
    counts: dict[str, int] = {}
    source_errors: dict[str, str] = {}
    for url in urls:
        items, err = fetch_feed(url)
        counts[url] = len(items)
        if err:
            source_errors[url] = err
        all_items.extend(items)

    in_window = [it for it in all_items if _in_window(it, cutoff)]
    new_items = [
        it for it in in_window
        if it.get("guid") and it["guid"] not in seen
    ]

    for it in in_window:
        guid = it.get("guid")
        if not guid:
            continue
        seen[guid] = it.get("published")

    seen = _prune_seen(seen, horizon_cutoff)
    atomic_write(seen_path, json.dumps(seen, separators=(",", ":"), sort_keys=True))

    return new_items, counts, source_errors
