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


def _build_item(cve_id: str, *,
                kev_by_id: dict, cand_by_id: dict, mover_by_id: dict,
                epss_curr: dict) -> dict | None:
    """Gather all available structured fields about a cve_id.

    Returns None if the cve_id isn't in any of our pools (Codex hallucinated
    or picked something we filtered out).
    """
    k = kev_by_id.get(cve_id)
    c = cand_by_id.get(cve_id)
    m = mover_by_id.get(cve_id)
    if not any((k, c, m)):
        return None
    item: dict = {
        "cve_id": cve_id,
        "cvss": None,
        "cvss_source": None,
        "epss": None,
        "vendor": "",
        "product": "",
        "rationale": "",
        "kev": k is not None,
        "due_date": None,
    }
    if k:
        item["vendor"] = k.get("vendorProject", "")
        item["product"] = k.get("product", "")
        item["due_date"] = k.get("dueDate")
    if c:
        if c.get("cvss"):
            item["cvss"] = c["cvss"]["score"]
            item["cvss_source"] = c["cvss"].get("label", "?")
        if not item["vendor"]:
            item["vendor"] = c.get("vendor", "")
        if not item["product"]:
            item["product"] = c.get("product", "")
        if c.get("epss"):
            item["epss"] = c["epss"]["epss"]
    if item["epss"] is None:
        score = epss_curr.get(cve_id)
        if score:
            item["epss"] = score["epss"]
    return item


def _assemble_brief(rationale: dict, *,
                    kev_by_id: dict, cand_by_id: dict, mover_by_id: dict,
                    epss_curr: dict, news_by_url: dict,
                    date: str, run_id: str) -> dict:
    """Merge Codex's rationale JSON with Python's structured records.

    Tracks seen cve_ids across sections so a CVE can't appear twice even if
    Codex's dedup instruction slips.
    """
    seen_cve_ids: set[str] = set()

    def _section(entries: list[dict], *, with_rise: bool = False) -> list[dict]:
        out = []
        for entry in entries:
            cve_id = entry.get("cve_id")
            if not cve_id or cve_id in seen_cve_ids:
                continue
            item = _build_item(
                cve_id,
                kev_by_id=kev_by_id,
                cand_by_id=cand_by_id,
                mover_by_id=mover_by_id,
                epss_curr=epss_curr,
            )
            if item is None:
                continue
            item["rationale"] = entry.get("rationale", "")
            if with_rise:
                m = mover_by_id.get(cve_id)
                if m:
                    item["epss_prev"] = m["epss_prev"]
                    item["epss_delta"] = m["delta"]
                    if item["epss"] is None:
                        item["epss"] = m["epss_curr"]
            seen_cve_ids.add(cve_id)
            out.append(item)
        return out

    news_out = []
    for entry in rationale.get("news", []):
        url = entry.get("url")
        if not url:
            continue
        n = news_by_url.get(url)
        if not n:
            continue
        news_out.append({
            "title": n.get("title", "?"),
            "source": n.get("feed", ""),
            "url": url,
            "relevance": entry.get("relevance", ""),
        })

    return {
        "date": date,
        "run_id": run_id,
        "notes": rationale.get("notes"),
        "act_now": _section(rationale.get("act_now", [])),
        "rising":  _section(rationale.get("rising", []), with_rise=True),
        "cves":    _section(rationale.get("cves", [])),
        "news":    news_out,
    }


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
    news, feed_counts = rss.get_new_items(data_dir, cfg["feeds"]["rss"])

    # Gate + cap
    candidates = _candidate_cves(nvd_items, epss_curr, cfg)
    caps = cfg["caps"]
    kev_capped = kev_new[: caps["kev"]]
    cands_capped = candidates[: caps["cve"]]
    moves_capped = epss_moves[: caps["cve"]]
    news_capped = news[: caps["news"]]
    first_run = kev_first or epss_first

    # Codex: selection + rationale (JSON)
    prompt_text = prompt_mod.build_brief_prompt(
        kev_new=kev_capped,
        epss_movers=moves_capped,
        cve_candidates=cands_capped,
        news=news_capped,
        first_run=first_run,
    )
    rationale_text = brief.run_codex(prompt_text)
    rationale = brief.parse_rationale_json(rationale_text)

    # Lookup tables
    kev_by_id = {k["cveID"]: k for k in kev_capped if k.get("cveID")}
    cand_by_id = {c["cve"]: c for c in cands_capped if c.get("cve")}
    mover_by_id = {m["cve"]: m for m in moves_capped if m.get("cve")}
    news_by_url = {n["link"]: n for n in news_capped if n.get("link")}

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_id = f"{_release_sha()}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"

    brief_obj = _assemble_brief(
        rationale,
        kev_by_id=kev_by_id,
        cand_by_id=cand_by_id,
        mover_by_id=mover_by_id,
        epss_curr=epss_curr,
        news_by_url=news_by_url,
        date=today,
        run_id=run_id,
    )

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
        "brief": brief_obj,
    }
    with open(run_log, "a") as f:
        f.write(json.dumps(record) + "\n")

    return 1 if len(delivery_errors) == 2 else 0


if __name__ == "__main__":
    sys.exit(main())
