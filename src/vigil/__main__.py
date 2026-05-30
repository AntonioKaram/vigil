"""vigil entry point — run once, exit.

Fetches sources, applies inclusion logic, builds the Codex prompt, runs the
brief, posts it to #vigil via the OWUI webhook, emails it to the operator,
and appends a record to runs.jsonl.

Each delivery leg is independent. If one fails the other still ships; if
both fail, main returns non-zero so run.sh can page via notify.sh.
"""
from __future__ import annotations

import json
import os
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from . import _paths, brief, deliver, post
from . import prompt as prompt_mod
from .sources import epss, kev, nvd, rss


def _config_path() -> Path:
    if cfg := os.environ.get("VIGIL_CONFIG"):
        return Path(cfg).expanduser()
    # src/vigil/__main__.py -> project root is parents[2]
    return Path(__file__).resolve().parents[2] / "config.toml"


def _load_config() -> dict:
    with open(_config_path(), "rb") as f:
        return tomllib.load(f)


def _candidate_cves(nvd_items: list[dict],
                    epss_scores: dict[str, dict],
                    cfg: dict) -> list[dict]:
    """Apply inclusion rules to the NVD set.

    A CVE enters if any of:
      - EPSS >= epss_high, or percentile >= epss_top_decile
      - CVSS from any source >= cvss_high
    KEV-listed CVEs are surfaced separately (always-include), so we don't
    duplicate them here.
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


def main(argv: list[str] | None = None) -> int:
    cfg = _load_config()
    data_dir = _paths.data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    kev_new, kev_first = kev.get_new_kev_entries(data_dir)
    epss_curr, epss_moves, epss_first = epss.get_epss_state(
        data_dir,
        delta_threshold=cfg["thresholds"]["epss_delta"],
        top_decile=cfg["thresholds"]["epss_top_decile"],
    )
    nvd_items = nvd.fetch_last_24h()
    news, feed_counts = rss.get_new_items(data_dir, cfg["feeds"]["rss"])

    candidates = _candidate_cves(nvd_items, epss_curr, cfg)

    caps = cfg["caps"]
    kev_capped = kev_new[: caps["kev"]]
    cands_capped = candidates[: caps["cve"]]
    moves_capped = epss_moves[: caps["cve"]]
    news_capped = news[: caps["news"]]

    first_run = kev_first or epss_first

    prompt_text = prompt_mod.build_prompt(
        kev_new=kev_capped,
        epss_movers=moves_capped,
        cve_candidates=cands_capped,
        news=news_capped,
        first_run=first_run,
    )

    brief_text = brief.run_codex(prompt_text)

    sys.stdout.write(brief_text)
    if not brief_text.endswith("\n"):
        sys.stdout.write("\n")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    subject = f"vigil: daily cyber brief {today}"
    delivery_errors: list[str] = []
    try:
        post.post(brief_text)
    except Exception as e:
        delivery_errors.append(f"post: {e!r}")
    try:
        deliver.send_brief(subject=subject, body=brief_text)
    except Exception as e:
        delivery_errors.append(f"deliver: {e!r}")
    for err in delivery_errors:
        level = "ERROR" if len(delivery_errors) == 2 else "WARN"
        print(f"DELIVERY {level}: {err}", file=sys.stderr)

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
        "brief": brief_text,
    }
    with open(run_log, "a") as f:
        f.write(json.dumps(record) + "\n")
    return 1 if len(delivery_errors) == 2 else 0


if __name__ == "__main__":
    sys.exit(main())
