"""Build the Codex prompt from the filtered candidate set."""
from __future__ import annotations

SYSTEM = (
    "You are vigil, a daily cyber-signal analyst. Produce a tight, structured "
    "brief ranked by what a security engineer should act on first today. Be "
    "terse and factual. Where context is missing from the data below, say so "
    "rather than guessing."
)

TASK = """Produce a brief in this exact structure, ordered by urgency:

1. **Act now.** Newly KEV-listed vulns, with the CISA remediation due date when present, plus any fresh CVE that is both high-EPSS and high-severity. One line of exploitation context each.

2. **Rising risk (EPSS movers).** CVEs whose exploitation probability jumped overnight, with old and new EPSS. Early warning before KEV.

3. **New high-severity CVEs.** CVE ID, score with its source labeled (NVD vs CNA vs third-party), affected vendor/product when known, one line on why it matters.

4. **In the news.** Top items, one-line relevance call each.

Rules:
- If a section has no items, write "No new items." and move on.
- Lead with what to act on first. Do not pad.
- Do not invent CVEs, scores, or vendors not present in the data above.
- Plain text with markdown structure (headers, bullets). No preamble, no signoff."""


def build_prompt(*,
                 kev_new: list[dict],
                 epss_movers: list[dict],
                 cve_candidates: list[dict],
                 news: list[dict],
                 first_run: bool) -> str:
    parts = [SYSTEM, ""]
    if first_run:
        parts.append(
            "NOTE: This is the first run. KEV diffing and EPSS-delta start "
            "tomorrow — include a single-line note about that in the brief."
        )
        parts.append("")
    parts.append("# DATA")
    parts.append("")
    parts.append("## Newly KEV-listed (last 24h)")
    if kev_new:
        for k in kev_new:
            parts.append(_fmt_kev(k))
    else:
        parts.append("(none)")
    parts.append("")
    parts.append("## EPSS movers (overnight)")
    if epss_movers:
        for m in epss_movers:
            parts.append(
                f"- {m['cve']}: EPSS {m['epss_prev']:.3f} -> {m['epss_curr']:.3f} "
                f"(delta {m['delta']:+.3f}, percentile {m['percentile']:.3f})"
            )
    else:
        parts.append("(none)")
    parts.append("")
    parts.append("## Candidate CVEs (NVD last-24h, filtered by EPSS/CVSS)")
    if cve_candidates:
        for c in cve_candidates:
            parts.append(_fmt_cve(c))
    else:
        parts.append("(none)")
    parts.append("")
    parts.append("## News (last 24h)")
    if news:
        for n in news:
            summary = (n.get("summary") or "").strip()[:300]
            parts.append(
                f"- [{n['feed']}] {n['title']}\n"
                f"  {n['link']}\n"
                f"  {summary}"
            )
    else:
        parts.append("(none)")
    parts.append("")
    parts.append("# TASK")
    parts.append(TASK)
    return "\n".join(parts)


def _fmt_kev(k: dict) -> str:
    cve = k.get("cveID", "?")
    vendor = k.get("vendorProject", "")
    product = k.get("product", "")
    name = k.get("vulnerabilityName", "")
    desc = k.get("shortDescription", "")
    due = k.get("dueDate", "")
    action = k.get("requiredAction", "")
    ransom = k.get("knownRansomwareCampaignUse", "")
    return (
        f"- {cve} -- {vendor} {product}: {name}\n"
        f"  {desc}\n"
        f"  Due: {due}; ransomware-use: {ransom}; action: {action}"
    )


def _fmt_cve(c: dict) -> str:
    cve = c.get("cve", "?")
    cvss = c.get("cvss")
    epss = c.get("epss")
    if cvss:
        cvss_str = (
            f"CVSS {cvss['score']:.1f} v{cvss['version']} "
            f"({cvss.get('label', 'unknown')})"
        )
    else:
        cvss_str = "no CVSS (post-2026-04-15 NVD triage)"
    if epss:
        epss_str = f"EPSS {epss['epss']:.3f} (p{epss['percentile']:.2f})"
    else:
        epss_str = "no EPSS"
    cwe = ", ".join(c.get("cwe") or []) or "no CWE"
    desc = c.get("description", "")
    return f"- {cve} | {cvss_str} | {epss_str} | {cwe}\n  {desc}"
