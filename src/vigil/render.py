"""Render the structured brief object to channel markdown and HTML email.

The brief object is assembled in __main__.py from Python-owned source records
+ Codex's rationale JSON (parsed via brief.parse_rationale_json). One renderer
emits both the markdown for the OWUI webhook and the HTML for the multipart
email, so the two stay in lockstep.
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

# templates/ lives at the repo root (sibling of src/), shipped via git archive.
TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html", "htm", "j2"]),
)


def render_markdown(brief: dict) -> str:
    """Render the channel-facing markdown brief."""
    parts: list[str] = []
    parts.append(f"# vigil · daily cyber brief · {brief.get('date', '')}")
    if brief.get("notes"):
        parts.append("")
        parts.append(f"_{brief['notes']}_")
    parts.append("")

    parts.append("## 1. Act now")
    items = brief.get("act_now") or []
    if items:
        for it in items:
            parts.append(_md_cve_line(it, show_kev=True))
            if it.get("rationale"):
                parts.append(f"  {it['rationale']}")
    else:
        parts.append("_Nothing new today._")
    parts.append("")

    parts.append("## 2. Rising risk (EPSS movers)")
    items = brief.get("rising") or []
    if items:
        for it in items:
            parts.append(_md_rising_line(it))
            if it.get("rationale"):
                parts.append(f"  {it['rationale']}")
    else:
        parts.append("_Nothing new today._")
    parts.append("")

    parts.append("## 3. New high-severity CVEs")
    items = brief.get("cves") or []
    if items:
        for it in items:
            if it.get("type") == "kernel_summary":
                parts.append(f"- _{it.get('rationale', '')}_")
                cve_ids = it.get("cve_ids") or []
                if cve_ids:
                    parts.append(f"  CVEs: {', '.join(cve_ids)}")
                continue
            parts.append(_md_cve_line(it))
            if it.get("rationale"):
                parts.append(f"  {it['rationale']}")
    else:
        parts.append("_Nothing new today._")
    parts.append("")

    parts.append("## 4. In the news")
    items = brief.get("news") or []
    if items:
        for n in items:
            title = n.get("title", "?")
            url = n.get("url", "")
            source = n.get("source", "")
            line = f"- [{title}]({url})"
            if source:
                line += f" · {source}"
            parts.append(line)
            if n.get("relevance"):
                parts.append(f"  {n['relevance']}")
    else:
        parts.append("_Nothing new today._")
    parts.append("")

    return "\n".join(parts)


def render_html(brief: dict, *, template_name: str = "email_template.html.j2") -> str:
    """Render the HTML email body via the Jinja2 template."""
    tmpl = _env.get_template(template_name)
    return tmpl.render(brief=brief)


def _md_cve_line(it: dict, *, show_kev: bool = False) -> str:
    cve = it.get("cve_id", "?")
    bits = [f"- **{cve}**"]
    if show_kev and it.get("kev"):
        badge = "[KEV"
        if it.get("due_date"):
            badge += f" due {it['due_date']}"
        badge += "]"
        bits.append(badge)
    cvss = it.get("cvss")
    if cvss is not None:
        src = it.get("cvss_source") or "unknown"
        bits.append(f"| CVSS {cvss:.1f} ({src})")
    else:
        bits.append("| no CVSS")
    epss = it.get("epss")
    if epss is not None:
        bits.append(f"| EPSS {epss:.2f}")
    vendor = (it.get("vendor") or "").strip()
    product = (it.get("product") or "").strip()
    if vendor and product:
        bits.append(f"| {vendor} · {product}")
    elif vendor:
        bits.append(f"| {vendor}")
    elif product:
        bits.append(f"| {product}")
    return " ".join(bits)


def _md_rising_line(it: dict) -> str:
    cve = it.get("cve_id", "?")
    bits = [f"- **{cve}**"]
    prev = it.get("epss_prev")
    curr = it.get("epss")
    delta = it.get("epss_delta")
    if prev is not None and curr is not None:
        if delta is not None:
            bits.append(f"| EPSS {prev:.3f} → {curr:.3f} ({delta:+.3f})")
        else:
            bits.append(f"| EPSS {prev:.3f} → {curr:.3f}")
    vendor = (it.get("vendor") or "").strip()
    product = (it.get("product") or "").strip()
    if vendor and product:
        bits.append(f"| {vendor} · {product}")
    elif vendor:
        bits.append(f"| {vendor}")
    elif product:
        bits.append(f"| {product}")
    return " ".join(bits)
