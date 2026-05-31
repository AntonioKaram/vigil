"""Call Codex (read-only sandbox) and extract the final agent message.

v1: `codex exec --json --sandbox read-only --skip-git-repo-check` (+ stdin
prompt). The JSONL event schema has drifted in past versions (completion
event was renamed turn.completed where older tooling expected
response.completed), so we scan event payloads structurally rather than
hardcoding event-type paths.

v1.1: same Codex invocation; the *brief* prompt now asks Codex for a JSON
rationale object. parse_rationale_json() pulls that object out defensively
(handles bare JSON, ```json fences, prose preambles, etc.); on parse failure
it returns an empty rationale skeleton so the renderer can still produce
output from Python's structured data.

For Q&A (Feature 2), run_codex(..., web_search=True) flips the web-search
feature on. Session-resume is handled by the caller (listen.py).
"""
from __future__ import annotations

import json
import subprocess
from typing import Iterable

# --skip-git-repo-check: release dirs are git-archive snapshots, no .git.
CODEX_CMD = ["codex", "exec", "--json", "--sandbox", "read-only", "--skip-git-repo-check"]

TEXT_FIELDS = ("text", "output_text", "value")
CONTAINER_FIELDS = (
    "content", "message", "response", "turn", "delta",
    "item", "output", "items", "outputs",
)


def run_codex(prompt: str, *,
              timeout: int = 600,
              web_search: bool = False) -> str:
    """Send prompt to Codex on stdin; return the final assistant message text.

    Set web_search=True for Q&A invocations (operator-approved injection risk
    is in scope: RSS-sourced URLs may be attacker-controlled, but the Q&A
    system prompt instructs Codex to treat fetched content as untrusted data).

    If `codex exec` in your build doesn't accept stdin, swap to passing the
    prompt as a positional argument: cmd + [prompt].
    """
    cmd = list(CODEX_CMD)
    if web_search:
        cmd += ["--enable", "web_search"]
    proc = subprocess.run(
        cmd,
        input=prompt,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"codex exec failed (rc={proc.returncode}): "
            f"{(proc.stderr or '')[-2000:]}"
        )
    return extract_final_message(proc.stdout.splitlines())


def extract_final_message(lines: Iterable[str]) -> str:
    """Scan JSONL and return the largest substantive assistant payload.

    The final assistant turn is typically the largest single text block in
    the stream. Picking the largest payload survives event-type renames.
    """
    longest = ""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        text = _harvest_text(evt)
        if text and len(text) > len(longest):
            longest = text
    if not longest:
        raise RuntimeError("no assistant message found in Codex output")
    return longest


def _harvest_text(evt, depth: int = 0) -> str:
    """Recursively pull text-like strings from an event dict/list.

    Walks text-bearing leaf fields and known container keys. Bounded depth
    to avoid pathological structures.
    """
    if depth > 10:
        return ""
    if isinstance(evt, str):
        return evt
    if isinstance(evt, list):
        return "\n".join(
            s for s in (_harvest_text(x, depth + 1) for x in evt) if s
        )
    if not isinstance(evt, dict):
        return ""
    for k in TEXT_FIELDS:
        v = evt.get(k)
        if isinstance(v, str) and v:
            return v
    chunks = []
    for k in CONTAINER_FIELDS:
        if k in evt:
            sub = _harvest_text(evt[k], depth + 1)
            if sub:
                chunks.append(sub)
    return "\n".join(chunks).strip()


# ---------------------------------------------------------------------------
# Rationale-JSON parsing (v1.1 brief output)
# ---------------------------------------------------------------------------

def empty_rationale() -> dict:
    """Empty rationale shape — used as the fallback when parsing fails."""
    return {"notes": None, "act_now": [], "rising": [], "cves": [], "news": []}


def parse_rationale_json(text: str) -> dict:
    """Parse Codex's brief-rationale JSON defensively.

    Tries (in order): bare JSON, ```json fence, ``` fence, outermost {...}
    block. On any failure, returns empty_rationale() so the renderer can
    still merge with Python's structured data and produce output.

    Returns a dict with keys: notes (str|None), act_now/rising/cves/news
    (lists of dicts). Unexpected/malformed entries are filtered out.
    """
    parsed = _try_parse(text)
    if not isinstance(parsed, dict):
        return empty_rationale()
    return {
        "notes": parsed["notes"] if isinstance(parsed.get("notes"), str) else None,
        "act_now": _list_of_dicts(parsed.get("act_now")),
        "rising":  _list_of_dicts(parsed.get("rising")),
        "cves":    _list_of_dicts(parsed.get("cves")),
        "news":    _list_of_dicts(parsed.get("news")),
    }


def _try_parse(text: str):
    """Return a parsed object or None. Tries multiple strategies."""
    text = text.strip()
    if not text:
        return None
    # 1. Bare JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # 2. ```json ... ``` fence
    for fence in ("```json", "```JSON", "```"):
        i = text.find(fence)
        if i == -1:
            continue
        body_start = text.find("\n", i)
        if body_start == -1:
            continue
        body_start += 1
        end = text.find("```", body_start)
        if end == -1:
            continue
        try:
            return json.loads(text[body_start:end].strip())
        except json.JSONDecodeError:
            continue
    # 3. Outermost balanced {...} block
    block = _outermost_brace_block(text)
    if block:
        try:
            return json.loads(block)
        except json.JSONDecodeError:
            pass
    return None


def _outermost_brace_block(text: str) -> str | None:
    """Find first '{' and return through its matching '}'.

    Tracks strings and escapes so JSON-quoted braces don't confuse balance.
    """
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
    return None


def _list_of_dicts(v) -> list[dict]:
    if not isinstance(v, list):
        return []
    return [x for x in v if isinstance(x, dict)]
