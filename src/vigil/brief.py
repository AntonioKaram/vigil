"""Call Codex (read-only sandbox) and extract the final agent message.

Per spec: `codex exec --json --sandbox read-only`. The JSONL event schema
has drifted in past versions (completion event was renamed turn.completed
where older tooling expected response.completed), so we scan event payloads
structurally rather than hardcoding event-type paths.
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


def run_codex(prompt: str, *, timeout: int = 600) -> str:
    """Send prompt to Codex on stdin; return the final assistant message text.

    If `codex exec` in your build doesn't accept stdin, swap to passing the
    prompt as a positional argument: CODEX_CMD + [prompt].
    """
    proc = subprocess.run(
        CODEX_CMD,
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
