"""vigil listener — answer operator follow-up questions in #vigil.

Long-running poll loop (`KeepAlive=true` LaunchAgent). For each new
top-level operator message in the channel:

  1. Load today's context (data/context-today.json — the full pool, not
     just the capped brief).
  2. Build a Q&A prompt and call Codex (read-only sandbox, web search ON
     per operator decision — the Q&A system prompt warns Codex to treat
     fetched-content as untrusted).
  3. Post the answer as a threaded reply under the question.
  4. Advance the cursor.

Loop prevention is two-layer:
  - skip if user_id == bot_user_id  (filters bot's own top-level posts)
  - skip if content matches one of the configured own_content_prefixes
    (filters webhook-attributed brief + notify alerts that share user_id
    with the operator)
  - skip if parent_id is set         (any threaded reply — including our
    own answers, which thread under the question)

Multi-turn memory: within a single day we use `codex exec resume --last`
so follow-ups like "and the second one?" continue the same session. At
day rollover (context-today.json's date changes) the next call starts a
fresh session.

Cursor: nanosecond `created_at` of the last message we've processed.
Persisted atomically in data/listener-cursor.json. On first start
(no cursor file) the cursor is initialized to "now" so the listener
doesn't try to answer the channel's history.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import httpx

from . import _paths, prompt as prompt_mod
from .sources import atomic_write

# --skip-git-repo-check: release dirs are git-archive snapshots, no .git.
# --enable web_search: Q&A goes online (operator-accepted injection risk).
CODEX_CMD = [
    "codex", "exec",
    "--json", "--sandbox", "read-only",
    "--skip-git-repo-check",
    "--enable", "web_search",
]
CODEX_RESUME_CMD = [
    "codex", "exec", "resume", "--last",
    "--json", "--sandbox", "read-only",
    "--skip-git-repo-check",
    "--enable", "web_search",
]
CODEX_TIMEOUT = 600

OWUI_URL = os.environ.get("OPEN_WEBUI_URL", "http://localhost:3000")
HTTP_TIMEOUT = 30.0


# ---------------------------------------------------------------------------
# config / paths
# ---------------------------------------------------------------------------

def _config_path() -> Path:
    if cfg := os.environ.get("VIGIL_CONFIG"):
        return Path(cfg).expanduser()
    return Path(__file__).resolve().parents[2] / "config.toml"


def _load_config() -> dict:
    with open(_config_path(), "rb") as f:
        return tomllib.load(f)


def _load_api_key() -> str:
    p = _paths.secrets_dir() / "owui-api-key"
    if not p.exists():
        raise RuntimeError(f"owui-api-key secret missing: {p}")
    key = p.read_text().strip()
    if not key:
        raise RuntimeError(f"owui-api-key file is empty: {p}")
    return key


# ---------------------------------------------------------------------------
# OWUI REST helpers
# ---------------------------------------------------------------------------

def _auth_headers(api_key: str) -> dict:
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }


def post_message(client: httpx.Client, channel_id: str, content: str, *,
                 parent_id: str | None = None,
                 reply_to_id: str | None = None) -> dict:
    body: dict = {"content": content}
    if parent_id:
        body["parent_id"] = parent_id
    if reply_to_id:
        body["reply_to_id"] = reply_to_id
    r = client.post(
        f"{OWUI_URL}/api/v1/channels/{channel_id}/messages/post",
        json=body, timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def delete_message(client: httpx.Client, channel_id: str, message_id: str) -> None:
    r = client.delete(
        f"{OWUI_URL}/api/v1/channels/{channel_id}/messages/{message_id}/delete",
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()


def fetch_messages(client: httpx.Client, channel_id: str, *,
                   limit: int = 50) -> list[dict]:
    r = client.get(
        f"{OWUI_URL}/api/v1/channels/{channel_id}/messages",
        params={"limit": limit, "skip": 0},
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# bot identity discovery
# ---------------------------------------------------------------------------

def discover_bot_user_id(client: httpx.Client, channel_id: str) -> str:
    """Post a tiny probe message, capture our own user_id, delete the probe.

    OWUI's self-info endpoints (/auths, /auths/api_key, /users/{id}) are
    admin-gated, so we discover by posting + reading the response (which
    OWUI populates with the authenticated poster's user_id).
    """
    resp = post_message(
        client, channel_id,
        content="vigil-listener startup probe (auto-deleted)",
    )
    user_id = resp["user_id"]
    probe_id = resp["id"]
    try:
        delete_message(client, channel_id, probe_id)
    except Exception as e:
        print(f"listener: warn — probe cleanup failed: {e}", file=sys.stderr)
    return user_id


# ---------------------------------------------------------------------------
# cursor persistence
# ---------------------------------------------------------------------------

def _cursor_path(data_dir: Path) -> Path:
    return data_dir / "listener-cursor.json"


def load_cursor(data_dir: Path) -> int:
    """Returns the last-processed created_at (nanosecond int).

    On first start with no cursor file, initializes to current time so we
    don't try to answer the channel's history.
    """
    p = _cursor_path(data_dir)
    if p.exists():
        try:
            return int(json.loads(p.read_text()).get("last_created_at", 0))
        except (json.JSONDecodeError, ValueError):
            pass
    # Seed: "now" in nanoseconds (matches OWUI created_at scale)
    now_ns = int(time.time() * 1_000_000_000)
    save_cursor(data_dir, now_ns)
    return now_ns


def save_cursor(data_dir: Path, last_created_at: int) -> None:
    p = _cursor_path(data_dir)
    atomic_write(p, json.dumps({"last_created_at": int(last_created_at)}))


# ---------------------------------------------------------------------------
# message filtering
# ---------------------------------------------------------------------------

def is_question(msg: dict, *,
                bot_user_id: str,
                own_content_prefixes: list[str]) -> bool:
    """Decide whether `msg` is an operator question we should answer.

    Skip if:
      - authored by the bot (our own top-level posts)
      - threaded reply (parent_id set) — covers both our answers and any
        operator follow-up that's already in a thread
      - content starts with one of the brief / notify markers (webhook
        posts share user_id with the operator, so this is the only way
        to tell them apart)
    """
    if msg.get("user_id") == bot_user_id:
        return False
    if msg.get("parent_id"):
        return False
    content = (msg.get("content") or "").lstrip()
    for prefix in own_content_prefixes:
        if content.startswith(prefix):
            return False
    return True


# ---------------------------------------------------------------------------
# Codex Q&A
# ---------------------------------------------------------------------------

class _CodexSession:
    """Tracks day-scoped Codex session state for multi-turn Q&A.

    Within the same day (context-today.json's date), we resume the previous
    session so follow-ups like "and the second one?" work conversationally.
    On day rollover we start fresh — yesterday's context is stale.
    """

    def __init__(self) -> None:
        self._current_date: str | None = None
        self._has_session = False

    def ask(self, question: str, context: dict) -> str:
        ctx_date = context.get("date")
        if ctx_date != self._current_date:
            self._current_date = ctx_date
            self._has_session = False
        cmd = list(CODEX_RESUME_CMD if self._has_session else CODEX_CMD)
        prompt_text = prompt_mod.build_qa_prompt(question, context)
        proc = subprocess.run(
            cmd, input=prompt_text,
            capture_output=True, text=True, timeout=CODEX_TIMEOUT,
        )
        if proc.returncode != 0:
            self._has_session = False  # session might be invalid; restart next time
            raise RuntimeError(
                f"codex Q&A failed (rc={proc.returncode}): "
                f"{(proc.stderr or '')[-1500:]}"
            )
        self._has_session = True
        # Re-use the same defensive JSONL scanner as the brief job.
        from . import brief
        return brief.extract_final_message(proc.stdout.splitlines())


def load_context() -> dict | None:
    """Read data/context-today.json. None if missing (no brief run yet today)."""
    p = _paths.data_dir() / "context-today.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# main loop
# ---------------------------------------------------------------------------

def _format_error_reply(exc: Exception) -> str:
    return (
        "vigil hit an error answering this — "
        f"`{type(exc).__name__}: {exc}`. Try again, or check the listener logs."
    )


def main(argv: list[str] | None = None) -> int:
    cfg = _load_config()
    channel_id = cfg["delivery"]["channel_id"]
    poll_seconds = int(cfg["listener"]["poll_seconds"])
    fetch_limit = int(cfg["listener"]["fetch_limit"])
    own_prefixes = list(cfg["listener"]["own_content_prefixes"])

    api_key = _load_api_key()
    data_dir = _paths.data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    # Graceful shutdown on SIGTERM / SIGINT (launchd uses SIGTERM on bootout).
    _stop = {"flag": False}
    def _on_signal(signum, frame):
        _stop["flag"] = True
        print(f"listener: signal {signum} received, shutting down", file=sys.stderr)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    with httpx.Client(headers=_auth_headers(api_key)) as client:
        bot_user_id = discover_bot_user_id(client, channel_id)
        print(f"listener: bot_user_id={bot_user_id}", file=sys.stderr)

        cursor = load_cursor(data_dir)
        session = _CodexSession()

        print(
            f"listener: started, polling #{channel_id[:8]}.. every "
            f"{poll_seconds}s (initial cursor={cursor})",
            file=sys.stderr,
        )

        while not _stop["flag"]:
            try:
                messages = fetch_messages(client, channel_id, limit=fetch_limit)
            except Exception as e:
                print(f"listener: fetch failed: {e}", file=sys.stderr)
                _sleep_interruptible(poll_seconds, _stop)
                continue

            # OWUI returns newest first; process chronologically.
            messages.sort(key=lambda m: int(m.get("created_at") or 0))

            new_cursor = cursor
            for msg in messages:
                created_at = int(msg.get("created_at") or 0)
                if created_at <= cursor:
                    continue
                if not is_question(
                    msg,
                    bot_user_id=bot_user_id,
                    own_content_prefixes=own_prefixes,
                ):
                    new_cursor = max(new_cursor, created_at)
                    continue

                _handle_question(client, channel_id, msg, session)
                new_cursor = max(new_cursor, created_at)

            if new_cursor != cursor:
                cursor = new_cursor
                try:
                    save_cursor(data_dir, cursor)
                except Exception as e:
                    print(f"listener: cursor save failed: {e}", file=sys.stderr)

            _sleep_interruptible(poll_seconds, _stop)

    print("listener: shutdown clean", file=sys.stderr)
    return 0


def _handle_question(client: httpx.Client, channel_id: str,
                     question: dict, session: _CodexSession) -> None:
    qid = question["id"]
    qtext = question.get("content", "").strip()
    if not qtext:
        return
    print(f"listener: answering id={qid[:8]}.. content={qtext[:80]!r}", file=sys.stderr)

    context = load_context()
    if context is None:
        answer = (
            "No brief has run yet today — context-today.json isn't on disk. "
            "Once the next scheduled brief lands (or a manual run.sh) I can "
            "answer follow-ups."
        )
    else:
        try:
            answer = session.ask(qtext, context)
        except Exception as e:
            print(f"listener: codex Q&A failed: {e}", file=sys.stderr)
            answer = _format_error_reply(e)

    try:
        post_message(
            client, channel_id, answer,
            parent_id=qid, reply_to_id=qid,
        )
    except Exception as e:
        print(f"listener: reply post failed for q={qid[:8]}: {e}", file=sys.stderr)


def _sleep_interruptible(seconds: float, stop_flag: dict) -> None:
    """Sleep in 0.5s ticks so SIGTERM doesn't have to wait the full interval."""
    end = time.monotonic() + seconds
    while time.monotonic() < end and not stop_flag["flag"]:
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
