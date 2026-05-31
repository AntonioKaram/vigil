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
# Web search: enabled by default in codex-cli 0.131.0+ (the previous
# `--enable web_search` flag is deprecated and now errors out — observed
# in v1.2.2 deploy where the deprecation message was posted as the
# "answer" to operator follow-ups).
CODEX_CMD_QA = [
    "codex", "exec",
    "--json", "--sandbox", "read-only",
    "--skip-git-repo-check",
]
# B3: resume by explicit thread_id (UUID), never --last. SESSION_ID is a
# positional that follows OPTIONS per `codex exec resume --help`; append
# the thread_id at call time. `--sandbox` is invalid at resume (inherited
# from session start) — fixed in v1.2.2.
CODEX_CMD_QA_RESUME_PREFIX = [
    "codex", "exec", "resume",
    "--json",
    "--skip-git-repo-check",
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


def fetch_thread(client: httpx.Client, channel_id: str,
                 parent_message_id: str) -> list[dict]:
    """Fetch a single message's thread. Returns a flat list that may include
    the parent itself plus all replies; caller is responsible for dedupe.
    """
    r = client.get(
        f"{OWUI_URL}/api/v1/channels/{channel_id}/messages/{parent_message_id}/thread",
        timeout=HTTP_TIMEOUT,
    )
    r.raise_for_status()
    return r.json()


def fetch_messages_with_threads(client: httpx.Client, channel_id: str, *,
                                limit: int,
                                thread_lookback_seconds: float,
                                now_seconds: float | None = None,
                                ) -> list[dict]:
    """v1.2.1: top-level messages + threads for any recent enough parent.

    OWUI's `/messages` endpoint returns top-level messages only, so threaded
    replies stay invisible to flat polling. Threaded operator follow-ups
    (e.g., 'Reply' under the daily brief) end up silently dropped without
    this. Lookback bounds the cost: we only fetch threads for top-level
    messages whose created_at is within `thread_lookback_seconds` of now.
    """
    if now_seconds is None:
        now_seconds = time.time()
    cutoff_ns = int((now_seconds - thread_lookback_seconds) * 1_000_000_000)

    top_level = fetch_messages(client, channel_id, limit=limit)
    seen_by_id: dict[str, dict] = {m["id"]: m for m in top_level if m.get("id")}

    for parent in top_level:
        if int(parent.get("created_at") or 0) < cutoff_ns:
            continue
        # Skip threads with no replies — saves the round-trip.
        if not parent.get("reply_count"):
            continue
        try:
            thread = fetch_thread(client, channel_id, parent["id"])
        except Exception as e:
            print(
                f"listener: thread fetch failed for {parent['id'][:8]}: {e}",
                file=sys.stderr,
            )
            continue
        for m in thread:
            mid = m.get("id")
            if mid:
                seen_by_id.setdefault(mid, m)
    return list(seen_by_id.values())


# ---------------------------------------------------------------------------
# bot identity discovery (B4: pinned to secrets/owui-bot-id, probe is fallback)
# ---------------------------------------------------------------------------

def load_bot_user_id(client: httpx.Client, channel_id: str) -> str:
    """Returns the pinned bot user_id from secrets/owui-bot-id.

    If the file is missing or empty, falls back to probe-and-delete (the
    legacy v1.1 mechanism) AND writes the discovered id to the file so
    subsequent restarts are fast and don't leave stray probes. This makes
    layer 1 of loop prevention reliable enough that we can drop layer 2.
    """
    p = _paths.secrets_dir() / "owui-bot-id"
    if p.exists():
        pinned = p.read_text().strip()
        if pinned:
            return pinned
    # Fallback: probe + delete + persist
    print("listener: bot id not pinned; probing to discover", file=sys.stderr)
    discovered = _discover_via_probe(client, channel_id)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(discovered)
        try:
            p.chmod(0o600)
        except OSError:
            pass
    except OSError as e:
        print(f"listener: warn — could not pin bot id to {p}: {e}", file=sys.stderr)
    return discovered


def _discover_via_probe(client: httpx.Client, channel_id: str) -> str:
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


# Back-compat alias for any external caller (test scripts, prior smoke tests).
discover_bot_user_id = load_bot_user_id


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

def should_answer(msg: dict, *,
                  bot_user_id: str,
                  own_content_prefixes: list[str]) -> bool:
    """B6: respond to every operator message that passes loop prevention.

    There is no question-detection heuristic — imperatives like "tell me
    more about the OneUptime one" are valid follow-ups. The gate here is
    pure loop prevention:

      - layer 1: skip if user_id == bot_user_id. Catches our own REST
        posts. Reliable because the bot id is pinned at setup (B4).
      - layer 3: skip if content starts with a brief or notify prefix.
        Catches webhook brief posts (attributed to the operator's user_id)
        and notify alerts. Layer 2 (parent_id) was dropped in B4 so
        threaded operator follow-ups process correctly.
    """
    if msg.get("user_id") == bot_user_id:
        return False
    content = (msg.get("content") or "").lstrip()
    for prefix in own_content_prefixes:
        if content.startswith(prefix):
            return False
    return True


# Back-compat alias for any external caller; new code uses `should_answer`.
is_question = should_answer


# ---------------------------------------------------------------------------
# Codex Q&A
# ---------------------------------------------------------------------------

def _extract_thread_id(jsonl_lines) -> str | None:
    """Scan codex `--json` output for the thread_id.

    Verified against live codex-cli 0.131.0: the field is `thread_id` on the
    top-level `thread.started` event, e.g.:
      {"type":"thread.started","thread_id":"019e7f51-f58f-7a73-..."}
    The defensive scan walks top-level fields rather than hardcoding the
    event type, in case the schema drifts the way response.completed did.
    """
    for line in jsonl_lines:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(evt, dict) and isinstance(evt.get("thread_id"), str):
            return evt["thread_id"]
    return None


class _CodexSession:
    """B3: day-scoped Codex session with EXPLICIT thread_id persistence.

    First Q&A call of the day runs without resume; we capture the thread_id
    from the JSONL output and persist it to data/listener-session.json with
    today's date. Subsequent calls that day use `codex exec resume <thread_id>`
    so follow-ups continue the same conversation. Day rollover or a failed
    call invalidates the thread_id and starts a fresh session.

    We never use `--last` (the v1.1 mechanism) because --last picks the most
    recent session anywhere on the box, which could be the brief job, an
    interactive session, or a future roster agent's session.
    """

    SESSION_FILE = "listener-session.json"

    def __init__(self, data_dir: Path) -> None:
        self._path = data_dir / self.SESSION_FILE
        self._date, self._thread_id = self._load()

    def _load(self) -> tuple[str | None, str | None]:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                d = data.get("date") if isinstance(data, dict) else None
                t = data.get("thread_id") if isinstance(data, dict) else None
                if isinstance(d, str) and isinstance(t, str):
                    return d, t
            except (json.JSONDecodeError, OSError):
                pass
        return None, None

    def _save(self) -> None:
        atomic_write(
            self._path,
            json.dumps({"date": self._date, "thread_id": self._thread_id}),
        )

    def ask(self, question: str, context: dict) -> str:
        ctx_date = context.get("date")
        if ctx_date != self._date:
            # Day rollover -> fresh session, drop yesterday's thread.
            self._date = ctx_date
            self._thread_id = None

        if self._thread_id:
            cmd = list(CODEX_CMD_QA_RESUME_PREFIX) + [self._thread_id]
        else:
            cmd = list(CODEX_CMD_QA)

        prompt_text = prompt_mod.build_qa_prompt(question, context)
        proc = subprocess.run(
            cmd, input=prompt_text,
            capture_output=True, text=True, timeout=CODEX_TIMEOUT,
        )
        if proc.returncode != 0:
            # Invalidate the thread_id so the next call doesn't blindly try
            # to resume a dead session. _save() persists the cleared state.
            self._thread_id = None
            self._save()
            raise RuntimeError(
                f"codex Q&A failed (rc={proc.returncode}): "
                f"{(proc.stderr or '')[-1500:]}"
            )

        lines = proc.stdout.splitlines()
        if not self._thread_id:
            tid = _extract_thread_id(lines)
            if tid:
                self._thread_id = tid
                self._save()

        from . import brief
        return brief.extract_final_message(lines)


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
# B1 circuit breaker + B2 notify integration
# ---------------------------------------------------------------------------

NOTIFY_SCRIPT = str(Path.home() / "work" / "bin" / "notify.sh")
NOTIFY_AGENT = "vigil-listener"


def notify_fatal(reason: str) -> None:
    """Fire ~/work/bin/notify.sh once per failure episode. Best-effort: the
    listener never raises out of a notify call.
    """
    try:
        subprocess.run(
            [NOTIFY_SCRIPT, NOTIFY_AGENT, "fatal", reason],
            timeout=30, check=False,
        )
    except Exception as e:
        print(f"listener: notify.sh failed: {e}", file=sys.stderr)


class _CircuitBreaker:
    """B1: rolling-window post counter. Trips inert (does NOT exit) when the
    listener posts more than `threshold` answers in `window_seconds`.

    Inert means: keep polling, keep advancing the cursor, just don't answer.
    Exit would cause KeepAlive to restart -> re-trip -> notify-spam-and-flap.

    State persisted to data/listener-breaker.json so the count survives
    crash-restart loops (which the breaker should also catch). Manual reset:
    delete the file then bootout/bootstrap the listener (or just delete the
    file and wait for the breaker's `reload()` on the next poll iteration).
    """

    def __init__(self, data_dir: Path, *,
                 window_seconds: int, threshold: int) -> None:
        self._path = data_dir / "listener-breaker.json"
        self._window = float(window_seconds)
        self._threshold = int(threshold)
        self._state = self._load()
        # Suppress re-notify on restart-into-tripped: only notify on the
        # *transition* from healthy to tripped this process saw.
        self._notified_for_trip = bool(self._state.get("tripped"))

    def _load(self) -> dict:
        if not self._path.exists():
            return {"post_timestamps": [], "tripped": False, "tripped_at": None}
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            return {"post_timestamps": [], "tripped": False, "tripped_at": None}

    def _save(self) -> None:
        atomic_write(self._path, json.dumps(self._state))

    def reload(self) -> None:
        """Re-read state from disk so an externally-deleted breaker file is
        picked up without requiring a listener restart.
        """
        if not self._path.exists() and self._state.get("tripped"):
            print(
                "listener: breaker file missing — treating as external reset",
                file=sys.stderr,
            )
            self._state = {"post_timestamps": [], "tripped": False, "tripped_at": None}
            self._notified_for_trip = False

    def is_tripped(self) -> bool:
        return bool(self._state.get("tripped"))

    def record_post_and_check_trip(self) -> bool:
        """Record a successful post. Returns True iff this post just tripped
        the breaker (transition from healthy to tripped) — caller should
        notify once on True.
        """
        now = time.time()
        cutoff = now - self._window
        timestamps = [
            t for t in (self._state.get("post_timestamps") or [])
            if isinstance(t, (int, float)) and t >= cutoff
        ]
        timestamps.append(now)
        self._state["post_timestamps"] = timestamps
        was_tripped = self._state.get("tripped", False)
        if len(timestamps) > self._threshold:
            self._state["tripped"] = True
            if not was_tripped:
                self._state["tripped_at"] = now
            self._save()
            if not was_tripped and not self._notified_for_trip:
                self._notified_for_trip = True
                return True
            return False
        self._save()
        return False


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
    thread_lookback = float(cfg["listener"].get("thread_lookback_seconds", 86400))
    own_prefixes = list(cfg["listener"]["own_content_prefixes"])
    breaker_cfg = (cfg.get("listener") or {}).get("breaker") or {}
    notify_cfg = (cfg.get("listener") or {}).get("notify") or {}
    consec_failure_threshold = int(notify_cfg.get("consecutive_failures", 5))

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
        bot_user_id = load_bot_user_id(client, channel_id)
        print(f"listener: bot_user_id={bot_user_id}", file=sys.stderr)

        cursor = load_cursor(data_dir)
        session = _CodexSession(data_dir)
        breaker = _CircuitBreaker(
            data_dir,
            window_seconds=int(breaker_cfg.get("window_seconds", 300)),
            threshold=int(breaker_cfg.get("threshold", 10)),
        )
        if breaker.is_tripped():
            print(
                "listener: started in TRIPPED state — polling but not "
                "answering. Reset: rm data/listener-breaker.json, then restart.",
                file=sys.stderr,
            )

        consecutive_failures = 0
        notified_for_failure_episode = False

        print(
            f"listener: started, polling #{channel_id[:8]}.. every "
            f"{poll_seconds}s (initial cursor={cursor})",
            file=sys.stderr,
        )

        while not _stop["flag"]:
            try:
                breaker.reload()
                messages = fetch_messages_with_threads(
                    client, channel_id,
                    limit=fetch_limit,
                    thread_lookback_seconds=thread_lookback,
                )
                messages.sort(key=lambda m: int(m.get("created_at") or 0))

                new_cursor = cursor
                for msg in messages:
                    created_at = int(msg.get("created_at") or 0)
                    if created_at <= cursor:
                        continue
                    if not should_answer(
                        msg,
                        bot_user_id=bot_user_id,
                        own_content_prefixes=own_prefixes,
                    ):
                        new_cursor = max(new_cursor, created_at)
                        continue
                    if breaker.is_tripped():
                        # Inert: skip the answer but advance cursor so we
                        # don't re-evaluate the same backlog on every poll.
                        new_cursor = max(new_cursor, created_at)
                        continue

                    _handle_question(
                        client, channel_id, msg, session, breaker,
                    )
                    new_cursor = max(new_cursor, created_at)

                if new_cursor != cursor:
                    cursor = new_cursor
                    try:
                        save_cursor(data_dir, cursor)
                    except Exception as e:
                        print(f"listener: cursor save failed: {e}", file=sys.stderr)

                # Loop completed cleanly: reset failure counter + episode flag.
                consecutive_failures = 0
                notified_for_failure_episode = False

            except Exception as e:
                consecutive_failures += 1
                print(
                    f"listener: loop failure {consecutive_failures}: "
                    f"{type(e).__name__}: {e}",
                    file=sys.stderr,
                )
                if (consecutive_failures >= consec_failure_threshold
                        and not notified_for_failure_episode):
                    notified_for_failure_episode = True
                    notify_fatal(
                        f"{consecutive_failures} consecutive listener loop "
                        f"failures; latest: {type(e).__name__}: {e}"
                    )

            _sleep_interruptible(poll_seconds, _stop)

    print("listener: shutdown clean", file=sys.stderr)
    return 0


def _handle_question(client: httpx.Client, channel_id: str,
                     question: dict, session: _CodexSession,
                     breaker: _CircuitBreaker) -> None:
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
        return

    if breaker.record_post_and_check_trip():
        notify_fatal(
            f"circuit breaker tripped: posted more than threshold answers in "
            f"the rolling window. Listener is now inert. Reset: rm "
            f"data/listener-breaker.json, then bootout/bootstrap the listener."
        )


def _sleep_interruptible(seconds: float, stop_flag: dict) -> None:
    """Sleep in 0.5s ticks so SIGTERM doesn't have to wait the full interval."""
    end = time.monotonic() + seconds
    while time.monotonic() < end and not stop_flag["flag"]:
        time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
