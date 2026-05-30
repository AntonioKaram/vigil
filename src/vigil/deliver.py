"""Email the brief via Fastmail SMTP submission.

Sender is jarvis@fastmail.org (spec-fixed). The app password and the
operator's recipient address both live in secrets/fastmail.env so the
operator's personal email never enters the repo. SMTP_SSL on port 465
(implicit TLS) — Fastmail's recommended submission path.
"""
from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from . import _paths

SMTP_HOST = "smtp.fastmail.com"
SMTP_PORT = 465
SENDER = "jarvis@fastmail.org"
ENV_FILENAME = "fastmail.env"
TIMEOUT = 30.0


def _parse_env(path: Path) -> dict[str, str]:
    """Minimal KEY=value parser. Strips surrounding quotes and whitespace.

    Ignores blank lines and `#`-prefixed comments. No shell expansion —
    secrets files are not shell scripts.
    """
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def _load_creds() -> tuple[str, str]:
    """Returns (fastmail_password, recipient_email)."""
    env_path = _paths.secrets_dir() / ENV_FILENAME
    if not env_path.exists():
        raise RuntimeError(f"fastmail.env missing: {env_path}")
    env = _parse_env(env_path)
    password = env.get("FASTMAIL_PASSWORD", "")
    recipient = env.get("RECIPIENT_EMAIL", "")
    if not password:
        raise RuntimeError(f"FASTMAIL_PASSWORD missing in {env_path}")
    if not recipient:
        raise RuntimeError(f"RECIPIENT_EMAIL missing in {env_path}")
    return password, recipient


def send_brief(*, subject: str, body: str) -> None:
    """Send the brief to the operator's personal address.

    Raises on auth failure, transport failure, or any SMTP error. The
    caller decides whether to surface (success path: log + continue) or
    page (failure path: notify).
    """
    password, recipient = _load_creds()
    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=TIMEOUT) as s:
        s.login(SENDER, password)
        s.send_message(msg)
