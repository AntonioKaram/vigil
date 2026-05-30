"""Filesystem path resolution.

AGENT_DATA_DIR (set by the LaunchAgent plist) is authoritative when present.
Fallback is ~/work/agents/vigil/data per the prod layout in the spec.
"""
from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    if d := os.environ.get("AGENT_DATA_DIR"):
        return Path(d).expanduser()
    return Path.home() / "work" / "agents" / "vigil" / "data"


def secrets_dir() -> Path:
    return data_dir().parent / "secrets"


def logs_dir() -> Path:
    return data_dir().parent / "logs"
