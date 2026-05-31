#!/bin/zsh
# Entry point for the vigil-listener LaunchAgent. KeepAlive=true in the plist
# handles auto-restart on crash, so this stays minimal — the long-running
# loop, signal handling, and error recovery all live inside listen.py.
set -u
cd "$(dirname "$0")"

mkdir -p "$HOME/work/agents/vigil/logs/stdout" \
         "$HOME/work/agents/vigil/logs/stderr"

if [[ ! -x .venv/bin/python ]]; then
    echo "vigil-listener: .venv missing at $(pwd)/.venv — run 'uv sync'." >&2
    exit 1
fi

exec .venv/bin/python -m vigil.listen
