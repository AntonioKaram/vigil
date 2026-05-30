#!/bin/zsh
# Entry point invoked by launchd (via the LaunchAgent plist) and runnable
# manually for testing. Activates the venv, runs vigil once, and pages via
# notify.sh on non-zero exit so silent failures don't slip past.
set -u
cd "$(dirname "$0")"

mkdir -p "$HOME/work/agents/vigil/logs/stdout" \
         "$HOME/work/agents/vigil/logs/stderr"

if [[ ! -x .venv/bin/python ]]; then
    msg=".venv missing at $(pwd)/.venv — run 'uv sync' from this directory."
    echo "vigil: $msg" >&2
    "$HOME/work/bin/notify.sh" vigil fatal "$msg"
    exit 1
fi

if ! .venv/bin/python -m vigil; then
    rc=$?
    err_path="$HOME/work/agents/vigil/logs/stderr/launchd.err"
    tail_msg=$(tail -c 200 "$err_path" 2>/dev/null | tr -s '\n' ' ')
    "$HOME/work/bin/notify.sh" vigil fatal "run failed (rc=$rc): ${tail_msg}"
    exit "$rc"
fi
