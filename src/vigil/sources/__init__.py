"""vigil source fetchers (KEV, EPSS, NVD, RSS)."""
from __future__ import annotations

from pathlib import Path


def atomic_write(path: Path, content: str) -> None:
    """Write content to path atomically (tmp + rename).

    Avoids leaving a corrupt prev-day snapshot if the process crashes mid-write,
    which would silently break tomorrow's diff.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    tmp.replace(path)
