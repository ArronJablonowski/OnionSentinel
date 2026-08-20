"""Bound the wake/resume grace before SQLite backup SLO evaluation."""

from __future__ import annotations

from pathlib import Path
import time
from typing import Callable


DEFAULT_MAX_AGE_SECONDS = 2 * 60 * 60
DEFAULT_GRACE_SECONDS = 90
DEFAULT_POLL_SECONDS = 1


def newest_backup_age_seconds(
    backup_dir: Path,
    *,
    now: float | None = None,
) -> int | None:
    """Return the age of the newest non-symlinked backup commit metadata."""
    candidates = [
        path
        for path in backup_dir.glob("*.backup.json")
        if path.is_file() and not path.is_symlink()
    ]
    if not candidates:
        return None
    current_time = time.time() if now is None else now
    newest = max(path.stat().st_mtime for path in candidates)
    return max(0, int(current_time - newest))


def wait_for_fresh_backup(
    backup_dir: Path,
    *,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    grace_seconds: int = DEFAULT_GRACE_SECONDS,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    wall_time: Callable[[], float] = time.time,
    monotonic_time: Callable[[], float] = time.monotonic,
) -> bool:
    """Wait only when backup evidence is stale, then report final freshness."""

    def is_fresh() -> bool:
        age = newest_backup_age_seconds(backup_dir, now=wall_time())
        return age is not None and age <= max_age_seconds

    if is_fresh():
        return True
    deadline = monotonic_time() + grace_seconds
    while True:
        remaining = deadline - monotonic_time()
        if remaining <= 0:
            return False
        time.sleep(min(poll_seconds, remaining))
        if is_fresh():
            return True
