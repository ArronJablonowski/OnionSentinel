"""Crash-safe publication helpers for generated Onion Sentinel assets."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_text(path: Path, value: str, *, mode: int = 0o644) -> Path:
    """Durably replace ``path`` without exposing a partially written file.

    Dashboard readers run concurrently with the builder. Writing beside the
    destination, syncing, and then using ``os.replace`` gives those readers
    either the previous complete file or the next complete file.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, destination)
        _sync_directory(destination.parent)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def atomic_write_json(path: Path, value: Any, *, mode: int = 0o644) -> Path:
    """Serialize JSON deterministically and publish it atomically."""
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    return atomic_write_text(path, rendered, mode=mode)


def _sync_directory(directory: Path) -> None:
    """Persist the rename where the platform supports directory fsync."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
