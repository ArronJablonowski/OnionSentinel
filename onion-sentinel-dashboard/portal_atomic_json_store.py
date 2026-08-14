"""Crash-safe owner-only JSON document persistence."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_owner_only_json(path: Path, document: dict) -> None:
    """Durably replace one JSON document without leaving staged content."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, staged_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    staged = Path(staged_name)
    descriptor_open = True
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor_open = False
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        staged.chmod(0o600)
        staged.replace(path)
        _sync_directory(path.parent)
    finally:
        if descriptor_open:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            staged.unlink(missing_ok=True)
        except OSError:
            pass
