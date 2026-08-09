#!/usr/bin/env python3
"""Write bounded cohort evaluation artifacts with owner-only permissions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping


def _private_target(path: Path, error: type[RuntimeError]) -> Path:
    target = path.expanduser()
    parent = target.parent.resolve()
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or not parent.is_dir():
        raise error(f"output parent is not a real directory: {parent}")
    os.chmod(parent, 0o700)
    return parent / target.name


def write_private_bytes(
    path: Path,
    payload: bytes,
    *,
    replace: bool = False,
    error: type[RuntimeError] = RuntimeError,
) -> None:
    target = _private_target(path, error)
    if target.is_symlink():
        raise error(f"refusing to replace symlink: {target}")
    if target.exists() and not replace:
        raise error(f"refusing to overwrite output: {target}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        _commit_private_file(descriptor, temporary, target, payload)
    finally:
        if temporary.exists():
            temporary.unlink()


def _commit_private_file(
    descriptor: int, temporary: Path, target: Path, payload: bytes
) -> None:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, target)
    os.chmod(target, 0o600)
    directory_descriptor = os.open(target.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


def write_private_json(
    path: Path,
    document: Mapping[str, Any],
    *,
    maximum_bytes: int,
    replace: bool = False,
    error: type[RuntimeError] = RuntimeError,
) -> None:
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
    if len(payload) > maximum_bytes:
        raise error("rendered JSON report exceeds the size bound")
    write_private_bytes(path, payload + b"\n", replace=replace, error=error)
