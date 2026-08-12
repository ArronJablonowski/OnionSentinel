#!/usr/bin/env python3
"""Owner-controlled bounded JSON reads for Software Inventory state."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path


def _state_file_identity(
    path: Path, error_type: type[ValueError]
) -> os.stat_result:
    try:
        return path.lstat()
    except FileNotFoundError as exc:
        raise error_type(
            "Software Inventory has not been collected yet"
        ) from exc
    except OSError as exc:
        raise error_type("Software Inventory state is unavailable") from exc


def _validate_state_file(
    identity: os.stat_result,
    maximum_bytes: int,
    error_type: type[ValueError],
) -> None:
    if stat.S_ISLNK(identity.st_mode) or not stat.S_ISREG(identity.st_mode):
        raise error_type("Software Inventory state is not a regular file")
    if identity.st_uid != os.getuid():
        raise error_type("Software Inventory state has an unexpected owner")
    if identity.st_mode & 0o022:
        raise error_type(
            "Software Inventory state is writable by another user"
        )
    if identity.st_size <= 0 or identity.st_size > maximum_bytes:
        raise error_type("Software Inventory state exceeds its size boundary")


def _open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _verify_opened_file(
    before: os.stat_result,
    opened: os.stat_result,
    error_type: type[ValueError],
) -> None:
    if (
        opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_size != before.st_size
    ):
        raise error_type("Software Inventory state changed while opening")


def _read_bounded_descriptor(descriptor: int, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(1024 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_opened_file(
    path: Path,
    before: os.stat_result,
    maximum_bytes: int,
    error_type: type[ValueError],
) -> bytes:
    try:
        descriptor = os.open(str(path), _open_flags())
        try:
            _verify_opened_file(before, os.fstat(descriptor), error_type)
            return _read_bounded_descriptor(descriptor, maximum_bytes)
        finally:
            os.close(descriptor)
    except error_type:
        raise
    except OSError as exc:
        raise error_type(
            "Software Inventory state could not be read"
        ) from exc


def _decode_state_object(
    raw: bytes, error_type: type[ValueError]
) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise error_type("Software Inventory state is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise error_type("Software Inventory state must be an object")
    return payload


def read_bounded_regular_json(
    path: Path,
    maximum_bytes: int,
    error_type: type[ValueError],
) -> tuple[dict, str]:
    """Read one owner-controlled regular JSON object without following links."""
    before = _state_file_identity(path, error_type)
    _validate_state_file(before, maximum_bytes, error_type)
    raw = _read_opened_file(path, before, maximum_bytes, error_type)
    if len(raw) > maximum_bytes:
        raise error_type("Software Inventory state exceeds its size boundary")
    payload = _decode_state_object(raw, error_type)
    return payload, hashlib.sha256(raw).hexdigest()
