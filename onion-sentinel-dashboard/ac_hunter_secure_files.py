"""Owner-only, no-follow, bounded AC Hunter trust-file reads."""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Type


def _initial_file_invalid(
    info: os.stat_result,
    *,
    maximum_bytes: int,
    exact_mode: int,
    allow_empty: bool,
) -> bool:
    return (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != exact_mode
        or (not allow_empty and info.st_size <= 0)
        or info.st_size > maximum_bytes
    )


def _opened_file_changed(
    opened: os.stat_result,
    before: os.stat_result,
    exact_mode: int,
) -> bool:
    return (
        opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
        or opened.st_uid != before.st_uid
        or opened.st_size != before.st_size
        or stat.S_IMODE(opened.st_mode) != exact_mode
        or not stat.S_ISREG(opened.st_mode)
    )


def _read_bounded_descriptor(descriptor: int, maximum_bytes: int) -> bytes:
    chunks = []
    remaining = maximum_bytes + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(64 * 1024, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _open_and_read(
    path: Path,
    before: os.stat_result,
    *,
    maximum_bytes: int,
    exact_mode: int,
    error_type: Type[Exception],
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(path), flags)
    try:
        opened = os.fstat(descriptor)
        if _opened_file_changed(opened, before, exact_mode):
            raise error_type(
                f"AC Hunter trust file changed while opening: {path.name}"
            )
        return _read_bounded_descriptor(descriptor, maximum_bytes)
    finally:
        os.close(descriptor)


def read_secure_file_bytes(
    path: Path,
    *,
    maximum_bytes: int,
    exact_mode: int,
    allow_empty: bool,
    error_type: Type[Exception],
) -> bytes:
    """Read one same-UID regular file without following symlinks."""

    try:
        before = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise error_type(
            f"AC Hunter trust file is unavailable: {path.name}"
        ) from exc
    if _initial_file_invalid(
        before,
        maximum_bytes=maximum_bytes,
        exact_mode=exact_mode,
        allow_empty=allow_empty,
    ):
        raise error_type(
            f"AC Hunter trust file failed owner-only validation: {path.name}"
        )
    try:
        raw = _open_and_read(
            path,
            before,
            maximum_bytes=maximum_bytes,
            exact_mode=exact_mode,
            error_type=error_type,
        )
    except error_type:
        raise
    except OSError as exc:
        raise error_type(
            f"AC Hunter trust file could not be read: {path.name}"
        ) from exc
    if len(raw) > maximum_bytes:
        raise error_type(
            f"AC Hunter trust file exceeds its byte limit: {path.name}"
        )
    return raw
