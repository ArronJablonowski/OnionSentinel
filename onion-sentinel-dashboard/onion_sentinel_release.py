"""Literal, secret-safe runtime release identity loading."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
from typing import Any


def current_runtime_release_id(
    *,
    environ: object,
    env_path: Path,
    env_key: str,
    release_pattern: re.Pattern[str],
    max_bytes: int,
) -> str:
    supplied, candidate = _explicit_candidate(environ, env_key)
    if supplied:
        return candidate if release_pattern.fullmatch(candidate) else ""
    raw = _read_private_runtime_env(env_path, max_bytes=max_bytes)
    if raw is None:
        return ""
    candidate = _single_literal_value(raw, env_key)
    return candidate if release_pattern.fullmatch(candidate) else ""


def _explicit_candidate(source: object, env_key: str) -> tuple[bool, str]:
    try:
        supplied = env_key in source  # type: ignore[operator]
    except TypeError:
        return False, ""
    if not supplied:
        return False, ""
    value = source.get(env_key, "")  # type: ignore[attr-defined]
    return True, value if isinstance(value, str) else ""


def _read_private_runtime_env(path: Path, *, max_bytes: int) -> bytes | None:
    try:
        metadata = path.lstat()
        if not _private_regular_file(metadata, max_bytes=max_bytes):
            return None
        raw = path.read_bytes()
    except OSError:
        return None
    return raw if len(raw) <= max_bytes else None


def _private_regular_file(metadata: Any, *, max_bytes: int) -> bool:
    return (
        not stat.S_ISLNK(metadata.st_mode)
        and stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        and metadata.st_size <= max_bytes
    )


def _single_literal_value(raw: bytes, env_key: str) -> str:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return ""
    candidates: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == env_key:
            candidates.append(value.strip())
    return candidates[0] if len(candidates) == 1 else ""
