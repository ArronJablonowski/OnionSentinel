#!/usr/bin/env python3
"""Load bounded, owner-only cohort evaluation inputs without following links."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any


@dataclass(frozen=True)
class PrivateInputPolicy:
    maximum_bytes: int
    error: type[RuntimeError]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def private_regular_file(
    path: Path,
    label: str,
    policy: PrivateInputPolicy,
) -> Path:
    """Require an owner-only regular input within the configured size bound."""
    target = path.expanduser()
    if target.is_symlink() or not target.is_file():
        raise policy.error(f"{label} is not a regular file: {target}")
    metadata = target.stat()
    if metadata.st_uid != os.geteuid():
        raise policy.error(f"{label} is not owned by the current user")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        raise policy.error(
            f"{label} must be owner-only (0600); current mode is {mode:04o}"
        )
    if metadata.st_size > policy.maximum_bytes:
        raise policy.error(f"{label} exceeds the bounded input size")
    return target.resolve()


def load_private_json(
    path: Path,
    label: str,
    policy: PrivateInputPolicy,
) -> tuple[dict[str, Any], str]:
    """Return one private JSON object and the digest of its exact source bytes."""
    target = private_regular_file(path, label, policy)
    try:
        raw = target.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise policy.error(
            f"could not read {label}: {type(exc).__name__}"
        ) from exc
    if not isinstance(document, dict):
        raise policy.error(f"{label} root must be an object")
    return document, hashlib.sha256(raw).hexdigest()
