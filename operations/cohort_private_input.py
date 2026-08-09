#!/usr/bin/env python3
"""Load bounded owner-only cohort manifests and frozen source rows."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, Callable, Mapping


@dataclass(frozen=True)
class CohortPrivateInputPolicy:
    error: type[RuntimeError]
    maximum_manifest_bytes: int
    maximum_source_rows_bytes: int
    maximum_cohort_size: int
    validate_manifest_document: Callable[[Mapping[str, Any]], None]


def _private_file(
    path: Path,
    *,
    label: str,
    mode_label: str | None = None,
    maximum_bytes: int,
    policy: CohortPrivateInputPolicy,
) -> Path:
    target = path.expanduser()
    if target.is_symlink() or not target.is_file():
        raise policy.error(f"{label} is not a regular file: {target}")
    metadata = target.stat()
    mode = stat.S_IMODE(metadata.st_mode)
    if mode & 0o077:
        raise policy.error(
            f"{mode_label or label} must be owner-only (0600); "
            f"current mode is {mode:04o}"
        )
    if metadata.st_uid != os.geteuid():
        raise policy.error(f"{label} is not owned by the current user")
    if metadata.st_size > maximum_bytes:
        raise policy.error(f"{label} exceeds the bounded input size")
    return target


def load_private_manifest(
    path: Path,
    policy: CohortPrivateInputPolicy,
) -> dict[str, Any]:
    target = _private_file(
        path,
        label="manifest",
        maximum_bytes=policy.maximum_manifest_bytes,
        policy=policy,
    )
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise policy.error(f"could not read manifest: {type(exc).__name__}") from exc
    if not isinstance(document, dict):
        raise policy.error("unsupported cohort manifest schema")
    policy.validate_manifest_document(document)
    return document


def load_private_source_rows(
    path: Path,
    policy: CohortPrivateInputPolicy,
) -> tuple[list[dict[str, Any]], str]:
    """Load an already-frozen owner-only JSON array without changing its order."""
    target = _private_file(
        path,
        label="source rows file",
        mode_label="source rows",
        maximum_bytes=policy.maximum_source_rows_bytes,
        policy=policy,
    )
    try:
        raw = target.read_bytes()
        document = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise policy.error(
            f"could not read source rows: {type(exc).__name__}"
        ) from exc
    if not _valid_source_rows(document, policy.maximum_cohort_size):
        raise policy.error(
            "source rows must be a JSON array of "
            f"1-{policy.maximum_cohort_size} objects"
        )
    return [dict(item) for item in document], hashlib.sha256(raw).hexdigest()


def _valid_source_rows(document: Any, maximum_cohort_size: int) -> bool:
    return bool(
        isinstance(document, list)
        and document
        and len(document) <= maximum_cohort_size
        and all(isinstance(item, dict) for item in document)
    )
