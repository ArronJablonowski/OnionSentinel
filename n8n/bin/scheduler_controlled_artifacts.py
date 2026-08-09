"""Owner-private recovery artifacts and frozen-memory settlement."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class FrozenMemoryPolicy:
    directory_names: tuple[str, ...] = (
        "memory-writeback-pending",
        "memory-writeback-committed",
    )
    task_schema: str = "onion-sentinel-memory-writeback-task-v1"
    max_task_bytes: int = 256 * 1024


def owner_private_directory(
    path: Path,
    runtime_root: Path,
    *,
    effective_uid: int,
) -> bool:
    """Return whether one canonical descendant is an owner-only directory."""
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(runtime_root)
    except (FileNotFoundError, OSError, ValueError):
        return False
    return bool(
        resolved == path
        and not path.is_symlink()
        and path.is_dir()
        and metadata.st_uid == effective_uid
        and not (stat.S_IMODE(metadata.st_mode) & 0o077)
    )


def _canonical_artifact_path(path: Path, runtime_root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(runtime_root)
        parent = path.parent.resolve(strict=True)
    except (FileNotFoundError, OSError, ValueError) as exc:
        raise RuntimeError(
            "controlled evaluation recovery artifact is unsafe"
        ) from exc
    if resolved != path or parent != path.parent:
        raise RuntimeError(
            "controlled evaluation recovery artifact is not canonical"
        )
    return resolved


def _validate_artifact_metadata(
    metadata: os.stat_result,
    *,
    effective_uid: int,
    max_bytes: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != effective_uid
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or metadata.st_size > max_bytes
    ):
        raise RuntimeError(
            "controlled evaluation recovery artifact must be one "
            "bounded owner-only regular file"
        )


def load_owner_private_json(
    path: Path,
    runtime_root: Path,
    *,
    max_bytes: int,
    effective_uid: int,
) -> dict[str, Any]:
    """Read one non-symlink owner-only artifact with a strict byte cap."""
    _canonical_artifact_path(path, runtime_root)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        _validate_artifact_metadata(
            os.fstat(descriptor),
            effective_uid=effective_uid,
            max_bytes=max_bytes,
        )
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = -1
            payload = json.load(handle)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "controlled evaluation recovery artifact is invalid JSON"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(payload, dict):
        raise RuntimeError(
            "controlled evaluation recovery artifact must contain an object"
        )
    return payload


def _frozen_task_matches(
    task: dict[str, Any],
    recovery: dict[str, Any],
    policy: FrozenMemoryPolicy,
) -> bool:
    lanes = (task.get("primary"), task.get("reviewer"))
    return bool(
        task.get("schema") == policy.task_schema
        and task.get("analysis_id") == str(recovery["analysis_id"])
        and task.get("submitted_response_sha256")
        == recovery["response_digest"]
        and all(
            isinstance(lane, dict)
            and lane.get("allowed") is False
            and lane.get("candidates") == []
            for lane in lanes
        )
    )


def _durably_unlink(path: Path) -> None:
    path.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def settle_controlled_frozen_memory_artifacts(
    runtime_root: Path,
    recovery: dict[str, Any],
    *,
    policy: FrozenMemoryPolicy,
    effective_uid: int,
) -> None:
    """Remove only exact frozen, response-bound memory tasks."""
    task_name = f"{recovery['analysis_id']}.json"
    for directory_name in policy.directory_names:
        directory = runtime_root / directory_name
        if not directory.exists():
            continue
        if not owner_private_directory(
            directory, runtime_root, effective_uid=effective_uid
        ):
            raise RuntimeError(
                "controlled evaluation memory recovery directory is unsafe"
            )
        task_path = directory / task_name
        if not task_path.exists():
            continue
        task = load_owner_private_json(
            task_path,
            runtime_root,
            max_bytes=policy.max_task_bytes,
            effective_uid=effective_uid,
        )
        if not _frozen_task_matches(task, recovery, policy):
            raise RuntimeError(
                "controlled evaluation frozen-memory task is not exact"
            )
        _durably_unlink(task_path)
