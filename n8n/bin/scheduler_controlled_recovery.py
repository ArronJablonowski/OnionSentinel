"""Crash-safe replay and retirement of one controlled result spool."""
from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ControlledRecoveryPolicy:
    max_spool_bytes: int
    indeterminate_submission_marker: str


@dataclass(frozen=True)
class ControlledRecoverySources:
    effective_uid: Callable[[], int]
    owner_private_directory: Callable[[Path, Path], bool]
    load_owner_private_json: Callable[..., dict[str, Any]]
    validate_payload: Callable[[dict[str, Any], Any], dict[str, Any]]
    post_result: Callable[[dict[str, Any], str], dict[str, Any]]
    terminal_success: Callable[[Any, dict[str, Any]], bool]
    settle_frozen_memory: Callable[[Path, dict[str, Any]], None]


def controlled_recovery_spool_pending(
    runtime_root: Path,
    *,
    effective_uid: Callable[[], int] = os.getuid,
) -> bool:
    """Return true without following an unsafe recovery-directory symlink."""
    queue_dir = runtime_root / "analysis-index-pending"
    try:
        metadata = queue_dir.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    unsafe = any(
        (
            queue_dir.is_symlink(),
            not stat.S_ISDIR(metadata.st_mode),
            metadata.st_uid != effective_uid(),
            bool(stat.S_IMODE(metadata.st_mode) & 0o077),
        )
    )
    if unsafe:
        return True
    try:
        return any(queue_dir.iterdir())
    except OSError:
        return True


def _exact_spool_path(
    sources: ControlledRecoverySources,
    runtime_root: Path,
) -> Path | None:
    queue_dir = runtime_root / "analysis-index-pending"
    if not queue_dir.exists():
        return None
    if not sources.owner_private_directory(queue_dir, runtime_root):
        raise RuntimeError(
            "controlled evaluation recovery spool directory is unsafe"
        )
    entries = list(queue_dir.iterdir())
    spool_files = [path for path in entries if path.suffix == ".json"]
    if not spool_files:
        if entries:
            raise RuntimeError(
                "controlled evaluation recovery spool contains an unexpected artifact"
            )
        return None
    if len(entries) != 1 or len(spool_files) != 1:
        raise RuntimeError(
            "controlled evaluation recovery requires exactly one spool"
        )
    return spool_files[0]


def _post_or_prove_terminal(
    sources: ControlledRecoverySources,
    policy: ControlledRecoveryPolicy,
    args: Any,
    payload: dict[str, Any],
    recovery: dict[str, Any],
) -> None:
    try:
        receipt = sources.post_result(payload, args.alert_store_url)
        recovery["stored_response_digest"] = str(
            receipt.get("stored_response_sha256") or ""
        ).lower()
    except RuntimeError as error:
        if (
            policy.indeterminate_submission_marker not in str(error)
            or not sources.terminal_success(args, recovery)
        ):
            raise
    else:
        if not sources.terminal_success(args, recovery):
            raise RuntimeError(
                "controlled evaluation recovered result has no exact terminal "
                "database proof"
            )


def _durably_unlink(path: Path) -> None:
    directory = path.parent
    path.unlink()
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def recover_controlled_evaluation_spool(
    sources: ControlledRecoverySources,
    policy: ControlledRecoveryPolicy,
    args: Any,
    runtime_root: Path,
) -> bool:
    """Commit and retire one prior exact lease before any new inference."""
    spool_path = _exact_spool_path(sources, runtime_root)
    if spool_path is None:
        return False
    payload = sources.load_owner_private_json(
        spool_path,
        runtime_root,
        max_bytes=policy.max_spool_bytes,
    )
    recovery = sources.validate_payload(payload, args)
    if spool_path.name != f"{recovery['analysis_id']}.json":
        raise RuntimeError(
            "controlled evaluation recovery spool filename is not exact"
        )
    _post_or_prove_terminal(sources, policy, args, payload, recovery)
    sources.settle_frozen_memory(runtime_root, recovery)
    _durably_unlink(spool_path)
    return True
