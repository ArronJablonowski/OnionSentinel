#!/usr/bin/env python3
"""Owner-controlled atomic activation and rollback for signed v2 registries."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Iterator, Mapping

import investigation_skill_registry_v2 as registry


MAX_REGISTRY_BYTES = 4 * 1024 * 1024
CURRENT_FILE = "current.json"
SNAPSHOT_DIRECTORY = "snapshots"
LOCK_FILE = ".registry.lock"
_DIGEST_RE = re.compile(r"[a-f0-9]{64}")


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _secure_directory(path: Path, *, create: bool) -> None:
    if create and not path.exists():
        path.mkdir(mode=0o700)
    try:
        details = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("registry directory is unavailable") from exc
    if path.is_symlink():
        raise ValueError("registry directory must not be a symlink")
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise ValueError("registry directory ownership is invalid")
    if details.st_mode & 0o077:
        raise ValueError("registry directory must be owner-only")


def _ensure_layout(root: Path) -> Path:
    _secure_directory(root, create=True)
    snapshots = root / SNAPSHOT_DIRECTORY
    _secure_directory(snapshots, create=True)
    return snapshots


def _regular_owner_file(path: Path) -> os.stat_result:
    try:
        details = path.lstat()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError("registry file is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(details.st_mode):
        raise ValueError("registry file must be a regular non-symlink")
    if details.st_uid != os.getuid() or details.st_mode & 0o077:
        raise ValueError("registry file must be owner-only")
    if details.st_size > MAX_REGISTRY_BYTES:
        raise ValueError("registry file exceeds its byte limit")
    return details


def _read_json(path: Path) -> dict[str, Any]:
    details = _regular_owner_file(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if os.fstat(descriptor) != details:
            raise ValueError("registry file changed during admission")
        raw = os.read(descriptor, MAX_REGISTRY_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError("registry file exceeds its byte limit")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("registry file JSON is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError("registry file must contain an object")
    return value


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write(path: Path, value: Mapping[str, Any]) -> None:
    payload = _canonical_bytes(value)
    if len(payload) > MAX_REGISTRY_BYTES:
        raise ValueError("registry snapshot exceeds its byte limit")
    temporary = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary = handle.name
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        temporary = ""
        _fsync_directory(path.parent)
    finally:
        if temporary:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


@contextlib.contextmanager
def _exclusive_lock(root: Path) -> Iterator[None]:
    lock_path = root / LOCK_FILE
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _snapshot_path(snapshots: Path, digest: str) -> Path:
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ValueError("registry snapshot digest is invalid")
    return snapshots / f"{digest}.json"


def _persist_snapshot(snapshots: Path, value: dict[str, Any]) -> None:
    path = _snapshot_path(snapshots, value["registry_digest"])
    if path.exists():
        if _read_json(path) != value:
            raise ValueError("immutable registry snapshot collision")
        return
    _atomic_write(path, value)


def _load_optional_current(
    root: Path, *, verifier: registry.Verifier | None,
) -> dict[str, Any] | None:
    path = root / CURRENT_FILE
    if not path.exists():
        return None
    return registry.validate_registry(_read_json(path), verifier=verifier)


def load_current(
    root: str | Path, *, verifier: registry.Verifier | None,
) -> dict[str, Any]:
    """Load and verify the exact atomically active snapshot."""
    root_path = Path(root)
    _secure_directory(root_path, create=False)
    value = _load_optional_current(root_path, verifier=verifier)
    if value is None:
        raise ValueError("active registry snapshot is unavailable")
    return value


def _current_digest(value: dict[str, Any] | None) -> str:
    return "" if value is None else str(value["registry_digest"])


def _activation_predecessor(
    value: dict[str, Any], current: dict[str, Any] | None,
) -> None:
    expected = _current_digest(current)
    if value["previous_registry_digest"] != expected:
        raise ValueError("registry predecessor does not match current snapshot")
    if current is not None and value["revision"] <= current["revision"]:
        raise ValueError("registry revision must advance during activation")


def _receipt(
    action: str, value: dict[str, Any], previous_digest: str,
) -> dict[str, Any]:
    return {
        "schema": "onion-sentinel-investigation-skill-lifecycle-receipt-v1",
        "action": action,
        "registry_version": value["revision"],
        "registry_digest": value["registry_digest"],
        "previous_registry_digest": previous_digest,
        "mode": value["mode"],
        "record_count": len(value["records"]),
    }


def activate_snapshot(
    root: str | Path,
    snapshot: Any,
    *,
    expected_current_digest: str,
    verifier: registry.Verifier | None,
) -> dict[str, Any]:
    """Atomically activate one verified successor using compare-and-swap."""
    value = registry.validate_registry(snapshot, verifier=verifier)
    if value["mode"] != "active":
        raise ValueError("only an active signed registry may be activated")
    root_path = Path(root)
    snapshots = _ensure_layout(root_path)
    with _exclusive_lock(root_path):
        current = _load_optional_current(root_path, verifier=verifier)
        observed = _current_digest(current)
        if observed != expected_current_digest:
            raise ValueError("current registry changed before activation")
        _activation_predecessor(value, current)
        _persist_snapshot(snapshots, value)
        _atomic_write(root_path / CURRENT_FILE, value)
        return _receipt("activate", value, observed)


def rollback_active(
    root: str | Path,
    *,
    expected_current_digest: str,
    verifier: registry.Verifier | None,
) -> dict[str, Any]:
    """Atomically restore the exact verified predecessor snapshot."""
    root_path = Path(root)
    snapshots = _ensure_layout(root_path)
    with _exclusive_lock(root_path):
        current = _load_optional_current(root_path, verifier=verifier)
        if current is None or current["registry_digest"] != expected_current_digest:
            raise ValueError("current registry changed before rollback")
        previous_path = _snapshot_path(
            snapshots,
            current["previous_registry_digest"],
        )
        previous = registry.validate_registry(
            _read_json(previous_path),
            verifier=verifier,
        )
        restored = registry.rollback_snapshot(
            [current, previous],
            current["registry_digest"],
            verifier=verifier,
        )
        _atomic_write(root_path / CURRENT_FILE, restored)
        return _receipt(
            "rollback",
            restored,
            current["registry_digest"],
        )
