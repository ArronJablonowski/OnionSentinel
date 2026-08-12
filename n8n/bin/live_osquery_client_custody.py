"""Concurrent immutable artifact custody for live OSQuery results."""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Callable

from live_osquery_client_primitives import LiveOsqueryClientError
from live_osquery_contract import bounded_json_bytes


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    encoded = json.dumps(value, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        temp_path = Path(handle.name)
        os.fchmod(handle.fileno(), 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, path)


def _admit_case_directory(case_dir: Path) -> None:
    case_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        info = case_dir.lstat()
    except OSError as exc:
        raise LiveOsqueryClientError(
            "cannot inspect live OSQuery artifact case directory"
        ) from exc
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise LiveOsqueryClientError(
            "live OSQuery artifact case directory must be an "
            "owner-controlled directory with mode 0700"
        )


def _open_manifest_lock(lock_path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise LiveOsqueryClientError(
            "cannot open live OSQuery artifact manifest lock"
        ) from exc


def _validate_locked_manifest(descriptor: int, lock_path: Path) -> None:
    lock_info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(lock_info.st_mode)
        or lock_info.st_uid != os.geteuid()
        or stat.S_IMODE(lock_info.st_mode) != 0o600
    ):
        raise LiveOsqueryClientError(
            "live OSQuery artifact manifest lock must be an "
            "owner-controlled regular file with mode 0600"
        )
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    path_info = lock_path.lstat()
    if (
        stat.S_ISLNK(path_info.st_mode)
        or not stat.S_ISREG(path_info.st_mode)
        or path_info.st_uid != os.geteuid()
        or stat.S_IMODE(path_info.st_mode) != 0o600
        or path_info.st_dev != lock_info.st_dev
        or path_info.st_ino != lock_info.st_ino
    ):
        raise LiveOsqueryClientError(
            "live OSQuery artifact manifest lock changed while acquiring it"
        )


def open_locked_case_manifest(case_dir: Path) -> int:
    _admit_case_directory(case_dir)
    lock_path = case_dir / ".manifest.lock"
    descriptor = _open_manifest_lock(lock_path)
    try:
        _validate_locked_manifest(descriptor, lock_path)
        return descriptor
    except (OSError, LiveOsqueryClientError):
        os.close(descriptor)
        raise


def _existing_entries(
    manifest_path: Path,
    case_id: str,
    read_json: Callable[[Path], dict[str, Any]],
) -> list[Any]:
    if not manifest_path.exists():
        return []
    manifest = read_json(manifest_path)
    if (
        manifest.get("schema") != "onion-sentinel-live-osquery-manifest-v1"
        or manifest.get("case_id") != case_id
        or not isinstance(manifest.get("entries"), list)
    ):
        raise LiveOsqueryClientError(
            "existing live OSQuery artifact manifest is invalid"
        )
    return list(manifest["entries"])


def _entry(
    artifact_name: str,
    artifact: dict[str, Any],
    artifact_digest: str,
    request_digest: str,
    artifact_size: int,
) -> dict[str, Any]:
    return {
        "artifact": artifact_name,
        "artifact_sha256": artifact_digest,
        "request_sha256": request_digest,
        "generated_at": str(artifact.get("generated_at") or ""),
        "complete": artifact.get("complete") is True,
        "results": len(artifact.get("results") or []),
        "size_bytes": artifact_size,
    }


def _retirement_name(entry: Any) -> str:
    name = str(entry.get("artifact") or "") if isinstance(entry, dict) else ""
    if (
        not name
        or Path(name).name != name
        or not name.endswith(".json")
        or name == "manifest.json"
    ):
        return ""
    return name


def _retire_entry(case_dir: Path, entry: Any) -> None:
    name = _retirement_name(entry)
    if not name:
        return
    candidate = case_dir / name
    try:
        info = candidate.lstat()
    except FileNotFoundError:
        return
    if (
        stat.S_ISREG(info.st_mode)
        and not stat.S_ISLNK(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
    ):
        candidate.unlink()


def _publish_locked(
    *,
    case_dir: Path,
    manifest_path: Path,
    case_id: str,
    request_digest: str,
    artifact_digest: str,
    artifact_bytes: bytes,
    artifact: dict[str, Any],
    maximum_batches: int,
    read_json: Callable[[Path], dict[str, Any]],
    write_json: Callable[[Path, dict[str, Any]], None],
) -> Path:
    created = dt.datetime.now(dt.timezone.utc)
    stamp = created.strftime("%Y%m%dT%H%M%S.%fZ")
    artifact_name = f"{stamp}-{request_digest[:16]}-{os.urandom(4).hex()}.json"
    artifact_path = case_dir / artifact_name
    entries = _existing_entries(manifest_path, case_id, read_json)
    if artifact_path.exists():
        raise LiveOsqueryClientError(
            "live OSQuery immutable artifact identity collided"
        )
    write_json(artifact_path, artifact)
    entries.append(
        _entry(
            artifact_name,
            artifact,
            artifact_digest,
            request_digest,
            len(artifact_bytes),
        )
    )
    write_json(
        manifest_path,
        {
            "schema": "onion-sentinel-live-osquery-manifest-v1",
            "case_id": case_id,
            "updated_at": created.isoformat().replace("+00:00", "Z"),
            "current": artifact_name,
            "retention_limit": maximum_batches,
            "entries": entries[-maximum_batches:],
        },
    )
    for entry in entries[:-maximum_batches]:
        _retire_entry(case_dir, entry)
    return artifact_path


def persist_artifact(
    *,
    artifact_dir: Path,
    case_id: str,
    request_payload: dict[str, Any],
    artifact: dict[str, Any],
    maximum_batches: int,
    read_json: Callable[[Path], dict[str, Any]],
    write_json: Callable[[Path, dict[str, Any]], None],
    open_lock: Callable[[Path], int],
) -> Path:
    safe_case = re.sub(r"[^A-Za-z0-9._-]+", "-", case_id).strip("-")[:120]
    case_dir = artifact_dir / (safe_case or "incident")
    request_digest = hashlib.sha256(bounded_json_bytes(request_payload)).hexdigest()
    artifact_bytes = bounded_json_bytes(artifact)
    artifact_digest = hashlib.sha256(artifact_bytes).hexdigest()
    manifest_path = case_dir / "manifest.json"
    lock_descriptor = open_lock(case_dir)
    try:
        return _publish_locked(
            case_dir=case_dir,
            manifest_path=manifest_path,
            case_id=case_id,
            request_digest=request_digest,
            artifact_digest=artifact_digest,
            artifact_bytes=artifact_bytes,
            artifact=artifact,
            maximum_batches=maximum_batches,
            read_json=read_json,
            write_json=write_json,
        )
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
