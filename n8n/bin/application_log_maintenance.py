"""Bounded rotation, compression, cleanup, and disk-pressure policy for logs."""
from __future__ import annotations

import datetime as dt
import fcntl
import gzip
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
from typing import Any


try:
    from application_log_contract import (
        DISK_PRESSURE_PERCENT,
        LOG_SPECS,
        LogSpec,
    )
except ModuleNotFoundError:  # Source-tree execution; installed copies are adjacent.
    dashboard_dir = Path(__file__).resolve().parents[2] / "onion-sentinel-dashboard"
    sys.path.insert(0, str(dashboard_dir))
    from application_log_contract import (  # type: ignore[no-redef]
        DISK_PRESSURE_PERCENT,
        LOG_SPECS,
        LogSpec,
    )


CHUNK_BYTES = 1024 * 1024
LOCK_BASENAME = "application-log-maintenance.lock"


class ApplicationLogMaintenanceError(Exception):
    """An operator-safe maintenance failure without log content or secrets."""


def log_roots(stack_dir: Path) -> dict[str, Path]:
    return {
        "runtime": stack_dir / "logs",
        "analysis": stack_dir / "soc-alerts" / "llm-analysis-logs",
    }


def managed_specs() -> tuple[LogSpec, ...]:
    return tuple(spec for spec in LOG_SPECS if spec.maintenance and not spec.family)


def _validate_directory(path: Path) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ApplicationLogMaintenanceError("managed log root is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ApplicationLogMaintenanceError("managed log root failed security validation")
    return metadata


def _directory_fd(path: Path) -> int:
    _validate_directory(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise ApplicationLogMaintenanceError("managed log root is unavailable") from exc


def _regular_metadata(root_fd: int, basename: str) -> os.stat_result | None:
    try:
        metadata = os.stat(basename, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ApplicationLogMaintenanceError("managed log metadata is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ApplicationLogMaintenanceError("managed log failed security validation")
    return metadata


def _open_current(root_fd: int, basename: str) -> tuple[int, os.stat_result] | None:
    flags = (
        os.O_RDWR
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(basename, flags, dir_fd=root_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ApplicationLogMaintenanceError("managed log could not be opened safely") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise ApplicationLogMaintenanceError("managed log failed security validation")
    return descriptor, metadata


def _read_suffix(descriptor: int, size: int, maximum: int) -> bytes:
    remaining = min(size, maximum)
    os.lseek(descriptor, max(0, size - remaining), os.SEEK_SET)
    chunks: list[bytes] = []
    while remaining:
        chunk = os.read(descriptor, min(CHUNK_BYTES, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_gzip_temporary(root_fd: int, basename: str, content: bytes) -> str:
    temporary = f".{basename}.{os.getpid()}.{secrets.token_hex(6)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600, dir_fd=root_fd)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as archive:
                archive.write(content)
            raw.flush()
            os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    return temporary


def _archive_basename(spec: LogSpec, generation: int) -> str:
    return f"{spec.basename}.{generation}.gz"


def _shift_archives(root_fd: int, spec: LogSpec) -> None:
    existing = {
        generation
        for generation in range(1, spec.backups + 1)
        if _regular_metadata(root_fd, _archive_basename(spec, generation)) is not None
    }
    oldest = _archive_basename(spec, spec.backups)
    if spec.backups in existing:
        os.unlink(oldest, dir_fd=root_fd)
    for generation in range(spec.backups - 1, 0, -1):
        if generation not in existing:
            continue
        source = _archive_basename(spec, generation)
        os.replace(
            source,
            _archive_basename(spec, generation + 1),
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )


def _rotation_result(spec: LogSpec) -> dict[str, Any]:
    return {
        "id": spec.id,
        "rotated": False,
        "source_bytes": 0,
        "archived_bytes": 0,
        "archive_truncated": False,
        "permission_hardened": False,
    }


def _harden_current_permissions(
    descriptor: int,
    metadata: os.stat_result,
    *,
    apply: bool,
    result: dict[str, Any],
) -> None:
    required = bool(stat.S_IMODE(metadata.st_mode) & 0o077)
    if apply and required:
        os.fchmod(descriptor, 0o600)
        result["permission_hardened"] = True
    elif required:
        result["permission_hardening_required"] = True


def _within_limit_status(result: dict[str, Any]) -> str:
    if result["permission_hardened"]:
        return "permissions_hardened"
    if result.get("permission_hardening_required"):
        return "permission_hardening_required"
    return "within_limit"


def _publish_rotation(
    root_fd: int,
    descriptor: int,
    spec: LogSpec,
    content: bytes,
) -> None:
    temporary = _write_gzip_temporary(root_fd, spec.basename, content)
    try:
        _shift_archives(root_fd, spec)
        os.replace(
            temporary,
            _archive_basename(spec, 1),
            src_dir_fd=root_fd,
            dst_dir_fd=root_fd,
        )
        os.fsync(root_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except OSError:
            pass
        raise
    os.ftruncate(descriptor, 0)
    os.fsync(descriptor)


def _rotate_opened(
    root_fd: int,
    descriptor: int,
    metadata: os.stat_result,
    spec: LogSpec,
    *,
    apply: bool,
    result: dict[str, Any],
) -> dict[str, Any]:
    size = int(metadata.st_size)
    result["source_bytes"] = size
    _harden_current_permissions(descriptor, metadata, apply=apply, result=result)
    if size <= spec.maximum_size_bytes:
        result["status"] = _within_limit_status(result)
        return result
    result["archive_truncated"] = size > spec.maximum_size_bytes
    if not apply:
        result["status"] = "rotation_required"
        return result
    content = _read_suffix(descriptor, size, spec.maximum_size_bytes)
    _publish_rotation(root_fd, descriptor, spec, content)
    result.update(status="rotated", rotated=True, archived_bytes=len(content))
    return result


def rotate_spec(root: Path, spec: LogSpec, *, apply: bool) -> dict[str, Any]:
    result = _rotation_result(spec)
    root_fd = _directory_fd(root)
    try:
        opened = _open_current(root_fd, spec.basename)
        if opened is None:
            result["status"] = "absent"
            return result
        descriptor, metadata = opened
        try:
            return _rotate_opened(
                root_fd,
                descriptor,
                metadata,
                spec,
                apply=apply,
                result=result,
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)


def cleanup_spec(
    root: Path,
    spec: LogSpec,
    *,
    now: dt.datetime,
    apply: bool,
    disk_pressure: bool,
) -> dict[str, Any]:
    cutoff = now.timestamp() - spec.retention_days * 86400
    removed: list[int] = []
    eligible: list[tuple[int, os.stat_result]] = []
    root_fd = _directory_fd(root)
    try:
        for generation in range(1, spec.backups + 1):
            metadata = _regular_metadata(root_fd, _archive_basename(spec, generation))
            if metadata is not None:
                eligible.append((generation, metadata))
        for generation, metadata in sorted(eligible, reverse=True):
            expired = metadata.st_mtime < cutoff
            pressure_prunable = disk_pressure and generation > 1
            if not (expired or pressure_prunable):
                continue
            removed.append(generation)
            if apply:
                os.unlink(_archive_basename(spec, generation), dir_fd=root_fd)
        if apply and removed:
            os.fsync(root_fd)
    finally:
        os.close(root_fd)
    return {"id": spec.id, "removed_generations": removed}


def filesystem_used_percent(path: Path) -> float:
    usage = shutil.disk_usage(path)
    return 0.0 if usage.total <= 0 else 100.0 * usage.used / usage.total


def _maintenance_lock(stack_dir: Path) -> int:
    run_dir = stack_dir / "run"
    _validate_directory(run_dir)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(run_dir / LOCK_BASENAME, flags, 0o600)
    except OSError as exc:
        raise ApplicationLogMaintenanceError("maintenance lock could not be opened safely") from exc
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        os.close(descriptor)
        raise ApplicationLogMaintenanceError("maintenance lock failed security validation")
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(descriptor)
        raise ApplicationLogMaintenanceError("application-log maintenance is already running") from exc
    return descriptor


def _maintain_specs(
    roots: dict[str, Path],
    *,
    apply: bool,
    now: dt.datetime,
    disk_pressure: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    rotations: list[dict[str, Any]] = []
    cleanups: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for spec in managed_specs():
        root = roots[spec.root]
        try:
            rotations.append(rotate_spec(root, spec, apply=apply))
            cleanups.append(
                cleanup_spec(
                    root,
                    spec,
                    now=now,
                    apply=apply,
                    disk_pressure=disk_pressure,
                )
            )
        except ApplicationLogMaintenanceError as exc:
            failures.append({"id": spec.id, "error": str(exc)})
        except OSError:
            failures.append({"id": spec.id, "error": "managed log operation failed"})
    return rotations, cleanups, failures


def maintain_logs(
    stack_dir: Path,
    *,
    apply: bool = False,
    now: dt.datetime | None = None,
    used_percent: float | None = None,
) -> dict[str, Any]:
    selected_now = now or dt.datetime.now(dt.timezone.utc)
    if selected_now.tzinfo is None:
        raise ApplicationLogMaintenanceError("maintenance time must include a timezone")
    roots = log_roots(stack_dir)
    lock_fd = _maintenance_lock(stack_dir)
    try:
        pressure = (
            filesystem_used_percent(stack_dir)
            if used_percent is None
            else float(used_percent)
        )
        disk_pressure = pressure >= DISK_PRESSURE_PERCENT
        rotations, cleanups, failures = _maintain_specs(
            roots,
            apply=apply,
            now=selected_now,
            disk_pressure=disk_pressure,
        )
        return {
            "ok": not failures,
            "apply": bool(apply),
            "disk_used_percent": round(pressure, 2),
            "disk_pressure": disk_pressure,
            "rotation_count": sum(bool(item["rotated"]) for item in rotations),
            "cleanup_count": sum(len(item["removed_generations"]) for item in cleanups),
            "rotations": rotations,
            "cleanups": cleanups,
            "failures": failures,
        }
    finally:
        os.close(lock_fd)
