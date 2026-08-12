"""Owner-controlled filesystem and rotation-policy access for application logs."""
from __future__ import annotations

import datetime as dt
import os
import stat
from pathlib import Path

from application_log_contract import (
    ApplicationLogError,
    DEFAULT_ROTATION_BACKUPS,
    DEFAULT_ROTATION_BYTES,
    MAX_ENV_BYTES,
)


def _roots(home: Path) -> dict[str, Path]:
    base = home.expanduser() / "n8n-local"
    return {
        "runtime": base / "logs",
        "analysis": base / "soc-alerts" / "llm-analysis-logs",
    }


def _root_descriptor(root: Path) -> int:
    try:
        metadata = root.lstat()
    except FileNotFoundError as exc:
        raise ApplicationLogError(404, "Log directory does not exist") from exc
    except OSError as exc:
        raise ApplicationLogError(503, "Log directory is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ApplicationLogError(403, "Log directory failed security validation")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(root, flags)
    except OSError as exc:
        raise ApplicationLogError(503, "Log directory is unavailable") from exc


def _validate_basename(value: str) -> None:
    if not value or value in {".", ".."} or Path(value).name != value or "/" in value or "\\" in value:
        raise ApplicationLogError(404, "Unknown log member")


def _member_metadata(root: Path, basename: str) -> dict[str, object] | None:
    _validate_basename(basename)
    try:
        root_fd = _root_descriptor(root)
    except ApplicationLogError as exc:
        if exc.status == 404:
            return None
        raise
    try:
        try:
            metadata = os.stat(basename, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        except OSError:
            return None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            return None
        return {
            "path": str(root / basename),
            "size_bytes": int(metadata.st_size),
            "modified_at": _iso_timestamp(metadata.st_mtime),
        }
    finally:
        os.close(root_fd)


def _iso_timestamp(epoch: float) -> str:
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_env_values(home: Path) -> dict[str, str]:
    path = home.expanduser() / "n8n-local" / ".env"
    try:
        metadata = path.lstat()
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size > MAX_ENV_BYTES
        ):
            return {}
        raw = path.read_bytes()
    except OSError:
        return {}
    if len(raw) > MAX_ENV_BYTES:
        return {}
    allowed = {
        "ALERT_STORE_APPLICATION_LOG_MAX_BYTES",
        "ALERT_STORE_APPLICATION_LOG_BACKUPS",
    }
    result: dict[str, str] = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() in allowed:
            result[key.strip()] = value.strip()
    return result


def _bounded_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value or "")
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _alert_store_policy(home: Path) -> tuple[int, int]:
    values = _safe_env_values(home)
    size = _bounded_int(
        values.get("ALERT_STORE_APPLICATION_LOG_MAX_BYTES"),
        DEFAULT_ROTATION_BYTES,
        1024 * 1024,
        1024 * 1024 * 1024,
    )
    backups = _bounded_int(
        values.get("ALERT_STORE_APPLICATION_LOG_BACKUPS"),
        DEFAULT_ROTATION_BACKUPS,
        1,
        20,
    )
    return size, backups


def _open_regular(root: Path, basename: str) -> tuple[int, os.stat_result]:
    _validate_basename(basename)
    root_fd = _root_descriptor(root)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        try:
            descriptor = os.open(basename, flags, dir_fd=root_fd)
        except FileNotFoundError as exc:
            raise ApplicationLogError(404, "Log file does not exist") from exc
        except OSError as exc:
            raise ApplicationLogError(403, "Log file failed security validation") from exc
    finally:
        os.close(root_fd)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        os.close(descriptor)
        raise ApplicationLogError(403, "Log file failed security validation")
    return descriptor, metadata
