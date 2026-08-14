"""Hermes disaster-recovery backup validation and inventory policy."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import datetime as dt
from pathlib import Path
import re


@dataclass(frozen=True)
class HermesBackupSources:
    backup_dir: Path
    remote_dest: str
    remote_directory: str
    format_timestamp: Callable[[dt.datetime], str]
    human_size: Callable[[int], str]
    relative_time_label: Callable[[float], str]
    redact_text: Callable[[str], str]


@dataclass(frozen=True)
class _BackupLog:
    text: str
    completed_archives: frozenset[str]
    non_dry_starts: tuple[dt.datetime, ...]
    scheduled_completions: tuple[dt.datetime, ...]
    warning: str = ""


def backup_base_path(path: Path) -> Path:
    raw = str(path)
    suffix = ".tar.zst.enc" if raw.endswith(".tar.zst.enc") else ".tar.zst"
    return Path(raw.removesuffix(suffix))


def backup_timestamp_from_name(path: Path) -> dt.datetime:
    name = path.name
    suffix = ".tar.zst.enc" if name.endswith(".tar.zst.enc") else ".tar.zst"
    marker = name.removeprefix("macstudio-hermes-dr_").removesuffix(suffix)
    try:
        return dt.datetime.strptime(marker, "%Y%m%d_%H%M%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except (TypeError, ValueError):
        return dt.datetime.fromtimestamp(path.stat().st_mtime, tz=dt.timezone.utc)


def _parse_log_timestamp(value: str) -> dt.datetime:
    return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    )


def _read_backup_log(log_file: Path) -> _BackupLog:
    try:
        text = log_file.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return _BackupLog("", frozenset(), (), (), f"Could not read backup log {log_file}: {exc}")
    completed = frozenset(
        re.findall(
            r"^Archive: (.*macstudio-hermes-dr_\d{8}_\d{6}Z\.tar\.zst(?:\.enc)?)$",
            text,
            re.MULTILINE,
        )
    )
    try:
        starts = tuple(
            _parse_log_timestamp(stamp)
            for stamp, dry_run in re.findall(
                r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\] Scheduled backup start: dry_run=(\d)",
                text,
                re.MULTILINE,
            )
            if dry_run == "0"
        )
        completions = tuple(
            _parse_log_timestamp(stamp)
            for stamp in re.findall(
                r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\] Scheduled backup complete\.",
                text,
                re.MULTILINE,
            )
        )
    except Exception as exc:
        warning = f"Could not parse backup log {log_file}: {exc}"
        return _BackupLog(text, completed, (), (), warning)
    return _BackupLog(text, completed, starts, completions)


def _find_archives(backup_dir: Path) -> list[Path]:
    try:
        archives = [
            *backup_dir.glob("macstudio-hermes-dr_*.tar.zst"),
            *backup_dir.glob("macstudio-hermes-dr_*.tar.zst.enc"),
        ]
        return sorted(archives, key=backup_timestamp_from_name)
    except Exception:
        return []


def _validate_archive(archive: Path, completed: frozenset[str]) -> dict:
    base = backup_base_path(archive)
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    restore = Path(str(base) + ".RESTORE.txt")
    missing = []
    if not checksum.exists():
        missing.append("checksum")
    if not restore.exists():
        missing.append("restore notes")
    try:
        size = archive.stat().st_size
        if size <= 0:
            missing.append("non-empty archive")
    except Exception:
        size = 0
        missing.append("readable archive")
    if completed and str(archive) not in completed:
        missing.append("success log entry")
    return {
        "archive": archive,
        "checksum": checksum,
        "restore": restore,
        "created": backup_timestamp_from_name(archive).astimezone(),
        "size": size,
        "ok": not missing,
        "rating": "Successful" if not missing else "Needs attention",
        "missing": missing,
    }


def _catalog(sources: HermesBackupSources) -> tuple[list[dict], _BackupLog]:
    log = _read_backup_log(sources.backup_dir / "backup-cron.log")
    rows = [
        _validate_archive(archive, log.completed_archives)
        for archive in _find_archives(sources.backup_dir)
    ]
    return rows, log


def _incomplete_description(row: dict) -> str:
    return f"{row['archive'].name} missing {', '.join(row['missing'])}"


def _attempt_warning(
    log: _BackupLog,
    last_success: dt.datetime,
    format_timestamp: Callable[[dt.datetime], str],
) -> str:
    if not log.non_dry_starts:
        return ""
    latest_start = max(log.non_dry_starts)
    latest_complete = max(log.scheduled_completions, default=None)
    if latest_start <= last_success or (
        latest_complete is not None and latest_complete >= latest_start
    ):
        return ""
    local_start = latest_start.astimezone()
    return (
        f"Latest scheduled backup attempt started {format_timestamp(local_start)} "
        "but did not log a successful completion"
    )


def _missing_success_metric(
    sources: HermesBackupSources,
    incomplete: list[dict],
    log: _BackupLog,
) -> tuple[str, str, bool]:
    details = [
        f"WARNING: No successful full Hermes backup sets found in {sources.backup_dir}"
    ]
    if incomplete:
        descriptions = [_incomplete_description(row) for row in incomplete[-3:]]
        details.append("Incomplete artifacts: " + "; ".join(descriptions))
    if log.warning:
        details.append(log.warning)
    return "⚠ None", " · ".join(details), True


def _successful_backup_warnings(
    rows: list[dict],
    newest: dict,
    log: _BackupLog,
    success_utc: dt.datetime,
    format_timestamp: Callable[[dt.datetime], str],
) -> list[str]:
    warnings = []
    if rows[-1]["created"] > newest["created"] and not rows[-1]["ok"]:
        warnings.append(
            "Newer backup artifact is incomplete/not confirmed successful: "
            + _incomplete_description(rows[-1])
        )
    attempt_warning = _attempt_warning(log, success_utc, format_timestamp)
    if attempt_warning:
        warnings.append(attempt_warning)
    if log.warning:
        warnings.append(log.warning)
    return warnings


def _successful_backup_metric(
    sources: HermesBackupSources,
    rows: list[dict],
    log: _BackupLog,
    newest: dict,
) -> tuple[str, str, bool]:
    success_utc = backup_timestamp_from_name(newest["archive"])
    warnings = _successful_backup_warnings(
        rows, newest, log, success_utc, sources.format_timestamp
    )
    value = ("⚠ " if warnings else "") + sources.relative_time_label(
        newest["created"].timestamp()
    )
    details = [
        f"Latest successful full Hermes backup: {newest['archive'].name}",
        sources.format_timestamp(newest["created"].astimezone()),
        sources.human_size(newest["size"]),
        "success confirmed by backup-cron.log",
    ]
    if warnings:
        details.insert(0, "WARNING: " + " | ".join(warnings))
    return value, " · ".join(details), bool(warnings)


def compose_latest_hermes_backup_metric(
    sources: HermesBackupSources,
) -> tuple[str, str, bool]:
    """Return display value, detail, and warning state for the newest valid set."""
    rows, log = _catalog(sources)
    complete = [row for row in rows if row["ok"]]
    incomplete = [row for row in rows if not row["ok"]]
    if not complete:
        return _missing_success_metric(sources, incomplete, log)
    return _successful_backup_metric(sources, rows, log, complete[-1])


def compose_backup_inventory(sources: HermesBackupSources) -> tuple[list[dict], dict]:
    """Return newest-first backup rows and display metadata."""
    rows, log = _catalog(sources)
    rows.reverse()
    successful = sum(1 for row in rows if row["ok"])
    total = len(rows)
    metadata = {
        "directory": sources.backup_dir,
        "remote_dest": sources.remote_dest,
        "remote_directory": sources.remote_directory,
        "remote_location": f"{sources.remote_dest}:{sources.remote_directory}",
        "log_file": sources.backup_dir / "backup-cron.log",
        "total": total,
        "successful": successful,
        "rating_percent": round(successful / total * 100, 1) if total else 0.0,
        "log_tail": sources.redact_text("\n".join(log.text.splitlines()[-40:])) if log.text else "",
    }
    return rows, metadata
