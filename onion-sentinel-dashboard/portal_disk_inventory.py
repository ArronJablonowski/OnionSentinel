"""Local disk usage and bounded largest-item inventory policy."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import datetime as dt
from pathlib import Path


@dataclass(frozen=True)
class DiskScanOutcome:
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    timed_out: bool = False


@dataclass(frozen=True)
class DiskInventorySources:
    home: Path
    cache: dict[str, object]
    now: Callable[[], dt.datetime]
    directory_scan: Callable[[], DiskScanOutcome]
    file_scan: Callable[[], DiskScanOutcome]


def compose_local_disk_usage(
    home: Path, disk_usage: Callable[[Path], object]
) -> tuple[int, int, float]:
    """Return free, total, and percent-free values with a stable failure fallback."""
    try:
        usage = disk_usage(home)
        free = int(getattr(usage, "free"))
        total = int(getattr(usage, "total"))
        percent_free = free / total * 100 if total else 0.0
        return free, total, percent_free
    except Exception:
        return 0, 0, 0.0


def parse_size_path_lines(output: str, multiplier: int = 1) -> list[dict]:
    rows = []
    for raw in output.splitlines():
        parts = raw.strip().split(None, 1)
        if len(parts) != 2:
            continue
        try:
            size = int(parts[0]) * multiplier
        except (TypeError, ValueError):
            continue
        rows.append({"size": size, "path": parts[1]})
    return rows


def parse_file_stat_lines(output: str) -> list[dict]:
    rows = []
    for raw in output.splitlines():
        parts = raw.strip().split(None, 2)
        if len(parts) != 3:
            continue
        try:
            allocated = int(parts[0]) * 512
            logical = int(parts[1])
        except (TypeError, ValueError):
            continue
        rows.append(
            {"size": allocated, "logical_size": logical, "path": parts[2]}
        )
    return rows


def _cached_inventory(
    sources: DiskInventorySources, now: dt.datetime, cache_seconds: int
) -> tuple[list[dict], list[dict], list[str], dt.datetime] | None:
    try:
        generated = float(sources.cache.get("generated") or 0.0)
    except (TypeError, ValueError):
        generated = 0.0
    if not generated or now.timestamp() - generated >= cache_seconds:
        return None
    return (
        list(sources.cache.get("dirs") or []),
        list(sources.cache.get("files") or []),
        list(sources.cache.get("warnings") or []),
        dt.datetime.fromtimestamp(generated).astimezone(),
    )


def _scan_warning(kind: str, outcome: DiskScanOutcome) -> str:
    if outcome.timed_out:
        return (
            f"{kind} scan timed out after 30 seconds; showing cached/empty "
            f"{kind.lower()} data."
        )
    if outcome.error:
        return f"{kind} scan failed: {outcome.error}"
    lines = outcome.stderr.strip().splitlines()
    return f"{kind} scan warnings: {lines[-1]}" if lines else ""


def _directory_inventory(
    outcome: DiskScanOutcome, home: Path, limit: int
) -> tuple[list[dict], str]:
    rows = [
        row
        for row in parse_size_path_lines(outcome.stdout, 1024)
        if row["path"] != str(home)
    ]
    top = sorted(rows, key=lambda row: row["size"], reverse=True)[:limit]
    return top, _scan_warning("Directory", outcome)


def _file_inventory(
    outcome: DiskScanOutcome, limit: int
) -> tuple[list[dict], str]:
    return parse_file_stat_lines(outcome.stdout)[:limit], _scan_warning(
        "File", outcome
    )


def compose_local_disk_inventory(
    sources: DiskInventorySources,
    limit: int = 10,
    cache_seconds: int = 600,
) -> tuple[list[dict], list[dict], list[str], dt.datetime]:
    """Return cached or freshly scanned largest directories and files."""
    now = sources.now()
    cached = _cached_inventory(sources, now, cache_seconds)
    if cached is not None:
        return cached
    try:
        directory_outcome = sources.directory_scan()
    except Exception as exc:
        directory_outcome = DiskScanOutcome(error=str(exc))
    try:
        file_outcome = sources.file_scan()
    except Exception as exc:
        file_outcome = DiskScanOutcome(error=str(exc))
    directories, directory_warning = _directory_inventory(
        directory_outcome, sources.home, limit
    )
    files, file_warning = _file_inventory(file_outcome, limit)
    warnings = [warning for warning in (directory_warning, file_warning) if warning]
    sources.cache.update(
        {
            "generated": now.timestamp(),
            "dirs": directories,
            "files": files,
            "warnings": warnings,
        }
    )
    return directories, files, warnings, now
