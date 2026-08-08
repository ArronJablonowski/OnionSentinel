"""Bounded active LLM status-file discovery and process validation."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import heapq
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class ActiveLlmSources:
    active_directory: Path
    record_max_bytes: int
    active_limit: int
    process_commands: Callable[[], list[str]]


def llm_queue_size(static_status: object) -> int:
    if not isinstance(static_status, dict):
        return 0
    ai = static_status.get("ai")
    counts = ai.get("counts") if isinstance(ai, dict) else {}
    try:
        return max(0, int(counts.get("queued") or 0))
    except (AttributeError, TypeError, ValueError):
        return 0


def read_bounded_llm_record(path: Path, max_bytes: int) -> dict:
    """Read one trusted status record without accepting unbounded input."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            return {}
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def active_llm_record_paths(directory: Path, limit: int) -> list[Path]:
    """Return a bounded newest-first set of regular per-run status files."""
    newest: list[tuple[int, str, Path]] = []
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.name.endswith(".json") or not entry.is_file(
                    follow_symlinks=False
                ):
                    continue
                try:
                    mtime_ns = entry.stat(follow_symlinks=False).st_mtime_ns
                except OSError:
                    continue
                item = (mtime_ns, entry.name, Path(entry.path))
                if len(newest) < limit:
                    heapq.heappush(newest, item)
                elif item[:2] > newest[0][:2]:
                    heapq.heapreplace(newest, item)
    except OSError:
        return []
    return [item[2] for item in sorted(newest, reverse=True)]


def llm_analysis_process_active(
    prompt_package: str,
    commands: list[str],
    runner_pid: object = None,
) -> bool:
    try:
        expected_pid = int(str(runner_pid or "").strip())
    except (TypeError, ValueError):
        expected_pid = 0
    if expected_pid > 0:
        for command in commands:
            parts = command.strip().split(maxsplit=1)
            if (
                len(parts) == 2
                and parts[0] == str(expected_pid)
                and "run-local-ai-analysis.py" in parts[1]
            ):
                return True
        return False
    if prompt_package:
        return any(
            "run-local-ai-analysis.py" in command and prompt_package in command
            for command in commands
        )
    return any("run-local-ai-analysis.py" in command for command in commands)


def read_active_llm_analyses(sources: ActiveLlmSources) -> list[dict]:
    """Read only live per-run records using one bounded process snapshot."""
    records = [
        record
        for path in active_llm_record_paths(
            sources.active_directory, sources.active_limit
        )
        if (
            record := read_bounded_llm_record(path, sources.record_max_bytes)
        )
        and record.get("status") == "running"
    ]
    if not records:
        return []
    commands = sources.process_commands()
    active = [
        record
        for record in records
        if llm_analysis_process_active(
            str(record.get("prompt_package") or ""),
            commands,
            record.get("runner_pid"),
        )
    ]
    active.sort(
        key=lambda record: (
            str(record.get("started_at") or ""),
            str(record.get("log_id") or ""),
        )
    )
    return active
