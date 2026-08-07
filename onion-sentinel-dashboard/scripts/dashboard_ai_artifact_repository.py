"""Read AI prompt/result artifacts and correlate prompts with running workers."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AiArtifactRepositoryConfig:
    """Explicit read/process boundaries for dashboard AI artifact state."""

    analysis_dir: Path
    prompt_dir: Path
    process_command: tuple[str, ...] = ("ps", "axo", "command=")
    runner_marker: str = "run-local-ai-analysis.py"
    process_timeout_seconds: float = 3.0


def _json_files(directory: Path, *, newest_first: bool = False) -> list[Path]:
    if not directory.is_dir():
        return []
    paths: list[tuple[float, Path]] = []
    for path in directory.glob("*.json"):
        try:
            if path.is_file():
                paths.append((path.stat().st_mtime, path))
        except OSError:
            continue
    return [path for _, path in sorted(paths, key=lambda item: item[0], reverse=newest_first)]


def _read_json_object(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def load_ai_analysis_records(
    config: AiArtifactRepositoryConfig,
    *,
    newest_first: bool = False,
) -> list[dict]:
    """Read bounded-by-directory result objects in deterministic mtime order."""
    records: list[dict] = []
    for path in _json_files(config.analysis_dir, newest_first=newest_first):
        data = _read_json_object(path)
        if data is None:
            continue
        data["_analysis_path"] = str(path)
        data["_analysis_filename"] = path.name
        records.append(data)
    return records


def index_ai_analysis_by_alert_id(config: AiArtifactRepositoryConfig) -> dict[str, dict]:
    """Index the newest valid result for each alert ID."""
    indexed: dict[str, dict] = {}
    for data in load_ai_analysis_records(config):
        alert_id = str(data.get("alert_id") or "").strip()
        if alert_id:
            indexed[alert_id] = data
    return indexed


def index_ai_prompts_by_alert_id(config: AiArtifactRepositoryConfig) -> dict[str, dict]:
    """Index the newest valid queued prompt package for each alert ID."""
    indexed: dict[str, dict] = {}
    for path in _json_files(config.prompt_dir):
        data = _read_json_object(path)
        if data is None:
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        alert_id = str(alert.get("alert_id") or data.get("alert_id") or "").strip()
        if not alert_id:
            continue
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        data.update({
            "_prompt_path": str(path),
            "_prompt_filename": path.name,
            "_prompt_mtime": mtime,
        })
        indexed[alert_id] = data
    return indexed


def running_prompt_alert_ids(
    prompts_by_alert_id: dict[str, dict],
    commands: object,
    *,
    runner_marker: str,
) -> set[str]:
    """Correlate exact prompt paths with bounded process command lines."""
    command_lines = commands if isinstance(commands, list) else []
    running: set[str] = set()
    for alert_id, prompt in prompts_by_alert_id.items():
        prompt_path = str(prompt.get("_prompt_path") or "")
        if prompt_path and any(
            runner_marker in str(command) and prompt_path in str(command)
            for command in command_lines
        ):
            running.add(alert_id)
    return running


def inspect_running_prompt_alert_ids(
    config: AiArtifactRepositoryConfig,
    prompts_by_alert_id: dict[str, dict],
) -> set[str]:
    """Read process state once and correlate it with queued prompt paths."""
    try:
        result = subprocess.run(
            list(config.process_command),
            check=False,
            capture_output=True,
            text=True,
            timeout=config.process_timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError):
        return set()
    return running_prompt_alert_ids(
        prompts_by_alert_id,
        result.stdout.splitlines(),
        runner_marker=config.runner_marker,
    )
