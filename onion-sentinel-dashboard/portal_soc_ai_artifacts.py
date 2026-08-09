"""SOC AI prompt and analysis artifact indexing."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Union


JsonObject = dict[str, object]
Row = Union[sqlite3.Row, dict]


@dataclass(frozen=True)
class AiArtifactSources:
    prompt_paths: Callable[[], Iterable[Path]]
    analysis_paths: Callable[[], Iterable[Path]]
    read_record: Callable[[Path], object]
    modified_time: Callable[[Path], float]


@dataclass(frozen=True)
class AiGroupArtifactDependencies:
    group_members: Callable[[str], Iterable[str]]
    latest_analysis_mtime: Callable[[str], float]


def empty_ai_artifact_index() -> JsonObject:
    return {
        "prompt_mtime_by_alert": {},
        "analysis_mtime_by_alert": {},
        "detection_outcome_by_alert": {},
    }


def _record(path: Path, sources: AiArtifactSources) -> dict | None:
    try:
        value = sources.read_record(path)
    except Exception:
        return None
    return value if isinstance(value, dict) else None


def _mtime(path: Path, sources: AiArtifactSources) -> float | None:
    try:
        return float(sources.modified_time(path))
    except (OSError, TypeError, ValueError, OverflowError):
        return None


def _prompt_alert_id(record: dict) -> str:
    alert = record.get("alert")
    alert = alert if isinstance(alert, dict) else {}
    return str(alert.get("alert_id") or record.get("alert_id") or "").strip()


def _analysis_outcome(record: dict) -> str:
    response = record.get("response")
    response = response if isinstance(response, dict) else {}
    return str(
        response.get("detection_outcome") or record.get("detection_outcome") or ""
    ).strip()


def _latest_mtime(alert_id: str, paths: Iterable[Path], sources: AiArtifactSources,
                  identity: Callable[[dict], str]) -> float:
    alert_id = str(alert_id or "").strip()
    if not alert_id:
        return 0.0
    newest = 0.0
    for path in paths:
        record = _record(path, sources)
        if record is None or identity(record) != alert_id:
            continue
        modified = _mtime(path, sources)
        if modified is not None:
            newest = max(newest, modified)
    return newest


def latest_prompt_mtime(alert_id: str, sources: AiArtifactSources) -> float:
    """Return the newest prompt modification time for one alert."""
    if not str(alert_id or "").strip():
        return 0.0
    return _latest_mtime(alert_id, sources.prompt_paths(), sources, _prompt_alert_id)


def latest_analysis_mtime(alert_id: str, sources: AiArtifactSources) -> float:
    """Return the newest analysis modification time for one alert."""
    if not str(alert_id or "").strip():
        return 0.0
    return _latest_mtime(
        alert_id,
        sources.analysis_paths(),
        sources,
        lambda record: str(record.get("alert_id") or "").strip(),
    )


def _row_text(row: Row, key: str) -> str:
    return str(row[key] or "").strip() if key in row.keys() else ""


def group_has_analysis_artifact(row: Row, dependencies: AiGroupArtifactDependencies) -> bool:
    """Return whether a representative or grouped member has AI analysis output."""
    representative = _row_text(row, "alert_id")
    member_ids = [representative] if representative else []
    seen = set(member_ids)
    group_key = _row_text(row, "group_key")
    if group_key:
        for value in dependencies.group_members(group_key):
            alert_id = str(value or "").strip()
            if alert_id and alert_id not in seen:
                seen.add(alert_id)
                member_ids.append(alert_id)
    return any(
        dependencies.latest_analysis_mtime(alert_id) > 0
        for alert_id in member_ids
    )


def _index_prompts(index: JsonObject, sources: AiArtifactSources) -> None:
    mtimes = index["prompt_mtime_by_alert"]
    for path in sources.prompt_paths():
        record = _record(path, sources)
        modified = _mtime(path, sources)
        alert_id = _prompt_alert_id(record) if record is not None else ""
        if alert_id and modified is not None:
            mtimes[alert_id] = max(mtimes.get(alert_id, 0.0), modified)


def _index_analyses(index: JsonObject, sources: AiArtifactSources) -> None:
    mtimes = index["analysis_mtime_by_alert"]
    outcomes = index["detection_outcome_by_alert"]
    for path in sources.analysis_paths():
        record = _record(path, sources)
        modified = _mtime(path, sources)
        alert_id = str(record.get("alert_id") or "").strip() if record is not None else ""
        if not alert_id or modified is None or modified < mtimes.get(alert_id, 0.0):
            continue
        mtimes[alert_id] = modified
        outcome = _analysis_outcome(record)
        if outcome:
            outcomes[alert_id] = outcome


def build_ai_artifact_index(sources: AiArtifactSources, *, include_prompts: bool) -> JsonObject:
    """Index newest prompt and analysis metadata without retaining evidence bodies."""
    index = empty_ai_artifact_index()
    if include_prompts:
        _index_prompts(index, sources)
    _index_analyses(index, sources)
    return index
