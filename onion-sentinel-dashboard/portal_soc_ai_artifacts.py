"""SOC AI prompt and analysis artifact indexing."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


JsonObject = dict[str, object]


@dataclass(frozen=True)
class AiArtifactSources:
    prompt_paths: Callable[[], Iterable[Path]]
    analysis_paths: Callable[[], Iterable[Path]]
    read_record: Callable[[Path], object]
    modified_time: Callable[[Path], float]


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
