"""Page-scoped SOC AI artifact correlation and outcome selection."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable


JsonObject = dict[str, object]
Row = sqlite3.Row | dict


@dataclass(frozen=True)
class AiArtifactContextDependencies:
    dashboard_group_id: Callable[[str], str]
    group_members: Callable[[list[str]], list[tuple[str, str]]]


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _sqlite_identity(row: sqlite3.Row) -> tuple[str, str]:
    keys = row.keys()
    group_key = str(row["group_key"] or "").strip() if "group_key" in keys else ""
    if "alert_id" in keys:
        alert_id = str(row["alert_id"] or "").strip()
    elif "representative_alert_id" in keys:
        alert_id = str(row["representative_alert_id"] or "").strip()
    else:
        alert_id = ""
    return group_key, alert_id


def _row_identity(row: Row) -> tuple[str, str]:
    if not isinstance(row, dict):
        return _sqlite_identity(row)
    group_key = str(row.get("group_key") or "").strip()
    alert_id = str(row.get("alert_id") or row.get("representative_alert_id") or "").strip()
    return group_key, alert_id


def _consider_outcome(group_id: str, alert_id: str, analysis_times: dict,
                      outcomes: dict, outcome_times: dict[str, float],
                      group_outcomes: dict[str, str]) -> None:
    outcome = str(outcomes.get(alert_id) or "").strip()
    try:
        mtime = float(analysis_times.get(alert_id, 0.0) or 0.0)
    except (TypeError, ValueError, OverflowError):
        mtime = 0.0
    if outcome and mtime >= outcome_times.get(group_id, 0.0):
        group_outcomes[group_id] = outcome
        outcome_times[group_id] = mtime


def _apply_identity(group_key: str, alert_id: str, analysis_times: dict, outcomes: dict,
                    analysis_groups: set[str], outcome_times: dict[str, float],
                    group_outcomes: dict[str, str],
                    deps: AiArtifactContextDependencies) -> None:
    if not group_key:
        return
    group_id = deps.dashboard_group_id(group_key)
    if alert_id in analysis_times:
        analysis_groups.add(group_id)
    _consider_outcome(
        group_id, alert_id, analysis_times, outcomes, outcome_times, group_outcomes,
    )


def compose_page_ai_artifact_context(rows: list[Row], artifact_index: object,
                                     dependencies: AiArtifactContextDependencies) -> JsonObject:
    """Correlate representative and member artifacts to visible dashboard groups."""
    index = _mapping(artifact_index)
    analysis_times = _mapping(index.get("analysis_mtime_by_alert"))
    outcomes = _mapping(index.get("detection_outcome_by_alert"))
    analysis_groups: set[str] = set()
    group_outcomes: dict[str, str] = {}
    outcome_times: dict[str, float] = {}
    group_keys: set[str] = set()
    for row in rows:
        group_key, alert_id = _row_identity(row)
        if group_key:
            group_keys.add(group_key)
        _apply_identity(
            group_key, alert_id, analysis_times, outcomes, analysis_groups,
            outcome_times, group_outcomes, dependencies,
        )
    if group_keys and analysis_times:
        for group_key, alert_id in dependencies.group_members(sorted(group_keys)):
            _apply_identity(
                group_key, alert_id, analysis_times, outcomes, analysis_groups,
                outcome_times, group_outcomes, dependencies,
            )
    return {
        **index,
        "analysis_group_ids": analysis_groups,
        "detection_outcome_by_group_id": group_outcomes,
    }
