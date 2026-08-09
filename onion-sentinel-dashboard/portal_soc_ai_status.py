"""SOC alert AI-analysis status policy and stale-state reconciliation."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable, Union


JsonObject = dict[str, object]
Row = Union[sqlite3.Row, dict]


@dataclass(frozen=True)
class SocAiStatusPolicy:
    severity_order: tuple[str, ...]
    eligible_filter_statuses: frozenset[str]
    test_prefixes: tuple[str, ...]
    latest_prompt_mtime: Callable[[str], float]
    latest_analysis_mtime: Callable[[str], float]
    static_reports: Callable[[], dict]
    group_has_artifact: Callable[[Row], bool]


def _has(row: Row, key: str) -> bool:
    return key in row.keys()


def _row_text(row: Row, key: str, default: str = "") -> str:
    return str(row[key] or default) if _has(row, key) else default


def _normalized_severity(value: object) -> str:
    severity = str(value or "informational").strip().lower()
    return "informational" if severity == "info" else severity


def severity_meets_threshold(severity: object, threshold: object,
                             severity_order: tuple[str, ...]) -> bool:
    normalized_severity = _normalized_severity(severity)
    normalized_threshold = _normalized_severity(threshold)
    if normalized_threshold == "disabled":
        return False
    if normalized_threshold not in severity_order:
        normalized_threshold = "informational"
    if normalized_severity not in severity_order:
        return False
    return severity_order.index(normalized_severity) >= severity_order.index(normalized_threshold)


def _artifact_times(alert_id: str, artifacts: object,
                    policy: SocAiStatusPolicy) -> tuple[float, float]:
    artifact_map = artifacts if isinstance(artifacts, dict) else {}
    prompt_times = artifact_map.get("prompt_mtime_by_alert", {})
    analysis_times = artifact_map.get("analysis_mtime_by_alert", {})
    prompt_times = prompt_times if isinstance(prompt_times, dict) else {}
    analysis_times = analysis_times if isinstance(analysis_times, dict) else {}
    prompt_mtime = float(prompt_times.get(alert_id, 0.0))
    analysis_mtime = float(analysis_times.get(alert_id, 0.0))
    if alert_id and not artifacts:
        return policy.latest_prompt_mtime(alert_id), policy.latest_analysis_mtime(alert_id)
    return prompt_mtime, analysis_mtime


def _has_artifact(row: Row, group_id: str, artifacts: object,
                  policy: SocAiStatusPolicy) -> bool:
    if artifacts:
        artifact_map = artifacts if isinstance(artifacts, dict) else {}
        groups = artifact_map.get("analysis_group_ids", set())
        return group_id in groups
    return policy.group_has_artifact(row)


def _status(key: str, label: str, detail: str) -> JsonObject:
    return {"ai_status_key": key, "ai_status_label": label, "ai_status_detail": detail}


def _eligibility_status(row: Row, has_artifact: bool, threshold: str,
                        policy: SocAiStatusPolicy) -> JsonObject | None:
    if has_artifact:
        return None
    triage_level = _row_text(row, "triage_level", "informational")
    normalized = _normalized_severity(triage_level)
    if normalized not in policy.severity_order:
        return _status(
            "not-queued", "Skipped",
            f"Unrecognized severity {normalized or 'blank'} is not eligible for automatic AI analysis",
        )
    if severity_meets_threshold(triage_level, threshold, policy.severity_order):
        return None
    threshold_label = str(threshold or "informational").strip().title()
    return _status(
        "not-queued", "Skipped",
        f"Below configured {threshold_label} automatic AI-analysis minimum",
    )


def _reported_status(report: object, filter_status: str, has_artifact: bool,
                     policy: SocAiStatusPolicy) -> JsonObject | None:
    if not isinstance(report, dict):
        return None
    key = str(report.get("ai_status_key") or "queued")
    if key in {"analyzed", "analyzing"} and not has_artifact:
        return _status(
            "queued", "Queued",
            "The previous AI status was stale; no AI analysis artifact exists for this group",
        )
    if key in {"not-queued", "skipped"} and filter_status in policy.eligible_filter_statuses and not has_artifact:
        return _status(
            "queued", "Queued",
            "No AI analysis artifact exists for this eligible group; queued for the scheduled local AI analysis worker",
        )
    return _status(
        key,
        str(report.get("ai_status_label") or "Queued"),
        str(report.get("ai_status_detail") or ""),
    )


def compose_soc_ai_status(row: Row, group_id: str, ai_reports: object,
                          ai_artifacts: object, analysis_min_severity: str,
                          policy: SocAiStatusPolicy) -> JsonObject:
    """Return truthful AI status using evidence before retained UI state."""
    alert_id = _row_text(row, "alert_id")
    prompt_mtime, analysis_mtime = _artifact_times(alert_id, ai_artifacts, policy)
    if alert_id and prompt_mtime > analysis_mtime:
        return _status(
            "queued", "Queued",
            "Manual SOC Analyst reanalysis prompt package is waiting for the local AI worker",
        )
    reports = ai_reports if isinstance(ai_reports, dict) else policy.static_reports()
    has_artifact = _has_artifact(row, group_id, ai_artifacts, policy)
    eligibility = _eligibility_status(row, has_artifact, analysis_min_severity, policy)
    if eligibility:
        return eligibility
    filter_status = _row_text(row, "filter_status", "accepted").strip().lower()
    reported = _reported_status(reports.get(group_id), filter_status, has_artifact, policy)
    if reported:
        return reported
    if alert_id and alert_id.startswith(policy.test_prefixes):
        return _status(
            "not-queued", "Skipped",
            "Test/validation alert is intentionally excluded from automatic local AI analysis",
        )
    if filter_status not in policy.eligible_filter_statuses:
        return _status(
            "not-queued", "Skipped",
            f"Filter status {filter_status or 'blank'} is not eligible for automatic local AI analysis",
        )
    return _status(
        "queued", "Queued", "Queued for the scheduled local AI analysis worker",
    )
