"""AI eligibility, artifact selection, and dashboard workflow status policy."""
from __future__ import annotations

from pathlib import Path

from dashboard_alert_detail_values import row_value
from dashboard_time_format import normalize_iso_display_text


AI_ELIGIBLE_FILTER_STATUSES = frozenset({"accepted", "escalated", "unknown", "suppressed"})
TEST_ALERT_PREFIXES = ("phase", "config-", "internal-test-", "sqlite-", "policy-", "codex-")
SOC_ANALYSIS_SEVERITY_LABELS = {
    "disabled": "Disabled",
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}
ANALYSIS_SEVERITY_LEVELS = ("informational", "low", "medium", "high", "critical")
StatusTuple = tuple[str, str, str]


def candidate_alert_ids_for_row(row: object) -> list[str]:
    """Return the representative and grouped member alert IDs in stable order."""
    candidate_ids = [row_value(row, "alert_id")]
    members = row_value(row, "member_alert_ids", [])
    if isinstance(members, list):
        candidate_ids.extend(members)
    return [str(alert_id) for alert_id in candidate_ids if alert_id]


def is_test_alert_id(alert_id: str) -> bool:
    return alert_id.startswith(TEST_ALERT_PREFIXES)


def normalized_severity(value: object, fallback: str = "informational") -> str:
    """Normalize the supported informational alias without accepting unknowns."""
    normalized = str(value or fallback).strip().lower()
    return "informational" if normalized == "info" else normalized


def severity_meets_analysis_threshold(severity: object, threshold: object) -> bool:
    """Return whether one recognized severity meets an enabled minimum."""
    normalized_value = normalized_severity(severity)
    normalized_threshold = normalized_severity(threshold)
    if normalized_threshold == "disabled":
        return False
    if normalized_threshold not in ANALYSIS_SEVERITY_LEVELS:
        normalized_threshold = "informational"
    if normalized_value not in ANALYSIS_SEVERITY_LEVELS:
        return False
    return ANALYSIS_SEVERITY_LEVELS.index(normalized_value) >= ANALYSIS_SEVERITY_LEVELS.index(normalized_threshold)


def row_is_ai_backlog_eligible(
    row: object,
    analysis_min_severity: str = "informational",
) -> tuple[bool, str]:
    """Apply automatic analysis exclusions and the configured severity floor."""
    candidate_ids = candidate_alert_ids_for_row(row)
    if candidate_ids and all(is_test_alert_id(alert_id) for alert_id in candidate_ids):
        return False, "Test/validation alert is intentionally excluded from automatic assigned-model analysis"
    status = str(row_value(row, "filter_status") or "accepted").strip().lower()
    if status not in AI_ELIGIBLE_FILTER_STATUSES:
        return False, f"Filter status {status or 'blank'} is not eligible for automatic assigned-model analysis"
    triage_level = row_value(row, "triage_level") or row_value(row, "severity_label") or "informational"
    normalized_level = normalized_severity(triage_level)
    if normalized_level not in ANALYSIS_SEVERITY_LEVELS:
        return False, f"Unrecognized severity {normalized_level or 'blank'} is not eligible for automatic assigned-model analysis"
    if not severity_meets_analysis_threshold(triage_level, analysis_min_severity):
        threshold = normalized_severity(analysis_min_severity)
        label = SOC_ANALYSIS_SEVERITY_LABELS.get(threshold, "Informational")
        return False, f"Below configured {label} automatic AI-analysis minimum"
    return True, "Queued for the scheduled assigned-model analysis worker"


def ai_analysis_for_row(row: object, ai_analysis_by_alert_id: dict[str, dict]) -> dict | None:
    """Return the first available analysis for the representative/group members."""
    for alert_id in candidate_alert_ids_for_row(row):
        analysis = ai_analysis_by_alert_id.get(alert_id)
        if analysis:
            return analysis
    return None


def analysis_artifact_mtime(analysis: dict | None) -> float:
    """Return an analysis artifact mtime without failing dashboard generation."""
    if not analysis:
        return 0
    path = Path(str(analysis.get("_analysis_path") or ""))
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


def matching_artifacts(candidate_ids: list[str], index: dict[str, dict]) -> list[dict]:
    """Select indexed artifacts for this grouped alert in candidate order."""
    return [index[alert_id] for alert_id in candidate_ids if alert_id in index]


def active_analysis_status(
    candidate_ids: list[str],
    prompts: dict[str, dict],
    running_ids: set[str],
) -> StatusTuple | None:
    """Return active runner status before considering queued/completed artifacts."""
    for alert_id in candidate_ids:
        if alert_id in running_ids:
            prompt = prompts.get(alert_id, {})
            detail = prompt.get("_prompt_filename") or "Assigned-model runner is active"
            return "analyzing", "Analyzing", str(detail)
    return None


def queued_prompt_status(prompt: dict) -> StatusTuple:
    """Render one prompt package as normalized queued status."""
    generated_at = prompt.get("generated_at") or "queued"
    filename = prompt.get("_prompt_filename") or "prompt package"
    return "queued", "Queued", normalize_iso_display_text(f"{filename} at {generated_at}")


def completed_analysis_status(analysis: dict) -> StatusTuple:
    """Render completed analysis provenance without assuming response shape."""
    response = analysis.get("response")
    model = str(response.get("_analysis_model") or "") if isinstance(response, dict) else ""
    generated_at = analysis.get("generated_at") or "complete"
    return "analyzed", "Analyzed", normalize_iso_display_text(f"{model} at {generated_at}".strip())


def prompt_is_newer(prompts: list[dict], analyses: list[dict]) -> bool:
    """Return whether a queued prompt supersedes every completed artifact."""
    newest_prompt = max((float(prompt.get("_prompt_mtime") or 0) for prompt in prompts), default=0)
    newest_analysis = max((analysis_artifact_mtime(analysis) for analysis in analyses), default=0)
    return bool(newest_prompt and newest_prompt > newest_analysis)


def ai_workflow_status_for_row(
    row: object,
    ai_analysis_by_alert_id: dict[str, dict],
    ai_prompts_by_alert_id: dict[str, dict],
    running_ai_alert_ids: set[str],
    analysis_min_severity: str = "informational",
) -> StatusTuple:
    """Resolve running, queued, completed, skipped, or backlog status."""
    candidate_ids = candidate_alert_ids_for_row(row)
    active = active_analysis_status(candidate_ids, ai_prompts_by_alert_id, running_ai_alert_ids)
    if active is not None:
        return active
    prompts = matching_artifacts(candidate_ids, ai_prompts_by_alert_id)
    analyses = matching_artifacts(candidate_ids, ai_analysis_by_alert_id)
    if prompt_is_newer(prompts, analyses):
        return queued_prompt_status(max(prompts, key=lambda item: float(item.get("_prompt_mtime") or 0)))
    if analyses:
        return completed_analysis_status(max(analyses, key=analysis_artifact_mtime))
    if prompts:
        return queued_prompt_status(max(prompts, key=lambda item: float(item.get("_prompt_mtime") or 0)))
    eligible, reason = row_is_ai_backlog_eligible(row, analysis_min_severity)
    return ("queued", "Queued", reason) if eligible else ("not-queued", "Skipped", reason)
