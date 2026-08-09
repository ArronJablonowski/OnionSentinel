"""Validate imported cohort source-row identities and frozen projections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Pattern, Type


@dataclass(frozen=True)
class CohortSourceRowPolicy:
    """Injected validation policy for externally supplied cohort rows."""

    error: Type[Exception]
    dashboard_group_id_pattern: Pattern[str]
    stable_group_id_pattern: Pattern[str]
    representative_alert_id_pattern: Pattern[str]
    summary_export_columns: tuple[str, ...]


def source_identity(
    row: Mapping[str, Any],
    policy: CohortSourceRowPolicy,
) -> tuple[str, str, str]:
    """Return and validate the three identities binding a source row."""
    dashboard_id = str(
        row.get("dashboard_group_id")
        or row.get("legacy_group_id")
        or row.get("group_id")
        or ""
    ).strip().lower()
    stable_id = str(row.get("stable_group_id") or "").strip().lower()
    representative_alert_id = str(
        row.get("representative_alert_id") or ""
    ).strip()
    if not policy.dashboard_group_id_pattern.fullmatch(dashboard_id):
        raise policy.error(
            f"source row has invalid dashboard group ID: {dashboard_id!r}"
        )
    if not policy.stable_group_id_pattern.fullmatch(stable_id):
        raise policy.error(
            f"source row has invalid stable group ID: {stable_id!r}"
        )
    if not policy.representative_alert_id_pattern.fullmatch(
        representative_alert_id
    ):
        raise policy.error(
            f"source row {dashboard_id} has an invalid representative "
            "alert ID"
        )
    return dashboard_id, stable_id, representative_alert_id


def source_detection_projection(
    source: Mapping[str, Any],
    policy: CohortSourceRowPolicy,
) -> dict[str, Any]:
    """Project supplied source and nested-detection fields for comparison."""
    supplied_detection = source.get("detection")
    if supplied_detection is not None and not isinstance(
        supplied_detection,
        dict,
    ):
        raise policy.error("source row detection must be an object")
    nested = supplied_detection if isinstance(supplied_detection, dict) else {}
    keys = tuple(
        key for key in policy.summary_export_columns if key != "group_id"
    ) + ("cohort_seen_at", "stable_group_key")
    comparisons = {key: source[key] for key in keys if key in source}
    comparisons.update({key: nested[key] for key in keys if key in nested})
    return comparisons


def validate_source_detection(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
    policy: CohortSourceRowPolicy,
) -> dict[str, Any]:
    """Fail closed when a supplied frozen detection no longer matches."""
    try:
        comparisons = source_detection_projection(source, policy)
    except policy.error as exc:
        raise policy.error(
            f"source row {dashboard_id} detection must be an object"
        ) from exc
    for key, value in comparisons.items():
        if key == "stable_group_key":
            # The summary table does not own this identity field. It is
            # compared against the exact raw alert by representative binding.
            continue
        if current.get(key) != value:
            raise policy.error(
                f"source row {dashboard_id} no longer matches frozen "
                f"detection field {key}"
            )
    return comparisons


def validate_source_pre_state(
    source: Mapping[str, Any],
    current: Mapping[str, Any],
    dashboard_id: str,
    policy: CohortSourceRowPolicy,
) -> None:
    """Fail closed when imported case state changed after selection."""
    if "pre_state" in source and source["pre_state"] != current:
        raise policy.error(
            f"source row {dashboard_id} pre-state changed after selection"
        )
    case = current.get("incident_case") or {}
    aliases = {
        "case_id": "case_id",
        "case_status": "status",
        "case_agent_status": "agent_status",
        "latest_analysis_id": "latest_analysis_id",
    }
    for source_key, case_key in aliases.items():
        if source_key in source and source[source_key] != case.get(case_key):
            raise policy.error(
                f"source row {dashboard_id} no longer matches {source_key}"
            )
