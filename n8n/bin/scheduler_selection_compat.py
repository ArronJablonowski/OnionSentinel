"""Compatibility policy for indexed and legacy scheduler selection."""
from __future__ import annotations

from typing import Any, Mapping


RuntimeNamespace = Mapping[str, Any]


def test_filter_sql(
    patterns: tuple[str, ...],
    column: str = "alert_id",
) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    for pattern in patterns:
        clauses.append(f"{column} NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def select_next_alert_indexed(
    runtime: RuntimeNamespace,
    conn: Any,
    args: Any,
    already_selected_groups: set[str] | None = None,
) -> Any | None:
    lane_sql, lane_params = runtime["provider_lane_sql"](args)
    del already_selected_groups
    request = runtime["IndexedSelectionRequest"](
        levels=args.levels,
        hours=args.hours,
        include_tests=args.include_tests,
        only_group_id=str(getattr(args, "only_group_id", "") or ""),
        lane_sql=lane_sql,
        lane_params=tuple(lane_params),
    )
    sources = runtime["IndexedSelectionSources"](
        now=lambda: runtime["dt"].datetime.now().astimezone(),
        precise_now=runtime["project_now_precise"],
        alert_time_sql=runtime["alert_time_sql"],
        severity_priority_sql=runtime["severity_priority_sql"],
        test_filter_sql=runtime["test_filter_sql"],
        eligible_filter_statuses=runtime["ELIGIBLE_FILTER_STATUSES"],
        fairness_age_seconds=runtime["AI_JOB_FAIRNESS_AGE_SECONDS"],
    )
    return runtime["select_next_indexed_alert"](conn, request, sources)


def select_next_alert_legacy(
    runtime: RuntimeNamespace,
    conn: Any,
    args: Any,
    already_analyzed: set[str],
    already_selected_groups: set[str] | None = None,
) -> Any | None:
    request = runtime["LegacySelectionRequest"](
        levels=args.levels,
        hours=args.hours,
        include_tests=args.include_tests,
        only_group_id=str(getattr(args, "only_group_id", "") or ""),
        analysis_dir=getattr(args, "analysis_dir", None),
        pcap_analysis_dir=getattr(args, "pcap_analysis_dir", None),
        prompt_dir=getattr(args, "prompt_dir", None),
        already_analyzed=frozenset(already_analyzed),
        already_selected_groups=frozenset(already_selected_groups or set()),
    )
    sources = runtime["LegacySelectionSources"](
        now=lambda: runtime["dt"].datetime.now().astimezone(),
        alert_time_sql=lambda: runtime["alert_time_sql"](),
        alert_group_key_sql=runtime["alert_group_key_sql"],
        severity_priority_sql=lambda: runtime["severity_priority_sql"](),
        test_filter_sql=lambda: runtime["test_filter_sql"](),
        latest_prompt_mtimes=runtime["latest_prompt_mtimes"],
        latest_analysis_mtimes=runtime["latest_analysis_mtimes"],
        analyzed_alert_groups=runtime["analyzed_alert_groups"],
        pending_ai_job_ids=runtime["pending_ai_job_ids"],
        alert_group_key=runtime["alert_group_key"],
        alert_group_id=runtime["alert_group_id"],
        eligible_filter_statuses=runtime["ELIGIBLE_FILTER_STATUSES"],
    )
    return runtime["select_next_legacy_alert"](conn, request, sources)


def durable_payload(runtime: RuntimeNamespace, selected: Any) -> dict[str, object]:
    if "durable_payload_json" not in selected.keys():
        return {}
    try:
        payload = runtime["json"].loads(
            str(selected["durable_payload_json"] or "{}")
        )
    except runtime["json"].JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}
