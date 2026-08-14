"""Scheduler queue selection and drain-loop state orchestration."""
from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SchedulerDrainState:
    selected_groups: set[str] = field(default_factory=set)
    analyzed_count: int = 0
    attempted_count: int = 0
    controlled_owned_job_failed: bool = False
    controlled_failure_detail: str = ""
    controlled_failure_group_id: str = ""

    def release_contended_attempt(self) -> None:
        self.attempted_count = max(0, self.attempted_count - 1)

    def apply_outcome(self, outcome: Any) -> None:
        self.analyzed_count += int(outcome.analyzed_increment)
        if outcome.controlled_owned_job_failed:
            self.controlled_owned_job_failed = True
            self.controlled_failure_detail = outcome.failure_detail
            self.controlled_failure_group_id = outcome.failure_group_id


@dataclass(frozen=True)
class SchedulerDrainSources:
    stop_for_drain: Callable[[Any], bool]
    configured_levels: Callable[[Any, str], list[str]]
    configured_incident_levels: Callable[[Any], list[str]]
    open_readonly_database: Callable[[Any], Any]
    select_indexed: Callable[[Any, Any, set[str]], Any | None]
    select_legacy: Callable[[Any, Any, set[str], set[str]], Any | None]
    analyzed_alert_ids: Callable[[Any, Any, Any], set[str]]
    alert_group_key: Callable[[Any], str]
    alert_group_id: Callable[[str], str]
    durable_payload: Callable[[Any], dict[str, object]]
    now: Callable[[], str]
    emit: Callable[[str], None]


@dataclass(frozen=True)
class SchedulerSelection:
    disposition: str
    allowed_analysis_levels: tuple[str, ...] = ()
    allowed_incident_levels: tuple[str, ...] = ()
    automatic_execution_eligible: bool = True
    selected: Any | None = None
    alert_id: str = ""
    group_id: str = ""
    job_type: str = "ai_analysis"
    job_payload: dict[str, object] = field(default_factory=dict)
    durable_intent: bool = False


def _has_field(selected: Any, field_name: str) -> bool:
    return field_name in selected.keys()


def _selected_group(
    sources: SchedulerDrainSources,
    selected: Any,
) -> tuple[str, str]:
    group_id = (
        str(selected["stable_group_id"] or "")
        if _has_field(selected, "stable_group_id")
        else ""
    )
    group_key = str(
        selected["queue_group_key"]
        or sources.alert_group_key(selected)
    )
    if not group_id:
        group_id = sources.alert_group_id(group_key)
    return group_id, group_key


def _select_candidate(
    sources: SchedulerDrainSources,
    args: Any,
    state: SchedulerDrainState,
    indexed_mode: bool,
) -> Any | None:
    connection = sources.open_readonly_database(args.db)
    try:
        if indexed_mode:
            return sources.select_indexed(
                connection,
                args,
                state.selected_groups,
            )
        analyzed_ids = sources.analyzed_alert_ids(
            args.analysis_dir,
            args.pcap_analysis_dir,
            args.prompt_dir,
        )
        return sources.select_legacy(
            connection,
            args,
            analyzed_ids,
            state.selected_groups,
        )
    finally:
        connection.close()


def _emit_selection(
    sources: SchedulerDrainSources,
    args: Any,
    selected: Any,
    alert_id: str,
    job_type: str,
    automatic_execution_eligible: bool,
) -> None:
    sources.emit(
        json.dumps(
            {
                "selected_alert_id": alert_id,
                "rule_name": selected["rule_name"],
                "triage_level": selected["triage_level"],
                "triage_score": selected["triage_score"],
                "last_seen": selected["last_seen"],
                "queue_time": selected["queue_time"],
                "job_type": job_type,
                "automatic_execution_eligible": automatic_execution_eligible,
                "provider_lane": args.provider_lane,
            },
            sort_keys=True,
        )
    )


def _project_selection(
    sources: SchedulerDrainSources,
    args: Any,
    state: SchedulerDrainState,
    selected: Any,
    allowed: tuple[str, ...],
    incident_allowed: tuple[str, ...],
) -> SchedulerSelection:
    alert_id = selected["alert_id"]
    group_id, group_key = _selected_group(sources, selected)
    state.selected_groups.update((group_id, group_key))
    job_type = (
        str(selected["durable_job_type"] or "ai_analysis")
        if _has_field(selected, "durable_job_type")
        else "ai_analysis"
    )
    payload = sources.durable_payload(selected)
    durable_intent = bool(
        selected["has_durable_intent"]
        if _has_field(selected, "has_durable_intent")
        else False
    )
    allowed_for_job = {
        "ai_analysis": allowed,
        "incident_response_analysis": incident_allowed,
    }.get(job_type)
    automatic_execution_eligible = (
        not durable_intent
        or payload.get("manual_reanalysis") is True
        or allowed_for_job is None
        or str(selected["triage_level"] or "").strip().lower()
        in set(allowed_for_job)
    )
    state.attempted_count += 1
    _emit_selection(
        sources, args, selected, alert_id, job_type,
        automatic_execution_eligible,
    )
    return SchedulerSelection(
        disposition="dry_run" if args.dry_run else "selected",
        allowed_analysis_levels=allowed,
        allowed_incident_levels=incident_allowed,
        automatic_execution_eligible=automatic_execution_eligible,
        selected=selected,
        alert_id=alert_id,
        group_id=group_id,
        job_type=job_type,
        job_payload=payload,
        durable_intent=durable_intent,
    )


def select_scheduler_work(
    sources: SchedulerDrainSources,
    args: Any,
    state: SchedulerDrainState,
    *,
    indexed_mode: bool,
    launch_levels: str,
    drain_file: Any,
) -> SchedulerSelection:
    """Select and project exactly one scheduler candidate, or stop safely."""
    if args.max_per_run and state.attempted_count >= args.max_per_run:
        return SchedulerSelection(disposition="stop")
    if sources.stop_for_drain(drain_file):
        return SchedulerSelection(disposition="stop")

    allowed = tuple(
        sources.configured_levels(args.ai_settings_file, launch_levels)
    )
    incident_allowed = tuple(
        sources.configured_incident_levels(args.ai_settings_file)
    )
    args.levels = ",".join(allowed or ("__disabled__",))
    sources.emit(
        f"{sources.now()} checking highest-priority unanalyzed alert queue"
    )
    selected = _select_candidate(sources, args, state, indexed_mode)
    if selected is None:
        if state.analyzed_count == 0:
            sources.emit(f"{sources.now()} no eligible unanalyzed alert found")
        return SchedulerSelection(disposition="stop")
    return _project_selection(
        sources, args, state, selected, allowed, incident_allowed
    )
