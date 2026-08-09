"""Scheduler evidence preparation, prompt construction, and runner dispatch."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SchedulerExecutionRequest:
    args: Any
    selected: Any
    job_payload: dict[str, object]
    alert_id: str
    group_id: str
    job_type: str
    indexed_mode: bool
    controlled: bool
    processing_transition: object
    processing_recorded: bool
    lease_token: str
    reanalysis_attempt_id: str


@dataclass(frozen=True)
class SchedulerExecutionSources:
    report_status: Callable[..., object]
    validate_controlled_route: Callable[[Any, dict], object]
    collect_incident_evidence: Callable[..., Path]
    build_prompt: Callable[..., Path]
    reusable_prompt: Callable[[Path, Any, Path], Path | None]
    run_analysis: Callable[..., Any]


@dataclass(frozen=True)
class SchedulerExecutionResult:
    process: Any
    prompt_path: Path
    assigned_agent_role: str
    controlled_result_identity: dict[str, object] | None


def _lease_renewer(
    sources: SchedulerExecutionSources,
    request: SchedulerExecutionRequest,
) -> Callable[[], None] | None:
    if not request.processing_recorded:
        return None

    def renew() -> None:
        renewed = sources.report_status(
            request.args.alert_store_url,
            request.group_id,
            "processing",
            lease_token=request.lease_token,
            job_type=request.job_type,
        )
        if renewed != request.lease_token:
            raise RuntimeError(
                "durable AI processing lease could not be renewed"
            )

    return renew


def _incident_evidence(
    sources: SchedulerExecutionSources,
    request: SchedulerExecutionRequest,
    renew: Callable[[], None] | None,
) -> Path | None:
    if request.job_type != "incident_response_analysis":
        return None
    if request.controlled:
        # Re-read strict settings immediately before the first Relay request.
        sources.validate_controlled_route(request.args, request.job_payload)
    return sources.collect_incident_evidence(
        request.alert_id,
        request.args,
        progress_callback=renew,
    )


def _prompt_path(
    sources: SchedulerExecutionSources,
    request: SchedulerExecutionRequest,
    incident_evidence_path: Path | None,
) -> Path:
    if request.indexed_mode:
        return sources.build_prompt(
            request.alert_id,
            request.args,
            request.job_payload,
            incident_evidence_path=incident_evidence_path,
        )
    reusable = sources.reusable_prompt(
        request.args.prompt_dir,
        request.selected,
        request.args.pcap_analysis_dir,
    )
    if reusable is not None:
        return reusable
    return sources.build_prompt(request.alert_id, request.args)


def _controlled_result_identity(
    request: SchedulerExecutionRequest,
    assigned_agent_role: str,
) -> dict[str, object] | None:
    if not request.controlled:
        return None
    payload = request.job_payload
    return {
        "job_id": int(
            getattr(request.processing_transition, "job_id", 0) or 0
        ),
        "job_type": request.job_type,
        "lease_token": request.lease_token,
        "cohort_id": str(payload.get("cohort_id") or ""),
        "dispatch_id": str(payload.get("dispatch_id") or ""),
        "representative_alert_id": request.alert_id,
        "stable_group_id": request.group_id,
        "stable_group_key": str(payload.get("stable_group_key") or ""),
        "agent_role": assigned_agent_role,
        "reanalysis_attempt_id": request.reanalysis_attempt_id,
        "release_id": str(payload.get("release_id") or ""),
        "expected_assigned_route": str(
            payload.get("expected_assigned_route") or ""
        ),
        "expected_reviewer_route": str(
            payload.get("expected_reviewer_route") or ""
        ),
        "reviewer_required": payload.get("reviewer_required") is True,
    }


def execute_scheduler_analysis(
    sources: SchedulerExecutionSources,
    request: SchedulerExecutionRequest,
) -> SchedulerExecutionResult:
    """Prepare exact evidence and invoke one bounded assigned-model run."""
    renew = _lease_renewer(sources, request)
    evidence = _incident_evidence(sources, request, renew)
    prompt_path = _prompt_path(sources, request, evidence)
    assigned_role = str(
        request.job_payload.get("agent_role") or "soc-analyst"
    )
    identity = _controlled_result_identity(request, assigned_role)
    process = sources.run_analysis(
        prompt_path,
        request.args,
        progress_callback=renew,
        reanalysis_attempt_id=request.reanalysis_attempt_id,
        agent_role=assigned_role,
        controlled_result_identity=identity,
    )
    return SchedulerExecutionResult(
        process=process,
        prompt_path=prompt_path,
        assigned_agent_role=assigned_role,
        controlled_result_identity=identity,
    )
