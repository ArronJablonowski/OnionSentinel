"""One selected scheduler job's claim, execution, and outcome workflow."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from scheduler_claim import SchedulerClaimRequest, SchedulerClaimState
from scheduler_execution import SchedulerExecutionRequest
from scheduler_outcome import SchedulerOutcomeRequest


@dataclass(frozen=True)
class SchedulerWorkerSources:
    acquire_claim: Callable[..., Any]
    claim_sources: Callable[[], Any]
    execute_analysis: Callable[..., Any]
    execution_sources: Callable[[], Any]
    handle_process_outcome: Callable[..., Any]
    handle_claim_rejection: Callable[..., Any]
    handle_exception: Callable[..., Any]
    outcome_sources: Callable[[], Any]
    controlled_claim_error: type[BaseException]
    execution_errors: tuple[type[BaseException], ...]


def _outcome_request(
    args: Any,
    selection: Any,
    *,
    controlled_evaluation_dir: Path | None,
    claim_state: SchedulerClaimState,
) -> SchedulerOutcomeRequest:
    return SchedulerOutcomeRequest(
        args=args,
        group_id=selection.group_id,
        job_type=selection.job_type,
        processing_recorded=claim_state.processing_recorded,
        lease_token=claim_state.lease_token,
        controlled=controlled_evaluation_dir is not None,
        controlled_evaluation_dir=controlled_evaluation_dir,
        controlled_exact_lease_owned=(
            claim_state.controlled_exact_lease_owned
        ),
    )


def _acquire_selection(
    sources: SchedulerWorkerSources,
    args: Any,
    selection: Any,
    indexed_mode: bool,
    controlled_evaluation_dir: Path | None,
    claim_state: SchedulerClaimState,
) -> Any:
    return sources.acquire_claim(
        sources.claim_sources(),
        SchedulerClaimRequest(
            args=args,
            selected=selection.selected,
            job_payload=selection.job_payload,
            alert_id=selection.alert_id,
            group_id=selection.group_id,
            job_type=selection.job_type,
            indexed_mode=indexed_mode,
            durable_intent=selection.durable_intent,
            controlled=controlled_evaluation_dir is not None,
            allowed_analysis_levels=selection.allowed_analysis_levels,
            allowed_incident_levels=selection.allowed_incident_levels,
            state=claim_state,
        ),
    )


def _execute_claimed_selection(
    sources: SchedulerWorkerSources,
    args: Any,
    selection: Any,
    claim: Any,
    claim_state: SchedulerClaimState,
    indexed_mode: bool,
    controlled_evaluation_dir: Path | None,
) -> Any:
    execution = sources.execute_analysis(
        sources.execution_sources(),
        SchedulerExecutionRequest(
            args=args,
            selected=selection.selected,
            job_payload=selection.job_payload,
            alert_id=selection.alert_id,
            group_id=selection.group_id,
            job_type=selection.job_type,
            indexed_mode=indexed_mode,
            controlled=controlled_evaluation_dir is not None,
            processing_transition=claim_state.processing_transition,
            processing_recorded=claim_state.processing_recorded,
            lease_token=claim_state.lease_token,
            reanalysis_attempt_id=claim.reanalysis_attempt_id,
        ),
    )
    return sources.handle_process_outcome(
        sources.outcome_sources(),
        _outcome_request(
            args,
            selection,
            controlled_evaluation_dir=controlled_evaluation_dir,
            claim_state=claim_state,
        ),
        execution.process,
    )


def _error_outcome(
    handler: Callable[..., Any],
    sources: SchedulerWorkerSources,
    args: Any,
    selection: Any,
    claim_state: SchedulerClaimState,
    controlled_evaluation_dir: Path | None,
    error: BaseException,
) -> Any:
    return handler(
        sources.outcome_sources(),
        _outcome_request(
            args,
            selection,
            controlled_evaluation_dir=controlled_evaluation_dir,
            claim_state=claim_state,
        ),
        error,
    )


def process_scheduler_selection(
    sources: SchedulerWorkerSources,
    args: Any,
    drain_state: Any,
    selection: Any,
    *,
    indexed_mode: bool,
    controlled_evaluation_dir: Path | None,
) -> bool:
    """Process one candidate and return whether the drain must stop."""
    claim_state = SchedulerClaimState()
    try:
        claim = _acquire_selection(
            sources, args, selection, indexed_mode,
            controlled_evaluation_dir, claim_state,
        )
        if claim.disposition == "contended":
            drain_state.release_contended_attempt()
            return False
        selection = dataclass_replace_claim_identity(selection, claim)
        if claim.disposition == "retired":
            return False
        outcome = _execute_claimed_selection(
            sources, args, selection, claim, claim_state, indexed_mode,
            controlled_evaluation_dir,
        )
    except sources.controlled_claim_error as error:
        outcome = _error_outcome(
            sources.handle_claim_rejection, sources, args, selection,
            claim_state, controlled_evaluation_dir, error,
        )
    except sources.execution_errors as error:
        outcome = _error_outcome(
            sources.handle_exception, sources, args, selection,
            claim_state, controlled_evaluation_dir, error,
        )
    drain_state.apply_outcome(outcome)
    return bool(outcome.stop)


def dataclass_replace_claim_identity(selection: Any, claim: Any) -> Any:
    """Copy server-authoritative claim identity into a selection receipt."""
    return replace(
        selection,
        job_payload=claim.job_payload,
        alert_id=claim.alert_id,
        group_id=claim.group_id,
    )
