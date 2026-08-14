"""Durable scheduler claim acquisition and server-authoritative identity."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from scheduler_job_reporting import ControlledClaimRejected


@dataclass
class SchedulerClaimState:
    processing_transition: object = False
    processing_recorded: bool = False
    lease_token: str = ""
    controlled_exact_lease_owned: bool = False


@dataclass(frozen=True)
class SchedulerClaimRequest:
    args: Any
    selected: Any
    job_payload: dict[str, object]
    alert_id: str
    group_id: str
    job_type: str
    indexed_mode: bool
    durable_intent: bool
    controlled: bool
    allowed_analysis_levels: tuple[str, ...]
    allowed_incident_levels: tuple[str, ...]
    state: SchedulerClaimState


@dataclass(frozen=True)
class SchedulerClaimSources:
    exact_expectations: Callable[..., dict[str, object]]
    report_status: Callable[..., object]
    load_claimed_job: Callable[..., tuple[dict, str, str, str]]
    require_controlled_identity: Callable[..., None]
    job_reanalysis_attempt_id: Callable[[dict, str], str]
    emit: Callable[[str], None]
    now: Callable[[], str]


@dataclass(frozen=True)
class SchedulerClaimResult:
    disposition: str
    job_payload: dict[str, object]
    alert_id: str
    group_id: str
    claimed_triage_level: str
    processing_transition: object
    processing_recorded: bool
    lease_token: str
    controlled_exact_lease_owned: bool
    reanalysis_attempt_id: str


def _exact_claim(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
) -> dict[str, object]:
    if request.controlled and not (
        request.indexed_mode and request.durable_intent
    ):
        raise ControlledClaimRejected(
            "controlled AI run requires a durable AI job claim"
        )
    if not request.controlled:
        return {}
    return sources.exact_expectations(
        request.args,
        request.selected,
        request.job_payload,
    )


def _claim_transition(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
    exact_claim: dict[str, object],
) -> tuple[object, bool, str, bool]:
    transition = sources.report_status(
        request.args.alert_store_url,
        request.group_id,
        "processing",
        job_type=request.job_type,
        **exact_claim,
    )
    recorded = bool(transition)
    lease_token = transition if isinstance(transition, str) else ""
    exact_owned = bool(
        request.controlled
        and recorded
        and int(getattr(transition, "job_id", 0) or 0)
        == int(exact_claim.get("expected_job_id") or 0)
    )
    request.state.processing_transition = transition
    request.state.processing_recorded = recorded
    request.state.lease_token = lease_token
    request.state.controlled_exact_lease_owned = exact_owned
    return transition, recorded, lease_token, exact_owned


def _contention_result(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
) -> SchedulerClaimResult:
    if request.controlled:
        raise ControlledClaimRejected(
            "controlled durable AI job disappeared before its processing "
            "lease was recorded"
        )
    sources.emit(
        f"{sources.now()} AI group {request.group_id} claim contention: "
        "another worker acquired the durable processing lease"
    )
    return SchedulerClaimResult(
        "contended", request.job_payload, request.alert_id, request.group_id,
        "", False, False, "", False, "",
    )


def _server_authoritative_identity(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
    transition: object,
    exact_claim: dict[str, object],
) -> tuple[dict[str, object], str, str, str]:
    triage_level = str(
        request.selected["triage_level"] or ""
    ).strip().lower()
    if not (request.indexed_mode and request.durable_intent):
        return request.job_payload, request.alert_id, request.group_id, triage_level
    try:
        return sources.load_claimed_job(
            transition,
            request.args.db,
            expected_job_type=request.job_type,
            expected_group_id=request.group_id,
            expected_job_id=int(exact_claim.get("expected_job_id") or 0),
        )
    except RuntimeError as error:
        if request.controlled:
            raise ControlledClaimRejected(str(error)) from error
        raise


def _validate_controlled_identity(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
    transition: object,
    exact_claim: dict[str, object],
    payload: dict[str, object],
    alert_id: str,
    group_id: str,
) -> None:
    if not request.controlled:
        return
    sources.require_controlled_identity(
        request.args,
        payload,
        claimed_alert_id=alert_id,
        claimed_group_id=group_id,
        claimed_job_id=int(getattr(transition, "job_id", 0) or 0),
        expected_job_id=int(exact_claim.get("expected_job_id") or 0),
    )


def _reanalysis_attempt(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
    transition: object,
    payload: dict[str, object],
    lease_token: str,
) -> str:
    if request.job_type != "incident_response_analysis":
        return ""
    run_id = str(payload.get("reanalysis_run_id") or "").strip()
    attempt_id = str(
        getattr(transition, "reanalysis_attempt_id", "") or ""
    ).strip()
    if not run_id and not attempt_id:
        return ""
    expected = sources.job_reanalysis_attempt_id(payload, lease_token)
    if not expected or attempt_id != expected:
        raise RuntimeError(
            "incident reanalysis lease identity did not match its "
            "server-bound attempt"
        )
    return attempt_id


def _below_automatic_floor(
    request: SchedulerClaimRequest,
    payload: dict[str, object],
    triage_level: str,
) -> bool:
    allowed = {
        "ai_analysis": request.allowed_analysis_levels,
        "incident_response_analysis": request.allowed_incident_levels,
    }.get(request.job_type)
    return (
        request.indexed_mode
        and request.durable_intent
        and allowed is not None
        and payload.get("manual_reanalysis") is not True
        and triage_level not in set(allowed)
    )


def _retire_below_floor(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
    group_id: str,
    triage_level: str,
    lease_token: str,
) -> None:
    if request.job_type == "incident_response_analysis":
        threshold = (
            request.allowed_incident_levels[-1]
            if request.allowed_incident_levels
            else "disabled"
        )
        detail = (
            "automatic incident response skipped: "
            f"{triage_level or 'unknown'} is below configured "
            f"{threshold} threshold"
        )
        sources.report_status(
            request.args.alert_store_url,
            group_id,
            "failed",
            detail,
            lease_token=lease_token,
            job_type=request.job_type,
            retryable=False,
        )
        sources.emit(f"{sources.now()} {detail}")
        return
    sources.report_status(
        request.args.alert_store_url,
        group_id,
        "completed",
        lease_token=lease_token,
        job_type=request.job_type,
    )
    sources.emit(
        f"{sources.now()} skipped automatic AI analysis for "
        f"{triage_level} group below configured threshold"
    )


def acquire_scheduler_claim(
    sources: SchedulerClaimSources,
    request: SchedulerClaimRequest,
) -> SchedulerClaimResult:
    """Acquire and validate one durable lease without preparing evidence."""
    exact_claim = _exact_claim(sources, request)
    transition, recorded, lease_token, exact_owned = _claim_transition(
        sources, request, exact_claim
    )
    if request.indexed_mode and request.durable_intent and not recorded:
        return _contention_result(sources, request)
    payload, alert_id, group_id, triage_level = _server_authoritative_identity(
        sources, request, transition, exact_claim
    )
    _validate_controlled_identity(
        sources, request, transition, exact_claim, payload, alert_id, group_id
    )
    attempt_id = _reanalysis_attempt(
        sources, request, transition, payload, lease_token
    )
    disposition = "claimed"
    if _below_automatic_floor(request, payload, triage_level):
        _retire_below_floor(
            sources, request, group_id, triage_level, lease_token
        )
        disposition = "retired"
    return SchedulerClaimResult(
        disposition,
        payload,
        alert_id,
        group_id,
        triage_level,
        transition,
        recorded,
        lease_token,
        exact_owned,
        attempt_id,
    )
