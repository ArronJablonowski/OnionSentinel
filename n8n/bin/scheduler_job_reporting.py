"""Durable AI job transition and exact-claim reporting contract."""
from __future__ import annotations

import json
import re
import urllib.error
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass

from bounded_http import BoundedHttpError


class ControlledClaimRejected(RuntimeError):
    """An exact controlled job was not claimed; no queue mutation is owned."""


class _IndeterminateStatus(Exception):
    def __init__(self, error: RuntimeError, cause: BaseException | None = None):
        super().__init__(str(error))
        self.error = error
        self.cause = cause


class ClaimedAiLease(str):
    """Lease token carrying the server-authoritative job snapshot it claimed."""

    job_payload: dict[str, object]
    job_type: str
    resolved_key: str
    job_id: int
    reanalysis_attempt_id: str

    def __new__(
        cls,
        token: str,
        *,
        job_payload: dict[str, object] | None = None,
        job_type: str = "",
        resolved_key: str = "",
        job_id: int = 0,
        reanalysis_attempt_id: str = "",
    ):
        value = super().__new__(cls, token)
        try:
            normalized_job_id = int(job_id or 0)
        except (TypeError, ValueError):
            normalized_job_id = 0
        value.job_payload = job_payload if isinstance(job_payload, dict) else {}
        value.job_type = str(job_type or "")
        value.resolved_key = str(resolved_key or "")
        value.job_id = normalized_job_id
        value.reanalysis_attempt_id = str(reanalysis_attempt_id or "")
        return value


@dataclass(frozen=True)
class SchedulerReportingSources:
    request_factory: Callable[..., object]
    open_url: Callable[..., object]
    read_json: Callable[..., dict]
    mutation_headers: Callable[[], dict[str, str]]
    sleep: Callable[[float], None]
    valid_stable_group_key: Callable[[object], bool]
    model_route_pattern: re.Pattern[str]
    max_response_bytes: int
    exact_claim_attempts: int


@dataclass(frozen=True)
class ExactClaim:
    job_id: int
    representative_alert_id: str
    dispatch_id: str
    stable_group_key: str
    assigned_route: str
    reviewer_route: str
    reviewer_required: bool

    @property
    def values(self) -> tuple[object, ...]:
        return (
            self.job_id,
            self.representative_alert_id,
            self.dispatch_id,
            self.stable_group_key,
            self.assigned_route,
            self.reviewer_route,
            self.reviewer_required,
        )

    @property
    def requested(self) -> bool:
        return any(self.values)

    @property
    def complete(self) -> bool:
        return all(self.values)


def _exact_claim(
    *,
    expected_job_id: int,
    expected_representative_alert_id: str,
    expected_dispatch_id: str,
    expected_stable_group_key: str,
    expected_assigned_route: str,
    expected_reviewer_route: str,
    reviewer_required: bool,
) -> ExactClaim:
    return ExactClaim(
        int(expected_job_id or 0),
        str(expected_representative_alert_id or ""),
        str(expected_dispatch_id or ""),
        str(expected_stable_group_key or ""),
        str(expected_assigned_route or ""),
        str(expected_reviewer_route or ""),
        reviewer_required is True,
    )


def _validate_exact_claim(
    sources: SchedulerReportingSources,
    claim: ExactClaim,
    *,
    status: str,
    lease_token: str,
) -> None:
    if not claim.requested:
        return
    if status != "processing" or lease_token or not claim.complete:
        raise ControlledClaimRejected(
            "controlled durable AI claim identity is incomplete"
        )
    if not sources.valid_stable_group_key(claim.stable_group_key):
        raise ControlledClaimRejected(
            "controlled durable AI claim stable group key is invalid"
        )
    assigned_identity = claim.assigned_route.rsplit(":", 1)[0]
    reviewer_identity = claim.reviewer_route.rsplit(":", 1)[0]
    if (
        not sources.model_route_pattern.fullmatch(claim.assigned_route)
        or not sources.model_route_pattern.fullmatch(claim.reviewer_route)
        or assigned_identity == reviewer_identity
        or claim.reviewer_required is not True
    ):
        raise ControlledClaimRejected(
            "controlled durable AI claim route identity is invalid"
        )


def _request_payload(
    sources: SchedulerReportingSources,
    *,
    group_id: str,
    status: str,
    error: str,
    lease_token: str,
    job_type: str,
    retryable: bool,
    exact_claim: ExactClaim,
) -> bytes:
    _validate_exact_claim(
        sources,
        exact_claim,
        status=status,
        lease_token=lease_token,
    )
    payload = {
        "job_type": job_type,
        "dedupe_key": group_id,
        "status": status,
        "error": error[:1000],
        "lease_token": lease_token,
        "retryable": bool(retryable),
    }
    if exact_claim.requested:
        payload.update({
            "expected_job_id": exact_claim.job_id,
            "expected_representative_alert_id": exact_claim.representative_alert_id,
            "expected_dispatch_id": exact_claim.dispatch_id,
            "expected_stable_group_key": exact_claim.stable_group_key,
            "expected_assigned_route": exact_claim.assigned_route,
            "expected_reviewer_route": exact_claim.reviewer_route,
            "reviewer_required": True,
        })
    return json.dumps(payload).encode("utf-8")


def _send_status_request(
    sources: SchedulerReportingSources,
    base_url: str,
    payload: bytes,
) -> dict:
    request = sources.request_factory(
        f"{base_url.rstrip('/')}/jobs/status",
        data=payload,
        headers=sources.mutation_headers(),
        method="POST",
    )
    with sources.open_url(request, timeout=10) as response:
        if response.status not in range(200, 300):
            raise RuntimeError(
                f"AI job status returned HTTP {response.status}"
            )
        result = sources.read_json(
            response,
            max_bytes=sources.max_response_bytes,
        )
    if not result.get("ok", True):
        raise RuntimeError(
            str(result.get("reason") or "AI job status was rejected")
        )
    return result


def _claimed_lease(
    result: dict,
    group_id: str,
) -> tuple[ClaimedAiLease | None, bool]:
    token = str(result.get("lease_token") or "")
    claim = result.get("claim")
    claim = claim if isinstance(claim, dict) else {}
    payload = claim.get("payload")
    if not token:
        return None, False
    payload_valid = isinstance(payload, dict)
    return ClaimedAiLease(
        token,
        job_payload=payload if payload_valid else {},
        job_type=str(claim.get("job_type") or ""),
        resolved_key=str(
            claim.get("dedupe_key") or result.get("dedupe_key") or group_id
        ),
        job_id=claim.get("job_id") or 0,
        reanalysis_attempt_id=str(claim.get("reanalysis_attempt_id") or ""),
    ), payload_valid


def _retryable_http_status(status_code: int) -> bool:
    return status_code >= 500 or status_code in {408, 425, 429}


def _has_retry(exact: bool, attempt_index: int, attempts: int) -> bool:
    return exact and attempt_index + 1 < attempts


def _transition_attempt(
    sources: SchedulerReportingSources,
    *,
    base_url: str,
    payload: bytes,
    status: str,
    group_id: str,
    exact: bool,
) -> bool | ClaimedAiLease:
    try:
        result = _send_status_request(sources, base_url, payload)
    except urllib.error.HTTPError as exc:
        status_code = int(exc.code)
        with suppress(Exception):
            exc.close()
        if status_code == 409:
            raise ControlledClaimRejected(
                "controlled durable AI job changed before it could be claimed"
            ) from exc
        if status_code == 404:
            return False
        error = RuntimeError(f"AI job status returned HTTP {status_code}")
        if _retryable_http_status(status_code):
            raise _IndeterminateStatus(error, exc) from exc
        raise error from exc
    except (urllib.error.URLError, TimeoutError, OSError, BoundedHttpError) as exc:
        error = RuntimeError(f"AI job status request failed: {exc}")
        raise _IndeterminateStatus(error, exc) from exc
    if status != "processing":
        return True
    lease, payload_valid = _claimed_lease(result, group_id)
    if lease is not None and (not exact or payload_valid):
        return lease
    raise _IndeterminateStatus(RuntimeError(
        "AI job processing transition did not return an exact lease receipt"
    ))


def _raise_indeterminate(failure: _IndeterminateStatus) -> None:
    if failure.cause is not None:
        raise failure.error from failure.cause
    raise failure.error


def _prepare_transition_request(
    sources: SchedulerReportingSources,
    *,
    group_id: str,
    status: str,
    error: str,
    lease_token: str,
    job_type: str,
    retryable: bool,
    exact_claim: ExactClaim,
) -> tuple[bytes, bool, int]:
    payload = _request_payload(
        sources,
        group_id=group_id,
        status=status,
        error=error,
        lease_token=lease_token,
        job_type=job_type,
        retryable=retryable,
        exact_claim=exact_claim,
    )
    exact = exact_claim.complete
    attempts = sources.exact_claim_attempts if exact else 1
    return payload, exact, attempts


def _run_transition_attempts(
    sources: SchedulerReportingSources,
    *,
    base_url: str,
    payload: bytes,
    status: str,
    group_id: str,
    exact: bool,
    attempts: int,
) -> bool | ClaimedAiLease:
    last_error: RuntimeError | None = None
    for attempt_index in range(attempts):
        if attempt_index:
            sources.sleep(0.05 * attempt_index)
        try:
            return _transition_attempt(
                sources,
                base_url=base_url,
                payload=payload,
                status=status,
                group_id=group_id,
                exact=exact,
            )
        except _IndeterminateStatus as failure:
            last_error = failure.error
            if _has_retry(exact, attempt_index, attempts):
                continue
            _raise_indeterminate(failure)
    if last_error is not None:
        raise last_error
    raise RuntimeError("AI job status retry invariant failed")


def transition_ai_job_status(
    sources: SchedulerReportingSources,
    base_url: str,
    group_id: str,
    status: str,
    error: str = "",
    lease_token: str = "",
    job_type: str = "ai_analysis",
    retryable: bool = True,
    expected_job_id: int = 0,
    expected_representative_alert_id: str = "",
    expected_dispatch_id: str = "",
    expected_stable_group_key: str = "",
    expected_assigned_route: str = "",
    expected_reviewer_route: str = "",
    reviewer_required: bool = False,
) -> bool | ClaimedAiLease:
    """Transition durable AI intent through the bounded local HTTP contract."""
    exact_claim = _exact_claim(
        expected_job_id=expected_job_id,
        expected_representative_alert_id=expected_representative_alert_id,
        expected_dispatch_id=expected_dispatch_id,
        expected_stable_group_key=expected_stable_group_key,
        expected_assigned_route=expected_assigned_route,
        expected_reviewer_route=expected_reviewer_route,
        reviewer_required=reviewer_required,
    )
    payload, exact, attempts = _prepare_transition_request(
        sources,
        group_id=group_id,
        status=status,
        error=error,
        lease_token=lease_token,
        job_type=job_type,
        retryable=retryable,
        exact_claim=exact_claim,
    )
    return _run_transition_attempts(
        sources,
        base_url=base_url,
        payload=payload,
        status=status,
        group_id=group_id,
        exact=exact,
        attempts=attempts,
    )
