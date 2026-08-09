"""Bounded HTTP and pure dispatch-contract adapters for cohort execution."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from cohort_dispatch_contract import (
    CohortDispatchContract,
    request_for_member as build_dispatch_request,
    validate_dispatch_job_payload as validate_job_payload,
    validate_success_response as validate_dispatch_response,
)
from cohort_http import (
    CohortHttpPolicy,
    HttpResult,
    dashboard_post_json as post_dashboard_json,
    load_evaluation_token as read_evaluation_token,
    validate_loopback_base_url as validate_dashboard_base_url,
)
from cohort_runner_contracts import (
    CASE_ID_RE,
    MAX_EVALUATION_TOKEN_BYTES,
    MAX_HTTP_BODY_BYTES,
    RUN_ID_RE,
    SHA256_RE,
    AmbiguousDispatchError,
    CohortError,
    canonical_bytes,
    sha256_value,
)


@dataclass(frozen=True)
class DispatchContractPorts:
    """Identity functions needed by the pure dispatch contract."""

    validate_release_id: Callable[[Any], str]
    member_stable_group_key: Callable[[Mapping[str, Any]], str]
    deterministic_dispatch_id: Callable[
        [Mapping[str, Any], Mapping[str, Any]], str
    ]


def http_policy() -> CohortHttpPolicy:
    return CohortHttpPolicy(
        maximum_http_body_bytes=MAX_HTTP_BODY_BYTES,
        evaluation_token_bytes=MAX_EVALUATION_TOKEN_BYTES,
        token_pattern=SHA256_RE,
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        canonical_bytes=canonical_bytes,
    )


def validate_loopback_base_url(value: str) -> str:
    """Validate and normalize a plain loopback dashboard origin."""
    return validate_dashboard_base_url(http_policy(), value)


def load_evaluation_token(path: Path) -> str:
    """Read the owner-only evaluation token through the bounded policy."""
    return read_evaluation_token(http_policy(), path)


def dashboard_post_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    timeout: float,
    evaluation_token: str | None = None,
) -> HttpResult:
    """Send one bounded dashboard POST through the loopback-only policy."""
    return post_dashboard_json(
        http_policy(),
        url,
        payload,
        timeout=timeout,
        evaluation_token=evaluation_token,
    )


def dispatch_contract(ports: DispatchContractPorts) -> CohortDispatchContract:
    return CohortDispatchContract(
        cohort_error=CohortError,
        ambiguous_dispatch_error=AmbiguousDispatchError,
        case_id_pattern=CASE_ID_RE,
        run_id_pattern=RUN_ID_RE,
        validate_release_id=ports.validate_release_id,
        member_stable_group_key=ports.member_stable_group_key,
        deterministic_dispatch_id=ports.deterministic_dispatch_id,
        sha256_value=sha256_value,
    )


def request_for_member(
    ports: DispatchContractPorts,
    base_url: str,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    return build_dispatch_request(
        dispatch_contract(ports),
        base_url,
        manifest,
        member,
    )


def validate_success_response(
    ports: DispatchContractPorts,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    result: HttpResult,
) -> dict[str, Any]:
    return validate_dispatch_response(
        dispatch_contract(ports),
        manifest,
        member,
        result,
    )


def validate_dispatch_job_payload(
    ports: DispatchContractPorts,
    manifest: Mapping[str, Any],
    member: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    manual_reanalysis: bool,
    expected_case_id: str = "",
    expected_reanalysis_run_id: str = "",
) -> dict[str, Any]:
    return validate_job_payload(
        dispatch_contract(ports),
        manifest,
        member,
        job,
        manual_reanalysis=manual_reanalysis,
        expected_case_id=expected_case_id,
        expected_reanalysis_run_id=expected_reanalysis_run_id,
    )
