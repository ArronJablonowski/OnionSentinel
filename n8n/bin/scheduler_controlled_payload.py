"""Validation and immutable projection for controlled recovery payloads."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Pattern


@dataclass(frozen=True)
class ControlledPayloadPolicy:
    lease_token_pattern: Pattern[str]
    cohort_id_pattern: Pattern[str]
    model_route_pattern: Pattern[str]
    analysis_id_pattern: Pattern[str]


@dataclass(frozen=True)
class ControlledPayloadSources:
    current_release_id: Callable[[], str]
    incident_attempt_id: Callable[[str], str]
    canonical_digest: Callable[..., str]
    storage_canonical_digest: Callable[[object], str]
    expected_accepted_fields: Callable[
        [dict[str, Any], dict[str, Any]], dict[str, str | None]
    ]


IDENTITY_FIELDS = {
    "job_id",
    "job_type",
    "lease_token",
    "cohort_id",
    "dispatch_id",
    "representative_alert_id",
    "stable_group_id",
    "stable_group_key",
    "agent_role",
    "reanalysis_attempt_id",
    "release_id",
    "expected_assigned_route",
    "expected_reviewer_route",
    "reviewer_required",
}


def _identity_matches(
    policy: ControlledPayloadPolicy,
    identity: dict[str, Any],
    args: Any,
    *,
    expected_role: str | None,
    expected_attempt: str,
    current_release_id: str,
) -> bool:
    assigned_route = identity.get("expected_assigned_route")
    reviewer_route = identity.get("expected_reviewer_route")
    return all(
        (
            isinstance(identity.get("job_id"), int),
            not isinstance(identity.get("job_id"), bool),
            identity.get("job_id", 0) >= 1,
            isinstance(identity.get("job_type"), str),
            isinstance(identity.get("lease_token"), str),
            bool(
                policy.lease_token_pattern.fullmatch(
                    identity.get("lease_token", "")
                )
            ),
            isinstance(identity.get("cohort_id"), str),
            bool(
                policy.cohort_id_pattern.fullmatch(
                    identity.get("cohort_id", "")
                )
            ),
            identity.get("dispatch_id") == args.only_dispatch_id,
            identity.get("representative_alert_id") == args.only_alert_id,
            identity.get("stable_group_id") == args.only_group_id,
            identity.get("stable_group_key") == args.only_stable_group_key,
            identity.get("agent_role") == expected_role,
            identity.get("reanalysis_attempt_id") == expected_attempt,
            identity.get("release_id") == current_release_id,
            isinstance(assigned_route, str),
            bool(policy.model_route_pattern.fullmatch(assigned_route or "")),
            isinstance(reviewer_route, str),
            bool(policy.model_route_pattern.fullmatch(reviewer_route or "")),
            (assigned_route or "").rsplit(":", 1)[0]
            != (reviewer_route or "").rsplit(":", 1)[0],
            identity.get("reviewer_required") is True,
        )
    )


def _response_matches(
    policy: ControlledPayloadPolicy,
    payload: dict[str, Any],
    response: dict[str, Any],
    identity: dict[str, Any],
    args: Any,
    claim_digest: str,
) -> bool:
    analysis_id = payload.get("analysis_id")
    reviewer = response.get("_second_opinion")
    reviewer_response = (
        reviewer.get("response") if isinstance(reviewer, dict) else None
    )
    return all(
        (
            isinstance(analysis_id, str),
            bool(policy.analysis_id_pattern.fullmatch(analysis_id or "")),
            payload.get("alert_id") == args.only_alert_id,
            payload.get("agent_role") == identity["agent_role"],
            str(payload.get("reanalysis_attempt_id") or "")
            == identity["reanalysis_attempt_id"],
            response.get("_analysis_evaluation_memory_frozen") is True,
            response.get("_analysis_controlled_claim_sha256")
            == claim_digest,
            response.get("_analysis_model_route")
            == identity["expected_assigned_route"],
            isinstance(reviewer, dict),
            isinstance(reviewer, dict)
            and reviewer.get("status") == "completed",
            isinstance(reviewer, dict)
            and reviewer.get("model_route")
            == identity["expected_reviewer_route"],
            isinstance(reviewer_response, dict),
            isinstance(reviewer_response, dict)
            and reviewer_response.get("_analysis_model_route")
            == identity["expected_reviewer_route"],
        )
    )


def _recovery_projection(
    sources: ControlledPayloadSources,
    payload: dict[str, Any],
    response: dict[str, Any],
    identity: dict[str, Any],
    args: Any,
    claim_digest: str,
) -> dict[str, Any]:
    return {
        "analysis_id": payload["analysis_id"],
        "job_id": identity["job_id"],
        "job_type": identity["job_type"],
        "lease_token": identity["lease_token"],
        "stable_group_id": args.only_group_id,
        "response_digest": sources.canonical_digest(response),
        "stored_response_fallback_digest": (
            sources.storage_canonical_digest(response)
        ),
        "accepted_fields": sources.expected_accepted_fields(
            payload, response
        ),
        "claim_digest": claim_digest,
        "identity": identity,
    }


def validate_controlled_recovery_payload(
    policy: ControlledPayloadPolicy,
    sources: ControlledPayloadSources,
    payload: dict[str, Any],
    args: Any,
) -> dict[str, Any]:
    """Bind one recovery payload to exact frozen scheduler pins."""
    identity = payload.get("controlled_job")
    response = payload.get("response")
    if (
        not isinstance(identity, dict)
        or set(identity) != IDENTITY_FIELDS
        or not isinstance(response, dict)
    ):
        raise RuntimeError(
            "controlled evaluation recovery identity is incomplete"
        )
    job_type = identity.get("job_type")
    lease_token = str(identity.get("lease_token") or "")
    expected_role = {
        "ai_analysis": "soc-analyst",
        "incident_response_analysis": "incident-responder",
    }.get(job_type)
    expected_attempt = (
        ""
        if job_type == "ai_analysis"
        else sources.incident_attempt_id(lease_token)
    )
    claim_digest = sources.canonical_digest(identity, ensure_ascii=False)
    if not _identity_matches(
        policy,
        identity,
        args,
        expected_role=expected_role,
        expected_attempt=expected_attempt,
        current_release_id=sources.current_release_id(),
    ) or not _response_matches(
        policy,
        payload,
        response,
        identity,
        args,
        claim_digest,
    ):
        raise RuntimeError(
            "controlled evaluation recovery identity does not match "
            "the frozen scheduler pins"
        )
    return _recovery_projection(
        sources, payload, response, identity, args, claim_digest
    )
