"""Frozen dispatch, route, and incident-attempt claim contracts."""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Pattern


@dataclass(frozen=True)
class ControlledRoutePolicy:
    model_route_pattern: Pattern[str]
    allowed_roles: frozenset[str] = frozenset(
        {"soc-analyst", "incident-responder"}
    )


@dataclass(frozen=True)
class ControlledRouteSources:
    load_settings: Callable[
        [], tuple[dict[str, Any], dict[str, Any], set[str]]
    ]
    reject: Callable[[str], BaseException]
    settings_errors: tuple[type[BaseException], ...]


@dataclass(frozen=True)
class ControlledClaimSources:
    stable_group_key_valid: Callable[[object], bool]
    require_release: Callable[[dict[str, object]], str]
    route_contract: Callable[[dict[str, object]], dict[str, object]]
    reject: Callable[[str], BaseException]


@dataclass(frozen=True)
class ControlledLeaseIdentitySources:
    stable_group_key_valid: Callable[[object], bool]
    require_release: Callable[[dict[str, object]], str]
    route_contract: Callable[[dict[str, object]], dict[str, object]]
    reject: Callable[[str], BaseException]


def incident_reanalysis_attempt_id(lease_token: str) -> str:
    """Return the non-secret fingerprint used for one IR lease."""
    token = str(lease_token or "").strip()
    if not token:
        return ""
    return "ira-" + hashlib.sha256(token.encode("utf-8")).hexdigest()[:40]


def _route_identity(
    policy: ControlledRoutePolicy,
    job_payload: dict[str, object],
    reject: Callable[[str], BaseException],
) -> tuple[str, str, str]:
    assigned = job_payload.get("expected_assigned_route")
    reviewer = job_payload.get("expected_reviewer_route")
    role = str(job_payload.get("agent_role") or "").strip().lower()
    if (
        not isinstance(assigned, str)
        or not isinstance(reviewer, str)
        or not policy.model_route_pattern.fullmatch(assigned)
        or not policy.model_route_pattern.fullmatch(reviewer)
        or assigned.rsplit(":", 1)[0] == reviewer.rsplit(":", 1)[0]
        or job_payload.get("reviewer_required") is not True
        or role not in policy.allowed_roles
    ):
        raise reject("controlled durable AI job route contract is invalid")
    return assigned, reviewer, role


def _routes_match_settings(
    settings: dict[str, Any],
    raw: dict[str, Any],
    enabled_routes: set[str],
    assigned: str,
    reviewer: str,
    role: str,
) -> bool:
    assignments = raw.get("agent_models")
    reviewers = raw.get("agent_second_opinion_models")
    normalized_assignments = settings.get("agent_models")
    normalized_reviewers = settings.get("agent_second_opinion_models")
    return bool(
        isinstance(assignments, dict)
        and assignments.get(role) == assigned
        and isinstance(reviewers, dict)
        and reviewers.get(role) == reviewer
        and isinstance(normalized_assignments, dict)
        and normalized_assignments.get(role) == assigned
        and isinstance(normalized_reviewers, dict)
        and normalized_reviewers.get(role) == reviewer
        and assigned in enabled_routes
        and reviewer in enabled_routes
    )


def controlled_job_route_contract(
    policy: ControlledRoutePolicy,
    sources: ControlledRouteSources,
    job_payload: dict[str, object],
) -> dict[str, object]:
    """Bind a controlled job to canonical enabled role assignments."""
    assigned, reviewer, role = _route_identity(
        policy, job_payload, sources.reject
    )
    try:
        settings, raw, enabled_routes = sources.load_settings()
    except sources.settings_errors as exc:
        raise sources.reject(
            "controlled AI route settings are unavailable"
        ) from exc
    if not _routes_match_settings(
        settings, raw, enabled_routes, assigned, reviewer, role
    ):
        raise sources.reject(
            "controlled AI job routes do not exactly match enabled settings"
        )
    return {
        "expected_assigned_route": assigned,
        "expected_reviewer_route": reviewer,
        "reviewer_required": True,
    }


def _requested_identity(args: Any) -> tuple[str, str, str, str]:
    return (
        str(getattr(args, "only_group_id", "") or "").strip().lower(),
        str(getattr(args, "only_alert_id", "") or "").strip(),
        str(getattr(args, "only_stable_group_key", "") or ""),
        str(getattr(args, "only_dispatch_id", "") or "").strip(),
    )


def _selected_job_id(selected: Any) -> int:
    try:
        return int(selected["durable_job_id"] or 0)
    except (IndexError, KeyError, TypeError, ValueError):
        return 0


def _payload_matches_identity(
    sources: ControlledClaimSources,
    job_payload: dict[str, object],
    identity: tuple[str, str, str, str],
) -> bool:
    group_id, alert_id, stable_key, dispatch_id = identity
    payload_identity = (
        str(job_payload.get("group_id") or "").strip().lower(),
        str(job_payload.get("alert_id") or "").strip(),
        str(job_payload.get("representative_alert_id") or "").strip(),
        str(job_payload.get("stable_group_id") or "").strip().lower(),
        job_payload.get("stable_group_key"),
        str(job_payload.get("dispatch_id") or "").strip(),
    )
    expected_payload_identity = (
        group_id,
        alert_id,
        alert_id,
        group_id,
        stable_key,
        dispatch_id,
    )
    return bool(
        payload_identity == expected_payload_identity
        and sources.stable_group_key_valid(payload_identity[4])
    )


def controlled_claim_expectations(
    sources: ControlledClaimSources,
    args: Any,
    selected: Any,
    job_payload: dict[str, object],
) -> dict[str, object]:
    """Validate a read-only candidate before its exact atomic claim."""
    identity = _requested_identity(args)
    if not any(identity):
        return {}
    if not all(identity):
        raise sources.reject(
            "controlled AI run identity arguments are incomplete"
        )
    group_id, alert_id, stable_key, dispatch_id = identity
    if not sources.stable_group_key_valid(stable_key):
        raise sources.reject("controlled AI run stable group key is invalid")
    sources.require_release(job_payload)
    route_contract = sources.route_contract(job_payload)
    job_id = _selected_job_id(selected)
    if job_id < 1:
        raise sources.reject(
            "controlled AI run requires an exact durable AI job"
        )
    if not _payload_matches_identity(sources, job_payload, identity):
        raise sources.reject(
            "controlled durable AI candidate no longer matches the frozen dispatch"
        )
    return {
        "expected_job_id": job_id,
        "expected_representative_alert_id": alert_id,
        "expected_dispatch_id": dispatch_id,
        "expected_stable_group_key": stable_key,
        **route_contract,
    }


def _claimed_job_identity_matches(
    claimed_job_id: int,
    expected_job_id: int,
) -> bool:
    return bool(
        int(claimed_job_id or 0) == int(expected_job_id or 0)
        and int(expected_job_id or 0) >= 1
    )


def _claimed_group_identity_matches(
    claimed_payload: dict[str, object],
    claimed_group_id: str,
    expected_group_id: str,
) -> bool:
    return bool(
        str(claimed_group_id or "").strip().lower()
        == expected_group_id
        and str(claimed_payload.get("group_id") or "").strip().lower()
        == expected_group_id
        and str(
            claimed_payload.get("stable_group_id") or ""
        ).strip().lower()
        == expected_group_id
    )


def _claimed_alert_identity_matches(
    claimed_payload: dict[str, object],
    claimed_alert_id: str,
    expected_alert_id: str,
) -> bool:
    return bool(
        str(claimed_alert_id or "").strip() == expected_alert_id
        and str(claimed_payload.get("alert_id") or "").strip()
        == expected_alert_id
        and str(
            claimed_payload.get("representative_alert_id") or ""
        ).strip()
        == expected_alert_id
    )


def _required_lease_identity(
    sources: ControlledLeaseIdentitySources,
    args: Any,
    claimed_payload: dict[str, object],
) -> tuple[str, str, str, str] | None:
    identity = _requested_identity(args)
    if not any(identity):
        return None
    if not all(identity):
        raise sources.reject(
            "controlled AI run identity arguments are incomplete"
        )
    if not sources.stable_group_key_valid(identity[2]):
        raise sources.reject("controlled AI run stable group key is invalid")
    sources.require_release(claimed_payload)
    sources.route_contract(claimed_payload)
    return identity


def _require_claimed_stable_dispatch(
    sources: ControlledLeaseIdentitySources,
    claimed_payload: dict[str, object],
    stable_key: str,
    dispatch_id: str,
) -> None:
    if (
        not sources.stable_group_key_valid(
            claimed_payload.get("stable_group_key")
        )
        or claimed_payload.get("stable_group_key") != stable_key
    ):
        raise sources.reject(
            "controlled AI claim stable group key did not match "
            "--only-stable-group-key"
        )
    if str(claimed_payload.get("dispatch_id") or "").strip() != dispatch_id:
        raise sources.reject(
            "controlled AI claim dispatch identity did not match "
            "--only-dispatch-id"
        )


def require_controlled_lease_identity(
    sources: ControlledLeaseIdentitySources,
    args: Any,
    claimed_payload: dict[str, object],
    *,
    claimed_alert_id: str,
    claimed_group_id: str,
    claimed_job_id: int,
    expected_job_id: int,
) -> None:
    """Fail closed when an exact lease differs from its frozen dispatch."""
    identity = _required_lease_identity(sources, args, claimed_payload)
    if identity is None:
        return
    expected_group_id, expected_alert_id, stable_key, dispatch_id = identity
    if not _claimed_job_identity_matches(claimed_job_id, expected_job_id):
        raise sources.reject(
            "controlled AI claim job identity did not match the selected job"
        )
    if not _claimed_group_identity_matches(
        claimed_payload, claimed_group_id, expected_group_id
    ):
        raise sources.reject(
            "controlled AI claim group identity did not match --only-group-id"
        )
    if not _claimed_alert_identity_matches(
        claimed_payload, claimed_alert_id, expected_alert_id
    ):
        raise sources.reject(
            "controlled AI claim alert identity did not match --only-alert-id"
        )
    _require_claimed_stable_dispatch(
        sources, claimed_payload, stable_key, dispatch_id
    )
