"""Metadata-only projection for compatibility-preserving access observation."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac

from portal_access_enforcement import AccessDecision, decide_write_access
from portal_request_routes import PostRoute
from portal_session_principal import HumanPrincipal


AUTHENTICATION_PERMISSION = "authentication.login"


class AccessObservationError(ValueError):
    """Raised when trusted observation inputs cannot form safe metadata."""


@dataclass(frozen=True)
class AccessObservation:
    request_id: str
    principal_fingerprint: str
    role: str
    permission: str
    action: str
    target_type: str
    target_digest: str
    decision: AccessDecision


def _key(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) < 32:
        raise AccessObservationError(
            "signing_key must contain at least 32 bytes"
        )
    return value


def _fingerprint(
    principal: HumanPrincipal | None,
    signing_key: bytes,
) -> str:
    identity = (
        principal.principal_id if principal is not None else "unauthenticated"
    )
    return hmac.new(
        signing_key,
        ("human-principal:" + identity).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _target(route: PostRoute) -> tuple[str, str]:
    if route.resource_id is not None:
        target_type = "resource"
        identifier = route.resource_id
    else:
        target_type = "route"
        identifier = route.path
    return target_type, hashlib.sha256(identifier.encode("utf-8")).hexdigest()


def begin_observation(
    route: PostRoute,
    *,
    mode: object,
    principal: HumanPrincipal | None,
    same_origin_authorized: bool,
    csrf_authorized: bool,
    request_id: str,
    signing_key: object,
) -> AccessObservation | None:
    """Compute target-policy metadata without changing request admission."""
    if mode == "legacy":
        return None
    key = _key(signing_key)
    decision = decide_write_access(
        route,
        mode=mode,
        principal=principal,
        same_origin_authorized=same_origin_authorized,
        csrf_authorized=csrf_authorized,
    )
    permission = decision.permission or AUTHENTICATION_PERMISSION
    action = route.operation or permission
    target_type, target_digest = _target(route)
    return AccessObservation(
        request_id=request_id,
        principal_fingerprint=_fingerprint(principal, key),
        role=principal.role if principal is not None else "unauthenticated",
        permission=permission,
        action=action,
        target_type=target_type,
        target_digest=target_digest,
        decision=decision,
    )


def _outcome(http_status: int) -> str:
    if http_status >= 500:
        return "error"
    if http_status >= 400:
        return "denied"
    return "allowed"


def _reason(decision: AccessDecision) -> str:
    if decision.reason == "authentication_boundary":
        return "observe_authentication_boundary"
    if decision.would_authorize:
        return "observe_would_allow"
    return "observe_would_deny_" + decision.reason


def finalize_observation(
    observation: AccessObservation,
    *,
    http_status: int,
    occurred_at: str,
) -> dict[str, object]:
    """Project one actual response and target-policy decision into audit fields."""
    return {
        "occurred_at": occurred_at,
        "request_id": observation.request_id,
        "principal_fingerprint": observation.principal_fingerprint,
        "role": observation.role,
        "permission": observation.permission,
        "action": observation.action,
        "target_type": observation.target_type,
        "target_digest": observation.target_digest,
        "outcome": _outcome(http_status),
        "http_status": http_status,
        "reason_code": _reason(observation.decision),
    }


__all__ = (
    "AUTHENTICATION_PERMISSION",
    "AccessObservation",
    "AccessObservationError",
    "begin_observation",
    "finalize_observation",
)
