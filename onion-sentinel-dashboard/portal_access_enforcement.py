"""Pure phased enforcement decisions for classified portal writes."""
from __future__ import annotations

from dataclasses import dataclass

from portal_access_policy import (
    ADMINISTRATOR_PERMISSIONS,
    ANALYST_PERMISSIONS,
    AccessPolicyError,
    is_authorized,
    required_permission,
)
from portal_request_routes import PostRoute
from portal_session_principal import HumanPrincipal


MODE_LEGACY = "legacy"
MODE_OBSERVE = "observe"
MODE_ADMIN_ENFORCE = "admin-enforce"
MODE_RBAC_ENFORCE = "rbac-enforce"
ACCESS_MODES = frozenset({
    MODE_LEGACY,
    MODE_OBSERVE,
    MODE_ADMIN_ENFORCE,
    MODE_RBAC_ENFORCE,
})
ADMIN_ENFORCED_PERMISSIONS = ADMINISTRATOR_PERMISSIONS - ANALYST_PERMISSIONS


class AccessEnforcementError(ValueError):
    """Raised when enforcement configuration or route policy is invalid."""


@dataclass(frozen=True)
class AccessDecision:
    mode: str
    permission: str | None
    allowed: bool
    enforced: bool
    would_authorize: bool
    reason: str


def parse_mode(value: object) -> str:
    if not isinstance(value, str) or value not in ACCESS_MODES:
        raise AccessEnforcementError("access mode has an unsupported value")
    return value


def _candidate_decision(
    principal: HumanPrincipal | None,
    permission: str,
    same_origin_authorized: bool,
    csrf_authorized: bool,
) -> tuple[bool, str]:
    if principal is None:
        return False, "unauthenticated"
    if not is_authorized(
        principal_kind=principal.principal_kind,
        role=principal.role,
        permission=permission,
    ):
        return False, "role_denied"
    if not same_origin_authorized:
        return False, "origin_denied"
    if not csrf_authorized:
        return False, "csrf_denied"
    return True, "authorized"


def _compatibility_decision(
    mode: str,
    permission: str,
    candidate: bool,
    reason: str,
) -> AccessDecision:
    return AccessDecision(mode, permission, True, False, candidate, reason)


def decide_write_access(
    route: PostRoute,
    *,
    mode: object,
    principal: HumanPrincipal | None,
    same_origin_authorized: bool,
    csrf_authorized: bool,
) -> AccessDecision:
    selected_mode = parse_mode(mode)
    try:
        permission = required_permission(route)
    except AccessPolicyError as exc:
        raise AccessEnforcementError(str(exc)) from exc
    if permission is None:
        return AccessDecision(
            selected_mode, None, True, False, True, "authentication_boundary"
        )
    candidate, reason = _candidate_decision(
        principal, permission, same_origin_authorized, csrf_authorized
    )
    if selected_mode in {MODE_LEGACY, MODE_OBSERVE}:
        return _compatibility_decision(
            selected_mode, permission, candidate, reason
        )
    if (
        selected_mode == MODE_ADMIN_ENFORCE
        and permission not in ADMIN_ENFORCED_PERMISSIONS
    ):
        return _compatibility_decision(
            selected_mode, permission, candidate, reason
        )
    return AccessDecision(
        selected_mode, permission, candidate, True, candidate, reason
    )


__all__ = (
    "ACCESS_MODES",
    "ADMIN_ENFORCED_PERMISSIONS",
    "AccessDecision",
    "AccessEnforcementError",
    "MODE_ADMIN_ENFORCE",
    "MODE_LEGACY",
    "MODE_OBSERVE",
    "MODE_RBAC_ENFORCE",
    "decide_write_access",
    "parse_mode",
)
