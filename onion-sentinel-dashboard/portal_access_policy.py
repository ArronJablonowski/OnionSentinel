"""Pure human-role and portal write-permission policy.

This module defines the target authorization contract without reading sessions,
credentials, request bodies, or runtime configuration.  Transport adapters may
ask which permission a classified write requires, then evaluate that permission
against an independently authenticated human-session principal.
"""
from __future__ import annotations

from portal_request_routes import PostRoute


class AccessPolicyError(ValueError):
    """Raised when a classified write has no safe authorization decision."""


HUMAN_PRINCIPAL_KIND = "human_session"
SERVICE_PRINCIPAL_KIND = "service_identity"

ROLE_VIEWER = "viewer"
ROLE_ANALYST = "analyst"
ROLE_ADMINISTRATOR = "administrator"
HUMAN_ROLES = frozenset({ROLE_VIEWER, ROLE_ANALYST, ROLE_ADMINISTRATOR})

VIEWER_PERMISSIONS = frozenset({
    "evidence.view",
    "session.logout",
})
ANALYST_PERMISSIONS = VIEWER_PERMISSIONS | frozenset({
    "alert.acknowledge",
    "alert.adjudicate",
    "alert.escalate",
    "case.reanalyze",
    "evidence.capture-request",
    "incident.adjudicate",
    "incident.status",
})
ADMINISTRATOR_PERMISSIONS = ANALYST_PERMISSIONS | frozenset({
    "asset.manage",
    "cti.manage",
    "integration.manage",
    "privileged-action.execute",
    "resource.manage",
    "settings.manage",
})
ROLE_PERMISSIONS = {
    ROLE_VIEWER: VIEWER_PERMISSIONS,
    ROLE_ANALYST: ANALYST_PERMISSIONS,
    ROLE_ADMINISTRATOR: ADMINISTRATOR_PERMISSIONS,
}
ALL_HUMAN_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())

_OPERATION_PERMISSIONS = {
    "soc_alert_ack": "alert.acknowledge",
    "soc_alert_pcap": "evidence.capture-request",
    "soc_alert_analyze": "case.reanalyze",
    "soc_alert_escalate": "alert.escalate",
    "soc_alert_adjudicate": "alert.adjudicate",
    "soc_incident_adjudicate": "incident.adjudicate",
    "soc_incident_status": "incident.status",
    "soc_incident_reanalyze": "case.reanalyze",
    "soc_incident_reanalyze_all": "case.reanalyze",
}
_PATH_PERMISSIONS = {
    "/admin/login": None,
    "/admin/logout": "session.logout",
    "/admin/action": "privileged-action.execute",
    "/api/admin/start-service": "integration.manage",
    "/api/ac-hunter/refresh": "integration.manage",
    "/api/soc-alerts/status": "incident.status",
}


def _classified_permission(route: PostRoute) -> str | None:
    if route.prompt_write or route.path.startswith("/api/soc-settings/"):
        return "settings.manage"
    if route.resource_write:
        return "resource.manage"
    if route.asset_write:
        return "asset.manage"
    if route.cti_program_write:
        return "cti.manage"
    return _OPERATION_PERMISSIONS.get(route.operation or "")


def required_permission(route: PostRoute) -> str | None:
    """Return one human permission for an accepted write.

    ``None`` is reserved for the login authentication boundary, which creates
    a principal only after credential verification.  Rejected or newly added
    writes without an explicit mapping fail closed.
    """
    if not route.accepted:
        raise AccessPolicyError("route is not an accepted write")
    if route.path in _PATH_PERMISSIONS:
        return _PATH_PERMISSIONS[route.path]
    permission = _classified_permission(route)
    if permission is None:
        raise AccessPolicyError("accepted write has no permission mapping")
    return permission


def is_authorized(
    *,
    principal_kind: str,
    role: str,
    permission: str,
) -> bool:
    """Return a fail-closed human-session authorization decision."""
    if principal_kind != HUMAN_PRINCIPAL_KIND:
        return False
    if permission not in ALL_HUMAN_PERMISSIONS:
        return False
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def is_human_authorized(role: str, permission: str) -> bool:
    return is_authorized(
        principal_kind=HUMAN_PRINCIPAL_KIND,
        role=role,
        permission=permission,
    )


__all__ = (
    "ADMINISTRATOR_PERMISSIONS",
    "ALL_HUMAN_PERMISSIONS",
    "ANALYST_PERMISSIONS",
    "AccessPolicyError",
    "HUMAN_PRINCIPAL_KIND",
    "HUMAN_ROLES",
    "ROLE_ADMINISTRATOR",
    "ROLE_ANALYST",
    "ROLE_PERMISSIONS",
    "ROLE_VIEWER",
    "SERVICE_PRINCIPAL_KIND",
    "VIEWER_PERMISSIONS",
    "is_authorized",
    "is_human_authorized",
    "required_permission",
)
