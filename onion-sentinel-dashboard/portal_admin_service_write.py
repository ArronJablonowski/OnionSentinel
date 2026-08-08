"""Transport-neutral request policy for Administration service starts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute


ADMIN_START_SERVICE_PATH = "/api/admin/start-service"


@dataclass(frozen=True)
class AdminServiceWriteCallbacks:
    expected_token: Callable[[], str]
    start_service: Callable[[str], tuple[bool, str, dict | None]]


@dataclass(frozen=True)
class AdminServiceWriteResult:
    status: int
    payload: dict


def prepare_admin_service_write(
    route: PostRoute,
    raw: str,
    *,
    admin_authenticated: Callable[[], bool],
    callbacks: AdminServiceWriteCallbacks,
) -> AdminServiceWriteResult | None:
    """Authorize and dispatch an allowlisted service-start request."""
    if route.path != ADMIN_START_SERVICE_PATH:
        return None
    parsed = parse_json_body(raw, empty_object=True).value_or({})
    payload = parsed if isinstance(parsed, dict) else {}
    if not admin_authenticated():
        return AdminServiceWriteResult(403, {
            "ok": False,
            "error": "Sign in before starting services.",
        })
    if str(payload.get("token", "")) != callbacks.expected_token():
        return AdminServiceWriteResult(403, {
            "ok": False,
            "error": "Admin action token validation failed.",
        })
    service_id = str(payload.get("service", "")).strip()
    ok, message, service_status = callbacks.start_service(service_id)
    response = {"ok": ok, "message": message, "service": service_status}
    if not ok:
        response["error"] = message
    return AdminServiceWriteResult(200 if ok else 400, response)
