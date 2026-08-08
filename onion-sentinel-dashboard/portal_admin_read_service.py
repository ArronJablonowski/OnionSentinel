"""Transport-neutral orchestration for Administration GET operations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


ADMIN_READ_OPERATIONS = frozenset({
    "admin_login", "admin", "admin_session_status", "admin_service_status",
})


@dataclass(frozen=True)
class AdminReadResult:
    status: int
    view: str = ""
    message: str = ""
    error: bool = False
    redirect: str = ""
    payload: dict = field(default_factory=dict)


def _admin_page_result(
    operation: str,
    query: dict[str, list[str]],
    authenticated: bool,
) -> AdminReadResult | None:
    if operation == "admin_login":
        return AdminReadResult(302, redirect="/admin") if authenticated else (
            AdminReadResult(200, view="login")
        )
    if operation != "admin":
        return None
    if not authenticated:
        return AdminReadResult(302, redirect="/admin/login")
    message = (query.get("admin_msg") or [""])[0]
    error = (query.get("admin_error") or [""])[0]
    return AdminReadResult(200, "dashboard", message or error, bool(error))


def prepare_admin_read(
    operation: str | None,
    query: dict[str, list[str]],
    *,
    admin_authenticated: Callable[[], bool],
    asset_write_auth_required: bool,
    service_status: Callable[[], dict],
) -> AdminReadResult | None:
    """Authorize and project one classified Administration read."""
    if operation not in ADMIN_READ_OPERATIONS:
        return None
    authenticated = admin_authenticated()
    page_result = _admin_page_result(operation, query, authenticated)
    if page_result is not None:
        return page_result
    if operation == "admin_session_status":
        return AdminReadResult(200, payload={
            "ok": True,
            "authenticated": authenticated,
            "required": asset_write_auth_required,
        })
    if not authenticated:
        return AdminReadResult(403, payload={
            "ok": False,
            "error": "Sign in before reading Administration service status.",
        })
    return AdminReadResult(200, payload=service_status())
