"""Transport-neutral orchestration for Administration form posts."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import parse_qs, quote

from portal_request_routes import PostRoute


ADMIN_FORM_PATHS = frozenset({"/admin/login", "/admin/logout", "/admin/action"})


@dataclass(frozen=True)
class AdminFormCallbacks:
    expected_token: Callable[[], str]
    password_configured: Callable[[], bool]
    verify_password: Callable[[str], bool]
    create_session: Callable[[str], str]
    session_cookie: Callable[[str], str]
    current_session_id: Callable[[], str]
    destroy_session: Callable[[str], None]
    expired_session_cookie: Callable[[], str]
    start_action: Callable[[str, str], tuple[bool, str]]


@dataclass(frozen=True)
class AdminFormResult:
    status: int
    view: str = ""
    message: str = ""
    error: bool = False
    redirect: str = ""
    headers: dict[str, str] = field(default_factory=dict)


def _login_result(
    form: dict[str, list[str]],
    client_ip: str,
    callbacks: AdminFormCallbacks,
) -> AdminFormResult:
    if not callbacks.password_configured():
        return AdminFormResult(
            503,
            "login",
            "Admin password is not configured yet. Run the local password setup script first.",
            True,
        )
    if not callbacks.verify_password(form.get("password", [""])[0]):
        return AdminFormResult(401, "login", "Invalid admin password.", True)
    session_id = callbacks.create_session(client_ip)
    return AdminFormResult(
        302,
        redirect="/admin",
        headers={"Set-Cookie": callbacks.session_cookie(session_id)},
    )


def _logout_result(callbacks: AdminFormCallbacks) -> AdminFormResult:
    callbacks.destroy_session(callbacks.current_session_id())
    return AdminFormResult(
        302,
        redirect="/admin/login",
        headers={"Set-Cookie": callbacks.expired_session_cookie()},
    )


def _action_result(
    form: dict[str, list[str]],
    admin_authenticated: Callable[[], bool],
    callbacks: AdminFormCallbacks,
) -> AdminFormResult:
    if not admin_authenticated():
        return AdminFormResult(
            403, "login", "Sign in before running Administration actions.", True,
        )
    ok, message = callbacks.start_action(
        form.get("action", [""])[0],
        form.get("confirmation", [""])[0],
    )
    result_key = "admin_msg" if ok else "admin_error"
    return AdminFormResult(303, redirect=f"/admin?{result_key}={quote(message)}")


def prepare_admin_form(
    route: PostRoute,
    raw: str,
    *,
    client_ip: str,
    admin_authenticated: Callable[[], bool],
    callbacks: AdminFormCallbacks,
) -> AdminFormResult | None:
    """Authorize and apply one classified Administration form request."""
    if route.path not in ADMIN_FORM_PATHS:
        return None
    form = parse_qs(raw, keep_blank_values=True)
    token = form.get("token", [""])[0]
    if token != callbacks.expected_token():
        if route.path == "/admin/action" and admin_authenticated():
            return AdminFormResult(
                403, "dashboard", "Admin action token validation failed.", True,
            )
        return AdminFormResult(
            403, "login", "Form token validation failed.", True,
        )
    if route.path == "/admin/login":
        return _login_result(form, client_ip, callbacks)
    if route.path == "/admin/logout":
        return _logout_result(callbacks)
    return _action_result(form, admin_authenticated, callbacks)
