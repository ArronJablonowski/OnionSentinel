"""HTTP method dispatch for the dedicated Onion Sentinel service."""

from __future__ import annotations

import json
from http import HTTPStatus
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs, urlparse


JSON_TYPE = "application/json; charset=utf-8"
_UNHANDLED = object()


def _admin_authenticated(handler: object, c: ModuleType) -> bool:
    access_runtime = getattr(c, "ACCESS_RUNTIME", None)
    authenticate = getattr(access_runtime, "admin_authenticated", None)
    if callable(authenticate):
        return bool(authenticate(handler))
    return bool(handler._admin_authenticated())


def _read_authenticated(handler: object, c: ModuleType) -> bool:
    access_runtime = getattr(c, "ACCESS_RUNTIME", None)
    authenticate = getattr(access_runtime, "read_authenticated", None)
    return True if not callable(authenticate) else bool(authenticate(handler))


def _current_principal(handler: object, c: ModuleType) -> object | None:
    access_runtime = getattr(c, "ACCESS_RUNTIME", None)
    resolve = getattr(access_runtime, "current_principal", None)
    if callable(resolve):
        return resolve(handler)
    if _admin_authenticated(handler, c):
        return SimpleNamespace(role="administrator")
    return None


def _read_denial(handler: object, *, json_request: bool) -> object:
    if json_request:
        return _json_response(
            handler,
            HTTPStatus.UNAUTHORIZED,
            {
                "ok": False,
                "authentication_required": True,
                "error": "Sign-in is required to view evidence.",
            },
        )
    return handler._redirect("/admin/login")


def do_head(handler: object, c: ModuleType) -> None:
    path = urlparse(handler.path).path
    if c.CONTROLLED_EVALUATION_MODE and handler.path != "/healthz":
        handler.send_response(HTTPStatus.FORBIDDEN)
        handler.end_headers()
        return
    target = c.resolve_dashboard_target(handler.dashboard_root, handler.path)
    status = _head_status(handler, c, path, target)
    if status != HTTPStatus.NOT_FOUND:
        return _send_head(handler, status)
    handler.send_response(HTTPStatus.NOT_FOUND)
    handler.end_headers()


def _head_status(
    handler: object,
    c: ModuleType,
    path: str,
    target: object,
) -> int:
    dedicated_status = _dedicated_head_status(handler, c, path)
    if dedicated_status is not None:
        return dedicated_status
    soc_read = c.is_soc_get_api(path)
    if (soc_read or target is not None) and not _read_authenticated(handler, c):
        return HTTPStatus.UNAUTHORIZED
    if path in ("/healthz", "/admin", "/admin/login") or soc_read or target:
        return HTTPStatus.OK
    return HTTPStatus.NOT_FOUND


def _dedicated_head_status(
    handler: object,
    c: ModuleType,
    path: str,
) -> int | None:
    if c.is_application_log_get_api(path):
        return (
            HTTPStatus.OK
            if _admin_authenticated(handler, c)
            else HTTPStatus.FORBIDDEN
        )
    if path == "/session" and _current_principal(handler, c) is None:
        return HTTPStatus.UNAUTHORIZED
    if path == "/session":
        return HTTPStatus.OK
    return None


def _send_head(handler: object, status: int) -> None:
    handler.send_response(status)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    for key, value in handler._security_headers().items():
        handler.send_header(key, value)
    handler.end_headers()


def do_get(handler: object, c: ModuleType) -> None:
    parsed = urlparse(handler.path)
    path = parsed.path
    if c.CONTROLLED_EVALUATION_MODE and handler.path != "/healthz":
        return _json_error(
            handler,
            HTTPStatus.FORBIDDEN,
            "route is disabled in controlled evaluation mode",
        )
    if path == "/healthz":
        return _health(handler, c)
    return _dispatch_get(handler, c, parsed, path)


def _dispatch_get(
    handler: object,
    c: ModuleType,
    parsed: object,
    path: str,
) -> object:
    log_id = c.application_log_route_identifier(path)
    if path == c.APPLICATION_LOG_API_PATH or log_id is not None:
        return _application_logs(handler, c, parsed, log_id)
    soc_read = c.is_soc_get_api(path)
    if soc_read and not _read_authenticated(handler, c):
        return _read_denial(handler, json_request=True)
    dedicated = _dedicated_get(handler, c, path)
    if dedicated is not _UNHANDLED:
        return dedicated
    if soc_read:
        return c.runtime.PortalHandler.do_GET(handler)
    return _static_get(handler, c)


def _static_get(handler: object, c: ModuleType) -> object:
    target = c.resolve_dashboard_target(handler.dashboard_root, handler.path)
    if target is not None:
        if not _read_authenticated(handler, c):
            return _read_denial(handler, json_request=False)
        return handler._serve_file(target)
    return handler._send(
        HTTPStatus.NOT_FOUND,
        b"Not found",
        "text/plain; charset=utf-8",
    )


def _dedicated_get(handler: object, c: ModuleType, path: str) -> object:
    if path == "/api/ac-hunter/deep-review":
        status, data = c.ac_hunter_review.deep_review_response(
            force_refresh=False
        )
        return _json_response(handler, status, data, indent=2)
    if path == "/admin/login":
        principal = _current_principal(handler, c)
        if getattr(principal, "role", "") == "administrator":
            return handler._redirect("/admin")
        if principal is not None:
            return handler._send(
                HTTPStatus.OK,
                c.render_session_status(getattr(principal, "role", "")),
            )
        return handler._send(HTTPStatus.OK, c.render_login())
    if path == "/session":
        principal = _current_principal(handler, c)
        if principal is None:
            return handler._redirect("/admin/login")
        return handler._send(
            HTTPStatus.OK,
            c.render_session_status(getattr(principal, "role", "")),
        )
    if path == "/admin":
        if not _admin_authenticated(handler, c):
            return handler._redirect("/admin/login")
        return handler._send(HTTPStatus.OK, c.render_admin_status())
    return _UNHANDLED


def _health(handler: object, c: ModuleType) -> None:
    dashboard_ready = (handler.dashboard_root / "index.html").is_file()
    alert_store_ready = c.runtime.SOC_ALERT_STORE_DB.is_file()
    health: dict[str, object] = {
        "status": (
            "local_database_ready"
            if alert_store_ready
            else "local_database_missing"
        ),
    }
    if c.CONTROLLED_EVALUATION_MODE:
        downstream_ready, health = c.controlled_alert_store_readiness()
        alert_store_ready = alert_store_ready and downstream_ready
    data = {
        "ok": dashboard_ready and alert_store_ready,
        "service": "onion-sentinel",
        "controlled_evaluation": c.CONTROLLED_EVALUATION_MODE,
        "release_id": c.RUNTIME_RELEASE_ID or "unversioned",
        "listen_host": handler.server.server_address[0],
        "listen_port": handler.server.server_address[1],
        "alert_store_origin": c.runtime.SOC_ALERT_STORE_API_URL,
        "dispatch_route_patterns": (
            list(c.CONTROLLED_EVALUATION_DISPATCH_ROUTES)
            if c.CONTROLLED_EVALUATION_MODE
            else []
        ),
        "dashboard_ready": dashboard_ready,
        "alert_store_ready": alert_store_ready,
        "alert_store_health": health,
        "time": c.runtime.now_iso_local(),
        "http_runtime": handler.server.runtime_snapshot(),
    }
    status = HTTPStatus.OK if data["ok"] else HTTPStatus.SERVICE_UNAVAILABLE
    return _json_response(handler, status, data, indent=2)


def _application_logs(
    handler: object,
    c: ModuleType,
    parsed: object,
    log_id: str | None,
) -> None:
    if not _admin_authenticated(handler, c):
        return handler._send(
            HTTPStatus.FORBIDDEN,
            json.dumps(
                {
                    "ok": False,
                    "authentication_required": True,
                    "error": (
                        "Administration sign-in is required to view "
                        "application logs"
                    ),
                }
            ).encode(),
            JSON_TYPE,
        )
    try:
        data = _application_log_data(c, parsed, log_id)
        return _json_response(handler, HTTPStatus.OK, data, indent=2)
    except c.application_logs.ApplicationLogError as exc:
        return _json_response(
            handler,
            exc.status,
            {"ok": False, "error": exc.message},
        )
    except Exception as exc:
        c.APPLICATION_LOGGER.log(
            "error",
            "application_logs.read_failed",
            request_id=getattr(handler, "application_request_id", ""),
            log_id=log_id or "catalog",
            error_type=type(exc).__name__,
        )
        return _json_response(
            handler,
            HTTPStatus.INTERNAL_SERVER_ERROR,
            {"ok": False, "error": "Application logs are unavailable"},
        )


def _application_log_data(
    c: ModuleType,
    parsed: object,
    log_id: str | None,
) -> dict[str, object]:
    if log_id is None:
        return c.application_logs.catalog_response()
    query = parse_qs(parsed.query, keep_blank_values=True)
    raw_lines = (
        query.get("lines") or [str(c.application_logs.DEFAULT_TAIL_LINES)]
    )[0]
    try:
        lines = int(raw_lines)
    except (TypeError, ValueError) as exc:
        raise c.application_logs.ApplicationLogError(
            HTTPStatus.BAD_REQUEST,
            "lines must be an integer",
        ) from exc
    lines = max(1, min(c.application_logs.MAX_TAIL_LINES, lines))
    member = str((query.get("member") or [""])[0])
    raw_before = str((query.get("before") or [""])[0])
    try:
        before = None if raw_before == "" else int(raw_before)
    except (TypeError, ValueError) as exc:
        raise c.application_logs.ApplicationLogError(
            HTTPStatus.BAD_REQUEST,
            "before must be an integer",
        ) from exc
    if before is not None and before < 0:
        raise c.application_logs.ApplicationLogError(
            HTTPStatus.BAD_REQUEST,
            "before must be a non-negative integer",
        )
    return c.application_logs.content_response(
        str(log_id),
        member=member,
        lines=lines,
        before=before,
    )


def do_post(handler: object, c: ModuleType) -> None:
    path = urlparse(handler.path).path
    if c.CONTROLLED_EVALUATION_MODE and (
        not c.is_controlled_evaluation_dispatch(path) or handler.path != path
    ):
        return _json_error(
            handler,
            HTTPStatus.FORBIDDEN,
            "route is disabled in controlled evaluation mode",
        )
    if c.CONTROLLED_EVALUATION_MODE and not c.hmac.compare_digest(
        str(handler.headers.get("X-Onion-Sentinel-Evaluation-Token", "")),
        c.CONTROLLED_EVALUATION_TOKEN,
    ):
        handler.close_connection = True
        return _json_error(
            handler,
            HTTPStatus.FORBIDDEN,
            "controlled evaluation authorization failed",
        )
    if path in ("/admin/login", "/admin/logout"):
        return _admin_post(handler, c, path)
    if c.is_soc_post_api(path):
        return _soc_post(handler, c, path)
    return handler._send(
        HTTPStatus.NOT_FOUND,
        b"Not found",
        "text/plain; charset=utf-8",
    )


def send_access_denial(
    handler: object,
    c: ModuleType,
    admission: object,
) -> None:
    status = int(getattr(admission, "status", HTTPStatus.FORBIDDEN))
    reason = str(getattr(admission, "reason", "access_denied"))
    if status == HTTPStatus.UNAUTHORIZED:
        message = "Administrator sign-in is required."
    elif status == HTTPStatus.SERVICE_UNAVAILABLE:
        message = "Administrator authorization is unavailable."
    else:
        message = "Administrator authorization failed."
    if bool(getattr(admission, "json_request", False)):
        return _json_response(
            handler,
            status,
            {
                "ok": False,
                "authentication_required": status == HTTPStatus.UNAUTHORIZED,
                "error": message,
                "reason": reason,
            },
        )
    if status == HTTPStatus.UNAUTHORIZED:
        return handler._redirect("/admin/login")
    return handler._send(status, c.render_login(message, True))


def _admin_post(handler: object, c: ModuleType, path: str) -> None:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0
    if length <= 0 or length > 8192:
        return handler._send(
            HTTPStatus.BAD_REQUEST,
            c.render_login("Invalid request size.", True),
        )
    form = parse_qs(
        handler.rfile.read(length).decode("utf-8", errors="replace"),
        keep_blank_values=True,
    )
    if form.get("token", [""])[0] != c.runtime.ensure_admin_token():
        return handler._send(
            HTTPStatus.FORBIDDEN,
            c.render_login("Form token validation failed.", True),
        )
    if path == "/admin/logout":
        session_id = handler._admin_session_id()
        c.runtime.destroy_admin_session(session_id)
        c.ACCESS_RUNTIME.destroy_session(session_id)
        return handler._redirect(
            "/admin/login",
            {"Set-Cookie": c.ACCESS_RUNTIME.logout_cookie_headers()},
        )
    return _admin_login_post(handler, c, form)


def _admin_login_post(
    handler: object,
    c: ModuleType,
    form: dict[str, list[str]],
) -> None:
    if not c.ACCESS_RUNTIME.password_configured():
        return handler._send(
            HTTPStatus.SERVICE_UNAVAILABLE,
            c.render_login(
                "An Onion Sentinel admin password has not been configured.",
                True,
            ),
        )
    principal = c.ACCESS_RUNTIME.authenticate(
        form.get("username", [""])[0],
        form.get("password", [""])[0],
    )
    if principal is None:
        return handler._send(
            HTTPStatus.UNAUTHORIZED,
            c.render_login("Invalid username or password.", True),
        )
    session_id = c.ACCESS_RUNTIME.create_browser_session_id(
        handler, principal
    )
    csrf_token = c.ACCESS_RUNTIME.create_session(
        handler, session_id, principal
    )
    if getattr(c.ACCESS_RUNTIME, "session_required", False) and csrf_token is None:
        c.runtime.destroy_admin_session(session_id)
        return handler._send(
            HTTPStatus.SERVICE_UNAVAILABLE,
            c.render_login(
                "Administrator session creation is unavailable.", True
            ),
        )
    return handler._redirect(
        (
            "/admin"
            if getattr(principal, "role", "") == "administrator"
            else "/session"
        ),
        {"Set-Cookie": c.ACCESS_RUNTIME.login_cookie_headers(
            session_id, csrf_token
        )},
    )


def _soc_post(handler: object, c: ModuleType, path: str) -> None:
    valid, status, message = c.is_same_origin_json_request(handler.headers)
    if not valid:
        return _json_error(handler, status, message)
    if path == "/api/ac-hunter/refresh":
        return _ac_hunter_refresh(handler, c)
    return c.runtime.PortalHandler.do_POST(handler)


def _ac_hunter_refresh(handler: object, c: ModuleType) -> None:
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError:
        length = 0
    if length <= 0 or length > 1024:
        return _json_error(
            handler,
            HTTPStatus.BAD_REQUEST,
            "Invalid AC Hunter refresh request size.",
        )
    try:
        payload = json.loads(
            handler.rfile.read(length).decode("utf-8", errors="strict")
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict) or payload:
        return _json_error(
            handler,
            HTTPStatus.BAD_REQUEST,
            "AC Hunter refresh requires an empty JSON object.",
        )
    status, data = c.ac_hunter_review.deep_review_response(force_refresh=False)
    return _json_response(handler, status, data, indent=2)


def _json_error(handler: object, status: int, message: str) -> None:
    return _json_response(handler, status, {"ok": False, "error": message})


def _json_response(
    handler: object,
    status: int,
    data: object,
    *,
    indent: int | None = None,
) -> None:
    return handler._send(
        status,
        json.dumps(data, indent=indent).encode(),
        JSON_TYPE,
    )
