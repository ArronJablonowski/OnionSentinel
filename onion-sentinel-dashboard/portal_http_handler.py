"""Thin late-bound HTTP adapter for the report portal runtime."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from portal_http_read_adapter import _do_get


RuntimeProvider = Callable[[], Any]


def _log_message(handler: Any, runtime: Any, fmt: str, *args: object) -> None:
    runtime.sys.stderr.write(
        "%s - - [%s] %s\n"
        % (handler.client_address[0], handler.log_date_time_string(), fmt % args)
    )


def _send(
    handler: Any,
    _runtime: Any,
    status: int,
    body: bytes,
    content_type: str = "text/html; charset=utf-8",
    extra: dict[str, str] | None = None,
) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    if extra:
        for key, value in extra.items():
            handler.send_header(key, value)
    handler.end_headers()
    handler.wfile.write(body)


def _redirect(
    handler: Any,
    runtime: Any,
    location: str,
    extra: dict[str, str] | None = None,
    status: Any = None,
) -> None:
    status = runtime.HTTPStatus.FOUND if status is None else status
    handler.send_response(status)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    if extra:
        for key, value in extra.items():
            handler.send_header(key, value)
    handler.end_headers()


def _send_soc_alert_events(handler: Any, runtime: Any) -> None:
    runtime.send_soc_alert_events(
        handler,
        snapshot=runtime.cached_soc_alert_events_snapshot,
        revision_digest=runtime._revision_digest,
        now_seconds=runtime.time.time,
        sleep=runtime.time.sleep,
    )


def _admin_session_id(handler: Any, runtime: Any) -> str:
    return runtime.parse_cookie_header(handler.headers.get("Cookie")).get(
        runtime.ADMIN_SESSION_COOKIE, ""
    )


def _admin_authenticated(handler: Any, runtime: Any) -> bool:
    session_id = handler._admin_session_id()
    if not session_id:
        return False
    sessions = runtime.prune_admin_sessions()
    return runtime.admin_session_hash(session_id) in sessions


def _require_admin_auth(handler: Any, _runtime: Any) -> bool:
    if handler._admin_authenticated():
        return True
    handler._redirect("/admin/login")
    return False


def _admin_policy(handler: Any, _runtime: Any) -> bool:
    return handler._admin_authenticated()


def _cti_program_mutation_audit(
    _handler: Any, _runtime: Any, _program: dict[str, object]
) -> None:
    return None


def _soc_review_origin_authorized(handler: Any, runtime: Any) -> bool:
    origin = str(handler.headers.get("Origin") or "").strip()
    if not origin:
        return True
    parsed_origin = runtime.urlparse(origin)
    request_host = str(handler.headers.get("Host") or "").strip().lower()
    return bool(
        parsed_origin.scheme in {"http", "https"}
        and parsed_origin.netloc
        and parsed_origin.netloc.lower() == request_host
    )


def _soc_review_write_authorized(handler: Any, runtime: Any) -> bool:
    content_type = str(handler.headers.get("Content-Type") or "").lower()
    if not content_type.startswith("application/json"):
        return False
    if handler.headers.get("X-Onion-Sentinel-Request") != "dashboard":
        return False
    fetch_site = str(handler.headers.get("Sec-Fetch-Site") or "").strip().lower()
    if fetch_site and fetch_site != "same-origin":
        return False
    return _soc_review_origin_authorized(handler, runtime)


def _do_head(handler: Any, runtime: Any) -> None:
    parsed = runtime.urlparse(handler.path)
    allowed = runtime.is_head_route(
        parsed.path,
        cti_program_path=runtime.CTI_PROGRAM_API_PATH,
        prompt_paths=runtime.SOC_SETTINGS_PROMPT_API_PATHS,
    )
    if not allowed:
        handler.send_response(runtime.HTTPStatus.NOT_FOUND)
        handler.end_headers()
        return
    if parsed.path == "/admin" and not handler._admin_authenticated():
        handler.send_response(runtime.HTTPStatus.FOUND)
        handler.send_header("Location", "/admin/login")
        handler.send_header("Cache-Control", "no-store")
        handler.end_headers()
        return
    handler.send_response(runtime.HTTPStatus.OK)
    handler.send_header("Content-Type", runtime.head_content_type(parsed.path))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()


def _do_post(handler: Any, runtime: Any) -> None:
    parsed = runtime.urlparse(handler.path)
    route = runtime.classify_post_route(
        parsed.path,
        cti_program_path=runtime.CTI_PROGRAM_API_PATH,
        prompt_paths=runtime.SOC_SETTINGS_PROMPT_API_PATHS,
    )
    intake = runtime.prepare_post_intake(
        route,
        handler.headers.get("Content-Length"),
        cti_file_bytes=runtime.cti_program.MAX_FILE_BYTES,
        admin_authenticated=lambda: handler._admin_authenticated(),
    )
    if not intake.ready:
        if intake.view:
            renderer = (
                runtime.render_admin_dashboard
                if intake.view == "dashboard"
                else runtime.render_admin_login
            )
            return handler._send(intake.status, renderer(intake.message, True))
        return handler._send(intake.status, intake.body, intake.content_type)
    raw = handler.rfile.read(intake.length).decode("utf-8", errors="replace")
    json_write = runtime.dispatch_json_write(
        route,
        raw,
        asset_admin_required=runtime.ASSET_INVENTORY_ADMIN_WRITE_REQUIRED,
        callbacks=runtime.portal_json_write_callbacks(handler),
    )
    if json_write is not None:
        return handler._send(
            json_write.status,
            runtime.json.dumps(json_write.payload, indent=2).encode(),
            "application/json; charset=utf-8",
        )
    admin_form = runtime.prepare_admin_form(
        route,
        raw,
        client_ip=handler.client_address[0],
        admin_authenticated=lambda: handler._admin_authenticated(),
        callbacks=runtime.AdminFormCallbacks(
            runtime.ensure_admin_token,
            runtime.admin_password_configured,
            runtime.verify_admin_password,
            runtime.create_admin_session,
            runtime.admin_session_cookie_header,
            handler._admin_session_id,
            runtime.destroy_admin_session,
            runtime.expired_admin_session_cookie_header,
            runtime.start_admin_action,
        ),
    )
    assert admin_form is not None
    if admin_form.redirect:
        return handler._redirect(
            admin_form.redirect, admin_form.headers, status=admin_form.status
        )
    renderer = (
        runtime.render_admin_dashboard
        if admin_form.view == "dashboard"
        else runtime.render_admin_login
    )
    return handler._send(
        admin_form.status, renderer(admin_form.message, admin_form.error)
    )


def _bind(method: Callable[..., Any], runtime_provider: RuntimeProvider):
    def bound(handler: Any, *args: object, **kwargs: object):
        return method(handler, runtime_provider(), *args, **kwargs)

    bound.__name__ = method.__name__.removeprefix("_")
    return bound


def build_portal_handler(base_handler: type, runtime_provider: RuntimeProvider) -> type:
    methods = {
        "server_version": "ArronReportPortal/1.0",
        "log_message": _bind(_log_message, runtime_provider),
        "_send": _bind(_send, runtime_provider),
        "_redirect": _bind(_redirect, runtime_provider),
        "_send_soc_alert_events": _bind(_send_soc_alert_events, runtime_provider),
        "_admin_session_id": _bind(_admin_session_id, runtime_provider),
        "_admin_authenticated": _bind(_admin_authenticated, runtime_provider),
        "_require_admin_auth": _bind(_require_admin_auth, runtime_provider),
        "_soc_settings_write_authorized": _bind(_admin_policy, runtime_provider),
        "_cti_program_write_authorized": _bind(_admin_policy, runtime_provider),
        "_cti_program_mutation_audit": _bind(_cti_program_mutation_audit, runtime_provider),
        "_soc_review_write_authorized": _bind(_soc_review_write_authorized, runtime_provider),
        "do_HEAD": _bind(_do_head, runtime_provider),
        "do_POST": _bind(_do_post, runtime_provider),
        "do_GET": _bind(_do_get, runtime_provider),
    }
    return type("PortalHandler", (base_handler,), methods)
