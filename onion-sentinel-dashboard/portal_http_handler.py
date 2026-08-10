"""Thin late-bound HTTP adapter for the report portal runtime."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


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


def _soc_review_write_authorized(handler: Any, runtime: Any) -> bool:
    content_type = str(handler.headers.get("Content-Type") or "").lower()
    if not content_type.startswith("application/json"):
        return False
    if handler.headers.get("X-Onion-Sentinel-Request") != "dashboard":
        return False
    fetch_site = str(handler.headers.get("Sec-Fetch-Site") or "").strip().lower()
    if fetch_site and fetch_site != "same-origin":
        return False
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


def _encoded_read_response(handler: Any, runtime: Any, response: Any) -> None:
    body = (
        response.payload
        if response.encoded
        else runtime.json.dumps(response.payload, indent=2).encode()
    )
    return handler._send(response.status, body, response.content_type)


def _dispatch_primary_read(
    handler: Any, runtime: Any, operation: str, _path: str, query: dict, _route: Any
) -> tuple[bool, Any]:
    general_read = runtime.dispatch_general_read(
        operation,
        query=query,
        callbacks=runtime.portal_general_read_callbacks(
            lambda: runtime.render_home(
                runtime.scan_reports(),
                handler.server.server_address[0],
                handler.server.server_address[1],
            )
        ),
    )
    if general_read is not None:
        return True, _encoded_read_response(handler, runtime, general_read)
    admin_read = runtime.prepare_admin_read(
        operation,
        query,
        admin_authenticated=lambda: handler._admin_authenticated(),
        asset_write_auth_required=runtime.ASSET_INVENTORY_ADMIN_WRITE_REQUIRED,
        service_status=lambda: runtime.defang_admin_service_json(
            runtime.admin_service_statuses()
        ),
    )
    if admin_read is not None:
        if admin_read.redirect:
            return True, handler._redirect(
                admin_read.redirect, status=admin_read.status
            )
        if admin_read.view:
            renderer = (
                runtime.render_admin_dashboard
                if admin_read.view == "dashboard"
                else runtime.render_admin_login
            )
            return True, handler._send(
                admin_read.status, renderer(admin_read.message, admin_read.error)
            )
        return True, handler._send(
            admin_read.status,
            runtime.json.dumps(admin_read.payload, indent=2).encode(),
            "application/json; charset=utf-8",
        )
    if operation == "soc_alert_events":
        return True, handler._send_soc_alert_events()
    return False, None


def _dispatch_soc_read(
    handler: Any, runtime: Any, operation: str, path: str, query: dict, route: Any
) -> tuple[bool, Any]:
    soc_read = runtime.dispatch_soc_read(
        operation,
        path=path,
        resource_id=route.resource_id,
        query=query,
        callbacks=runtime.portal_soc_read_callbacks(),
    )
    if soc_read is not None:
        body = (
            soc_read.payload
            if soc_read.encoded
            else runtime.json.dumps(soc_read.payload, indent=2).encode()
        )
        return True, handler._send(
            soc_read.status, body, "application/json; charset=utf-8"
        )
    action_read = runtime.read_resource_action_status(
        operation,
        query,
        status_directory=runtime.RESOURCE_LIBRARY_ACTION_STATUS_DIR,
    )
    if action_read is None:
        return False, None
    body = (
        action_read.payload
        if action_read.encoded
        else runtime.json.dumps(action_read.payload).encode()
    )
    return True, handler._send(
        action_read.status, body, "application/json; charset=utf-8"
    )


def _dispatch_catalog_read(
    handler: Any, runtime: Any, _operation: str, path: str, _query: dict, _route: Any
) -> tuple[bool, Any]:
    catalog_route = runtime.classify_catalog_route(path)
    catalog_read = runtime.dispatch_catalog_read(
        catalog_route,
        runtime.CatalogReadCallbacks(
            runtime.scan_reports,
            runtime.render_system_uptime_detail,
            runtime.render_prioritized_updates_detail,
            runtime.render_macos_updates_detail,
            runtime.render_hermes_backups_detail,
            runtime.render_local_disk_detail,
            runtime.render_portal_update_detail,
        ),
    )
    if catalog_read is not None:
        return True, _encoded_read_response(handler, runtime, catalog_read)
    delivery = runtime.deliver_catalog_route(
        catalog_route,
        forest_asset_root=runtime.HOME / "report_portal" / "library" / "Prototype Web App" / "forest_room5_assets",
        qr_landing_source=runtime.HOME / "report_portal" / "library" / "Prototype Web App" / "qr_landing_source.pdf",
        callbacks=runtime.CatalogDeliveryCallbacks(
            lambda: {report.rid: report for report in runtime.scan_reports()}
        ),
    )
    if delivery is None:
        return False, None
    if delivery.redirect:
        return True, handler._redirect(delivery.redirect, status=delivery.status)
    return True, handler._send(
        delivery.status, delivery.body, delivery.content_type, delivery.headers
    )


def _do_get(handler: Any, runtime: Any) -> None:
    parsed = runtime.urlparse(handler.path)
    path = parsed.path
    query = runtime.parse_qs(parsed.query, keep_blank_values=True)
    route = runtime.classify_get_route(
        path,
        cti_program_path=runtime.CTI_PROGRAM_API_PATH,
        prompt_paths=runtime.SOC_SETTINGS_PROMPT_API_PATHS,
    )
    for dispatcher in (
        _dispatch_primary_read, _dispatch_soc_read, _dispatch_catalog_read
    ):
        handled, result = dispatcher(
            handler, runtime, route.operation, path, query, route
        )
        if handled:
            return result
    return handler._send(
        runtime.HTTPStatus.NOT_FOUND,
        b"Not found",
        "text/plain; charset=utf-8",
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
