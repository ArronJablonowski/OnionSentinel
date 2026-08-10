"""Late-bound GET read dispatch for the portal HTTP adapter."""
from __future__ import annotations

from typing import Any


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


