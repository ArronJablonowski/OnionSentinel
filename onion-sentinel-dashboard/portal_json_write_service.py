"""Application dispatch across the portal's JSON write services."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from portal_admin_service_write import prepare_admin_service_write
from portal_asset_write_request import prepare_asset_write_request
from portal_cti_program_service import prepare_cti_program_write
from portal_request_routes import PostRoute
from portal_resource_library_write import prepare_resource_library_write
from portal_soc_settings_write import prepare_soc_settings_write
from portal_soc_status_write import prepare_soc_status_write
from portal_soc_write_request import prepare_soc_write_request


@dataclass(frozen=True)
class JsonWriteCallbacks:
    same_origin_authorized: Callable[[], bool]
    cti_admin_authenticated: Callable[[], bool]
    cti_program: Any
    asset_admin_authenticated: Callable[[], bool]
    asset_dispatcher: Callable
    soc_dispatcher: Callable
    soc: Any
    clear_soc_cache: Callable[[], None]
    status_update: Callable
    settings_admin_authenticated: Callable[[], bool]
    settings: Any
    admin_authenticated: Callable[[], bool]
    admin_service: Any
    resource_library: Any


@dataclass(frozen=True)
class JsonWriteResult:
    status: int
    payload: dict


def _result(value: Any) -> JsonWriteResult:
    return JsonWriteResult(int(value.status), value.payload)


def _priority_write(
    route: PostRoute,
    raw: str,
    asset_admin_required: bool,
    callbacks: JsonWriteCallbacks,
) -> JsonWriteResult | None:
    if route.cti_program_write:
        value = prepare_cti_program_write(
            route, raw,
            same_origin_authorized=callbacks.same_origin_authorized(),
            admin_authenticated=callbacks.cti_admin_authenticated,
            callbacks=callbacks.cti_program,
        )
        return _result(value)
    if route.asset_write:
        value = prepare_asset_write_request(
            route, raw,
            same_origin_authorized=callbacks.same_origin_authorized(),
            admin_required=asset_admin_required,
            admin_authenticated=callbacks.asset_admin_authenticated,
            dispatcher=callbacks.asset_dispatcher,
        )
        return _result(value)
    return None


def _soc_write(
    route: PostRoute,
    raw: str,
    callbacks: JsonWriteCallbacks,
) -> JsonWriteResult | None:
    value = prepare_soc_write_request(
        route, raw,
        same_origin_authorized=(
            not (route.incident_reanalysis or route.review_write)
            or callbacks.same_origin_authorized()
        ),
        dispatcher=callbacks.soc_dispatcher,
        callbacks=callbacks.soc,
    )
    if value is not None:
        if value.clear_cache:
            callbacks.clear_soc_cache()
        return _result(value)
    value = prepare_soc_status_write(route, raw, update=callbacks.status_update)
    if value is not None:
        if value.clear_cache:
            callbacks.clear_soc_cache()
        return _result(value)
    return None


def _governance_write(
    route: PostRoute,
    raw: str,
    callbacks: JsonWriteCallbacks,
) -> JsonWriteResult | None:
    value = prepare_soc_settings_write(
        route, raw,
        admin_authenticated=callbacks.settings_admin_authenticated,
        callbacks=callbacks.settings,
    )
    if value is not None:
        return _result(value)
    value = prepare_admin_service_write(
        route, raw,
        admin_authenticated=callbacks.admin_authenticated,
        callbacks=callbacks.admin_service,
    )
    if value is not None:
        return _result(value)
    value = prepare_resource_library_write(
        route, raw, callbacks=callbacks.resource_library,
    )
    if value is not None:
        return _result(value)
    return None


def dispatch_json_write(
    route: PostRoute,
    raw: str,
    *,
    asset_admin_required: bool,
    callbacks: JsonWriteCallbacks,
) -> JsonWriteResult | None:
    """Dispatch one classified JSON write, declining Administration forms."""
    value = _priority_write(route, raw, asset_admin_required, callbacks)
    if value is not None:
        return value
    value = _soc_write(route, raw, callbacks)
    return value if value is not None else _governance_write(route, raw, callbacks)
