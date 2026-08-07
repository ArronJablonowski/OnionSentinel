"""Authorization and JSON policy for classified SOC write requests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute
from portal_soc_write_dispatch import SocWriteCallbacks, WriteResponse


WriteDispatcher = Callable[[PostRoute, dict, SocWriteCallbacks], WriteResponse]


@dataclass(frozen=True)
class SocWriteRequestResult:
    status: int
    payload: dict
    clear_cache: bool = False


def _error(status: int, message: str) -> SocWriteRequestResult:
    return SocWriteRequestResult(status, {"ok": False, "error": message})


def _authorized_payload(
    route: PostRoute,
    raw: str,
    same_origin_authorized: bool,
) -> SocWriteRequestResult | dict:
    if route.incident_reanalysis:
        if not same_origin_authorized:
            return _error(
                403,
                "Incident reanalysis requests must come from the same-origin dashboard.",
            )
        payload = parse_json_body(raw).value_or(None)
        return payload if isinstance(payload, dict) else _error(
            400, "Request body must be a JSON object.",
        )
    if route.review_write:
        if not same_origin_authorized:
            return _error(
                403,
                "Analyst review writes must come from the same-origin dashboard.",
            )
        parsed = parse_json_body(raw)
        if not parsed.valid:
            return _error(400, "Request body must be valid JSON.")
        return parsed.value if isinstance(parsed.value, dict) else _error(
            400, "Request body must be a JSON object.",
        )
    return parse_json_body(raw, empty_object=True).value_or({})


def prepare_soc_write_request(
    route: PostRoute,
    raw: str,
    *,
    same_origin_authorized: bool,
    dispatcher: WriteDispatcher,
    callbacks: SocWriteCallbacks,
) -> SocWriteRequestResult | None:
    """Validate and dispatch one SOC write, or decline non-SOC routes."""
    if not (route.incident_reanalysis or route.review_write or route.alert_action):
        return None
    payload = _authorized_payload(route, raw, same_origin_authorized)
    if isinstance(payload, SocWriteRequestResult):
        return payload
    status, response = dispatcher(route, payload, callbacks)
    return SocWriteRequestResult(int(status), response, int(status) < 400)
