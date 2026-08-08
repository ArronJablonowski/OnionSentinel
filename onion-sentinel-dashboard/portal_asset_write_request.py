"""Authorization, JSON, and dispatch policy for Asset Inventory writes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute


AssetWriteDispatcher = Callable[[str, object], tuple[int, dict]]


@dataclass(frozen=True)
class AssetWriteRequestResult:
    status: int
    payload: dict


def _error(status: int, message: str, *, authentication: bool = False) -> AssetWriteRequestResult:
    payload = {"ok": False, "error": message}
    if authentication:
        payload["authentication_required"] = True
    return AssetWriteRequestResult(status, payload)


def prepare_asset_write_request(
    route: PostRoute,
    raw: str,
    *,
    same_origin_authorized: bool,
    admin_required: bool,
    admin_authenticated: Callable[[], bool],
    dispatcher: AssetWriteDispatcher,
) -> AssetWriteRequestResult | None:
    """Authorize and dispatch one Asset write, or decline other routes."""
    if not route.asset_write:
        return None
    if not same_origin_authorized:
        return _error(
            403,
            "Asset inventory changes must come from the same-origin Onion Sentinel dashboard.",
        )
    if admin_required and not admin_authenticated():
        return _error(
            403,
            "Sign in to Onion Sentinel Administration before approving asset inventory changes.",
            authentication=True,
        )
    payload = parse_json_body(raw).value_or(None)
    status, response = dispatcher(route.path, payload)
    return AssetWriteRequestResult(int(status), response)
