"""Transport-neutral request orchestration for legacy SOC alert status writes."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from portal_json_body import parse_json_body
from portal_request_routes import PostRoute


SOC_ALERT_STATUS_PATH = "/api/soc-alerts/status"


@dataclass(frozen=True)
class SocStatusWriteResult:
    status: int
    payload: dict
    clear_cache: bool = False


def prepare_soc_status_write(
    route: PostRoute,
    raw: str,
    *,
    update: Callable[[dict], tuple[bool, dict]],
) -> SocStatusWriteResult | None:
    """Dispatch one legacy status request and preserve downstream HTTP status."""
    if route.path != SOC_ALERT_STATUS_PATH:
        return None
    parsed = parse_json_body(raw, empty_object=True).value_or({})
    payload = parsed if isinstance(parsed, dict) else {}
    ok, response = update(payload)
    status = 200 if ok else int(response.get("status") or 400)
    return SocStatusWriteResult(status, response, clear_cache=ok)
