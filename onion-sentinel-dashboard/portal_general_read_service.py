"""Transport-neutral dispatch for general portal reads."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


Query = dict[str, list[str]]
StatusPayload = tuple[int, Any]


@dataclass(frozen=True)
class GeneralReadCallbacks:
    home: Callable[[], bytes]
    health: Callable[[], dict[str, Any]]
    resource_favorites: Callable[[], Any]
    system_health_beacons: Callable[[Query], dict[str, Any]]
    asset_inventory: Callable[[Query], StatusPayload]
    dhcp_asset_discovery: Callable[[], StatusPayload]
    software_inventory: Callable[[Query], StatusPayload]
    cti_program: Callable[[], StatusPayload]


@dataclass(frozen=True)
class GeneralReadResult:
    status: int
    payload: Any
    content_type: str = "application/json; charset=utf-8"
    encoded: bool = False


GENERAL_READ_OPERATIONS = frozenset({
    "home",
    "health",
    "resource_favorites",
    "system_health_beacons",
    "asset_inventory",
    "dhcp_asset_discovery",
    "software_inventory",
    "cti_program",
})


def _pair_result(pair: StatusPayload) -> GeneralReadResult:
    status, payload = pair
    return GeneralReadResult(int(status), payload)


def dispatch_general_read(
    operation: str | None,
    *,
    query: Query,
    callbacks: GeneralReadCallbacks,
) -> GeneralReadResult | None:
    """Dispatch an exact general read without owning HTTP serialization."""
    if operation not in GENERAL_READ_OPERATIONS:
        return None
    handlers: dict[str, Callable[[], GeneralReadResult]] = {
        "home": lambda: GeneralReadResult(
            200, callbacks.home(), "text/html; charset=utf-8", True,
        ),
        "health": lambda: GeneralReadResult(200, callbacks.health()),
        "resource_favorites": lambda: GeneralReadResult(
            200, {"ok": True, "favorites": callbacks.resource_favorites()},
        ),
        "system_health_beacons": lambda: GeneralReadResult(
            200, callbacks.system_health_beacons(query),
        ),
        "asset_inventory": lambda: _pair_result(callbacks.asset_inventory(query)),
        "dhcp_asset_discovery": lambda: _pair_result(
            callbacks.dhcp_asset_discovery(),
        ),
        "software_inventory": lambda: _pair_result(
            callbacks.software_inventory(query),
        ),
        "cti_program": lambda: _pair_result(callbacks.cti_program()),
    }
    return handlers[operation]()
