"""Redacted, fixed-query preflight for scheduled endpoint inventory."""
from __future__ import annotations

from typing import Any, Callable


IDENTITY_QUERY = "SELECT hostname FROM system_info LIMIT 1;"
PREFLIGHT_PURPOSE = "Operator-safe scheduled inventory preflight"


def _approved_aliases(
    config: dict[str, Any],
    *,
    approved: Callable[[dict[str, Any], str], bool],
    error_type: type[RuntimeError],
) -> list[str]:
    aliases = list(
        (config.get("scheduled_inventory_approval") or {}).get("target_aliases")
        or []
    )
    if not aliases:
        raise error_type("no scheduled inventory endpoint alias is approved")
    if any(not approved(config, alias) for alias in aliases):
        raise error_type("scheduled inventory approval is incomplete")
    return aliases


def run_preflight(
    config: dict[str, Any],
    *,
    approved: Callable[[dict[str, Any], str], bool],
    query: Callable[..., list[dict[str, str]]],
    now: Callable[[], Any],
    timestamp: Callable[[Any], str],
    error_type: type[RuntimeError],
) -> dict[str, Any]:
    """Run one identity query per approved target and return no query data."""
    aliases = _approved_aliases(
        config,
        approved=approved,
        error_type=error_type,
    )
    checked_at = timestamp(now())
    case_id = "scheduled-endpoint-preflight-" + checked_at[:10].replace("-", "")
    for alias in aliases:
        rows = query(
            config,
            alias,
            IDENTITY_QUERY,
            PREFLIGHT_PURPOSE,
            case_id,
        )
        if len(rows) != 1:
            raise error_type(
                "scheduled inventory preflight identity was ambiguous",
                reason_code="ambiguous_identity",
            )
    return {
        "status": "ok",
        "targets": len(aliases),
        "checked_at": checked_at,
    }
