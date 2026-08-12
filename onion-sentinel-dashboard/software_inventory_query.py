"""Software Inventory query validation and public record projection."""
from __future__ import annotations

import datetime as dt

from software_inventory_state import (
    API_SCHEMA,
    CONFIDENCES,
    DEFAULT_LIMIT,
    ENDPOINT_OS_SOURCES,
    FRESHNESS_VALUES,
    InventoryQueryError,
    MAX_LIMIT,
    MAX_OFFSET,
    SORT_FIELDS,
    TIERS,
    WINDOWS,
    _utc_iso,
)


def _one(query: dict[str, list[str]], key: str, default: str) -> str:
    values = query.get(key)
    if not values:
        return default
    if len(values) != 1:
        raise InventoryQueryError(f"{key} must appear once")
    return str(values[0])


def parse_filters(query: dict[str, list[str]] | None) -> dict[str, object]:
    query = query or {}
    allowed = {
        "limit",
        "offset",
        "search",
        "tier",
        "confidence",
        "freshness",
        "platform",
        "window",
        "sort",
        "direction",
    }
    unknown = set(query) - allowed
    if unknown:
        raise InventoryQueryError(
            f"unsupported query parameter: {sorted(unknown)[0]}"
        )
    try:
        limit = int(_one(query, "limit", str(DEFAULT_LIMIT)))
        offset = int(_one(query, "offset", "0"))
    except ValueError as exc:
        raise InventoryQueryError("limit and offset must be integers") from exc
    if not 1 <= limit <= MAX_LIMIT:
        raise InventoryQueryError(f"limit must be between 1 and {MAX_LIMIT}")
    if not 0 <= offset <= MAX_OFFSET:
        raise InventoryQueryError(f"offset must be between 0 and {MAX_OFFSET}")
    search = _one(query, "search", "").strip()
    if len(search) > 253 or any(ord(char) < 32 for char in search):
        raise InventoryQueryError("search is invalid")
    tier = _one(query, "tier", "all").strip().lower()
    confidence = _one(query, "confidence", "all").strip().lower()
    freshness = _one(query, "freshness", "all").strip().lower()
    platform = _one(query, "platform", "all").strip()
    window = _one(query, "window", "30d").strip().lower()
    sort_field = _one(query, "sort", "last_seen").strip().lower()
    direction = _one(query, "direction", "desc").strip().lower()
    if tier != "all" and tier not in TIERS:
        raise InventoryQueryError("tier is unsupported")
    if confidence != "all" and confidence not in CONFIDENCES:
        raise InventoryQueryError("confidence is unsupported")
    if freshness != "all" and freshness not in FRESHNESS_VALUES:
        raise InventoryQueryError("freshness is unsupported")
    if (
        not platform
        or len(platform) > 160
        or any(ord(char) < 32 for char in platform)
    ):
        raise InventoryQueryError("platform is invalid")
    if window not in WINDOWS:
        raise InventoryQueryError("window is unsupported")
    if sort_field not in SORT_FIELDS:
        raise InventoryQueryError("sort is unsupported")
    if direction not in {"asc", "desc"}:
        raise InventoryQueryError("direction is unsupported")
    return {
        "limit": limit,
        "offset": offset,
        "search": search,
        "tier": tier,
        "confidence": confidence,
        "freshness": freshness,
        "platform": platform,
        "window": window,
        "sort": sort_field,
        "direction": direction,
    }


def _freshness(record: dict[str, object], observed_at: dt.datetime) -> str:
    age = observed_at - record["_last_seen"]  # type: ignore[operator]
    if age <= dt.timedelta(hours=24):
        return "current"
    if age <= dt.timedelta(days=7):
        return "recent"
    if record["tier"] in {"observed", "inferred"} and age <= dt.timedelta(days=30):
        return "historical"
    return "expired"


def _public_record(
    record: dict[str, object], observed_at: dt.datetime
) -> dict[str, object]:
    freshness = _freshness(record, observed_at)
    public = {
        key: value
        for key, value in record.items()
        if not key.startswith("_")
    } | {
        "freshness": freshness,
        "operating_system_observed_at": str(
            record.get("operating_system_observed_at") or ""
        ),
        "operating_system_freshness": str(
            record.get("operating_system_freshness") or ""
        ),
        "operating_system_association": str(
            record.get("operating_system_association") or ""
        ),
    }
    if (
        record["source"] == "osquery_apps"
        and record["operating_system_source"] in ENDPOINT_OS_SOURCES
        and (
            record["operating_system_type"]
            or record["operating_system_version"]
        )
    ):
        public["operating_system_observed_at"] = record["last_seen"]
        public["operating_system_freshness"] = freshness
    observed_user_agent = ""
    if record["source"] == "http_user_agent":
        observed_user_agent = str(record["product"])
    elif (
        record["source"] == "zeek_software"
        and str(record["category"]).casefold() == "http::browser"
    ):
        observed_user_agent = str(record["version"])
    if observed_user_agent:
        public["observed_user_agent"] = observed_user_agent
    return public




def _empty_payload(
    observed_at: dt.datetime,
    filters: dict[str, object],
    *,
    error: str,
) -> dict[str, object]:
    return {
        "ok": False,
        "schema": API_SCHEMA,
        "generated_at": "",
        "observed_at": _utc_iso(observed_at),
        "collection": {
            "status": "unavailable",
            "complete": False,
            "window": {},
            "last_attempt_at": "",
            "last_success_at": "",
            "last_error": error,
            "source_statuses": {},
        },
        "summary": {
            "records": 0,
            "products": 0,
            "assets": 0,
            "installed": 0,
            "observed": 0,
            "inferred": 0,
            "current": 0,
            "recent": 0,
            "historical": 0,
            "expired": 0,
        },
        "coverage": {
            "authoritative_denominator": None,
            "denominator_status": "unknown",
            "osquery_ready": None,
            "fresh_endpoint_inventories": 0,
            "network_observed_assets": 0,
            "coverage_gaps": None,
            "labeled_visible_records": 0,
            "asset_label_inventory_complete": False,
            "asset_os_correlated_records": 0,
        },
        "filters": filters,
        "platforms": [],
        "page": {
            "limit": filters["limit"],
            "offset": filters["offset"],
            "filtered_total": 0,
            "has_more": False,
        },
        "items": [],
        "warnings": [error],
        "revision": "",
        "error": error,
    }
