"""Software Inventory bounded response composition."""
from __future__ import annotations

import datetime as dt
from pathlib import Path

from software_inventory_assets import (
    apply_asset_labels,
    correlate_asset_operating_systems,
)
from software_inventory_query import (
    _empty_payload,
    _freshness,
    _public_record,
    parse_filters,
)
from software_inventory_state import (
    API_SCHEMA,
    InventoryQueryError,
    InventoryStateError,
    MAX_STATE_BYTES,
    TIERS,
    WINDOWS,
    _utc_iso,
    load_state,
)


def build_response(
    path: Path,
    query: dict[str, list[str]] | None = None,
    *,
    observed_at: dt.datetime | None = None,
    maximum_bytes: int = MAX_STATE_BYTES,
    assets: object = None,
    asset_inventory_complete: bool = False,
) -> tuple[int, dict[str, object]]:
    """Build one bounded public response from the local derived snapshot."""
    now = observed_at or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        now = now.astimezone()
    now = now.astimezone(dt.timezone.utc)
    try:
        filters = parse_filters(query)
    except InventoryQueryError as exc:
        filters = parse_filters(None)
        payload = _empty_payload(now, filters, error=str(exc))
        return 400, payload
    try:
        state, revision = load_state(path, maximum_bytes=maximum_bytes)
    except InventoryStateError as exc:
        return 503, _empty_payload(now, filters, error=str(exc))

    state_records = state["records"]  # type: ignore[assignment]
    apply_asset_labels(
        state_records,
        assets,
        inventory_complete=asset_inventory_complete,
    )
    correlate_asset_operating_systems(
        state_records,
        state_records,
        assets=assets,
        observed_at=now,
    )
    window_start = now - WINDOWS[str(filters["window"])]
    all_window_records = [
        item
        for item in state_records
        if item["_last_seen"] >= window_start  # type: ignore[index,operator]
    ]
    records = list(all_window_records)
    if filters["tier"] != "all":
        records = [item for item in records if item["tier"] == filters["tier"]]
    if filters["confidence"] != "all":
        records = [
            item
            for item in records
            if item["confidence"] == filters["confidence"]
        ]
    if filters["freshness"] != "all":
        records = [
            item
            for item in records
            if _freshness(item, now) == filters["freshness"]
        ]
    if str(filters["platform"]).lower() != "all":
        platform = str(filters["platform"]).casefold()
        records = [
            item
            for item in records
            if str(item["platform"]).casefold() == platform
        ]
    if filters["search"]:
        needle = str(filters["search"]).casefold()
        records = [
            item
            for item in records
            if needle
            in " ".join(
                str(item[key])
                for key in (
                    "product",
                    "version",
                    "asset_ref",
                    "platform",
                    "operating_system_type",
                    "operating_system_version",
                    "category",
                    "source",
                )
            ).casefold()
        ]

    sort_key = {
        "last_seen": lambda item: (item["_last_seen"], item["evidence_id"]),
        "first_seen": lambda item: (item["_first_seen"], item["evidence_id"]),
        "product": lambda item: (
            str(item["product"]).casefold(),
            str(item["version"]).casefold(),
            item["evidence_id"],
        ),
        "asset": lambda item: (
            str(item["asset_ref"]).casefold(),
            str(item["product"]).casefold(),
            item["evidence_id"],
        ),
        "tier": lambda item: (
            str(item["tier"]),
            str(item["product"]).casefold(),
            item["evidence_id"],
        ),
        "confidence": lambda item: (
            str(item["confidence"]),
            str(item["product"]).casefold(),
            item["evidence_id"],
        ),
    }[str(filters["sort"])]
    records.sort(key=sort_key, reverse=filters["direction"] == "desc")
    offset = int(filters["offset"])
    limit = int(filters["limit"])
    selected = records[offset : offset + limit]
    public_records = [_public_record(item, now) for item in records]
    summary = {
        "records": len(records),
        "products": len(
            {
                str(item["product"]).casefold()
                for item in records
            }
        ),
        "assets": len({str(item["asset_ref"]) for item in records}),
    }
    for tier in sorted(TIERS):
        summary[tier] = sum(item["tier"] == tier for item in records)
    for freshness in ("current", "recent", "historical", "expired"):
        summary[freshness] = sum(
            item["freshness"] == freshness for item in public_records
        )

    window_public = [_public_record(item, now) for item in all_window_records]
    fresh_endpoint_assets = {
        str(item["asset_ref"])
        for item in window_public
        if item["tier"] == "installed" and item["freshness"] == "current"
    }
    network_assets = {
        str(item["asset_ref"])
        for item in window_public
        if item["tier"] in {"observed", "inferred"}
    }
    collection = state["collection"]
    osquery_ready = collection.get("osquery_ready")  # type: ignore[union-attr]
    if isinstance(osquery_ready, bool) or not isinstance(osquery_ready, int):
        osquery_ready = None
    coverage_gaps = (
        max(osquery_ready - len(fresh_endpoint_assets), 0)
        if osquery_ready is not None
        else None
    )
    warnings = [
        (
            "LAN software coverage has no authoritative asset denominator; "
            "counts describe only observable evidence."
        )
    ]
    if not collection.get("complete"):  # type: ignore[union-attr]
        warnings.append(
            "The latest collection was incomplete; showing the last valid snapshot."
        )
    last_error = str(collection.get("last_error") or "")  # type: ignore[union-attr]
    if last_error:
        warnings.append(f"Latest collection warning: {last_error}")
    if not fresh_endpoint_assets:
        warnings.append(
            "No current endpoint-reported inventory is visible; passive "
            "network evidence cannot prove software is absent."
        )

    return 200, {
        "ok": True,
        "schema": API_SCHEMA,
        "generated_at": state["updated_at"],
        "observed_at": _utc_iso(now),
        "collection": collection,
        "summary": summary,
        "coverage": {
            "authoritative_denominator": None,
            "denominator_status": "unknown",
            "osquery_ready": osquery_ready,
            "fresh_endpoint_inventories": len(fresh_endpoint_assets),
            "network_observed_assets": len(network_assets),
            "coverage_gaps": coverage_gaps,
            "labeled_visible_records": sum(
                bool(item.get("asset_label")) for item in records
            ),
            "asset_label_inventory_complete": asset_inventory_complete,
            "asset_os_correlated_records": sum(
                bool(item.get("operating_system_association"))
                for item in records
            ),
        },
        "filters": filters,
        "platforms": sorted(
            {
                str(item["platform"])
                for item in all_window_records
                if str(item["platform"])
            },
            key=str.casefold,
        ),
        "page": {
            "limit": limit,
            "offset": offset,
            "filtered_total": len(records),
            "has_more": offset + len(selected) < len(records),
        },
        "items": [_public_record(item, now) for item in selected],
        "warnings": warnings,
        "revision": revision,
    }
