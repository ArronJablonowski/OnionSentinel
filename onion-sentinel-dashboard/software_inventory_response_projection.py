"""Public Software Inventory summary and coverage projection."""
from __future__ import annotations

import datetime as dt

from software_inventory_query import _public_record
from software_inventory_state import API_SCHEMA, TIERS, _utc_iso


VERSION_CONFLICT = "simultaneous-version-disagreement"


def _conflict_key(record: dict[str, object]) -> tuple[str, str, str, str]:
    return (
        str(record.get("asset_ref_type") or ""),
        str(record.get("asset_ref") or ""),
        str(record.get("product") or "").casefold(),
        str(record.get("last_seen") or ""),
    )


def _version_groups(
    records: list[dict[str, object]],
) -> dict[tuple[str, str, str, str], set[str]]:
    groups: dict[tuple[str, str, str, str], set[str]] = {}
    for record in records:
        version = str(record.get("version") or "").strip().casefold()
        if version:
            groups.setdefault(_conflict_key(record), set()).add(version)
    return groups


def annotate_version_conflicts(records: list[dict[str, object]]) -> int:
    """Mark simultaneous version disagreements across the complete window."""
    groups = _version_groups(records)
    conflicting = 0
    for record in records:
        conflict = len(groups.get(_conflict_key(record), set())) > 1
        record["evidence_conflict"] = VERSION_CONFLICT if conflict else ""
        conflicting += int(conflict)
    return conflicting


def _summary(
    records: list[dict[str, object]],
    public_records: list[dict[str, object]],
) -> dict[str, int]:
    summary = {
        "records": len(records),
        "products": len(
            {str(item["product"]).casefold() for item in records}
        ),
        "assets": len({str(item["asset_ref"]) for item in records}),
        "conflicting_records": sum(
            item.get("evidence_conflict") == VERSION_CONFLICT for item in records
        ),
    }
    for tier in sorted(TIERS):
        summary[tier] = sum(item["tier"] == tier for item in records)
    for freshness in ("current", "recent", "historical", "expired"):
        summary[freshness] = sum(
            item["freshness"] == freshness for item in public_records
        )
    return summary


def _coverage_assets(
    window_public: list[dict[str, object]],
) -> tuple[set[str], set[str]]:
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
    return fresh_endpoint_assets, network_assets


def _osquery_ready(collection: dict[str, object]) -> int | None:
    value = collection.get("osquery_ready")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _coverage(
    records: list[dict[str, object]],
    window_public: list[dict[str, object]],
    collection: dict[str, object],
    asset_inventory_complete: bool,
) -> tuple[dict[str, object], set[str]]:
    fresh_endpoint_assets, network_assets = _coverage_assets(window_public)
    osquery_ready = _osquery_ready(collection)
    coverage_gaps = (
        max(osquery_ready - len(fresh_endpoint_assets), 0)
        if osquery_ready is not None
        else None
    )
    return {
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
    }, fresh_endpoint_assets


def _warnings(
    collection: dict[str, object],
    fresh_endpoint_assets: set[str],
    conflicting_records: int,
) -> list[str]:
    warnings = [
        (
            "LAN software coverage has no authoritative asset denominator; "
            "counts describe only observable evidence."
        )
    ]
    if not collection.get("complete"):
        warnings.append(
            "The latest collection was incomplete; showing the last valid snapshot."
        )
    last_error = str(collection.get("last_error") or "")
    if last_error:
        warnings.append(f"Latest collection warning: {last_error}")
    if not fresh_endpoint_assets:
        warnings.append(
            "No current endpoint-reported inventory is visible; passive "
            "network evidence cannot prove software is absent."
        )
    if conflicting_records:
        warnings.append(
            f"{conflicting_records} records have simultaneous version "
            "disagreements; each evidence row is retained and no version "
            "is selected as authoritative."
        )
    return warnings


def _platforms(records: list[dict[str, object]]) -> list[str]:
    return sorted(
        {
            str(item["platform"])
            for item in records
            if str(item["platform"])
        },
        key=str.casefold,
    )


def _page(
    records: list[dict[str, object]],
    selected: list[dict[str, object]],
    limit: int,
    offset: int,
) -> dict[str, object]:
    return {
        "limit": limit,
        "offset": offset,
        "filtered_total": len(records),
        "has_more": offset + len(selected) < len(records),
    }


def build_success_payload(
    *,
    state: dict[str, object],
    revision: str,
    filters: dict[str, object],
    observed_at: dt.datetime,
    all_window_records: list[dict[str, object]],
    records: list[dict[str, object]],
    selected: list[dict[str, object]],
    limit: int,
    offset: int,
    asset_inventory_complete: bool,
) -> dict[str, object]:
    """Build the exact public success payload from selected records."""
    annotate_version_conflicts(all_window_records)
    public_records = [_public_record(item, observed_at) for item in records]
    summary = _summary(records, public_records)
    window_public = [
        _public_record(item, observed_at) for item in all_window_records
    ]
    collection = state["collection"]
    coverage, fresh_endpoint_assets = _coverage(
        records,
        window_public,
        collection,  # type: ignore[arg-type]
        asset_inventory_complete,
    )
    return {
        "ok": True,
        "schema": API_SCHEMA,
        "generated_at": state["updated_at"],
        "observed_at": _utc_iso(observed_at),
        "collection": collection,
        "summary": summary,
        "coverage": coverage,
        "filters": filters,
        "platforms": _platforms(all_window_records),
        "page": _page(records, selected, limit, offset),
        "items": [_public_record(item, observed_at) for item in selected],
        "warnings": _warnings(
            collection,  # type: ignore[arg-type]
            fresh_endpoint_assets,
            summary["conflicting_records"],
        ),
        "revision": revision,
    }
