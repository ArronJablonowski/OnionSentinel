"""Bounded Software Inventory response filtering and ordering."""
from __future__ import annotations

import datetime as dt
from collections.abc import Callable

from software_inventory_query import _freshness
from software_inventory_state import WINDOWS


SortKey = Callable[[dict[str, object]], tuple[object, ...]]


def _filtered_records(
    records: list[dict[str, object]],
    filters: dict[str, object],
    observed_at: dt.datetime,
) -> list[dict[str, object]]:
    if filters["tier"] != "all":
        records = [
            item for item in records if item["tier"] == filters["tier"]
        ]
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
            if _freshness(item, observed_at) == filters["freshness"]
        ]
    return records


def _platform_records(
    records: list[dict[str, object]],
    platform_filter: object,
) -> list[dict[str, object]]:
    if str(platform_filter).lower() == "all":
        return records
    platform = str(platform_filter).casefold()
    return [
        item
        for item in records
        if str(item["platform"]).casefold() == platform
    ]


def _search_records(
    records: list[dict[str, object]],
    search_filter: object,
) -> list[dict[str, object]]:
    if not search_filter:
        return records
    needle = str(search_filter).casefold()
    keys = (
        "product",
        "version",
        "asset_ref",
        "platform",
        "operating_system_type",
        "operating_system_version",
        "category",
        "source",
    )
    return [
        item
        for item in records
        if needle
        in " ".join(str(item[key]) for key in keys).casefold()
    ]


def _sort_key(field: str) -> SortKey:
    return {
        "last_seen": lambda item: (
            item["_last_seen"],
            item["evidence_id"],
        ),
        "first_seen": lambda item: (
            item["_first_seen"],
            item["evidence_id"],
        ),
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
    }[field]


def select_response_records(
    state_records: list[dict[str, object]],
    filters: dict[str, object],
    observed_at: dt.datetime,
) -> tuple[
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    int,
    int,
]:
    """Return window, filtered, and paged records in stable order."""
    window_start = observed_at - WINDOWS[str(filters["window"])]
    all_window_records = [
        item
        for item in state_records
        if item["_last_seen"] >= window_start  # type: ignore[operator]
    ]
    records = _filtered_records(
        list(all_window_records), filters, observed_at
    )
    records = _platform_records(records, filters["platform"])
    records = _search_records(records, filters["search"])
    records.sort(
        key=_sort_key(str(filters["sort"])),
        reverse=filters["direction"] == "desc",
    )
    offset = int(filters["offset"])
    limit = int(filters["limit"])
    selected = records[offset : offset + limit]
    return all_window_records, records, selected, limit, offset
