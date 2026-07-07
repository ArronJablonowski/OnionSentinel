#!/usr/bin/env python3
"""Small, testable helpers for the SOC Alerts API.

The portal server owns HTTP routing, auth, and file serving. Keep repeated SOC
alert aggregation rules here so table payloads, metric cards, and EventSource
snapshots do not drift apart as the dashboard evolves.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any


UNKNOWN_VALUES = {"", "n/a", "na", "unknown", "unknown-source", "unknown-destination", "none", "null", "-"}


def row_value(row: Any, field: str, default: Any = None) -> Any:
    """Read a value from sqlite rows or dicts without making callers care."""
    if isinstance(row, dict):
        return row.get(field, default)
    try:
        keys = row.keys()
    except AttributeError:
        keys = ()
    if field in keys:
        return row[field]
    return default


def analyst_status_for_row(row: Any, group_id: str, statuses: dict) -> str:
    """Return the effective dashboard state for one grouped alert row."""
    local_status = "open"
    if isinstance(statuses, dict):
        meta = statuses.get(group_id, {}) or {}
        if isinstance(meta, dict):
            local_status = str(meta.get("status") or "open").strip().lower()
    filter_status = str(row_value(row, "filter_status", "accepted") or "accepted").strip().lower()
    if local_status == "suppressed" or filter_status == "suppressed":
        return "suppressed"
    if local_status == "acknowledged":
        return "acknowledged"
    return "open"


def status_bucket_counts(rows: list[Any], statuses: dict, group_id_for_row: Callable[[Any], str]) -> dict[str, int]:
    """Count grouped alerts by the same status buckets used by every API view."""
    counts = {"open": 0, "acknowledged": 0, "suppressed": 0}
    for row in rows:
        status = analyst_status_for_row(row, group_id_for_row(row), statuses)
        counts[status if status in counts else "open"] += 1
    counts["active"] = counts["open"]
    counts["total"] = counts["open"] + counts["acknowledged"] + counts["suppressed"]
    return counts


def top_endpoint_metrics(rows: list[Any]) -> dict[str, str]:
    """Find the most frequent source, destination, and destination port.

    Counts are weighted by grouped observation volume, not by current page size,
    so metric cards continue to represent all currently visible alerts.
    """
    counters: dict[str, dict[str, int]] = {"source_ip": {}, "destination_ip": {}, "destination_port": {}}
    for row in rows:
        weight = max(
            1,
            int(
                row_value(row, "total_seen_count", None)
                or row_value(row, "seen_count", None)
                or row_value(row, "raw_alert_count", None)
                or 1
            ),
        )
        for field in counters:
            value = str(row_value(row, field, "") or "").strip()
            if value.lower() in UNKNOWN_VALUES:
                continue
            counters[field][value] = counters[field].get(value, 0) + weight

    def top_value(values: dict[str, int]) -> str:
        if not values:
            return "n/a"
        return sorted(values.items(), key=lambda item: (-item[1], item[0]))[0][0]

    return {field: top_value(values) for field, values in counters.items()}
