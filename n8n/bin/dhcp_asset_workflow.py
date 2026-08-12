#!/usr/bin/env python3
"""Bounded DHCP live-window and historical backfill workflows."""
from __future__ import annotations

import datetime as dt

from dhcp_asset_contract import STATE_SCHEMA, format_timestamp, parse_timestamp


MAX_QUERY_SEGMENTS = 16
MIN_QUERY_SEGMENT = dt.timedelta(minutes=1)
MAX_BACKFILL_DAYS = 30
MAX_BACKFILL_QUERY_SEGMENTS = 64


def _validate_backfill_days(days: int) -> None:
    if (
        isinstance(days, bool)
        or not isinstance(days, int)
        or not 1 <= days <= MAX_BACKFILL_DAYS
    ):
        raise ValueError(
            f"DHCP backfill days must be from 1 through {MAX_BACKFILL_DAYS}"
        )


def collection_window(
    state: dict,
    now: dt.datetime,
    default_minutes: int,
) -> tuple[dt.datetime, dt.datetime]:
    start = now - dt.timedelta(minutes=default_minutes)
    last_success = state.get("collection", {}).get("last_success_at")
    if last_success:
        try:
            start = max(
                now - dt.timedelta(hours=24),
                parse_timestamp(last_success) - dt.timedelta(minutes=5),
            )
        except (TypeError, ValueError):
            pass
    return start, now


def query_complete_window(
    config: dict,
    start: dt.datetime,
    end: dt.datetime,
    size: int,
    *,
    max_segments: int = MAX_QUERY_SEGMENTS,
    query_fn,
) -> dict:
    """Split truncated time ranges without permitting an unbounded query loop."""
    if (
        isinstance(max_segments, bool)
        or not isinstance(max_segments, int)
        or not 1 <= max_segments <= MAX_BACKFILL_QUERY_SEGMENTS
    ):
        raise ValueError("DHCP query segment budget is invalid")
    pending = [(start, end)]
    completed: list[dict] = []
    queries = 0
    incomplete = False
    while pending:
        segment_start, segment_end = pending.pop(0)
        response = query_fn(config, segment_start, segment_end, size)
        queries += 1
        segment_length = segment_end - segment_start
        can_split = (
            response.get("truncated") is True
            and segment_length > MIN_QUERY_SEGMENT
            and queries + len(pending) + 2 <= max_segments
        )
        if can_split:
            midpoint = segment_start + segment_length / 2
            pending[0:0] = [
                (segment_start, midpoint),
                (midpoint, segment_end),
            ]
            continue
        completed.append(response)
        if (
            response.get("truncated") is True
            or response.get("status") == "partial"
        ):
            incomplete = True

    unique: dict[str, dict] = {}
    for response in completed:
        for observation in response["observations"]:
            unique[observation["evidence_id"]] = observation
    observations = sorted(
        unique.values(),
        key=lambda item: (item["observed_at"], item["evidence_id"]),
    )
    return {
        "status": "partial" if incomplete else "ok",
        "window": {
            "start": format_timestamp(start),
            "end": format_timestamp(end),
        },
        "hits_total": sum(
            int(response.get("hits_total") or 0) for response in completed
        ),
        "observations": observations,
        "truncated": incomplete,
        "query_segments": queries,
    }


def backfill(
    config: dict,
    state: dict,
    now: dt.datetime,
    days: int,
    *,
    query_window_fn,
    merge_fn,
) -> dict:
    """Merge bounded historical day windows without moving the live checkpoint."""
    _validate_backfill_days(days)
    requested_start = now - dt.timedelta(days=days)
    cursor = requested_start
    covered_through = requested_start
    incoming: list[dict] = []
    total_hits = 0
    total_segments = 0
    incomplete = False
    error = ""
    while cursor < now:
        remaining_budget = MAX_BACKFILL_QUERY_SEGMENTS - total_segments
        if remaining_budget <= 0:
            incomplete = True
            error = "DHCP backfill stopped at its global query-segment limit"
            break
        window_end = min(cursor + dt.timedelta(hours=24), now)
        response = query_window_fn(
            config,
            cursor,
            window_end,
            config["query_size"],
            max_segments=min(MAX_QUERY_SEGMENTS, remaining_budget),
        )
        total_segments += int(response.get("query_segments") or 0)
        total_hits += int(response.get("hits_total") or 0)
        incoming.extend(response["observations"])
        covered_through = window_end
        if response.get("status") != "ok" or response.get("truncated"):
            incomplete = True
            error = "DHCP backfill coverage was incomplete"
            break
        cursor = window_end

    result = dict(state)
    result.update(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": format_timestamp(now),
            "observations": merge_fn(
                state,
                incoming,
                now,
                config["retention_days"],
            ),
        }
    )
    previous = (
        state.get("backfill")
        if isinstance(state.get("backfill"), dict)
        else {}
    )
    complete = not incomplete and covered_through >= now
    result["backfill"] = {
        "status": "ok" if complete else "partial",
        "last_attempt_at": format_timestamp(now),
        "last_success_at": (
            format_timestamp(now)
            if complete
            else str(previous.get("last_success_at") or "")
        ),
        "last_error": error,
        "requested_start": format_timestamp(requested_start),
        "requested_end": format_timestamp(now),
        "covered_through": format_timestamp(covered_through),
        "last_returned": len(
            {item["evidence_id"]: item for item in incoming}
        ),
        "last_hits_total": total_hits,
        "last_query_segments": total_segments,
    }
    return result


def collect(
    config: dict,
    state: dict,
    now: dt.datetime,
    *,
    collection_window_fn,
    query_window_fn,
    merge_fn,
) -> dict:
    start, end = collection_window_fn(
        state,
        now,
        config["query_window_minutes"],
    )
    response = query_window_fn(config, start, end, config["query_size"])
    observations = merge_fn(
        state,
        response["observations"],
        now,
        config["retention_days"],
    )
    result = dict(state)
    result.update(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": format_timestamp(now),
            "observations": observations,
        }
    )
    complete = response.get("status") == "ok" and not response.get("truncated")
    previous_success = str(
        state.get("collection", {}).get("last_success_at") or ""
    )
    result["collection"] = {
        "status": (
            "partial"
            if response.get("status") == "partial" or response.get("truncated")
            else "ok"
        ),
        "last_attempt_at": format_timestamp(now),
        "last_success_at": format_timestamp(now) if complete else previous_success,
        "last_error": (
            ""
            if complete
            else "DHCP query coverage was incomplete; checkpoint was not advanced"
        ),
        "last_window": response["window"],
        "last_returned": len(response["observations"]),
        "last_hits_total": int(response.get("hits_total") or 0),
        "last_truncated": bool(response.get("truncated")),
        "last_query_segments": int(response.get("query_segments") or 0),
    }
    return result
