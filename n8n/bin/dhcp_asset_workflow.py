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


def _validate_segment_budget(max_segments: int) -> None:
    if (
        isinstance(max_segments, bool)
        or not isinstance(max_segments, int)
        or not 1 <= max_segments <= MAX_BACKFILL_QUERY_SEGMENTS
    ):
        raise ValueError("DHCP query segment budget is invalid")


def _can_split_segment(
    response: dict,
    segment_length: dt.timedelta,
    queries: int,
    pending: list[tuple[dt.datetime, dt.datetime]],
    max_segments: int,
) -> bool:
    return (
        response.get("truncated") is True
        and segment_length > MIN_QUERY_SEGMENT
        and queries + len(pending) + 2 <= max_segments
    )


def _completed_query_segments(
    config: dict,
    start: dt.datetime,
    end: dt.datetime,
    size: int,
    max_segments: int,
    query_fn,
) -> tuple[list[dict], int, bool]:
    pending = [(start, end)]
    completed: list[dict] = []
    queries = 0
    incomplete = False
    while pending:
        segment_start, segment_end = pending.pop(0)
        response = query_fn(config, segment_start, segment_end, size)
        queries += 1
        segment_length = segment_end - segment_start
        if _can_split_segment(
            response, segment_length, queries, pending, max_segments
        ):
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
    return completed, queries, incomplete


def _reduced_observations(completed: list[dict]) -> list[dict]:
    unique: dict[str, dict] = {}
    for response in completed:
        for observation in response["observations"]:
            unique[observation["evidence_id"]] = observation
    return sorted(
        unique.values(),
        key=lambda item: (item["observed_at"], item["evidence_id"]),
    )


def _complete_window_result(
    start: dt.datetime,
    end: dt.datetime,
    completed: list[dict],
    observations: list[dict],
    queries: int,
    incomplete: bool,
) -> dict:
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
    _validate_segment_budget(max_segments)
    completed, queries, incomplete = _completed_query_segments(
        config, start, end, size, max_segments, query_fn
    )
    observations = _reduced_observations(completed)
    return _complete_window_result(
        start, end, completed, observations, queries, incomplete
    )


def _backfill_windows(
    config: dict,
    requested_start: dt.datetime,
    now: dt.datetime,
    query_window_fn,
) -> dict:
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
    return {
        "covered_through": covered_through,
        "incoming": incoming,
        "total_hits": total_hits,
        "total_segments": total_segments,
        "incomplete": incomplete,
        "error": error,
    }


def _state_result(state: dict, now: dt.datetime, observations: list[dict]) -> dict:
    result = dict(state)
    result.update(
        {
            "schema": STATE_SCHEMA,
            "version": 1,
            "updated_at": format_timestamp(now),
            "observations": observations,
        }
    )
    return result


def _previous_backfill(state: dict) -> dict:
    return (
        state.get("backfill")
        if isinstance(state.get("backfill"), dict)
        else {}
    )


def _backfill_status(
    state: dict,
    now: dt.datetime,
    requested_start: dt.datetime,
    progress: dict,
) -> dict:
    previous = _previous_backfill(state)
    complete = not progress["incomplete"] and progress["covered_through"] >= now
    return {
        "status": "ok" if complete else "partial",
        "last_attempt_at": format_timestamp(now),
        "last_success_at": (
            format_timestamp(now)
            if complete
            else str(previous.get("last_success_at") or "")
        ),
        "last_error": progress["error"],
        "requested_start": format_timestamp(requested_start),
        "requested_end": format_timestamp(now),
        "covered_through": format_timestamp(progress["covered_through"]),
        "last_returned": len(
            {item["evidence_id"]: item for item in progress["incoming"]}
        ),
        "last_hits_total": progress["total_hits"],
        "last_query_segments": progress["total_segments"],
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
    progress = _backfill_windows(config, requested_start, now, query_window_fn)
    result = _state_result(
        state,
        now,
        merge_fn(
            state,
            progress["incoming"],
            now,
            config["retention_days"],
        ),
    )
    result["backfill"] = _backfill_status(state, now, requested_start, progress)
    return result


def _collection_status(state: dict, response: dict, now: dt.datetime) -> dict:
    complete = response.get("status") == "ok" and not response.get("truncated")
    previous_success = str(
        state.get("collection", {}).get("last_success_at") or ""
    )
    return {
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
    result = _state_result(state, now, observations)
    result["collection"] = _collection_status(state, response, now)
    return result
