#!/usr/bin/env python3
"""Project terminal tool outcomes and collector-owned control events."""
from __future__ import annotations

import collections
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping


@dataclass(frozen=True)
class TraceEventPolicy:
    success_statuses: frozenset[str]
    rejection_statuses: frozenset[str]
    gap_coverage: frozenset[str]
    normalize_status: Callable[[object], str]
    nonnegative_int: Callable[[object], int]
    safe_json: Callable[..., Any]


def tool_query_id(
    row: Mapping[str, Any], policy: TraceEventPolicy
) -> str:
    """Return the logical query identity encoded in a collector call ID."""
    call_id = str(row.get("call_id") or "")
    round_number = policy.nonnegative_int(row.get("round_number"))
    prefix = f"round-{round_number}-"
    return call_id[len(prefix) :] if call_id.startswith(prefix) else ""


def unresolved_tool_coverage_gaps(
    tool_calls: Iterable[Mapping[str, Any]],
    policy: TraceEventPolicy,
) -> list[str]:
    """Grade the terminal outcome of each logical query without hiding retries."""
    ordered = sorted(
        tool_calls,
        key=lambda row: (
            policy.nonnegative_int(row.get("round_number")),
            str(row.get("call_id") or ""),
        ),
    )
    terminal: dict[str, Mapping[str, Any]] = {}
    unresolved: list[str] = []
    for row in ordered:
        query_id = tool_query_id(row, policy)
        if query_id:
            terminal[query_id] = row
        elif _is_standalone_gap(row, policy):
            unresolved.append(str(row.get("call_id") or ""))
    unresolved.extend(
        str(row.get("call_id") or "")
        for row in terminal.values()
        if _is_terminal_gap(row, policy)
    )
    return unresolved


def _is_standalone_gap(
    row: Mapping[str, Any], policy: TraceEventPolicy
) -> bool:
    coverage = policy.normalize_status(row.get("coverage"))
    status = policy.normalize_status(row.get("status"))
    return coverage in policy.gap_coverage or status not in (
        policy.success_statuses | policy.rejection_statuses
    )


def _is_terminal_gap(
    row: Mapping[str, Any], policy: TraceEventPolicy
) -> bool:
    coverage = policy.normalize_status(row.get("coverage"))
    status = policy.normalize_status(row.get("status"))
    return coverage in policy.gap_coverage or status not in policy.success_statuses


def terminal_execution_summary(
    events: Iterable[Mapping[str, Any]],
    run_status: object,
    malformed: collections.Counter[str],
    policy: TraceEventPolicy,
) -> dict[str, Any]:
    """Project safe collector-owned completion controls without response content."""
    normalized = policy.normalize_status(run_status)
    terminal = next(
        (
            event
            for event in reversed(list(events))
            if str(event.get("event_type") or "") == f"run.{normalized}"
        ),
        None,
    )
    if terminal is None:
        return {}
    payload = policy.safe_json(
        terminal.get("payload_json"), {}, malformed, "event.terminal.payload_json"
    )
    summary = payload.get("summary")
    if not isinstance(summary, dict):
        return {}
    return _safe_terminal_fields(summary)


def _safe_terminal_fields(summary: Mapping[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for field in (
        "analysis_id",
        "submitted_response_sha256",
        "stored_response_sha256",
        "evaluation_memory_frozen",
    ):
        value = summary.get(field)
        if isinstance(value, (str, int, float, bool, type(None))):
            output[field] = value
    return output


def budget_operation_id(
    event: Mapping[str, Any], payload: Mapping[str, Any]
) -> str:
    """Return a stable operation identity across preflight and legacy events."""
    event_type = str(event.get("event_type") or "")
    idempotency_key = str(event.get("idempotency_key") or "")
    if event_type == "policy.budget":
        return _policy_budget_operation(event, payload, idempotency_key)
    if event_type == "queries.completed":
        return _completed_query_operation(event, payload, idempotency_key)
    return _fallback_operation(event_type, event)


def _policy_budget_operation(
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
    idempotency_key: str,
) -> str:
    if payload.get("operation_id"):
        return str(payload["operation_id"])
    encoded = _prefixed_value(idempotency_key, "policy.budget:")
    if encoded:
        return _decoded_policy_operation(encoded)
    observed = payload.get("observed")
    observed_operation = _observed_operation(observed)
    if observed_operation:
        return observed_operation
    operation = str(payload.get("operation") or "budget-preflight")
    return f"{operation}:{event.get('sequence') or 'unknown'}"


def _decoded_policy_operation(encoded: str) -> str:
    operation_id, separator, decision_digest = encoded.rpartition(":")
    if separator and operation_id and _is_decision_digest(decision_digest):
        return operation_id
    return encoded


def _is_decision_digest(value: str) -> bool:
    return len(value) == 24 and all(
        character in "0123456789abcdef" for character in value
    )


def _observed_operation(observed: object) -> str:
    if not isinstance(observed, dict):
        return ""
    if observed.get("call_id"):
        return f"model:{observed['call_id']}"
    if observed.get("round") is not None:
        return f"query-round:{observed['round']}"
    return ""


def _completed_query_operation(
    event: Mapping[str, Any],
    payload: Mapping[str, Any],
    idempotency_key: str,
) -> str:
    if payload.get("round") is not None:
        return f"query-round:{payload['round']}"
    encoded = _prefixed_value(idempotency_key, "queries.completed:")
    if encoded:
        return f"query-round:{encoded}"
    return _fallback_operation("queries.completed", event)


def _prefixed_value(value: str, prefix: str) -> str:
    return value[len(prefix) :] if value.startswith(prefix) else ""


def _fallback_operation(event_type: str, event: Mapping[str, Any]) -> str:
    return f"{event_type or 'budget'}:{event.get('sequence') or 'unknown'}"
