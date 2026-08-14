"""Canonical, bounded provenance ledger for governed investigation queries."""

from __future__ import annotations

import copy
import re
from typing import Any, Callable


SCHEMA = "onion-sentinel-query-ledger-v1"
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SUCCESS = frozenset({"ok", "complete", "completed", "success", "succeeded"})
_PARTIAL = frozenset({"partial", "incomplete"})
_AUTHORIZATION = frozenset({
    "blocked", "denied", "forbidden", "rejected", "unauthorized",
})
_FAILURES = {
    "timeout": "timeout",
    "timed_out": "timeout",
    "output_limit": "output_limit",
    "invalid_response": "invalid_response",
    "error": "transport_or_broker_error",
    "failed": "transport_or_broker_error",
    "failure": "transport_or_broker_error",
    "missing_result": "missing_result",
}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] \
        if isinstance(value, list) else []


def _query_ids(result: dict[str, Any]) -> list[str]:
    values = result.get("query_ids")
    if isinstance(values, list):
        return [str(item) for item in values if str(item)]
    return [str(result["query_id"])] if result.get("query_id") else []


def _results_by_id(results: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for result in results:
        for query_id in _query_ids(result):
            indexed[query_id] = result
    return indexed


def _entry_by_id(value: Any, query_id: str) -> dict[str, Any]:
    for item in _dict_list(value):
        if str(item.get("query_id") or "") == query_id:
            return item
    return {}


def _nested_result(result: dict[str, Any], query_id: str) -> dict[str, Any]:
    evidence = _dict(result.get("evidence"))
    return _entry_by_id(evidence.get("results"), query_id)


def _first(containers: tuple[dict[str, Any], ...], keys: tuple[str, ...]) -> Any:
    for container in containers:
        for key in keys:
            value = container.get(key)
            if value not in (None, ""):
                return value
    return None


def _first_text(
    containers: tuple[dict[str, Any], ...], keys: tuple[str, ...],
    default: str = "",
) -> str:
    value = _first(containers, keys)
    return str(value).strip() if value is not None else default


def _digest(value: Any) -> str:
    text = str(value or "").strip().lower()
    return text if _DIGEST.fullmatch(text) else ""


def _first_digest(
    containers: tuple[dict[str, Any], ...], key: str,
) -> str:
    for container in containers:
        value = _digest(container.get(key))
        if value:
            return value
    return ""


def _count(containers: tuple[dict[str, Any], ...]) -> int | None:
    keys = (
        "returned_hits", "returned_rows", "records_returned", "result_count",
        "total_hits", "total_rows",
    )
    for container in containers:
        for key in keys:
            value = container.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                return value
    return None


def _truncated(containers: tuple[dict[str, Any], ...]) -> bool | None:
    observed: list[bool] = []
    for container in containers:
        for key in (
            "truncated", "result_truncated", "index_scan_truncated",
            "model_projection_truncated",
        ):
            value = container.get(key)
            if isinstance(value, bool):
                observed.append(value)
    return any(observed) if observed else None


def _time_range(value: Any) -> dict[str, Any] | None:
    return copy.deepcopy(value) if isinstance(value, dict) else None


def _requested_range(request: dict[str, Any]) -> dict[str, Any] | None:
    normalization = _dict(request.get("normalization"))
    adjustment = _dict(normalization.get("window_adjustment"))
    return _time_range(
        adjustment.get("requested_window")
        or _dict(request.get("parameters")).get("window")
    )


def _actual_range(
    request: dict[str, Any], containers: tuple[dict[str, Any], ...],
) -> dict[str, Any] | None:
    observed = _first(containers, ("window", "actual_time_range"))
    if isinstance(observed, dict):
        return _time_range(observed)
    normalization = _dict(request.get("normalization"))
    adjustment = _dict(normalization.get("window_adjustment"))
    return _time_range(
        adjustment.get("executed_window")
        or _dict(request.get("parameters")).get("window")
    )


def _actual_for_status(
    status: str, request: dict[str, Any],
    containers: tuple[dict[str, Any], ...],
) -> dict[str, Any] | None:
    if status in _AUTHORIZATION or status == "missing_result":
        return None
    return _actual_range(request, containers)


def _failure_class(status: str, count: int | None, truncated: bool | None) -> str:
    if status in _SUCCESS:
        return "empty_evidence" if count == 0 and truncated is False else "none"
    if status in _PARTIAL:
        return "partial_evidence"
    if status in _AUTHORIZATION:
        return "authorization_denied"
    return _FAILURES.get(status, "broker_error")


def _round(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _maximum(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def _project(
    request: dict[str, Any], result: dict[str, Any], *, round_number: int,
    digest_json: Callable[[Any], str],
) -> dict[str, Any]:
    query_id = _first_text((request, result), ("query_id",))
    trusted = _entry_by_id(result.get("trusted_query_audit"), query_id)
    nested = _nested_result(result, query_id)
    evidence = _dict(result.get("evidence"))
    containers = (trusted, nested, evidence, result)
    status = _first_text(containers, ("status",), "missing_result").lower()
    count = _count(containers)
    truncated = _truncated(containers)
    normalized = copy.deepcopy(request)
    normalized_digest = digest_json(normalized)
    result_digest = _first_digest(containers, "result_digest")
    actual_range = _actual_for_status(status, request, containers)
    return {
        "schema": SCHEMA,
        "round": round_number,
        "query_id": query_id,
        "backend": _first_text((request, result), ("backend",)),
        "source": _first_text(
            containers + (result, request),
            ("execution_backend", "backend", "dialect"),
        ),
        "normalized_query": normalized,
        "normalized_query_digest": normalized_digest,
        "requested_time_range": _requested_range(request),
        "actual_time_range": actual_range,
        "result_count": count,
        "truncated": truncated,
        "query_digest": (
            _first_digest(containers, "query_digest") or normalized_digest
        ),
        "result_digest": result_digest or digest_json(result),
        "status": status,
        "failure_class": _failure_class(status, count, truncated),
        "read_only": result.get("read_only") is True,
    }


def entries(
    round_result: dict[str, Any], *, digest_json: Callable[[Any], str],
    maximum_entries: int,
) -> list[dict[str, Any]]:
    """Project one immutable, collector-bound ledger row per normalized query."""
    requests = _dict_list(round_result.get("requests"))
    results = _results_by_id(_dict_list(round_result.get("results")))
    round_number = _round(round_result.get("round"))
    projected: list[dict[str, Any]] = []
    for request in requests[:_maximum(maximum_entries)]:
        query_id = str(request.get("query_id") or "")
        if not query_id:
            continue
        projected.append(_project(
            request, results.get(query_id, {}), round_number=round_number,
            digest_json=digest_json,
        ))
    return projected
