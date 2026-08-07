"""Durable round audit and exact request/result tool-call bindings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from . import primitives


@dataclass(frozen=True)
class Policy:
    maximum_queries_per_round: int
    success_statuses: frozenset[str]
    nonexecution_statuses: frozenset[str]


@dataclass(frozen=True)
class Dependencies:
    digest_json: Callable[[Any], str]
    resolve_binding: Callable[[dict[str, Any], str], tuple[str, Any]]


def _round_number(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _result_ids(item: dict[str, Any]) -> list[str]:
    if isinstance(item.get("query_ids"), list):
        return [str(value) for value in item["query_ids"]]
    return [str(item["query_id"])] if item.get("query_id") else []


def _request_result_maps(
    round_result: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    requests = round_result.get("requests") if isinstance(round_result.get("requests"), list) else []
    results = round_result.get("results") if isinstance(round_result.get("results"), list) else []
    request_by_id = {
        str(item.get("query_id")): item
        for item in requests
        if isinstance(item, dict) and item.get("query_id")
    }
    result_by_id: dict[str, dict[str, Any]] = {}
    for item in results:
        if isinstance(item, dict):
            for query_id in _result_ids(item):
                result_by_id[query_id] = item
    for query_id, result in result_by_id.items():
        if query_id not in request_by_id:
            request_by_id[query_id] = {
                "query_id": query_id,
                "backend": result.get("backend"),
                "purpose": result.get("purpose") or "proposal rejected before execution",
                "rejected_before_execution": True,
            }
    return request_by_id, result_by_id


def tool_call_bindings(
    round_result: dict[str, Any], *, policy: Policy, dependencies: Dependencies,
) -> list[dict[str, Any]]:
    """Bind compact response audit rows to exact collector-owned tool rows."""
    round_number = _round_number(round_result.get("round"))
    requests, results = _request_result_maps(round_result)
    bindings = []
    for query_id, request in requests.items():
        result = results.get(query_id, {})
        backend = str(request.get("backend") or result.get("backend") or "")
        status, _observation = dependencies.resolve_binding(result, query_id)
        bindings.append({
            "call_id": f"round-{round_number}-{query_id}"[:128],
            "round": round_number,
            "round_number": round_number,
            "query_id": query_id[:128],
            "backend": backend[:80],
            "status": status[:40],
            "normalized_status": status.strip().lower()[:40],
            "request_digest": dependencies.digest_json(request),
            "result_digest": dependencies.digest_json(result),
            "read_only": result.get("read_only") is True,
        })
    return bindings[: policy.maximum_queries_per_round * 2]


def _status_history(bindings: list[dict[str, Any]]) -> dict[str, list[str]]:
    history: dict[str, list[str]] = {}
    for item in bindings:
        query_id = str(item.get("query_id") or "").strip()
        if query_id:
            history.setdefault(query_id, []).append(
                str(item.get("normalized_status") or "").strip().lower()
            )
    return history


def _normalized_status(item: dict[str, Any]) -> str:
    return str(item.get("normalized_status") or "").strip().lower()


def _executed_bindings(
    bindings: list[dict[str, Any]], policy: Policy
) -> list[dict[str, Any]]:
    return [
        item
        for item in bindings
        if _normalized_status(item) not in policy.nonexecution_statuses
    ]


def _successful_read_only_bindings(
    bindings: list[dict[str, Any]], policy: Policy
) -> list[dict[str, Any]]:
    return [
        item
        for item in bindings
        if item.get("read_only") is True
        and _normalized_status(item) in policy.success_statuses
    ]


def _all_read_only(bindings: list[dict[str, Any]]) -> bool:
    return bool(bindings) and all(item.get("read_only") is True for item in bindings)


def _terminal_success(bindings: list[dict[str, Any]], policy: Policy) -> bool:
    history = _status_history(bindings)
    return bool(history) and all(
        statuses and statuses[-1] in policy.success_statuses
        for statuses in history.values()
    )


def binding_summary(
    bindings: list[dict[str, Any]], *, queries_admitted: int, policy: Policy,
) -> dict[str, Any]:
    """Summarize collector-bound read-only execution without model assertions."""
    executed = _executed_bindings(bindings, policy)
    successful_read_only = _successful_read_only_bindings(bindings, policy)
    all_read_only = _all_read_only(bindings)
    executed_read_only = _all_read_only(executed)
    complete = bool(
        bindings
        and all_read_only
        and _terminal_success(bindings, policy)
        and len(bindings) >= max(1, int(queries_admitted))
    )
    return {
        "read_only": executed_read_only,
        "all_tool_call_bindings_read_only": all_read_only,
        "successful_read_only_queries": len(successful_read_only),
        "complete": complete,
        "evaluation_requirement_satisfied": bool(successful_read_only) and all_read_only,
    }


def _result_summary(item: dict[str, Any]) -> dict[str, Any]:
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    return {
        "query_id": primitives.text(item.get("query_id"), 64),
        "query_ids": item.get("query_ids") if isinstance(item.get("query_ids"), list) else [],
        "backend": primitives.text(item.get("backend"), 40),
        "status": primitives.text(item.get("status"), 40),
        "query_digest": primitives.text(evidence.get("query_digest"), 128),
        "error": primitives.text(item.get("error"), 500),
    }


def _normalizations(round_result: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    requests = round_result.get("requests") if isinstance(round_result.get("requests"), list) else []
    return [
        {"query_id": primitives.text(item.get("query_id"), 64), "normalization": item["normalization"]}
        for item in requests
        if isinstance(item, dict)
        and isinstance(item.get("normalization"), dict)
        and item["normalization"]
    ][:limit]


def round_audit(
    round_result: dict[str, Any], *, policy: Policy, dependencies: Dependencies,
) -> dict[str, Any]:
    results = round_result.get("results", [])
    results = results if isinstance(results, list) else []
    valid_results = [item for item in results if isinstance(item, dict)]
    trusted = [
        entry
        for item in valid_results
        for entry in (
            item.get("trusted_query_audit")
            if isinstance(item.get("trusted_query_audit"), list)
            else []
        )
        if isinstance(entry, dict)
    ]
    return {
        "round": round_result.get("round"),
        "request_count": len(round_result.get("requests") or []),
        "results": [_result_summary(item) for item in valid_results],
        "trusted_queries": trusted[: policy.maximum_queries_per_round],
        "tool_call_bindings": tool_call_bindings(
            round_result, policy=policy, dependencies=dependencies
        ),
        "broker_audit": round_result.get("audit") or [],
        "request_normalizations": _normalizations(
            round_result, policy.maximum_queries_per_round
        ),
    }
