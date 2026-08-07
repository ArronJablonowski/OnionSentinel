"""Deterministic logical-query outcomes and first-class evidence gaps."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Policy:
    success_statuses: frozenset[str]


@dataclass
class Ledger:
    counts: dict[str, int] = field(default_factory=lambda: {
        "successful_queries": 0,
        "partial_queries": 0,
        "rejected_queries": 0,
        "error_queries": 0,
        "timeout_queries": 0,
    })
    history: dict[str, list[str]] = field(default_factory=dict)
    adjusted_windows: int = 0

    def count(
        self,
        status: Any,
        policy: Policy,
        logical_queries: int = 1,
        *,
        query_id: str = "",
    ) -> None:
        normalized = _normalized(status)
        if query_id:
            self.history.setdefault(query_id, []).append(normalized)
        key = _count_key(normalized, policy)
        self.counts[key] += logical_queries


def _normalized(status: Any) -> str:
    return str(status or "").strip().lower()


def _count_key(status: str, policy: Policy) -> str:
    if status in policy.success_statuses:
        return "successful_queries"
    if status == "partial":
        return "partial_queries"
    if status == "rejected":
        return "rejected_queries"
    if status == "timeout":
        return "timeout_queries"
    return "error_queries"


def _logical_query_ids(result: dict[str, Any]) -> list[str]:
    query_ids = result.get("query_ids")
    if not isinstance(query_ids, list):
        return []
    return list(dict.fromkeys(
        str(item).strip() for item in query_ids if str(item).strip()
    ))


def _evidence(result: dict[str, Any]) -> dict[str, Any]:
    return result["evidence"] if isinstance(result.get("evidence"), dict) else {}


def _nested_results(evidence: dict[str, Any]) -> list[Any]:
    return evidence["results"] if isinstance(evidence.get("results"), list) else []


def _nested_status(
    nested: dict[str, Any], evidence: dict[str, Any], policy: Policy
) -> Any:
    status = nested.get("status")
    invalid_success = (
        _normalized(status) in policy.success_statuses
        and (
            evidence.get("controls_valid") is False
            or nested.get("semantic_valid") is False
        )
    )
    return "partial" if invalid_success else status


def _count_nested_results(
    ledger: Ledger,
    logical_ids: list[str],
    evidence: dict[str, Any],
    policy: Policy,
) -> set[str]:
    counted: set[str] = set()
    allowed = set(logical_ids)
    for nested in _nested_results(evidence):
        if not isinstance(nested, dict):
            continue
        query_id = str(nested.get("query_id") or "").strip()
        if query_id not in allowed or query_id in counted:
            continue
        ledger.count(
            _nested_status(nested, evidence, policy),
            policy,
            query_id=query_id,
        )
        counted.add(query_id)
    return counted


def _count_result(ledger: Ledger, result: Any, policy: Policy) -> None:
    if not isinstance(result, dict):
        ledger.count("error", policy)
        return
    logical_ids = _logical_query_ids(result)
    evidence = _evidence(result)
    counted = (
        _count_nested_results(ledger, logical_ids, evidence, policy)
        if logical_ids and _nested_results(evidence)
        else set()
    )
    remaining_ids = [query_id for query_id in logical_ids if query_id not in counted]
    if remaining_ids:
        for query_id in remaining_ids:
            ledger.count(result.get("status"), policy, query_id=query_id)
    elif not logical_ids:
        ledger.count(
            result.get("status"),
            policy,
            query_id=str(result.get("query_id") or "").strip(),
        )


def _round_adjusted_windows(round_item: dict[str, Any]) -> int:
    requests = round_item.get("requests")
    requests = requests if isinstance(requests, list) else []
    return sum(
        isinstance(request.get("normalization", {}).get("window_adjustment"), dict)
        for request in requests
        if isinstance(request, dict)
        and isinstance(request.get("normalization"), dict)
    )


def _consume_round(ledger: Ledger, round_item: Any, policy: Policy) -> None:
    if not isinstance(round_item, dict):
        return
    ledger.adjusted_windows += _round_adjusted_windows(round_item)
    results = round_item.get("results")
    for result in results if isinstance(results, list) else []:
        _count_result(ledger, result, policy)


def _resolved_retries(
    history: dict[str, list[str]], policy: Policy
) -> tuple[list[str], int]:
    query_ids = sorted(
        query_id
        for query_id, statuses in history.items()
        if statuses
        and statuses[-1] in policy.success_statuses
        and any(status not in policy.success_statuses for status in statuses[:-1])
    )
    resolved_attempts = sum(
        sum(status not in policy.success_statuses for status in history[query_id][:-1])
        for query_id in query_ids
    )
    return query_ids, resolved_attempts


def _evidence_gaps(
    *, zero_success: bool, unresolved: int, unreported: int, adjusted_windows: int
) -> list[str]:
    gaps = []
    if zero_success:
        gaps.append(
            "All requested iterative investigation pivots failed, timed out, "
            "or were rejected; no follow-up query evidence was collected."
        )
    elif unresolved or unreported:
        gaps.append(
            "One or more requested iterative investigation pivots did not "
            "return complete successful evidence."
        )
    if adjusted_windows:
        gaps.append(
            "One or more model-requested query windows were narrowed to the "
            "broker's 24-hour limit; omitted time remains an evidence gap."
        )
    return gaps


def summary(
    rounds: list[dict[str, Any]], *, queries_admitted: int, policy: Policy
) -> dict[str, Any]:
    """Count every logical query while preserving retry and gap semantics."""
    ledger = Ledger()
    for round_item in rounds:
        _consume_round(ledger, round_item, policy)
    counts: dict[str, Any] = dict(ledger.counts)
    accounted = sum(ledger.counts.values())
    unreported = max(0, int(queries_admitted) - accounted)
    zero_success = bool(queries_admitted and not counts["successful_queries"])
    resolved_ids, resolved_attempts = _resolved_retries(ledger.history, policy)
    non_success = sum(
        counts[key]
        for key in (
            "partial_queries", "rejected_queries", "error_queries", "timeout_queries"
        )
    )
    unresolved = max(0, non_success - resolved_attempts)
    counts.update({
        "unreported_queries": unreported,
        "queries_admitted": int(queries_admitted),
        "queries_accounted": accounted,
        "adjusted_windows": ledger.adjusted_windows,
        "zero_success": zero_success,
        "resolved_retry_query_ids": resolved_ids,
        "resolved_non_success_attempts": resolved_attempts,
        "unresolved_non_success_attempts": unresolved,
        "evidence_gaps": _evidence_gaps(
            zero_success=zero_success,
            unresolved=unresolved,
            unreported=unreported,
            adjusted_windows=ledger.adjusted_windows,
        ),
    })
    return counts


def append_evidence_gaps(response: dict[str, Any], gaps: list[str]) -> None:
    """Append deterministic gaps to top-level and report containers once."""
    for container in (response, response.get("incident_response_report")):
        if not isinstance(container, dict):
            continue
        existing = container.get("evidence_gaps")
        values = list(existing) if isinstance(existing, list) else []
        for gap in gaps:
            if gap not in values:
                values.append(gap)
        container["evidence_gaps"] = values[:100]
