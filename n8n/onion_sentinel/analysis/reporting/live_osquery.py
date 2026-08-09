"""Bounded public audit projection for live endpoint OSQuery evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    support_schema: str
    maximum_preview_rows: int = 100
    maximum_preview_bytes: int = 256 * 1024
    maximum_rows_per_query: int = 25
    maximum_columns_per_row: int = 64


@dataclass(frozen=True)
class Dependencies:
    bounded_text: Callable[[Any, int], str]
    safe_nonnegative_int: Callable[[Any], int]


@dataclass
class PreviewBudget:
    rows_remaining: int
    bytes_remaining: int
    truncated: bool = False


def _empty_audit() -> dict[str, Any]:
    return {
        "trusted_source": "restricted-elastic-osquery-manager-wrapper",
        "complete": False,
        "read_only": True,
        "queries": [],
        "error": "No endpoint live-host OSQuery batch was requested.",
    }


def _bounded_row(
    value: dict[str, Any],
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, str]:
    return {
        dependencies.bounded_text(key, 128): dependencies.bounded_text(item, 2000)
        for key, item in list(value.items())[:policy.maximum_columns_per_row]
    }


def _row_bytes(value: dict[str, str]) -> int:
    return len(json.dumps(
        value, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"))


def _preview_rows(
    source_rows: list[Any],
    budget: PreviewBudget,
    policy: Policy,
    dependencies: Dependencies,
) -> tuple[list[dict[str, str]], bool]:
    rows: list[dict[str, str]] = []
    query_truncated = False
    for raw in source_rows:
        if not isinstance(raw, dict):
            continue
        bounded = _bounded_row(raw, policy, dependencies)
        size = _row_bytes(bounded)
        if (
            len(rows) >= policy.maximum_rows_per_query
            or budget.rows_remaining <= 0
            or size > budget.bytes_remaining
        ):
            query_truncated = True
            budget.truncated = True
            break
        rows.append(bounded)
        budget.rows_remaining -= 1
        budget.bytes_remaining -= size
    if len(rows) < len(source_rows):
        query_truncated = True
        budget.truncated = True
    return rows, query_truncated


def _support_count(value: Any, policy: Policy) -> int:
    return len([
        item for item in value
        if isinstance(item, dict) and item.get("schema") == policy.support_schema
    ]) if isinstance(value, list) else 0


def _query_audit(
    result: dict[str, Any],
    budget: PreviewBudget,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    source_rows = result.get("rows")
    source_rows = source_rows if isinstance(source_rows, list) else []
    rows, truncated = _preview_rows(
        source_rows, budget, policy, dependencies
    )
    return {
        "target_alias": dependencies.bounded_text(result.get("target_alias"), 64),
        "status": dependencies.bounded_text(result.get("status"), 40),
        "purpose": dependencies.bounded_text(result.get("purpose"), 500),
        "query_digest": dependencies.bounded_text(result.get("query_digest"), 128),
        "query": dependencies.bounded_text(result.get("query"), 4096),
        "total_rows": dependencies.safe_nonnegative_int(result.get("total_rows")),
        "returned_rows": len(source_rows),
        "truncated": bool(result.get("truncated")),
        "duration_ms": dependencies.safe_nonnegative_int(result.get("duration_ms")),
        "rows_preview": rows,
        "rows_preview_truncated": truncated,
        "support_binding_count": _support_count(
            result.get("support_bindings"), policy
        ),
        "error": dependencies.bounded_text(result.get("error"), 1000),
    }


def _batch_counts(evidence: dict[str, Any]) -> tuple[list[Any], int, int]:
    batches = evidence.get("batches")
    batches = batches if isinstance(batches, list) else []
    valid = sum(
        1 for item in batches
        if isinstance(item, dict) and item.get("validated") is True
    )
    failed = sum(
        1 for item in batches
        if isinstance(item, dict) and item.get("validated") is not True
    )
    return batches, valid, failed


def audit(
    prompt_package: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Project the private accumulator into one bounded provenance audit."""
    evidence = prompt_package.get("_live_osquery_evidence_accumulator")
    if not isinstance(evidence, dict):
        evidence = prompt_package.get("live_osquery_evidence")
    if not isinstance(evidence, dict):
        return _empty_audit()
    budget = PreviewBudget(
        rows_remaining=policy.maximum_preview_rows,
        bytes_remaining=policy.maximum_preview_bytes,
    )
    results = evidence.get("results")
    queries = [
        _query_audit(item, budget, policy, dependencies)
        for item in results if isinstance(item, dict)
    ] if isinstance(results, list) else []
    batches, valid_batches, failed_batches = _batch_counts(evidence)
    writes = bool(evidence.get("control_plane_writes", True))
    return {
        "trusted_source": "restricted-elastic-osquery-manager-wrapper",
        "generated_at": dependencies.bounded_text(evidence.get("generated_at"), 100),
        "complete": bool(evidence.get("complete")),
        "read_only": bool(evidence.get("read_only", True)),
        "query_contract": dependencies.bounded_text(evidence.get("schema"), 200),
        "endpoint_read_only": bool(evidence.get("read_only", True)),
        "control_plane_writes": writes,
        "control_plane_write_status": dependencies.bounded_text(
            evidence.get("control_plane_write_status")
            or ("confirmed" if writes else "none"),
            20,
        ),
        "batches": len(batches),
        "validated_batches": valid_batches,
        "failed_batches": failed_batches,
        "preview_truncated": budget.truncated,
        "queries": queries,
        "error": dependencies.bounded_text(evidence.get("collection_error"), 1000),
    }
