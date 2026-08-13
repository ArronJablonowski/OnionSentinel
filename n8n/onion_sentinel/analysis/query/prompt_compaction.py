"""Model-safe row projection and trusted query-audit compaction."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from typing import Any, Callable

from . import primitives, prompt_facts


TEXT_LIMITS = {
    "query_id": 128,
    "dialect": 40,
    "backend": 40,
    "pack": 100,
    "purpose": 500,
    "aggregation": 40,
    "execution_backend": 100,
    "query_endpoint": 256,
    "endpoint": 256,
    "query_digest": 128,
    "result_digest": 128,
    "execution_digest": 128,
    "request_digest": 128,
    "item_digest": 128,
    "kql_digest": 128,
    "oql_digest": 128,
    "target_alias": 160,
    "operation": 80,
    "indicator": 253,
    "status": 40,
    "error": 500,
    "evidence_ref": 512,
}
NUMERIC_FIELDS = (
    "semantic_valid", "total_hits", "returned_hits", "total_rows",
    "returned_rows", "candidate_records_scanned", "unique_records_matched",
    "records_returned", "truncated", "result_truncated", "index_scan_truncated",
    "duration_ms", "timed_out", "took_ms",
)


@dataclass(frozen=True)
class Policy:
    maximum_rows: int


@dataclass(frozen=True)
class Dependencies:
    error_category: Callable[[Any], str]
    error_digest: Callable[[Any], str]


def _has_query_error(value: dict[str, Any]) -> bool:
    return bool(
        "error" in value
        and (
            "query_id" in value
            or ("status" in value and ("backend" in value or "read_only" in value))
        )
    )


def _project_list(
    value: list[Any],
    state: dict[str, int | bool],
    policy: Policy,
    dependencies: Dependencies,
) -> list[Any]:
    return [
        project_rows(item, state, policy=policy, dependencies=dependencies)
        for item in value
    ]


def _project_mapping(
    value: dict[str, Any],
    state: dict[str, int | bool],
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    has_error = _has_query_error(value)
    for raw_key, child in value.items():
        key = str(raw_key)
        if has_error and key.lower() in {"error", "error_digest", "error_sha256"}:
            continue
        if key.lower() in {"hits", "rows", "records"} and isinstance(child, list):
            remaining = max(0, policy.maximum_rows - int(state["rows"]))
            selected = child[:remaining]
            state["rows"] = int(state["rows"]) + len(selected)
            output[key] = _project_list(selected, state, policy, dependencies)
            if len(selected) < len(child):
                output[f"{key}_prompt_truncated"] = True
                state["truncated"] = True
            continue
        output[key] = project_rows(
            child, state, policy=policy, dependencies=dependencies
        )
    if has_error:
        output["error"] = dependencies.error_category(value.get("error"))
        output["error_sha256"] = dependencies.error_digest(value.get("error"))
    return output


def project_rows(
    value: Any, state: dict[str, int | bool], *, policy: Policy,
    dependencies: Dependencies,
) -> Any:
    """Copy broker evidence while enforcing one cumulative row budget."""
    if isinstance(value, list):
        return _project_list(value, state, policy, dependencies)
    if not isinstance(value, dict):
        return value
    return _project_mapping(value, state, policy, dependencies)


def _project_text(
    value: dict[str, Any], summary: dict[str, Any], dependencies: Dependencies,
) -> None:
    for key, limit in TEXT_LIMITS.items():
        if key not in value:
            continue
        if key == "error":
            summary[key] = dependencies.error_category(value.get(key))
            summary["error_sha256"] = dependencies.error_digest(value.get(key))
        else:
            summary[key] = primitives.text(value.get(key), limit)


def _project_numbers(value: dict[str, Any], summary: dict[str, Any]) -> None:
    for key in NUMERIC_FIELDS:
        item = value.get(key)
        finite = not (
            isinstance(item, float) and (math.isnan(item) or math.isinf(item))
        )
        if isinstance(item, (bool, int, float)) and finite:
            summary[key] = item


def _project_window(value: dict[str, Any], summary: dict[str, Any]) -> None:
    window = value.get("window")
    if isinstance(window, dict):
        summary["window"] = {
            key: primitives.text(window.get(key), 100)
            for key in ("start", "end")
            if window.get(key) not in (None, "")
        }


def compact_audit(value: Any, *, dependencies: Dependencies) -> dict[str, Any]:
    """Retain result-bound provenance and hash omitted audit representation."""
    encoded = prompt_facts.canonical_bytes(value)
    summary: dict[str, Any] = {
        "prompt_projection": "compacted_due_to_cumulative_byte_budget",
        "audit_bytes": len(encoded),
        "audit_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    if not isinstance(value, dict):
        summary["audit_type"] = type(value).__name__
        return summary
    _project_text(value, summary, dependencies)
    _project_numbers(value, summary)
    _project_window(value, summary)
    return summary
