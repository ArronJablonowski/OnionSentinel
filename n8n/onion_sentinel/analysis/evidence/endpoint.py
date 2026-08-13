"""Trust decisions for endpoint and live OSQuery evidence."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Callable, Type


@dataclass(frozen=True)
class Policy:
    live_schema: str
    support_schema: str
    success_statuses: frozenset[str]


@dataclass(frozen=True)
class Dependencies:
    normalize_live_query: Callable[[str], str]
    normalization_error: Type[Exception]


def _status(value: Any) -> str:
    return str(value or "").strip().lower()


def _completed_result(value: Any, policy: Policy) -> bool:
    return (
        isinstance(value, dict)
        and _status(value.get("status")) in policy.success_statuses
        and isinstance(value.get("rows"), list)
        and bool(value["rows"])
    )


def _support_metadata_matches(
    support: Any,
    result: dict[str, Any],
    digest: str,
    tables: set[str],
    policy: Policy,
) -> bool:
    return bool(
        isinstance(support, dict)
        and support.get("schema") == policy.support_schema
        and support.get("query_digest") == digest
        and support.get("target_alias") == result.get("target_alias")
        and support.get("source") == "trusted-investigation-context"
        and support.get("temporal_scope") == "collection_snapshot"
        and support.get("table") in tables
    )


def _valid_support_row_index(rows: Any, row_index: Any) -> bool:
    return (
        isinstance(row_index, int)
        and not isinstance(row_index, bool)
        and row_index >= 0
        and isinstance(rows, list)
        and row_index < len(rows)
    )


def _support_row_value(
    support: dict[str, Any],
    result: dict[str, Any],
) -> tuple[str, str] | None:
    rows = result.get("rows")
    row_index = support.get("row_index")
    column = str(support.get("column") or "")
    kind = str(support.get("observable_kind") or "")
    if (
        not _valid_support_row_index(rows, row_index)
        or not isinstance(rows[row_index], dict)
        or column not in rows[row_index]
        or kind not in {"ip", "port", "host", "domain", "user"}
    ):
        return None
    value = str(rows[row_index][column] or "").strip().rstrip(".")
    return kind, value.lower() if kind in {"host", "domain", "user"} else value


def _support_matches(
    support: Any,
    result: dict[str, Any],
    digest: str,
    tables: set[str],
    policy: Policy,
) -> bool:
    if not _support_metadata_matches(support, result, digest, tables, policy):
        return False
    bound = _support_row_value(support, result)
    if bound is None:
        return False
    kind, row_value = bound
    expected = hashlib.sha256(
        f"{kind}s\0{row_value}".encode("utf-8")
    ).hexdigest()
    return support.get("observable_digest") == expected


def _query_tables(query: str) -> set[str]:
    return {
        match.group(1).lower()
        for match in re.finditer(
            r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)",
            query,
            re.IGNORECASE,
        )
    }


def _relevant_live_result(
    value: Any,
    policy: Policy,
    dependencies: Dependencies,
) -> bool:
    if not _completed_result(value, policy):
        return False
    digest = str(value.get("query_digest") or "").strip().lower()
    query = str(value.get("query") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or not query:
        return False
    try:
        normalized = dependencies.normalize_live_query(query)
    except dependencies.normalization_error:
        return False
    if hashlib.sha256(normalized.encode("utf-8")).hexdigest() != digest:
        return False
    tables = _query_tables(query)
    supports = value.get("support_bindings")
    return isinstance(supports, list) and any(
        _support_matches(item, value, digest, tables, policy)
        for item in supports
    )


def _valid_live_batches(value: dict[str, Any], batches: Any, policy: Policy) -> bool:
    return (
        value.get("schema") == policy.live_schema
        and value.get("read_only") is True
        and isinstance(batches, list)
        and bool(batches)
        and all(
            isinstance(item, dict) and item.get("validated") is True
            for item in batches
        )
    )


def _live_accumulator_has_evidence(
    value: Any,
    policy: Policy,
    dependencies: Dependencies,
) -> bool:
    if not isinstance(value, dict):
        return False
    batches = value.get("batches")
    results = value.get("results")
    provenance_ok = _valid_live_batches(value, batches, policy)
    return bool(
        provenance_ok
        and value.get("complete") is True
        and isinstance(results, list)
        and any(_relevant_live_result(item, policy, dependencies) for item in results)
    )


def _endpoint_collection_has_evidence(value: Any, policy: Policy) -> bool:
    if isinstance(value, list):
        return any(_endpoint_collection_has_evidence(item, policy) for item in value)
    if not isinstance(value, dict):
        return False
    results = value.get("results")
    if isinstance(results, list) and any(
        _completed_result(item, policy) for item in results
    ):
        return True
    if _status(value.get("status")) not in policy.success_statuses:
        return False
    return any(
        isinstance(value.get(key), list) and bool(value[key])
        for key in ("rows", "findings", "observations", "artifacts", "processes")
    )


def has_trusted_evidence(
    prompt_package: dict[str, Any] | None,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> bool:
    """Return whether positive endpoint facts satisfy a trusted evidence path."""
    if not isinstance(prompt_package, dict):
        return False
    if _live_accumulator_has_evidence(
        prompt_package.get("_live_osquery_evidence_accumulator"),
        policy,
        dependencies,
    ):
        return True
    incident = prompt_package.get("incident_response_evidence")
    collections = [
        incident.get(key)
        for key in ("endpoint_evidence", "host_evidence", "osquery_evidence")
    ] if isinstance(incident, dict) else []
    collections.extend(
        prompt_package.get(key)
        for key in ("endpoint_evidence", "host_evidence", "osquery_evidence")
    )
    return any(_endpoint_collection_has_evidence(item, policy) for item in collections)


def _record_source_fields(source: Any, supplied: set[str]) -> None:
    if not isinstance(source, dict):
        return
    process = source.get("process")
    nested = process.get("executable") if isinstance(process, dict) else None
    direct = source.get("process.executable")
    if isinstance(nested, str) and nested.strip():
        supplied.add("process.executable")
    if isinstance(direct, str) and direct.strip():
        supplied.add("process.executable")


def _result_list(result: dict[str, Any], key: str) -> list[Any]:
    return result.get(key, []) if isinstance(result.get(key), list) else []


def _result_projection_blocked(result: dict[str, Any]) -> bool:
    return any(result.get(key) is True for key in (
        "truncated", "model_projection_truncated", "hits_prompt_truncated",
        "rows_prompt_truncated",
    )) or result.get("semantic_valid") is False


def _record_evidence_result_fields(
    result: Any,
    supplied: set[str],
    policy: Policy,
) -> None:
    if not isinstance(result, dict):
        return
    if _status(result.get("status")) not in policy.success_statuses:
        return
    if _result_projection_blocked(result):
        return
    for hit in _result_list(result, "hits"):
        if not isinstance(hit, dict):
            continue
        source = hit.get("_source")
        if not isinstance(source, dict):
            source = hit.get("source")
        _record_source_fields(source if isinstance(source, dict) else hit, supplied)
    for row in _result_list(result, "rows"):
        _record_source_fields(row, supplied)


def _record_round_result_fields(
    result: Any,
    supplied: set[str],
    policy: Policy,
) -> None:
    if (
        not isinstance(result, dict)
        or result.get("read_only") is not True
        or _status(result.get("status")) not in policy.success_statuses
    ):
        return
    evidence = result.get("evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("controls_valid") is False
        or evidence.get("partial") is True
        or evidence.get("complete") is False
    ):
        return
    evidence_results = evidence.get("results")
    if not isinstance(evidence_results, list):
        return
    for item in evidence_results:
        _record_evidence_result_fields(item, supplied, policy)


def trusted_fields(
    prompt_package: dict[str, Any] | None,
    *,
    policy: Policy,
) -> set[str]:
    """Return grounded endpoint fields present in complete read-only rows."""
    if not isinstance(prompt_package, dict):
        return set()
    iterative = prompt_package.get("investigation_query_results")
    rounds = iterative.get("rounds") if isinstance(iterative, dict) else None
    if not isinstance(rounds, list):
        return set()
    supplied: set[str] = set()
    for round_item in rounds:
        results = round_item.get("results") if isinstance(round_item, dict) else None
        if not isinstance(results, list):
            continue
        for result in results:
            _record_round_result_fields(result, supplied, policy)
    return supplied
