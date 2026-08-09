"""Fail-closed decoder for compact investigation provenance envelopes."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Callable, Protocol


class ReferenceSink(Protocol):
    def add(self, reference: Any, **kwargs: Any) -> None: ...


@dataclass(frozen=True)
class Policy:
    result_schema: str
    provenance_schema: str
    columns: tuple[str, ...]
    empty_ref_instruction: str
    success_statuses: frozenset[str]
    maximum_queries: int
    maximum_rounds: int


@dataclass(frozen=True)
class Dependencies:
    prompt_json_bytes: Callable[[Any], bytes]
    canonical_count: Callable[[Any], int | None]
    result_bound_reference: Callable[..., tuple[str, str]]


ENVELOPE_KEYS = frozenset({"schema", "rounds", "prompt_projection"})
PROJECTION_KEYS = frozenset({
    "max_bytes", "truncated", "columnar_provenance_fallback", "encoded_bytes",
})
ROUND_KEYS = frozenset({
    "schema", "prompt_projection", "source_bytes", "source_sha256",
    "source_provenance_rows", "columns", "backend_values", "status_values",
    "semantics_values", "result_summary_values", "empty_evidence_ref", "rows",
    "omitted_rows",
})
TABLE_LIMITS = {
    "backend_values": 40,
    "status_values": 40,
    "semantics_values": 1024,
    "result_summary_values": 256,
}


def _canonical_integer(raw: Any, *, minimum: int = 0) -> int | None:
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw if raw >= minimum else None


def _claimed_parts(
    value: Any, policy: Policy,
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    if not isinstance(value, dict):
        return False, None, None
    projection = value.get("prompt_projection")
    claimed = isinstance(projection, dict) and (
        projection.get("columnar_provenance_fallback") is True
    )
    if not claimed:
        return False, None, None
    rounds = value.get("rounds")
    valid = all((
        set(value) == ENVELOPE_KEYS,
        value.get("schema") == policy.result_schema,
        isinstance(rounds, list),
        isinstance(rounds, list) and len(rounds) == 1,
        isinstance(rounds, list) and len(rounds) == 1 and isinstance(rounds[0], dict),
        set(projection) == PROJECTION_KEYS,
        projection.get("truncated") is True,
    ))
    return (True, projection, rounds[0]) if valid else (True, None, None)


def _round_shape_valid(round_item: dict[str, Any], policy: Policy) -> bool:
    return bool(
        set(round_item) == ROUND_KEYS
        and round_item.get("schema") == policy.provenance_schema
        and round_item.get("prompt_projection")
        == "columnar_provenance_due_to_cumulative_byte_budget"
        and round_item.get("columns") == list(policy.columns)
        and round_item.get("empty_evidence_ref") == policy.empty_ref_instruction
    )


def _metadata_valid(
    value: dict[str, Any], projection: dict[str, Any],
    round_item: dict[str, Any], policy: Policy, deps: Dependencies,
) -> bool:
    maximum_bytes = _canonical_integer(projection.get("max_bytes"), minimum=1)
    encoded_bytes = _canonical_integer(projection.get("encoded_bytes"), minimum=1)
    source_bytes = _canonical_integer(round_item.get("source_bytes"))
    source_rows = _canonical_integer(round_item.get("source_provenance_rows"), minimum=1)
    omitted_rows = _canonical_integer(round_item.get("omitted_rows"))
    try:
        encoded_value = len(deps.prompt_json_bytes(value))
    except (TypeError, ValueError, OverflowError):
        return False
    rows = round_item.get("rows")
    return all((
        maximum_bytes is not None,
        encoded_bytes == encoded_value,
        maximum_bytes is not None and encoded_value <= maximum_bytes,
        source_bytes is not None,
        source_rows is not None,
        omitted_rows == 0,
        isinstance(round_item.get("source_sha256"), str),
        bool(re.fullmatch(r"[a-f0-9]{64}", round_item.get("source_sha256") or "")),
        isinstance(rows, list),
        bool(rows),
        isinstance(rows, list) and len(rows) == source_rows,
        isinstance(rows, list) and len(rows) <= policy.maximum_queries,
    ))


def _tables(
    round_item: dict[str, Any], maximum_queries: int,
) -> dict[str, list[str]] | None:
    result: dict[str, list[str]] = {}
    for name, maximum_bytes in TABLE_LIMITS.items():
        table = round_item.get(name)
        valid = (
            isinstance(table, list) and bool(table) and len(table) <= maximum_queries
            and all(
                isinstance(item, str) and bool(item)
                and len(item.encode("utf-8")) <= maximum_bytes
                for item in table
            )
        )
        if not valid:
            return None
        result[name] = table
    return result


def _table_value(tables: dict[str, list[str]], name: str, index: Any) -> str | None:
    if isinstance(index, bool) or not isinstance(index, int):
        return None
    table = tables[name]
    return table[index] if 0 <= index < len(table) else None


def _identity_valid(
    item: dict[str, Any], round_number: int | None,
    values: list[str | None], policy: Policy,
) -> bool:
    query_id = item.get("query_id")
    return bool(
        round_number is not None and round_number <= policy.maximum_rounds
        and isinstance(query_id, str)
        and re.fullmatch(r"[A-Za-z0-9_.:@+=-]{1,128}", query_id)
        and all(values)
    )


def _digests_valid(item: dict[str, Any]) -> bool:
    query_digest = item.get("query_digest")
    result_digest = item.get("result_digest")
    return bool(
        isinstance(query_digest, str)
        and re.fullmatch(r"[a-f0-9]{64}", query_digest)
        and isinstance(result_digest, str)
        and (
            not result_digest
            or re.fullmatch(r"[a-f0-9]{64}", result_digest)
        )
    )


def _reference_fields_valid(item: dict[str, Any]) -> bool:
    evidence_ref = item.get("evidence_ref_or_empty")
    return bool(
        isinstance(evidence_ref, str)
        and len(evidence_ref.encode("utf-8")) <= 512
        and isinstance(item.get("read_only"), bool)
    )


def _decode_row(
    row: Any, tables: dict[str, list[str]], policy: Policy, deps: Dependencies,
) -> dict[str, Any] | None:
    if not isinstance(row, list) or len(row) != len(policy.columns):
        return None
    item = dict(zip(policy.columns, row))
    round_number = _canonical_integer(item.get("round"), minimum=1)
    query_id = item.get("query_id")
    values = [
        _table_value(tables, "backend_values", item.get("backend_index")),
        _table_value(tables, "status_values", item.get("status_index")),
        _table_value(tables, "semantics_values", item.get("semantics_index")),
        _table_value(tables, "result_summary_values", item.get("result_summary_index")),
    ]
    if not all((
        _identity_valid(item, round_number, values, policy),
        _digests_valid(item),
        _reference_fields_valid(item),
    )):
        return None
    query_digest = item["query_digest"]
    result_digest = item["result_digest"]
    evidence_ref = item["evidence_ref_or_empty"]
    canonical_ref, evidence_digest = deps.result_bound_reference(
        query_digest, result_digest
    )
    evidence_ref = canonical_ref if not evidence_ref or evidence_ref.startswith("query:") else evidence_ref
    if not evidence_ref:
        return None
    returned = deps.canonical_count(item.get("returned"))
    status = values[1]
    if item["read_only"] is not True:
        status = "read_only_violation"
    elif returned is None:
        status = "invalid_result_count"
    return {
        "query_id": query_id, "status": status, "returned": returned,
        "query_digest": query_digest, "result_digest": result_digest,
        "evidence_ref": evidence_ref, "evidence_digest": evidence_digest,
    }


def _register(item: dict[str, Any], sink: ReferenceSink, policy: Policy, deps: Dependencies) -> None:
    common = {
        "source": "investigation_query_results.rounds.columnar_provenance",
        "source_class": "investigation_query_results",
        "corroborating": str(item["status"]).lower() in policy.success_statuses,
        "status": item["status"], "returned": item["returned"],
        "evidence_digest": item["evidence_digest"], "require_valid_count": True,
    }
    query_ref, _ = deps.result_bound_reference(item["query_digest"], item["result_digest"])
    sink.add(query_ref, **common)
    sink.add(item["evidence_ref"], **common)
    query_id_ref, _ = deps.result_bound_reference(
        item["query_digest"], item["result_digest"],
        namespace="query-id", label=item["query_id"],
    )
    sink.add(query_id_ref, **common)


def _decode_rows(
    rows: list[Any], tables: dict[str, list[str]],
    policy: Policy, deps: Dependencies,
) -> list[dict[str, Any]] | None:
    decoded = [_decode_row(row, tables, policy, deps) for row in rows]
    if any(item is None for item in decoded):
        return None
    return [item for item in decoded if item is not None]


def process(value: Any, sink: ReferenceSink, policy: Policy, deps: Dependencies) -> bool:
    """Decode a top-level compact claim; malformed claims remain inert and consumed."""
    claimed, projection, round_item = _claimed_parts(value, policy)
    if not claimed:
        return False
    if projection is None or round_item is None or not _round_shape_valid(round_item, policy):
        return True
    if not _metadata_valid(value, projection, round_item, policy, deps):
        return True
    tables = _tables(round_item, policy.maximum_queries)
    if tables is None:
        return True
    decoded = _decode_rows(round_item["rows"], tables, policy, deps)
    if decoded is None:
        return True
    for item in decoded:
        _register(item, sink, policy, deps)
    return True


def exact_hosted_envelope(
    value: Any,
    *,
    require_encoded_accounting: bool,
    policy: Policy,
    deps: Dependencies,
) -> bool:
    """Recognize only a complete runtime-owned top-level hosted envelope."""
    parts = _exact_hosted_parts(value, policy)
    if parts is None:
        return False
    projection, round_item = parts
    if not _exact_hosted_metadata(round_item, projection):
        return False
    tables = _tables(round_item, policy.maximum_queries)
    rows = round_item.get("rows")
    if tables is None or not _exact_hosted_rows(rows, round_item, policy, deps, tables):
        return False
    if require_encoded_accounting:
        return _exact_encoded_accounting(value, projection, deps)
    return True


def _exact_hosted_parts(
    value: Any, policy: Policy,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not isinstance(value, dict) or set(value) != ENVELOPE_KEYS:
        return None
    projection = value.get("prompt_projection")
    if not _exact_projection_shape(projection):
        return None
    round_item = _single_round(value.get("rounds"))
    if (
        value.get("schema") != policy.result_schema
        or round_item is None
        or not _round_shape_valid(round_item, policy)
    ):
        return None
    return projection, round_item


def _exact_projection_shape(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == PROJECTION_KEYS
        and value.get("truncated") is True
        and value.get("columnar_provenance_fallback") is True
    )


def _single_round(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, list) or len(value) != 1:
        return None
    return value[0] if isinstance(value[0], dict) else None


def _exact_hosted_metadata(
    round_item: dict[str, Any], projection: dict[str, Any]
) -> bool:
    maximum_bytes = _canonical_integer(projection.get("max_bytes"), minimum=1)
    encoded_bytes = _canonical_integer(projection.get("encoded_bytes"), minimum=1)
    source_bytes = _canonical_integer(round_item.get("source_bytes"))
    source_rows = _canonical_integer(
        round_item.get("source_provenance_rows"), minimum=1
    )
    omitted = _canonical_integer(round_item.get("omitted_rows"))
    source_digest = round_item.get("source_sha256")
    return bool(
        maximum_bytes is not None
        and encoded_bytes is not None
        and source_bytes is not None
        and source_rows is not None
        and omitted == 0
        and isinstance(source_digest, str)
        and re.fullmatch(r"[a-f0-9]{64}", source_digest)
    )


def _exact_hosted_rows(
    rows: Any,
    round_item: dict[str, Any],
    policy: Policy,
    deps: Dependencies,
    tables: dict[str, list[str]],
) -> bool:
    if (
        not isinstance(rows, list)
        or not rows
        or len(rows) != round_item["source_provenance_rows"]
        or len(rows) > policy.maximum_queries
    ):
        return False
    return all(_exact_hosted_row(row, policy, deps, tables) for row in rows)


def _exact_hosted_row(
    row: Any,
    policy: Policy,
    deps: Dependencies,
    tables: dict[str, list[str]],
) -> bool:
    if not isinstance(row, list) or len(row) != len(policy.columns):
        return False
    item = dict(zip(policy.columns, row))
    indexes = {
        "backend_values": item.get("backend_index"),
        "status_values": item.get("status_index"),
        "semantics_values": item.get("semantics_index"),
        "result_summary_values": item.get("result_summary_index"),
    }
    return all((
        _exact_round_and_query(item, policy),
        _digests_valid(item),
        _reference_fields_valid(item),
        _exact_returned_count(item.get("returned"), deps),
        all(_table_value(tables, name, index) is not None for name, index in indexes.items()),
    ))


def _exact_round_and_query(item: dict[str, Any], policy: Policy) -> bool:
    round_number = _canonical_integer(item.get("round"), minimum=1)
    query_id = item.get("query_id")
    return bool(
        round_number is not None
        and round_number <= policy.maximum_rounds
        and isinstance(query_id, str)
        and re.fullmatch(r"[A-Za-z0-9_.:@+=-]{1,128}", query_id)
    )


def _exact_returned_count(value: Any, deps: Dependencies) -> bool:
    return value is None or deps.canonical_count(value) is not None


def _exact_encoded_accounting(
    value: Any,
    projection: dict[str, Any],
    deps: Dependencies,
) -> bool:
    try:
        actual_bytes = len(deps.prompt_json_bytes(value))
    except (TypeError, ValueError, OverflowError):
        return False
    return bool(
        projection.get("encoded_bytes") == actual_bytes
        and actual_bytes <= projection["max_bytes"]
    )
