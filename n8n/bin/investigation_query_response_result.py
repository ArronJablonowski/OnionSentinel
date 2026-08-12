"""Coverage and per-pivot result validation for investigation responses."""
from __future__ import annotations

import hashlib
from typing import Any

from investigation_query_schema import (
    ALLOWED_STATUSES,
    PACKS,
    SAFE_ELASTIC_ID_RE,
    InvestigationQueryContractError,
)
from investigation_query_normalization import _index_matches_scope, _require_mapping
from investigation_query_rendering import (
    _expected_execution_digest,
    build_query_dsl,
    canonical_digest,
    kql_equivalent,
    oql_equivalent,
    query_endpoint,
)
from investigation_query_response_source import _validate_hit_source


def result_coverage(
    query: dict[str, Any],
    *,
    status: str,
    total_hits: int,
    total_hits_relation: str,
    returned_hits: int,
) -> dict[str, Any]:
    """Describe bounded evidence coverage without treating zero as absence."""
    exact_total = status == "ok" and total_hits_relation == "eq"
    if status != "ok":
        coverage_status = "partial"
        interpretation = "query_execution_incomplete"
    elif not exact_total:
        coverage_status = "partial"
        interpretation = "lower_bound_only"
    elif query["aggregation"] == "count":
        coverage_status = "exact_aggregate"
        interpretation = "exact_count_for_authorized_filter_and_window"
    elif total_hits == 0:
        coverage_status = "exact_zero"
        interpretation = "no_matching_documents_for_authorized_filter_and_window"
    elif returned_hits < total_hits:
        coverage_status = "bounded_sample"
        interpretation = "sample_only_not_complete_event_set"
    else:
        coverage_status = "complete_events"
        interpretation = "complete_matching_event_set"
    strategy = {
        "events": "newest_first",
        "timeline": "chronological",
        "anchor_nearest": "anchor_nearest",
        "count": "exact_count",
    }[query["aggregation"]]
    return {
        "coverage_status": coverage_status,
        "match_semantics": query["match_semantics"],
        "sample_strategy": strategy,
        "scope": "authorized_exact_filters_and_time_window",
        "exact_total_hits": exact_total,
        "zero_hits": exact_total and total_hits == 0,
        "event_bodies_complete": (
            exact_total
            and query["aggregation"] != "count"
            and returned_hits == total_hits
        ),
        "interpretation": interpretation,
    }


def _validate_result_binding(
    value: dict[str, Any], expected_query: dict[str, Any]
) -> None:
    for field in (
        "query_id", "dialect", "pack", "purpose", "window", "observables",
        "observable_provenance", "size", "aggregation", "match_semantics",
    ):
        if value.get(field) != expected_query[field]:
            raise InvestigationQueryContractError(
                f"result {expected_query['query_id']} changed its authorized {field}"
            )
    for field in ("event_tuple", "event_tuple_provenance", "anchor_time"):
        if value.get(field) != expected_query.get(field):
            raise InvestigationQueryContractError(
                f"result {expected_query['query_id']} changed its authorized {field}"
            )


def _validate_result_execution(
    value: dict[str, Any], expected_query: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    expected_dsl = build_query_dsl(expected_query)
    expected_scope = PACKS[expected_query["pack"]]["indices"]
    expected_endpoint = query_endpoint(expected_scope)
    if value.get("query_dsl") != expected_dsl:
        raise InvestigationQueryContractError("result query DSL was not generated from its pack")
    if value.get("index_scope") != expected_scope:
        raise InvestigationQueryContractError("result index scope is not reviewed")
    if value.get("query_endpoint") != expected_endpoint:
        raise InvestigationQueryContractError("result query endpoint is not reviewed")
    if value.get("query_digest") != canonical_digest(expected_dsl):
        raise InvestigationQueryContractError("result query digest is invalid")
    if value.get("execution_digest") != _expected_execution_digest(
        expected_dsl, expected_scope, expected_endpoint
    ):
        raise InvestigationQueryContractError("result execution digest is invalid")
    return expected_dsl, expected_scope


def _validate_result_representations(
    value: dict[str, Any], expected_query: dict[str, Any]
) -> None:
    expected_kql = kql_equivalent(expected_query)
    expected_oql = oql_equivalent(expected_query)
    if value.get("kql_equivalent") != expected_kql:
        raise InvestigationQueryContractError("result KQL representation is invalid")
    if value.get("oql_equivalent") != expected_oql:
        raise InvestigationQueryContractError("result OQL representation is invalid")
    if value.get("kql_digest") != hashlib.sha256(expected_kql.encode()).hexdigest():
        raise InvestigationQueryContractError("result KQL digest is invalid")
    if value.get("oql_digest") != hashlib.sha256(expected_oql.encode()).hexdigest():
        raise InvestigationQueryContractError("result OQL digest is invalid")
    if value.get("request_item_digest") != canonical_digest(expected_query):
        raise InvestigationQueryContractError("result request-item digest is invalid")
    expected_semantics = (
        "compiled_oql_equivalent"
        if expected_query["dialect"] == "oql"
        else "compiled_elastic_pack"
    )
    if (
        value.get("execution_backend") != "so-elasticsearch-query"
        or value.get("execution_semantics") != expected_semantics
    ):
        raise InvestigationQueryContractError("result execution semantics are mislabeled")


def _validate_result_hits(
    value: dict[str, Any],
    expected_query: dict[str, Any],
    expected_dsl: dict[str, Any],
    expected_scope: list[str],
) -> tuple[str, list[object]]:
    status = str(value.get("status") or "")
    if status not in ALLOWED_STATUSES:
        raise InvestigationQueryContractError("result status is unsupported")
    hits = value.get("hits")
    if not isinstance(hits, list):
        raise InvestigationQueryContractError("result hits must be an array")
    if len(hits) > expected_dsl["size"]:
        raise InvestigationQueryContractError("result exceeds its authorized hit limit")
    for hit in hits:
        item = _require_mapping(hit, "investigation hit")
        if not SAFE_ELASTIC_ID_RE.fullmatch(str(item.get("id") or "")):
            raise InvestigationQueryContractError("investigation hit id is invalid")
        if not _index_matches_scope(str(item.get("index") or ""), expected_scope):
            raise InvestigationQueryContractError("investigation hit escaped its index scope")
        _validate_hit_source(item.get("source"), expected_query)
    return status, hits


def _validate_nonnegative(value: object, message: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvestigationQueryContractError(message)


def _validate_result_counts(
    value: dict[str, Any],
    expected_query: dict[str, Any],
    status: str,
    hits: list[object],
) -> str:
    for field in ("returned_hits", "total_hits"):
        _validate_nonnegative(value.get(field), f"result {field} is invalid")
    if value["returned_hits"] != len(hits) or value["total_hits"] < len(hits):
        raise InvestigationQueryContractError("result hit counts are inconsistent")
    relation = value.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise InvestigationQueryContractError("result total-hits relation is invalid")
    expected_truncated = relation != "eq" or (
        expected_query["aggregation"] != "count" and value["total_hits"] > len(hits)
    )
    if value.get("truncated") is not expected_truncated:
        raise InvestigationQueryContractError("result truncation flag is inconsistent")
    expected_coverage = result_coverage(
        expected_query,
        status=status,
        total_hits=value["total_hits"],
        total_hits_relation=relation,
        returned_hits=value["returned_hits"],
    )
    if value.get("result_coverage") != expected_coverage:
        raise InvestigationQueryContractError(
            "result evidence coverage semantics are inconsistent"
        )
    if expected_query["aggregation"] == "count" and hits:
        raise InvestigationQueryContractError("count aggregation returned event bodies")
    return relation


def _validate_result_timing(value: dict[str, Any]) -> None:
    for field in ("duration_ms", "took_ms"):
        _validate_nonnegative(value.get(field), f"result {field} is invalid")
    if not isinstance(value.get("timed_out"), bool):
        raise InvestigationQueryContractError("result timed_out is invalid")


def _validate_result_shards(value: dict[str, Any]) -> dict[str, Any]:
    shards = _require_mapping(value.get("shards"), "result shard metadata")
    for field in ("total", "successful", "skipped", "failed"):
        _validate_nonnegative(shards.get(field), "result shard metadata is invalid")
    failures = shards.get("failures")
    if not isinstance(failures, list) or len(failures) > 20:
        raise InvestigationQueryContractError("result shard failures are invalid")
    if (
        shards["failed"] > shards["total"]
        or shards["successful"] > shards["total"]
        or shards["skipped"] > shards["successful"]
    ):
        raise InvestigationQueryContractError("result shard counts are inconsistent")
    return shards


def _validate_result_semantics(
    value: dict[str, Any], status: str, hits: list[object], shards: dict[str, Any]
) -> bool:
    expected_ok = status == "ok"
    if value.get("semantic_valid") is not expected_ok:
        raise InvestigationQueryContractError("result semantic validity contradicts its status")
    if expected_ok and (
        value["timed_out"]
        or shards["total"] == 0
        or shards["successful"] != shards["total"]
        or shards["failed"] != 0
    ):
        raise InvestigationQueryContractError("successful result has invalid shard coverage")
    if not expected_ok and hits:
        raise InvestigationQueryContractError("failed result retained unauthenticated hits")
    return expected_ok


def _validate_pivot_result(
    result: object,
    expected_query: dict[str, Any],
) -> bool:
    value = _require_mapping(result, f"result {expected_query['query_id']}")
    _validate_result_binding(value, expected_query)
    expected_dsl, expected_scope = _validate_result_execution(value, expected_query)
    _validate_result_representations(value, expected_query)
    status, hits = _validate_result_hits(
        value, expected_query, expected_dsl, expected_scope
    )
    _validate_result_counts(value, expected_query, status, hits)
    _validate_result_timing(value)
    shards = _validate_result_shards(value)
    return _validate_result_semantics(value, status, hits, shards)


__all__ = ["_validate_pivot_result", "result_coverage"]
