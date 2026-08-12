"""Positive- and negative-control validation for investigation responses."""
from __future__ import annotations

from typing import Any

from investigation_query_schema import (
    ALERT_INDEX_SCOPE,
    ALLOWED_STATUSES,
    SAFE_ELASTIC_ID_RE,
    InvestigationQueryContractError,
)
from investigation_query_normalization import (
    _index_matches_scope,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
)
from investigation_query_rendering import (
    _expected_execution_digest,
    canonical_digest,
    query_endpoint,
)
from investigation_query_response_source import _leaf_items, _path_values


def _control_name(positive: bool) -> str:
    return "positive anchor" if positive else "negative filter"


def _validate_control_shape(
    value: object, control_name: str
) -> dict[str, Any]:
    result = _require_mapping(value, f"investigation {control_name} control")
    _require_exact_keys(
        result,
        allowed={
            "passed", "query_dsl", "query_digest", "index_scope",
            "query_endpoint", "execution_digest", "status", "semantic_valid",
            "total_hits", "total_hits_relation", "returned_hits", "truncated",
            "duration_ms", "timed_out", "took_ms", "shards", "hits", "error",
        },
        required={
            "passed", "query_dsl", "query_digest", "index_scope",
            "query_endpoint", "execution_digest", "status", "semantic_valid",
            "total_hits", "total_hits_relation", "returned_hits", "truncated",
            "duration_ms", "timed_out", "took_ms", "shards", "hits",
        },
        label=f"investigation {control_name} control",
    )
    if not isinstance(result["passed"], bool):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control passed flag is invalid"
        )
    return result


def _expected_control_query(
    anchor: dict[str, str], positive: bool
) -> tuple[dict[str, Any], list[str]]:
    if positive:
        expected_dsl = {
            "size": 1,
            "track_total_hits": True,
            "timeout": "30s",
            "_source": ["@timestamp", "event.dataset"],
            "query": {"ids": {"values": [anchor["id"]]}},
        }
        return expected_dsl, [anchor["index"]]
    expected_dsl = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {
            "bool": {
                "filter": [{"ids": {"values": [anchor["id"]]}}],
                "must_not": [{"ids": {"values": [anchor["id"]]}}],
            }
        },
    }
    return expected_dsl, ALERT_INDEX_SCOPE


def _validate_control_query(
    result: dict[str, Any],
    anchor: dict[str, str],
    positive: bool,
    control_name: str,
) -> list[str]:
    expected_dsl, expected_scope = _expected_control_query(anchor, positive)
    if result.get("query_dsl") != expected_dsl:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control DSL is invalid"
        )
    if result.get("index_scope") != expected_scope:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control index scope is invalid"
        )
    expected_endpoint = query_endpoint(expected_scope)
    if result.get("query_endpoint") != expected_endpoint:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control endpoint is invalid"
        )
    if result.get("query_digest") != canonical_digest(expected_dsl):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control digest is invalid"
        )
    if result.get("execution_digest") != _expected_execution_digest(
        expected_dsl, expected_scope, expected_endpoint
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control execution digest is invalid"
        )
    return expected_scope


def _validate_nonnegative_control_field(
    value: object, control_name: str, field: str
) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control {field} is invalid"
        )


def _validate_control_execution(
    result: dict[str, Any], control_name: str
) -> tuple[str, list[object]]:
    status = str(result.get("status") or "")
    if status not in ALLOWED_STATUSES:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control status is unsupported"
        )
    if result.get("semantic_valid") is not (status == "ok"):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control semantic validity is invalid"
        )
    hits = result.get("hits")
    if not isinstance(hits, list):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hits are invalid"
        )
    return status, hits


def _validate_control_counts(
    result: dict[str, Any], hits: list[object], control_name: str
) -> str:
    for field in ("total_hits", "returned_hits", "duration_ms", "took_ms"):
        _validate_nonnegative_control_field(result.get(field), control_name, field)
    if result["returned_hits"] != len(hits) or result["total_hits"] < len(hits):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit counts are inconsistent"
        )
    relation = result.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control total-hits relation is invalid"
        )
    expected_truncated = relation != "eq" or result["total_hits"] > len(hits)
    if result.get("truncated") is not expected_truncated:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control truncation flag is invalid"
        )
    if not isinstance(result.get("timed_out"), bool):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control timed_out flag is invalid"
        )
    return relation


def _validate_control_shard_counts(
    shards: dict[str, Any], control_name: str
) -> None:
    for field in ("total", "successful", "skipped", "failed"):
        item = shards.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control shard metadata is invalid"
            )
    if (
        shards["failed"] > shards["total"]
        or shards["successful"] > shards["total"]
        or shards["skipped"] > shards["successful"]
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control shard counts are inconsistent"
        )


def _validate_control_shard_coverage(
    result: dict[str, Any],
    shards: dict[str, Any],
    status: str,
    hits: list[object],
    control_name: str,
) -> None:
    if status == "ok" and (
        result["timed_out"]
        or shards["total"] == 0
        or shards["successful"] != shards["total"]
        or shards["failed"] != 0
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control shard coverage is invalid"
        )
    if status != "ok" and hits:
        raise InvestigationQueryContractError(
            f"failed investigation {control_name} control retained hits"
        )


def _validate_control_shards(
    result: dict[str, Any], status: str, hits: list[object], control_name: str
) -> None:
    shards = _require_mapping(
        result.get("shards"), f"investigation {control_name} control shards"
    )
    _require_exact_keys(
        shards,
        allowed={"total", "successful", "skipped", "failed", "failures"},
        required={"total", "successful", "skipped", "failed", "failures"},
        label=f"investigation {control_name} control shards",
    )
    _validate_control_shard_counts(shards, control_name)
    if not isinstance(shards["failures"], list) or len(shards["failures"]) > 20:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control shard failures are invalid"
        )
    _validate_control_shard_coverage(
        result, shards, status, hits, control_name
    )


def _validate_control_hit(
    hit: object, expected_scope: list[str], control_name: str
) -> None:
    item = _require_mapping(hit, f"investigation {control_name} control hit")
    _require_exact_keys(
        item,
        allowed={"id", "index", "source"},
        required={"id", "index", "source"},
        label=f"investigation {control_name} control hit",
    )
    if not SAFE_ELASTIC_ID_RE.fullmatch(str(item["id"] or "")):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit id is invalid"
        )
    if not _index_matches_scope(str(item["index"] or ""), expected_scope):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit escaped its index scope"
        )
    source = _require_mapping(
        item["source"], f"investigation {control_name} control hit source"
    )
    if any(
        path not in {"@timestamp", "event.dataset"}
        for path, _item in _leaf_items(source)
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit projection is invalid"
        )
    timestamp_values = _path_values(source, "@timestamp")
    datasets = [str(value) for value in _path_values(source, "event.dataset")]
    if len(timestamp_values) != 1 or len(datasets) != 1:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit source is incomplete"
        )
    _parse_utc(
        timestamp_values[0], f"investigation {control_name} control hit timestamp"
    )
    if datasets[0] not in {"suricata.alert", "sigma.alert"}:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control hit dataset is invalid"
        )


def _control_logical_pass(
    result: dict[str, Any],
    hits: list[object],
    relation: str,
    status: str,
    anchor: dict[str, str],
    positive: bool,
) -> bool:
    if not positive:
        return (
            status == "ok"
            and relation == "eq"
            and not hits
            and result["total_hits"] == 0
            and result["returned_hits"] == 0
        )
    exact = [
        hit for hit in hits
        if isinstance(hit, dict)
        and hit.get("id") == anchor["id"]
        and hit.get("index") == anchor["index"]
    ]
    return (
        status == "ok"
        and relation == "eq"
        and len(exact) == 1
        and result["total_hits"] == 1
        and result["returned_hits"] == 1
    )


def _validate_control(
    value: object,
    *,
    anchor: dict[str, str],
    positive: bool,
) -> bool:
    control_name = _control_name(positive)
    result = _validate_control_shape(value, control_name)
    expected_scope = _validate_control_query(
        result, anchor, positive, control_name
    )
    status, hits = _validate_control_execution(result, control_name)
    relation = _validate_control_counts(result, hits, control_name)
    _validate_control_shards(result, status, hits, control_name)
    for hit in hits:
        _validate_control_hit(hit, expected_scope, control_name)
    logical_pass = _control_logical_pass(
        result, hits, relation, status, anchor, positive
    )
    if result["passed"] is not logical_pass:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control passed flag contradicts its result"
        )
    return logical_pass


__all__ = ["_validate_control"]
