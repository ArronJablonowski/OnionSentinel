"""Provenance, coverage, control, and response validation."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization import *  # noqa: F401,F403
from investigation_query_normalization import (  # noqa: F401
    _index_matches_scope,
    _normalize_event_tuple,
    _normalize_observable,
    _parse_utc,
    _require_exact_keys,
    _require_mapping,
)
from investigation_query_authorization import *  # noqa: F401,F403
from investigation_query_rendering import *  # noqa: F401,F403
from investigation_query_rendering import (  # noqa: F401
    _event_tuple_query_fields,
    _expected_execution_digest,
)


def _leaf_items(value: object, prefix: str = "") -> list[tuple[str, object]]:
    """Flatten source leaves while preserving ECS paths through arrays."""
    leaves: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.extend(_leaf_items(child, path))
    elif isinstance(value, list):
        for child in value:
            leaves.extend(_leaf_items(child, prefix))
    else:
        leaves.append((prefix, value))
    return leaves


def _path_values(source: dict[str, Any], path: str) -> list[object]:
    current: list[object] = [source]
    for part in path.split("."):
        following: list[object] = []
        for item in current:
            if isinstance(item, dict) and part in item:
                value = item[part]
                following.extend(value if isinstance(value, list) else [value])
            elif isinstance(item, list):
                for child in item:
                    if isinstance(child, dict) and part in child:
                        value = child[part]
                        following.extend(value if isinstance(value, list) else [value])
        current = following
    return [
        item
        for item in current
        if not isinstance(item, (dict, list))
    ]


def _observable_matches(kind: str, expected: str, candidate: object) -> bool:
    try:
        return _normalize_observable(kind, candidate) == expected
    except InvestigationQueryContractError:
        return False


def _event_tuple_value_matches(field: str, expected: Any, candidate: object) -> bool:
    try:
        normalized = _normalize_event_tuple(
            {field: candidate},
            label="investigation hit event tuple",
        )
    except InvestigationQueryContractError:
        return False
    return normalized.get(field) == expected


def _validate_hit_source(
    source: object,
    expected_query: dict[str, Any],
) -> None:
    source_map = _require_mapping(source, "investigation hit source")
    allowed_fields = set(PACKS[expected_query["pack"]]["fields"])
    leaves = _leaf_items(source_map)
    if any(path not in allowed_fields for path, _value in leaves):
        raise InvestigationQueryContractError(
            "investigation hit source contains a field outside its reviewed projection"
        )
    timestamp_values = _path_values(source_map, "@timestamp")
    if len(timestamp_values) != 1:
        raise InvestigationQueryContractError(
            "investigation hit source has no singular timestamp"
        )
    timestamp = _parse_utc(timestamp_values[0], "investigation hit timestamp")
    start = _parse_utc(expected_query["window"]["start"], "investigation window start")
    end = _parse_utc(expected_query["window"]["end"], "investigation window end")
    if timestamp < start or timestamp > end:
        raise InvestigationQueryContractError(
            "investigation hit timestamp escaped its authorized window"
        )
    datasets = [
        str(item)
        for item in _path_values(source_map, "event.dataset")
    ]
    allowed_datasets = PACKS[expected_query["pack"]]["datasets"]
    if len(datasets) != 1 or datasets[0] not in allowed_datasets:
        raise InvestigationQueryContractError(
            "investigation hit dataset escaped its reviewed pack"
        )
    observable_match = False
    for kind, fields in pack_observable_fields(expected_query["pack"]).items():
        for expected in expected_query["observables"].get(kind, []):
            if any(
                _observable_matches(kind, expected, candidate)
                for field in fields
                for candidate in _path_values(source_map, field)
            ):
                observable_match = True
                break
        if observable_match:
            break
    if not observable_match:
        raise InvestigationQueryContractError(
            "investigation hit does not contain an authorized matching observable"
        )
    event_tuple = expected_query.get("event_tuple") or {}
    for field in _event_tuple_query_fields(expected_query):
        expected = event_tuple[field]
        if not any(
            _event_tuple_value_matches(field, expected, candidate)
            for path in EVENT_TUPLE_PATHS[field]
            for candidate in _path_values(source_map, path)
        ):
            raise InvestigationQueryContractError(
                "investigation hit does not match its authorized event tuple"
            )


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
        interpretation = (
            "no_matching_documents_for_authorized_filter_and_window"
        )
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


def _validate_pivot_result(
    result: object,
    expected_query: dict[str, Any],
) -> bool:
    value = _require_mapping(result, f"result {expected_query['query_id']}")
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
    status = str(value.get("status") or "")
    if status not in ALLOWED_STATUSES:
        raise InvestigationQueryContractError("result status is unsupported")
    hits = value.get("hits")
    if not isinstance(hits, list):
        raise InvestigationQueryContractError("result hits must be an array")
    body_size = expected_dsl["size"]
    if len(hits) > body_size:
        raise InvestigationQueryContractError("result exceeds its authorized hit limit")
    for hit in hits:
        item = _require_mapping(hit, "investigation hit")
        if not SAFE_ELASTIC_ID_RE.fullmatch(str(item.get("id") or "")):
            raise InvestigationQueryContractError("investigation hit id is invalid")
        index_name = str(item.get("index") or "")
        if not _index_matches_scope(index_name, expected_scope):
            raise InvestigationQueryContractError("investigation hit escaped its index scope")
        _validate_hit_source(item.get("source"), expected_query)
    for field in ("returned_hits", "total_hits"):
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvestigationQueryContractError(f"result {field} is invalid")
    if value["returned_hits"] != len(hits) or value["total_hits"] < len(hits):
        raise InvestigationQueryContractError("result hit counts are inconsistent")
    relation = value.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise InvestigationQueryContractError("result total-hits relation is invalid")
    expected_truncated = (
        relation != "eq"
        or (
            expected_query["aggregation"] != "count"
            and value["total_hits"] > len(hits)
        )
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
    for field in ("duration_ms", "took_ms"):
        count = value.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvestigationQueryContractError(f"result {field} is invalid")
    if not isinstance(value.get("timed_out"), bool):
        raise InvestigationQueryContractError("result timed_out is invalid")
    shards = _require_mapping(value.get("shards"), "result shard metadata")
    for field in ("total", "successful", "skipped", "failed"):
        count = shards.get(field)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise InvestigationQueryContractError("result shard metadata is invalid")
    failures = shards.get("failures")
    if not isinstance(failures, list) or len(failures) > 20:
        raise InvestigationQueryContractError("result shard failures are invalid")
    if (
        shards["failed"] > shards["total"]
        or shards["successful"] > shards["total"]
        or shards["skipped"] > shards["successful"]
    ):
        raise InvestigationQueryContractError("result shard counts are inconsistent")
    semantic_valid = value.get("semantic_valid")
    expected_ok = status == "ok"
    if semantic_valid is not expected_ok:
        raise InvestigationQueryContractError("result semantic validity contradicts its status")
    if expected_ok:
        if (
            value["timed_out"]
            or shards["total"] == 0
            or shards["successful"] != shards["total"]
            or shards["failed"] != 0
        ):
            raise InvestigationQueryContractError("successful result has invalid shard coverage")
    elif hits:
        raise InvestigationQueryContractError("failed result retained unauthenticated hits")
    return expected_ok


def _validate_control(
    value: object,
    *,
    anchor: dict[str, str],
    positive: bool,
) -> bool:
    control_name = "positive anchor" if positive else "negative filter"
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
    expected_dsl: dict[str, Any]
    if positive:
        expected_dsl = {
            "size": 1,
            "track_total_hits": True,
            "timeout": "30s",
            "_source": ["@timestamp", "event.dataset"],
            "query": {"ids": {"values": [anchor["id"]]}},
        }
    else:
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
    expected_scope = [anchor["index"]] if positive else ALERT_INDEX_SCOPE
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
        expected_dsl,
        expected_scope,
        expected_endpoint,
    ):
        raise InvestigationQueryContractError(
            f"investigation {control_name} control execution digest is invalid"
        )

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
    for field in ("total_hits", "returned_hits", "duration_ms", "took_ms"):
        item = result.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control {field} is invalid"
            )
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
    shards = _require_mapping(
        result.get("shards"),
        f"investigation {control_name} control shards",
    )
    _require_exact_keys(
        shards,
        allowed={"total", "successful", "skipped", "failed", "failures"},
        required={"total", "successful", "skipped", "failed", "failures"},
        label=f"investigation {control_name} control shards",
    )
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
    if not isinstance(shards["failures"], list) or len(shards["failures"]) > 20:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control shard failures are invalid"
        )
    if status == "ok":
        if (
            result["timed_out"]
            or shards["total"] == 0
            or shards["successful"] != shards["total"]
            or shards["failed"] != 0
        ):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control shard coverage is invalid"
            )
    elif hits:
        raise InvestigationQueryContractError(
            f"failed investigation {control_name} control retained hits"
        )

    for hit in hits:
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
        index_name = str(item["index"] or "")
        if not _index_matches_scope(index_name, expected_scope):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit escaped its index scope"
            )
        source = _require_mapping(
            item["source"],
            f"investigation {control_name} control hit source",
        )
        if any(
            path not in {"@timestamp", "event.dataset"}
            for path, _item in _leaf_items(source)
        ):
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit projection is invalid"
            )
        timestamp_values = _path_values(source, "@timestamp")
        datasets = [str(item) for item in _path_values(source, "event.dataset")]
        if len(timestamp_values) != 1 or len(datasets) != 1:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit source is incomplete"
            )
        _parse_utc(
            timestamp_values[0],
            f"investigation {control_name} control hit timestamp",
        )
        if datasets[0] not in {"suricata.alert", "sigma.alert"}:
            raise InvestigationQueryContractError(
                f"investigation {control_name} control hit dataset is invalid"
            )

    if positive:
        exact = [
            hit for hit in hits
            if isinstance(hit, dict)
            and hit.get("id") == anchor["id"]
            and hit.get("index") == anchor["index"]
        ]
        logical_pass = (
            status == "ok"
            and relation == "eq"
            and len(exact) == 1
            and result["total_hits"] == 1
            and result["returned_hits"] == 1
        )
    else:
        logical_pass = (
            status == "ok"
            and relation == "eq"
            and not hits
            and result["total_hits"] == 0
            and result["returned_hits"] == 0
        )
    if result["passed"] is not logical_pass:
        raise InvestigationQueryContractError(
            f"investigation {control_name} control passed flag contradicts its result"
        )
    return logical_pass


def validate_investigation_query_response(
    response: object,
    request: object,
) -> dict[str, Any]:
    """Authenticate the forced-command response against the exact request."""
    expected_request = validate_authorized_investigation_query_request(request)
    value = _require_mapping(response, "investigation query response")
    if value.get("query_contract") != INVESTIGATION_QUERY_CONTRACT:
        raise InvestigationQueryContractError("response query contract is unsupported")
    if value.get("batch_id") != expected_request["batch_id"]:
        raise InvestigationQueryContractError("response batch id does not match")
    if value.get("request_digest") != canonical_digest(expected_request):
        raise InvestigationQueryContractError("response request digest does not match")
    if value.get("read_only") is not True or value.get("ok") is not True:
        raise InvestigationQueryContractError("response is not a successful read-only protocol result")
    results = value.get("results")
    if not isinstance(results, list) or len(results) != len(expected_request["queries"]):
        raise InvestigationQueryContractError("response result coverage is incomplete")
    query_valid = [
        _validate_pivot_result(result, query)
        for result, query in zip(results, expected_request["queries"])
    ]
    controls = _require_mapping(value.get("controls"), "investigation controls")
    if controls.get("anchor") != expected_request["authorization"]["anchor"]:
        raise InvestigationQueryContractError("response control anchor does not match")
    control_validity: list[bool] = []
    control_errors: list[str] = []
    for field, positive in (("positive_anchor", True), ("negative_filter", False)):
        try:
            control_validity.append(_validate_control(
                controls.get(field),
                anchor=expected_request["authorization"]["anchor"],
                positive=positive,
            ))
        except InvestigationQueryContractError as exc:
            control_validity.append(False)
            control_errors.append(f"{field}: {exc}")
    if control_errors:
        raise InvestigationQueryContractError(
            "investigation query controls are invalid: " + "; ".join(control_errors)
        )
    controls_valid = all(control_validity)
    complete = all(query_valid) and controls_valid
    if value.get("complete") is not complete or value.get("partial") is not (not complete):
        raise InvestigationQueryContractError("response completion flags are inconsistent")
    semantic = _require_mapping(
        value.get("semantic_validity"),
        "response semantic_validity",
    )
    if (
        semantic.get("transport_valid") is not True
        or semantic.get("controls_valid") is not controls_valid
        or semantic.get("query_execution_valid") is not all(query_valid)
        or semantic.get("semantic_valid") is not complete
    ):
        raise InvestigationQueryContractError("response semantic validity is inconsistent")
    return value


__all__ = [
    "ALLOWED_AGGREGATIONS",
    "ALLOWED_DIALECTS",
    "ALLOWED_PURPOSES",
    "EVENT_TUPLE_FIELDS",
    "EVENT_TUPLE_PATHS",
    "INVESTIGATION_QUERY_CONTRACT",
    "InvestigationQueryContractError",
    "SAFE_ATOM_RE",
    "authorize_investigation_query_request",
    "build_query_dsl",
    "canonical_digest",
    "kql_equivalent",
    "oql_equivalent",
    "pack_event_tuple_fields",
    "result_coverage",
    "tuple_match_semantics",
    "validate_pack_observables",
    "validate_authorized_investigation_query_request",
    "validate_investigation_query_request",
    "validate_investigation_query_response",
]
