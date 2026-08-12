"""Locally generated Elastic, KQL, and OQL investigation queries."""
from __future__ import annotations

from investigation_query_schema import *  # noqa: F401,F403
from investigation_query_normalization import *  # noqa: F401,F403
from investigation_query_normalization import _parse_utc  # noqa: F401
from investigation_query_authorization import *  # noqa: F401,F403


def observable_clause(
    observables: dict[str, list[str]],
    pack_name: str,
) -> dict[str, Any]:
    should: list[dict[str, Any]] = []
    for kind, fields in pack_observable_fields(pack_name).items():
        for value in observables.get(kind, []):
            should.extend({"term": {field: value}} for field in fields)
    if not should:
        raise InvestigationQueryContractError(
            f"pack {pack_name} produced no observable query clauses"
        )
    return {"bool": {"should": should, "minimum_should_match": 1}}


def _event_tuple_query_fields(query: dict[str, Any]) -> list[str]:
    event_tuple = query.get("event_tuple") or {}
    if query.get("match_semantics") == "community_id_cross_sensor":
        return ["community_id"]
    return list(event_tuple)


def _event_tuple_term_clause(field: str, value: Any) -> dict[str, Any]:
    paths = EVENT_TUPLE_PATHS[field]
    if len(paths) == 1:
        return {"term": {paths[0]: value}}
    return {
        "bool": {
            "should": [
                {"term": {path: value}}
                for path in paths
            ],
            "minimum_should_match": 1,
        }
    }


def event_tuple_clause(query: dict[str, Any]) -> dict[str, Any]:
    """Compile only role-compatible trusted tuple constraints."""
    event_tuple = query.get("event_tuple") or {}
    fields = _event_tuple_query_fields(query)
    if not fields:
        raise InvestigationQueryContractError(
            "event tuple produced no role-compatible query clauses"
        )
    return {
        "bool": {
            "filter": [
                _event_tuple_term_clause(field, event_tuple[field])
                for field in fields
            ]
        }
    }


def dataset_clause(datasets: list[str]) -> dict[str, Any]:
    if not datasets:
        raise InvestigationQueryContractError(
            "reviewed query pack has no datasets"
        )
    return {
        "bool": {
            "should": [
                {"term": {"event.dataset": dataset}}
                for dataset in datasets
            ],
            "minimum_should_match": 1,
        }
    }


def _query_filters(
    query: dict[str, Any],
    pack: dict[str, Any],
) -> list[dict[str, Any]]:
    return [
        {
            "range": {
                "@timestamp": {
                    "gte": query["window"]["start"],
                    "lte": query["window"]["end"],
                }
            }
        },
        dataset_clause(pack["datasets"]),
        observable_clause(query["observables"], query["pack"]),
        *(
            [event_tuple_clause(query)]
            if query.get("event_tuple")
            else []
        ),
    ]


def _compiled_query(
    query: dict[str, Any],
    filtered_query: dict[str, Any],
) -> dict[str, Any]:
    if query["aggregation"] == "anchor_nearest":
        start = _parse_utc(query["window"]["start"], "query window start")
        end = _parse_utc(query["window"]["end"], "query window end")
        scale_seconds = max(1, round((end - start).total_seconds() / 2))
        return {
            "function_score": {
                "query": filtered_query,
                "gauss": {
                    "@timestamp": {
                        "origin": query["anchor_time"],
                        "scale": f"{scale_seconds}s",
                        "decay": 0.5,
                    }
                },
                "boost_mode": "replace",
            }
        }
    return filtered_query


def _query_body(
    query: dict[str, Any],
    pack: dict[str, Any],
    compiled_query: dict[str, Any],
) -> dict[str, Any]:
    body = {
        "size": 0 if query["aggregation"] == "count" else query["size"],
        "track_total_hits": True,
        "timeout": "30s",
        "_source": False if query["aggregation"] == "count" else pack["fields"],
        "query": compiled_query,
    }
    if query["aggregation"] != "count":
        if query["aggregation"] == "anchor_nearest":
            body["sort"] = [
                {"_score": "desc"},
                {"@timestamp": {"order": "asc", "unmapped_type": "date"}},
                "_shard_doc",
            ]
        else:
            order = "asc" if query["aggregation"] == "timeline" else "desc"
            body["sort"] = [
                {"@timestamp": {"order": order, "unmapped_type": "date"}},
                "_shard_doc",
            ]
    return body


def build_query_dsl(query: dict[str, Any]) -> dict[str, Any]:
    pack = PACKS[query["pack"]]
    filters = _query_filters(query, pack)
    filtered_query = {"bool": {"filter": filters}}
    return _query_body(query, pack, _compiled_query(query, filtered_query))


def _quote(value: str) -> str:
    # All observable validators exclude quotes and backslashes.
    return f'"{value}"'


def _event_tuple_filter_value(field: str, value: Any) -> str:
    if field in {"source_port", "destination_port"}:
        return str(value)
    return _quote(str(value))


def _render_event_tuple_filter(
    query: dict[str, Any],
    *,
    separator: str,
    field_separator: str,
) -> str:
    event_tuple = query.get("event_tuple") or {}
    clauses: list[str] = []
    for field in _event_tuple_query_fields(query):
        value = _event_tuple_filter_value(field, event_tuple[field])
        alternatives = [
            f"{path}{field_separator}{value}"
            for path in EVENT_TUPLE_PATHS[field]
        ]
        clauses.append(
            alternatives[0]
            if len(alternatives) == 1
            else "(" + f" {separator} ".join(alternatives) + ")"
        )
    return f" {separator.replace('or', 'and').replace('OR', 'AND')} ".join(clauses)


def kql_equivalent(query: dict[str, Any]) -> str:
    datasets = " or ".join(
        f"event.dataset : {_quote(value)}" for value in PACKS[query["pack"]]["datasets"]
    )
    observables: list[str] = []
    for kind, fields in pack_observable_fields(query["pack"]).items():
        for value in query["observables"].get(kind, []):
            observables.append(
                "(" + " or ".join(f"{field} : {_quote(value)}" for field in fields) + ")"
            )
    rendered = (
        f'@timestamp >= {_quote(query["window"]["start"])} and '
        f'@timestamp <= {_quote(query["window"]["end"])} and '
        f"({datasets}) and (" + " or ".join(observables) + ")"
    )
    if query.get("event_tuple"):
        rendered += " and (" + _render_event_tuple_filter(
            query,
            separator="or",
            field_separator=" : ",
        ) + ")"
    return rendered


def oql_equivalent(query: dict[str, Any]) -> str:
    """Render Security Onion Hunt OQL (Lucene filters plus safe pipeline sort).

    The wrapper executes a locally compiled, semantically equivalent Query DSL
    request through ``so-elasticsearch-query``; it does not claim to call the
    SOC Hunt API.
    """
    datasets = " OR ".join(
        f"event.dataset:{_quote(value)}" for value in PACKS[query["pack"]]["datasets"]
    )
    observables: list[str] = []
    for kind, fields in pack_observable_fields(query["pack"]).items():
        for value in query["observables"].get(kind, []):
            observables.append(
                "(" + " OR ".join(f"{field}:{_quote(value)}" for field in fields) + ")"
            )
    rendered = (
        f'@timestamp:[{_quote(query["window"]["start"])} TO '
        f'{_quote(query["window"]["end"])}] AND '
        f"({datasets}) AND (" + " OR ".join(observables) + ")"
    )
    if query.get("event_tuple"):
        rendered += " AND (" + _render_event_tuple_filter(
            query,
            separator="OR",
            field_separator=":",
        ) + ")"
    if query["aggregation"] == "timeline":
        rendered += " | sortby @timestamp^"
    return rendered


def query_endpoint(index_scope: list[str]) -> str:
    return (
        f"{','.join(index_scope)}/_search"
        f"?ignore_unavailable=true&expand_wildcards=open&preference={QUERY_PREFERENCE}"
    )


def _expected_execution_digest(
    query_dsl: dict[str, Any],
    index_scope: list[str],
    endpoint: str,
) -> str:
    return canonical_digest({
        "index_scope": index_scope,
        "query_endpoint": endpoint,
        "query_dsl": query_dsl,
    })
