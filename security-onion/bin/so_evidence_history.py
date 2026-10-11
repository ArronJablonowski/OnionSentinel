"""Bounded evidence history owner."""
from __future__ import annotations





import json














from investigation_query_schema import (  # noqa: E402
    InvestigationQueryContractError as SharedQueryContractError,
)

from historical_osquery_schema import (  # noqa: E402
    compile_historical_osquery_schema_discovery,
    historical_osquery_field_caps_body,
    historical_osquery_field_caps_endpoint,
    historical_osquery_schema_failure,
)


def historical_osquery_observable_fields(
    r,
    observables: dict[str, list[str]],
) -> list[str]:
    """Return only fixed fields relevant to the authorized observable kinds."""
    return [
        field
        for kind, fields in r.pack_observable_fields("osquery_history").items()
        if observables.get(kind)
        for field in fields
    ]


def discover_historical_osquery_schema(
    r,
    observables: dict[str, list[str]],
) -> dict:
    """Run one bounded read-only field-capabilities preflight."""
    pack = r.PACKS["osquery_history"]
    endpoint = historical_osquery_field_caps_endpoint(pack["indices"])
    body = historical_osquery_field_caps_body(pack["fields"])
    r.AUDIT_CONTEXT["elastic_search_count"] = int(
        r.AUDIT_CONTEXT.get("elastic_search_count", 0)
    ) + 1
    try:
        completed = r.run_bounded_command(
            [str(r.SO_QUERY), endpoint, "-d", json.dumps(
                body, separators=(",", ":"), sort_keys=True
            )],
            timeout_seconds=r.QUERY_TIMEOUT_SECONDS,
            max_stdout_bytes=r.MAX_OUTPUT_BYTES,
            max_stderr_bytes=r.MAX_STDERR_BYTES,
        )
    except r.BoundedCommandError as exc:
        status = "timeout" if exc.reason == "timeout" else "output_limit"
        return historical_osquery_schema_failure(
            status,
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            error=(
                "Elasticsearch field-capabilities request exceeded its timeout"
                if status == "timeout"
                else "Elasticsearch field-capabilities response exceeded its output limit"
            ),
        )
    if completed.returncode != 0:
        return historical_osquery_schema_failure(
            "error",
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            error="Elasticsearch field-capabilities request failed",
        )
    try:
        raw = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return historical_osquery_schema_failure(
            "invalid_response",
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            error="Elasticsearch field-capabilities response was not valid JSON",
        )
    if isinstance(raw, dict) and raw.get("error") is not None:
        return historical_osquery_schema_failure(
            "error",
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            error="Elasticsearch field-capabilities response reported an error",
        )
    try:
        return compile_historical_osquery_schema_discovery(
            raw,
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            observable_fields=r.historical_osquery_observable_fields(observables),
        )
    except SharedQueryContractError:
        return historical_osquery_schema_failure(
            "invalid_response",
            index_scope=pack["indices"],
            projection_fields=pack["fields"],
            error="Elasticsearch field-capabilities response failed validation",
        )


def historical_schema_failure_result(
    r,
    body: dict,
    schema_discovery: dict,
) -> dict:
    status = str(schema_discovery.get("status") or "invalid_response")
    if status == "ok":
        status = "invalid_response"
        error = "Historical OSQuery field mapping is incompatible"
    else:
        error = str(schema_discovery.get("error") or "")
    return r.empty_search_result(
        body,
        r.PACKS["osquery_history"]["indices"],
        status,
        0,
        error=error,
    )


def execute_pack(r, pack_name: str, window: dict, observables: dict[str, list[str]], size: int) -> dict:
    pack = r.PACKS[pack_name]
    body = {
        "size": size,
        "track_total_hits": True,
        "timeout": "30s",
        "sort": [{"@timestamp": {"order": "asc", "unmapped_type": "date"}}, "_shard_doc"],
        "_source": pack["fields"],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": window["start"], "lte": window["end"]}}},
            r.dataset_clause(pack["datasets"]),
            r.observable_clause(observables, pack_name),
        ]}},
    }
    schema_discovery = (
        r.discover_historical_osquery_schema(observables)
        if pack_name == "osquery_history"
        else None
    )
    result = (
        r.historical_schema_failure_result(body, schema_discovery)
        if schema_discovery is not None
        and (
            schema_discovery.get("status") != "ok"
            or schema_discovery.get("mapping_compatible") is not True
        )
        else r.execute_search(body, pack["indices"])
    )
    if schema_discovery is not None:
        result["schema_discovery"] = schema_discovery
    return {"pack": pack_name, **result}


def pivot_query_dsl(r, query: dict) -> dict:
    pack = r.PACKS[query["pack"]]
    filters = [
        {"range": {"@timestamp": {
            "gte": query["window"]["start"],
            "lte": query["window"]["end"],
        }}},
        r.dataset_clause(pack["datasets"]),
        r.observable_clause(query["observables"], query["pack"]),
        *(
            [r.event_tuple_clause(query)]
            if query.get("event_tuple")
            else []
        ),
    ]
    filtered_query = {"bool": {"filter": filters}}
    if query["aggregation"] == "anchor_nearest":
        start = r.parse_time(query["window"]["start"])
        end = r.parse_time(query["window"]["end"])
        scale_seconds = max(1, round((end - start).total_seconds() / 2))
        compiled_query = {
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
    else:
        compiled_query = filtered_query
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


