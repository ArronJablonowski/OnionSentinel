"""Bounded evidence projection owner."""
from __future__ import annotations

import datetime as dt


import hashlib

import ipaddress


















def quoted_filter_value(r, value: str) -> str:
    # Exact observable validation excludes quote and backslash characters.
    return f'"{value}"'


def event_tuple_filter_value(r, field: str, value: object) -> str:
    if field in {"source_port", "destination_port"}:
        return str(value)
    return r.quoted_filter_value(str(value))


def render_pivot_event_tuple_filter(
    r,
    query: dict,
    *,
    alternate_separator: str,
    field_separator: str,
) -> str:
    event_tuple = query.get("event_tuple") or {}
    clauses = []
    for field in r.pivot_event_tuple_fields(query):
        value = r.event_tuple_filter_value(field, event_tuple[field])
        alternatives = [
            f"{path}{field_separator}{value}"
            for path in r.EVENT_TUPLE_PATHS[field]
        ]
        clauses.append(
            alternatives[0]
            if len(alternatives) == 1
            else "(" + f" {alternate_separator} ".join(alternatives) + ")"
        )
    joiner = " and " if alternate_separator == "or" else " AND "
    return joiner.join(clauses)


def pivot_kql_equivalent(r, query: dict) -> str:
    datasets = " or ".join(
        f"event.dataset : {r.quoted_filter_value(value)}"
        for value in r.PACKS[query["pack"]]["datasets"]
    )
    observable_filters = []
    for kind, fields in r.pack_observable_fields(query["pack"]).items():
        for value in query["observables"][kind]:
            observable_filters.append(
                "("
                + " or ".join(
                    f"{field} : {r.quoted_filter_value(value)}"
                    for field in fields
                )
                + ")"
            )
    rendered = (
        f'@timestamp >= {r.quoted_filter_value(query["window"]["start"])} and '
        f'@timestamp <= {r.quoted_filter_value(query["window"]["end"])} and '
        f"({datasets}) and (" + " or ".join(observable_filters) + ")"
    )
    if query.get("event_tuple"):
        rendered += " and (" + r.render_pivot_event_tuple_filter(
            query,
            alternate_separator="or",
            field_separator=" : ",
        ) + ")"
    return rendered


def pivot_oql_equivalent(r, query: dict) -> str:
    """Return real Hunt OQL while execution uses compiled equivalent DSL."""
    datasets = " OR ".join(
        f"event.dataset:{r.quoted_filter_value(value)}"
        for value in r.PACKS[query["pack"]]["datasets"]
    )
    observable_filters = []
    for kind, fields in r.pack_observable_fields(query["pack"]).items():
        for value in query["observables"][kind]:
            observable_filters.append(
                "("
                + " OR ".join(
                    f"{field}:{r.quoted_filter_value(value)}"
                    for field in fields
                )
                + ")"
            )
    rendered = (
        f'@timestamp:[{r.quoted_filter_value(query["window"]["start"])} TO '
        f'{r.quoted_filter_value(query["window"]["end"])}] AND '
        f"({datasets}) AND (" + " OR ".join(observable_filters) + ")"
    )
    if query.get("event_tuple"):
        rendered += " AND (" + r.render_pivot_event_tuple_filter(
            query,
            alternate_separator="OR",
            field_separator=":",
        ) + ")"
    if query["aggregation"] == "timeline":
        rendered += " | sortby @timestamp^"
    return rendered


def source_leaf_items(r, value: object, prefix: str = "") -> list[tuple[str, object]]:
    """Flatten returned ECS leaves without accepting unprojected siblings."""
    leaves: list[tuple[str, object]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            leaves.extend(r.source_leaf_items(child, path))
    elif isinstance(value, list):
        for child in value:
            leaves.extend(r.source_leaf_items(child, prefix))
    else:
        leaves.append((prefix, value))
    return leaves


def source_path_values(r, source: dict, path: str) -> list[object]:
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
    return [item for item in current if not isinstance(item, (dict, list))]


def returned_observable_matches(r, kind: str, expected: str, candidate: object) -> bool:
    text = str(candidate or "").strip().rstrip(".")
    if kind == "ips":
        try:
            return str(ipaddress.ip_address(text)) == expected
        except ValueError:
            return False
    if kind == "domains":
        return bool(r.SAFE_DOMAIN.fullmatch(text)) and text.lower() == expected
    return bool(r.SAFE_VALUE.fullmatch(text)) and text == expected


def returned_event_tuple_matches(r, field: str, expected: object, candidate: object) -> bool:
    text = str(candidate or "").strip()
    if field in {"source_ip", "destination_ip"}:
        try:
            return str(ipaddress.ip_address(text)) == expected
        except ValueError:
            return False
    if field in {"source_port", "destination_port"}:
        if isinstance(candidate, bool):
            return False
        try:
            return int(candidate) == expected
        except (TypeError, ValueError):
            return False
    if field in {"transport", "protocol"}:
        return bool(r.SAFE_VALUE.fullmatch(text.lower())) and text.lower() == expected
    if field == "community_id":
        return bool(r.SAFE_COMMUNITY_ID.fullmatch(text)) and text == expected
    return bool(r.SAFE_VALUE.fullmatch(text)) and text == expected


def valid_pivot_hit_source(r, source: object, query: dict) -> bool:
    if not isinstance(source, dict):
        return False
    pack = r.PACKS[query["pack"]]
    if any(
        path not in set(pack["fields"])
        for path, _value in r.source_leaf_items(source)
    ):
        return False
    timestamps = r.source_path_values(source, "@timestamp")
    if len(timestamps) != 1:
        return False
    timestamp_text = str(timestamps[0] or "").strip()
    if timestamp_text.endswith("Z"):
        timestamp_text = timestamp_text[:-1] + "+00:00"
    try:
        timestamp = dt.datetime.fromisoformat(timestamp_text)
    except ValueError:
        return False
    if timestamp.tzinfo is None or timestamp.utcoffset() != dt.timedelta(0):
        return False
    timestamp = timestamp.astimezone(dt.timezone.utc)
    start = r.parse_time(query["window"]["start"])
    end = r.parse_time(query["window"]["end"])
    if timestamp < start or timestamp > end:
        return False
    datasets = [str(item) for item in r.source_path_values(source, "event.dataset")]
    if len(datasets) != 1 or datasets[0] not in pack["datasets"]:
        return False
    observable_valid = any(
        r.returned_observable_matches(kind, expected, candidate)
        for kind, fields in r.pack_observable_fields(query["pack"]).items()
        for expected in query["observables"].get(kind, [])
        for field in fields
        for candidate in r.source_path_values(source, field)
    )
    if not observable_valid:
        return False
    event_tuple = query.get("event_tuple") or {}
    return all(
        any(
            r.returned_event_tuple_matches(field, expected, candidate)
            for path in r.EVENT_TUPLE_PATHS[field]
            for candidate in r.source_path_values(source, path)
        )
        for field in r.pivot_event_tuple_fields(query)
        for expected in (event_tuple[field],)
    )


def pivot_result_coverage(r, query: dict, result: dict) -> dict:
    status = str(result.get("status") or "")
    total_hits = int(result.get("total_hits") or 0)
    returned_hits = int(result.get("returned_hits") or 0)
    relation = str(result.get("total_hits_relation") or "")
    exact_total = status == "ok" and relation == "eq"
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


def execute_pivot_query(r, query: dict) -> dict:
    pack = r.PACKS[query["pack"]]
    body = r.pivot_query_dsl(query)
    kql = r.pivot_kql_equivalent(query)
    oql = r.pivot_oql_equivalent(query)
    schema_discovery = (
        r.discover_historical_osquery_schema(query["observables"])
        if query["pack"] == "osquery_history"
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
    if result.get("status") == "ok":
        invalid_projection = any(
            not isinstance(hit, dict)
            or not r.valid_pivot_hit_source(hit.get("source"), query)
            for hit in result.get("hits", [])
        )
        if invalid_projection or (
            query["aggregation"] == "count" and result.get("hits")
        ):
            result = r.empty_search_result(
                body,
                pack["indices"],
                "invalid_response",
                int(result.get("duration_ms") or 0),
                error="Elasticsearch returned data outside the reviewed pivot projection",
            )
    if schema_discovery is not None:
        result["schema_discovery"] = schema_discovery
    if query["aggregation"] == "count":
        # A size-zero exact count is an aggregate, not a truncated event list.
        result["truncated"] = result.get("total_hits_relation") != "eq"
    result["result_coverage"] = r.pivot_result_coverage(query, result)
    return {
        "query_id": query["query_id"],
        "dialect": query["dialect"],
        "pack": query["pack"],
        "purpose": query["purpose"],
        "window": query["window"],
        "observables": query["observables"],
        "observable_provenance": query["observable_provenance"],
        **(
            {
                "event_tuple": query["event_tuple"],
                "event_tuple_provenance": query["event_tuple_provenance"],
            }
            if query.get("event_tuple")
            else {}
        ),
        "size": query["size"],
        "aggregation": query["aggregation"],
        "match_semantics": query["match_semantics"],
        **(
            {"anchor_time": query["anchor_time"]}
            if query["aggregation"] == "anchor_nearest"
            else {}
        ),
        "request_item_digest": r.canonical_digest(query),
        "execution_backend": "so-elasticsearch-query",
        "execution_semantics": (
            "compiled_oql_equivalent"
            if query["dialect"] == "oql"
            else "compiled_elastic_pack"
        ),
        "kql_equivalent": kql,
        "kql_digest": hashlib.sha256(kql.encode("utf-8")).hexdigest(),
        "oql_equivalent": oql,
        "oql_digest": hashlib.sha256(oql.encode("utf-8")).hexdigest(),
        **result,
    }


def execute_controls(r, anchor: dict[str, str] | None) -> dict:
    if anchor is None:
        missing = {
            "status": "not_requested",
            "passed": False,
            "semantic_valid": False,
            "error": "A representative Security Onion alert anchor was not supplied",
        }
        return {
            "anchor": None,
            "positive_anchor": dict(missing),
            "negative_filter": dict(missing),
        }

    positive_body = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {"ids": {"values": [anchor["id"]]}},
    }
    # The positive control is bound to the exact trusted backing index, not
    # only the broader reviewed alert patterns. This prevents a duplicate ID
    # in another data stream from satisfying or confusing the anchor proof.
    positive = r.execute_search(positive_body, [anchor["index"]])
    exact_hits = [
        item for item in positive.get("hits", [])
        if item.get("id") == anchor["id"] and item.get("index") == anchor["index"]
    ]
    positive["passed"] = (
        positive.get("status") == "ok"
        and positive.get("total_hits_relation") == "eq"
        and positive.get("total_hits") == 1
        and len(exact_hits) == 1
    )
    if positive.get("status") == "ok" and not positive["passed"]:
        positive["error"] = "The exact representative alert anchor was not returned exactly once"

    # An intentionally contradictory query proves that the endpoint applied
    # the supplied filters rather than replaying or substituting the positive
    # control response.
    negative_body = {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {
            "bool": {
                "filter": [{"ids": {"values": [anchor["id"]]}}],
                "must_not": [{"ids": {"values": [anchor["id"]]}}],
            },
        },
    }
    negative = r.execute_search(negative_body, r.ALERT_INDEX_SCOPE)
    negative["passed"] = (
        negative.get("status") == "ok"
        and negative.get("total_hits_relation") == "eq"
        and negative.get("total_hits") == 0
        and negative.get("returned_hits") == 0
    )
    if negative.get("status") == "ok" and not negative["passed"]:
        negative["error"] = "The contradictory negative control unexpectedly returned hits"
    return {
        "anchor": anchor,
        "positive_anchor": positive,
        "negative_filter": negative,
    }


def semantic_validity(r, results: list[dict], osquery_results: list[dict], controls: dict) -> dict:
    query_execution_valid = all(
        result.get("status") == "ok" and result.get("semantic_valid") is True
        for result in results
    )
    osquery_valid = all(result.get("status") == "ok" for result in osquery_results)
    controls_valid = all(
        (controls.get(name) or {}).get("passed") is True
        for name in ("positive_anchor", "negative_filter")
    )
    coverage_valid = query_execution_valid and osquery_valid
    semantic_valid = controls_valid and coverage_valid
    reasons = []
    if not controls_valid:
        reasons.append("representative alert controls did not both pass")
    if not query_execution_valid:
        reasons.append("one or more Elasticsearch packs failed semantic validation")
    if not osquery_valid:
        reasons.append("one or more fixed local OSquery packs failed")
    return {
        "transport_valid": True,
        "controls_valid": controls_valid,
        "query_execution_valid": query_execution_valid,
        "coverage_valid": coverage_valid,
        "semantic_valid": semantic_valid,
        "reasons": reasons,
    }


def pivot_semantic_validity(r, results: list[dict], controls: dict) -> dict:
    query_execution_valid = all(
        result.get("status") == "ok" and result.get("semantic_valid") is True
        for result in results
    )
    controls_valid = all(
        (controls.get(name) or {}).get("passed") is True
        for name in ("positive_anchor", "negative_filter")
    )
    semantic_valid = controls_valid and query_execution_valid
    reasons = []
    if not controls_valid:
        reasons.append("representative alert controls did not both pass")
    if not query_execution_valid:
        reasons.append("one or more investigation pivots failed semantic validation")
    return {
        "transport_valid": True,
        "controls_valid": controls_valid,
        "query_execution_valid": query_execution_valid,
        "coverage_valid": query_execution_valid,
        "semantic_valid": semantic_valid,
        "reasons": reasons,
    }
