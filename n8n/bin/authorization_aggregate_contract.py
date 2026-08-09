#!/usr/bin/env python3
"""Shared contract for deterministic authorized-activity count evidence.

This module deliberately exposes no caller-authored query language.  A trusted
Mac-side collector may construct one optional request only after finding the
selected alert in an alert-store authorized-activity campaign.  The request is
the exact stored operator policy, split at UTC day boundaries.  Security Onion
then executes fixed ``size: 0`` searches and returns counts and provenance only;
event bodies never cross the restricted evidence lane.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
from typing import Any


AUTHORIZATION_AGGREGATE_VERSION = 1
AUTHORIZATION_AGGREGATE_SOURCE = (
    "selected_alert_campaign_membership_and_stored_operator_policy"
)
AUTHORIZATION_AGGREGATE_PARTITION_SCHEME = "utc_day_v1"
AUTHORIZATION_AGGREGATE_INDEX_SCOPE = [
    "logs-suricata.alerts-so",
    "logs-detections.alerts-so",
]
AUTHORIZATION_AGGREGATE_QUERY_PREFERENCE = (
    "onion-sentinel-incident-evidence"
)
MAX_AUTHORIZATION_AGGREGATE_DURATION = dt.timedelta(days=7)
MAX_AUTHORIZATION_AGGREGATE_PARTITIONS = 8
MAX_AUTHORIZATION_SELECTOR_VALUES = 100
MAX_AUTHORIZATION_PORT_RANGES = 20
MAX_AUTHORIZATION_AGGREGATE_REQUEST_BYTES = 12 * 1024
ALLOWED_SEARCH_STATUSES = {
    "ok",
    "timeout",
    "output_limit",
    "error",
    "invalid_response",
}
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=|/-]{1,1024}$")
SAFE_POLICY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,79}$")
SAFE_RULE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SAFE_PROTOCOL_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class AuthorizationAggregateContractError(ValueError):
    """An authorization aggregate escaped its exact bounded contract."""


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical_timestamp(value: object, label: str) -> tuple[str, dt.datetime]:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise AuthorizationAggregateContractError(
            f"{label} must be an ISO 8601 timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise AuthorizationAggregateContractError(f"{label} must include an offset")
    parsed = parsed.astimezone(dt.timezone.utc)
    return (
        parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        parsed,
    )


def _exact_keys(value: object, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AuthorizationAggregateContractError(
            f"{label} fields do not match the authorization aggregate contract"
        )
    return value


def _bounded_text(value: object, label: str, pattern: re.Pattern[str]) -> str:
    text = str(value or "").strip()
    if not pattern.fullmatch(text):
        raise AuthorizationAggregateContractError(f"{label} is invalid")
    return text


def _normalized_text_values(
    value: object,
    label: str,
    *,
    pattern: re.Pattern[str],
    lowercase: bool = False,
    required: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_AUTHORIZATION_SELECTOR_VALUES:
        raise AuthorizationAggregateContractError(f"{label} is not a bounded list")
    normalized = []
    for item in value:
        text = str(item or "").strip()
        if lowercase:
            text = text.lower()
        if not pattern.fullmatch(text):
            raise AuthorizationAggregateContractError(f"{label} contains an invalid value")
        if text not in normalized:
            normalized.append(text)
    normalized.sort()
    if required and not normalized:
        raise AuthorizationAggregateContractError(f"{label} must not be empty")
    return normalized


def _normalized_ips(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_AUTHORIZATION_SELECTOR_VALUES:
        raise AuthorizationAggregateContractError(f"{label} is not a bounded list")
    normalized: list[str] = []
    for item in value:
        try:
            text = str(ipaddress.ip_address(str(item or "").strip()))
        except ValueError as exc:
            raise AuthorizationAggregateContractError(
                f"{label} contains an invalid IP address"
            ) from exc
        if text not in normalized:
            normalized.append(text)
    return sorted(normalized)


def _normalized_ports(value: object, label: str) -> list[int]:
    if not isinstance(value, list) or len(value) > MAX_AUTHORIZATION_SELECTOR_VALUES:
        raise AuthorizationAggregateContractError(f"{label} is not a bounded list")
    normalized: list[int] = []
    for item in value:
        if isinstance(item, bool):
            raise AuthorizationAggregateContractError(f"{label} contains an invalid port")
        try:
            port = int(item)
        except (TypeError, ValueError) as exc:
            raise AuthorizationAggregateContractError(
                f"{label} contains an invalid port"
            ) from exc
        if port < 1 or port > 65535:
            raise AuthorizationAggregateContractError(f"{label} contains an invalid port")
        if port not in normalized:
            normalized.append(port)
    return sorted(normalized)


def _normalized_port_ranges(value: object) -> list[list[int]]:
    if not isinstance(value, list) or len(value) > MAX_AUTHORIZATION_PORT_RANGES:
        raise AuthorizationAggregateContractError(
            "destination_port_ranges is not a bounded list"
        )
    normalized: list[list[int]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2 or any(
            isinstance(part, bool) for part in item
        ):
            raise AuthorizationAggregateContractError(
                "destination_port_ranges contains an invalid range"
            )
        try:
            start, end = int(item[0]), int(item[1])
        except (TypeError, ValueError) as exc:
            raise AuthorizationAggregateContractError(
                "destination_port_ranges contains an invalid range"
            ) from exc
        if start < 1 or end > 65535 or start > end:
            raise AuthorizationAggregateContractError(
                "destination_port_ranges contains an invalid range"
            )
        candidate = [start, end]
        if candidate not in normalized:
            normalized.append(candidate)
    return sorted(normalized)


SELECTOR_KEYS = {
    "source_ips",
    "destination_ips",
    "rule_ids",
    "source_ports",
    "destination_ports",
    "destination_port_ranges",
    "transport_protocols",
}


def normalize_selectors(value: object) -> dict[str, Any]:
    selectors = _exact_keys(value, SELECTOR_KEYS, "authorization selectors")
    normalized = {
        "source_ips": _normalized_ips(selectors["source_ips"], "source_ips"),
        "destination_ips": _normalized_ips(
            selectors["destination_ips"], "destination_ips"
        ),
        "rule_ids": _normalized_text_values(
            selectors["rule_ids"],
            "rule_ids",
            pattern=SAFE_RULE_RE,
            required=True,
        ),
        "source_ports": _normalized_ports(selectors["source_ports"], "source_ports"),
        "destination_ports": _normalized_ports(
            selectors["destination_ports"], "destination_ports"
        ),
        "destination_port_ranges": _normalized_port_ranges(
            selectors["destination_port_ranges"]
        ),
        "transport_protocols": _normalized_text_values(
            selectors["transport_protocols"],
            "transport_protocols",
            pattern=SAFE_PROTOCOL_RE,
            lowercase=True,
            required=True,
        ),
    }
    if not normalized["source_ips"] and not normalized["destination_ips"]:
        raise AuthorizationAggregateContractError(
            "authorization selectors require an exact source or destination IP"
        )
    if (
        not normalized["destination_ports"]
        and not normalized["destination_port_ranges"]
    ):
        raise AuthorizationAggregateContractError(
            "authorization selectors require destination ports or ranges"
        )
    if not normalized["source_ports"]:
        raise AuthorizationAggregateContractError(
            "authorization aggregate requires explicit source port selectors"
        )
    return normalized


def utc_day_partitions(start: dt.datetime, end: dt.datetime) -> list[dict[str, Any]]:
    if end <= start or end - start > MAX_AUTHORIZATION_AGGREGATE_DURATION:
        raise AuthorizationAggregateContractError(
            "authorization aggregate window must be positive and no longer than 7 days"
        )
    partitions: list[dict[str, Any]] = []
    cursor = start
    while cursor < end:
        midnight = (cursor + dt.timedelta(days=1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        boundary = min(end, midnight)
        partitions.append(
            {
                "partition_index": len(partitions),
                "window": {
                    "start": cursor.isoformat(timespec="milliseconds").replace(
                        "+00:00", "Z"
                    ),
                    "end": boundary.isoformat(timespec="milliseconds").replace(
                        "+00:00", "Z"
                    ),
                },
                "end_inclusive": boundary == end,
            }
        )
        cursor = boundary
    if not partitions or len(partitions) > MAX_AUTHORIZATION_AGGREGATE_PARTITIONS:
        raise AuthorizationAggregateContractError(
            "authorization aggregate UTC-day partition count is out of bounds"
        )
    return partitions


REQUEST_KEYS = {
    "version",
    "source",
    "selected_alert_id",
    "campaign_id",
    "policy_id",
    "membership_observed_at",
    "campaign_window",
    "authorization_window",
    "selectors",
    "selector_digest",
    "partition_scheme",
    "partitions",
    "request_digest",
}


def build_authorization_aggregate_request(
    *,
    selected_alert_id: object,
    campaign_id: object,
    policy_id: object,
    membership_observed_at: object,
    campaign_window: object,
    authorization_window: object,
    selectors: object,
) -> dict[str, Any]:
    selected_id = _bounded_text(
        selected_alert_id, "selected alert id", SAFE_ID_RE
    )
    campaign = _bounded_text(campaign_id, "campaign id", SAFE_ID_RE)
    policy = _bounded_text(policy_id, "policy id", SAFE_POLICY_ID_RE)
    member_text, member_time = _canonical_timestamp(
        membership_observed_at, "membership observed_at"
    )
    campaign_map = _exact_keys(
        campaign_window, {"start", "end"}, "campaign window"
    )
    campaign_start_text, campaign_start = _canonical_timestamp(
        campaign_map["start"], "campaign window start"
    )
    campaign_end_text, campaign_end = _canonical_timestamp(
        campaign_map["end"], "campaign window end"
    )
    if (
        campaign_end <= campaign_start
        or campaign_end - campaign_start > dt.timedelta(hours=24)
        or not campaign_start <= member_time <= campaign_end
    ):
        raise AuthorizationAggregateContractError(
            "selected membership is outside its bounded campaign window"
        )
    authorization_map = _exact_keys(
        authorization_window, {"start", "end"}, "authorization window"
    )
    authorization_start_text, authorization_start = _canonical_timestamp(
        authorization_map["start"], "authorization window start"
    )
    authorization_end_text, authorization_end = _canonical_timestamp(
        authorization_map["end"], "authorization window end"
    )
    partitions = utc_day_partitions(authorization_start, authorization_end)
    if not authorization_start <= member_time <= authorization_end:
        raise AuthorizationAggregateContractError(
            "selected membership is outside the stored operator authorization window"
        )
    normalized_selectors = normalize_selectors(selectors)
    selector_scope = {
        "authorization_window": {
            "start": authorization_start_text,
            "end": authorization_end_text,
        },
        "selectors": normalized_selectors,
    }
    request: dict[str, Any] = {
        "version": AUTHORIZATION_AGGREGATE_VERSION,
        "source": AUTHORIZATION_AGGREGATE_SOURCE,
        "selected_alert_id": selected_id,
        "campaign_id": campaign,
        "policy_id": policy,
        "membership_observed_at": member_text,
        "campaign_window": {
            "start": campaign_start_text,
            "end": campaign_end_text,
        },
        "authorization_window": selector_scope["authorization_window"],
        "selectors": normalized_selectors,
        "selector_digest": canonical_digest(selector_scope),
        "partition_scheme": AUTHORIZATION_AGGREGATE_PARTITION_SCHEME,
        "partitions": partitions,
    }
    request["request_digest"] = canonical_digest(request)
    encoded = json.dumps(request, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    if len(encoded) > MAX_AUTHORIZATION_AGGREGATE_REQUEST_BYTES:
        raise AuthorizationAggregateContractError(
            "authorization aggregate request exceeds its byte bound"
        )
    return request


def validate_authorization_aggregate_request(value: object) -> dict[str, Any]:
    request = _exact_keys(value, REQUEST_KEYS, "authorization aggregate request")
    rebuilt = build_authorization_aggregate_request(
        selected_alert_id=request["selected_alert_id"],
        campaign_id=request["campaign_id"],
        policy_id=request["policy_id"],
        membership_observed_at=request["membership_observed_at"],
        campaign_window=request["campaign_window"],
        authorization_window=request["authorization_window"],
        selectors=request["selectors"],
    )
    if request != rebuilt:
        raise AuthorizationAggregateContractError(
            "authorization aggregate request is not canonical or digest-bound"
        )
    return request


def authorization_aggregate_query_endpoint() -> str:
    return (
        f"{','.join(AUTHORIZATION_AGGREGATE_INDEX_SCOPE)}/_search"
        "?expand_wildcards=open"
        f"&preference={AUTHORIZATION_AGGREGATE_QUERY_PREFERENCE}"
    )


def _one_or_many_terms(field: str, values: list[object]) -> dict[str, Any]:
    if len(values) == 1:
        return {"term": {field: values[0]}}
    return {"terms": {field: values}}


def _precedence_fields_clause(
    primary_field: str,
    fallback_field: str,
    values: list[object],
) -> dict[str, Any]:
    """Match admission semantics: primary value, else fallback when absent."""
    return {
        "bool": {
            "should": [
                _one_or_many_terms(primary_field, values),
                {
                    "bool": {
                        "filter": [
                            {
                                "bool": {
                                    "must_not": [
                                        {"exists": {"field": primary_field}}
                                    ]
                                }
                            },
                            _one_or_many_terms(fallback_field, values),
                        ]
                    }
                },
            ],
            "minimum_should_match": 1,
        }
    }


def build_authorization_aggregate_query_dsl(
    request: object,
    partition: object,
) -> dict[str, Any]:
    authorized = validate_authorization_aggregate_request(request)
    if partition not in authorized["partitions"]:
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition is not request-authorized"
        )
    partition_map = partition
    time_operator = "lte" if partition_map["end_inclusive"] else "lt"
    filters: list[dict[str, Any]] = [
        {
            "range": {
                "@timestamp": {
                    "gte": partition_map["window"]["start"],
                    time_operator: partition_map["window"]["end"],
                }
            }
        }
    ]
    selectors = authorized["selectors"]
    if selectors["source_ips"]:
        filters.append(_one_or_many_terms("source.ip", selectors["source_ips"]))
    if selectors["destination_ips"]:
        filters.append(
            _one_or_many_terms("destination.ip", selectors["destination_ips"])
        )
    # Alert admission maps the exported top-level ``rule_id`` from ECS
    # ``rule.uuid``.  A conflicting ``rule.id`` therefore cannot rescue a
    # nonmatching UUID; it is consulted only for older documents with no UUID.
    filters.append(
        _precedence_fields_clause("rule.uuid", "rule.id", selectors["rule_ids"])
    )
    if selectors["source_ports"]:
        filters.append(_one_or_many_terms("source.port", selectors["source_ports"]))
    destination_clauses = []
    if selectors["destination_ports"]:
        destination_clauses.append(
            _one_or_many_terms("destination.port", selectors["destination_ports"])
        )
    destination_clauses.extend(
        {
            "range": {
                "destination.port": {"gte": start, "lte": end}
            }
        }
        for start, end in selectors["destination_port_ranges"]
    )
    # Alert admission likewise prefers ``network.transport`` and consults
    # ``network.protocol`` only when transport is absent.
    filters.append(
        destination_clauses[0]
        if len(destination_clauses) == 1
        else {
            "bool": {
                "should": destination_clauses,
                "minimum_should_match": 1,
            }
        }
    )
    filters.append(
        _precedence_fields_clause(
            "network.transport",
            "network.protocol",
            selectors["transport_protocols"],
        )
    )
    return {
        "size": 0,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": False,
        "query": {"bool": {"filter": filters}},
        "aggs": {
            "by_source_port": {
                "terms": {
                    "field": "source.port",
                    "size": len(selectors["source_ports"]),
                    "min_doc_count": 1,
                    "order": {"_key": "asc"},
                }
            }
        },
    }


def authorization_aggregate_execution_digest(query_dsl: dict[str, Any]) -> str:
    return canonical_digest(
        {
            "index_scope": AUTHORIZATION_AGGREGATE_INDEX_SCOPE,
            "query_endpoint": authorization_aggregate_query_endpoint(),
            "query_dsl": query_dsl,
        }
    )


def bind_authorization_aggregate_partition_result(
    request: object,
    partition: object,
    search_result: object,
) -> dict[str, Any]:
    authorized = validate_authorization_aggregate_request(request)
    if partition not in authorized["partitions"]:
        raise AuthorizationAggregateContractError(
            "authorization aggregate result partition is not request-authorized"
        )
    if not isinstance(search_result, dict):
        raise AuthorizationAggregateContractError(
            "authorization aggregate search result must be an object"
        )
    query_dsl = build_authorization_aggregate_query_dsl(authorized, partition)
    result = {
        "partition_index": partition["partition_index"],
        "window": partition["window"],
        "end_inclusive": partition["end_inclusive"],
        **search_result,
    }
    if result.get("query_dsl") != query_dsl:
        raise AuthorizationAggregateContractError(
            "authorization aggregate exact query DSL changed during execution"
        )
    result["result_digest"] = canonical_digest(result)
    return result


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuthorizationAggregateContractError(
            f"authorization aggregate {label} is invalid"
        )
    return value


def _validate_shards(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationAggregateContractError(
            "authorization aggregate shard metadata is missing"
        )
    if set(value) != {"total", "successful", "skipped", "failed", "failures"}:
        raise AuthorizationAggregateContractError(
            "authorization aggregate shard metadata fields are invalid"
        )
    for key in ("total", "successful", "skipped", "failed"):
        _nonnegative_int(value.get(key), f"shards.{key}")
    if value["successful"] > value["total"] or value["failed"] > value["total"]:
        raise AuthorizationAggregateContractError(
            "authorization aggregate shard counts are inconsistent"
        )
    failures = value.get("failures")
    if not isinstance(failures, list) or len(failures) > 20:
        raise AuthorizationAggregateContractError(
            "authorization aggregate shard failures are invalid"
        )
    if any(
        not isinstance(item, dict)
        or set(item) != {"index", "type", "reason"}
        or any(not isinstance(item[key], str) for key in item)
        or len(item["index"]) > 255
        or len(item["type"]) > 255
        or len(item["reason"]) > 1000
        for item in failures
    ):
        raise AuthorizationAggregateContractError(
            "authorization aggregate shard failure diagnostics are invalid"
        )
    return value


def _validate_source_port_buckets(
    value: object,
    authorized_ports: list[int],
) -> list[dict[str, int]]:
    if not isinstance(value, list) or len(value) > len(authorized_ports):
        raise AuthorizationAggregateContractError(
            "authorization aggregate source-port buckets are out of bounds"
        )
    normalized: list[dict[str, int]] = []
    seen: set[int] = set()
    for item in value:
        if not isinstance(item, dict) or set(item) != {"source_port", "exact_count"}:
            raise AuthorizationAggregateContractError(
                "authorization aggregate source-port bucket fields are invalid"
            )
        source_port = item.get("source_port")
        exact_count = item.get("exact_count")
        if (
            isinstance(source_port, bool)
            or not isinstance(source_port, int)
            or source_port not in authorized_ports
            or source_port in seen
            or isinstance(exact_count, bool)
            or not isinstance(exact_count, int)
            or exact_count < 1
        ):
            raise AuthorizationAggregateContractError(
                "authorization aggregate source-port bucket is invalid"
            )
        seen.add(source_port)
        normalized.append(
            {"source_port": source_port, "exact_count": exact_count}
        )
    if normalized != sorted(normalized, key=lambda item: item["source_port"]):
        raise AuthorizationAggregateContractError(
            "authorization aggregate source-port buckets are not ordered"
        )
    return normalized


def _validate_partition_result(
    request: dict[str, Any],
    partition: dict[str, Any],
    value: object,
) -> tuple[dict[str, Any], bool]:
    if not isinstance(value, dict):
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition result must be an object"
        )
    required_fields = {
        "partition_index",
        "window",
        "end_inclusive",
        "query_digest",
        "execution_digest",
        "query_dsl",
        "index_scope",
        "query_endpoint",
        "status",
        "semantic_valid",
        "total_hits",
        "total_hits_relation",
        "returned_hits",
        "truncated",
        "duration_ms",
        "timed_out",
        "took_ms",
        "shards",
        "hits",
        "source_port_buckets",
        "result_digest",
    }
    if frozenset(value) not in {
        frozenset(required_fields),
        frozenset(required_fields | {"error"}),
    }:
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition result fields are invalid"
        )
    if "error" in value and (
        not isinstance(value["error"], str) or len(value["error"]) > 1000
    ):
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition error is invalid"
        )
    if (
        value.get("partition_index") != partition["partition_index"]
        or value.get("window") != partition["window"]
        or value.get("end_inclusive") is not partition["end_inclusive"]
    ):
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition coverage changed in transit"
        )
    query_dsl = build_authorization_aggregate_query_dsl(request, partition)
    expected_query_digest = canonical_digest(query_dsl)
    expected_execution_digest = authorization_aggregate_execution_digest(query_dsl)
    if (
        value.get("query_dsl") != query_dsl
        or value.get("query_digest") != expected_query_digest
        or value.get("execution_digest") != expected_execution_digest
        or value.get("index_scope") != AUTHORIZATION_AGGREGATE_INDEX_SCOPE
        or value.get("query_endpoint") != authorization_aggregate_query_endpoint()
    ):
        raise AuthorizationAggregateContractError(
            "authorization aggregate query provenance is invalid"
        )
    status = str(value.get("status") or "")
    if status not in ALLOWED_SEARCH_STATUSES:
        raise AuthorizationAggregateContractError(
            "authorization aggregate search status is unsupported"
        )
    total = _nonnegative_int(value.get("total_hits"), "total_hits")
    returned = _nonnegative_int(value.get("returned_hits"), "returned_hits")
    if returned != 0 or value.get("hits") != []:
        raise AuthorizationAggregateContractError(
            "authorization aggregate must never contain event bodies"
        )
    relation = value.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise AuthorizationAggregateContractError(
            "authorization aggregate total hit relation is invalid"
        )
    for key in ("duration_ms", "took_ms"):
        _nonnegative_int(value.get(key), key)
    shards = _validate_shards(value.get("shards"))
    source_port_buckets = _validate_source_port_buckets(
        value.get("source_port_buckets"),
        request["selectors"]["source_ports"],
    )
    semantic_valid = value.get("semantic_valid") is True
    complete = (
        status == "ok"
        and semantic_valid
        and relation == "eq"
        and value.get("timed_out") is False
        and value.get("truncated") is False
        and shards["total"] > 0
        and shards["successful"] == shards["total"]
        and shards["failed"] == 0
    )
    if complete and sum(
        item["exact_count"] for item in source_port_buckets
    ) != total:
        raise AuthorizationAggregateContractError(
            "authorization aggregate source-port buckets do not sum to exact total"
        )
    if not complete and source_port_buckets:
        raise AuthorizationAggregateContractError(
            "incomplete authorization aggregate partition cannot publish exact source-port buckets"
        )
    if value.get("result_digest") != canonical_digest(
        {key: item for key, item in value.items() if key != "result_digest"}
    ):
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition result digest is invalid"
        )
    return value, complete


def build_authorization_aggregate_response(
    request: object,
    partition_results: object,
) -> dict[str, Any]:
    authorized = validate_authorization_aggregate_request(request)
    if not isinstance(partition_results, list) or len(partition_results) != len(
        authorized["partitions"]
    ):
        raise AuthorizationAggregateContractError(
            "authorization aggregate partition response coverage is incomplete"
        )
    normalized_results: list[dict[str, Any]] = []
    completion: list[bool] = []
    for partition, value in zip(authorized["partitions"], partition_results):
        normalized, complete = _validate_partition_result(
            authorized, partition, value
        )
        normalized_results.append(normalized)
        completion.append(complete)
    all_complete = all(completion)
    buckets = [
        {
            "partition_index": result["partition_index"],
            "window": result["window"],
            "end_inclusive": result["end_inclusive"],
            "status": result["status"],
            "exact_count": result["total_hits"] if complete else None,
            "query_digest": result["query_digest"],
            "execution_digest": result["execution_digest"],
            "shards_digest": canonical_digest(result["shards"]),
            "source_port_buckets": result["source_port_buckets"],
            "source_port_buckets_digest": canonical_digest(
                result["source_port_buckets"]
            ),
            "result_digest": result["result_digest"],
        }
        for result, complete in zip(normalized_results, completion)
    ]
    merged_source_ports = [
        {
            "source_port": source_port,
            "exact_count": (
                sum(
                    next(
                        (
                            bucket["exact_count"]
                            for bucket in result["source_port_buckets"]
                            if bucket["source_port"] == source_port
                        ),
                        0,
                    )
                    for result in normalized_results
                )
                if all_complete
                else None
            ),
        }
        for source_port in authorized["selectors"]["source_ports"]
    ]
    merged = {
        "complete": all_complete,
        "partition_count": len(normalized_results),
        "complete_partition_count": sum(1 for item in completion if item),
        "exact_count": (
            sum(result["total_hits"] for result in normalized_results)
            if all_complete
            else None
        ),
        "buckets": buckets,
        "buckets_digest": canonical_digest(buckets),
        "source_port_buckets": merged_source_ports,
        "source_port_buckets_digest": canonical_digest(merged_source_ports),
    }
    merged["merged_digest"] = canonical_digest(merged)
    response: dict[str, Any] = {
        "version": AUTHORIZATION_AGGREGATE_VERSION,
        "request_digest": authorized["request_digest"],
        "selector_digest": authorized["selector_digest"],
        "read_only": True,
        "event_bodies_returned": 0,
        "index_scope": AUTHORIZATION_AGGREGATE_INDEX_SCOPE,
        "partition_scheme": AUTHORIZATION_AGGREGATE_PARTITION_SCHEME,
        "complete": all_complete,
        "partial": not all_complete,
        "partitions": normalized_results,
        "merged": merged,
    }
    response["aggregate_digest"] = canonical_digest(response)
    return response


def validate_authorization_aggregate_response(
    value: object,
    request: object,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AuthorizationAggregateContractError(
            "authorization aggregate response must be an object"
        )
    rebuilt = build_authorization_aggregate_response(
        request, value.get("partitions")
    )
    if value != rebuilt:
        raise AuthorizationAggregateContractError(
            "authorization aggregate response or merged provenance is invalid"
        )
    return value
