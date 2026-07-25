#!/usr/bin/env python3
"""Validate restricted Security Onion incident-evidence artifacts.

The Security Onion wrapper is the only component allowed to construct and
execute Elasticsearch Query DSL. Downstream workers use this module to make
sure the immutable artifact still contains every requested pack/window pair,
the reviewed index scope, shard metadata, human-readable KQL equivalent, exact
digest-matched DSL, and representative-alert controls. Partial query results
are valid evidence gaps; transport success without semantic validity is not a
complete evidence result.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from typing import Any


INCIDENT_EVIDENCE_CONTRACT = "onion-sentinel-incident-evidence-v2"
LEGACY_INCIDENT_EVIDENCE_CONTRACT = "onion-sentinel-incident-evidence-v1"
QUERY_PREFERENCE = "onion-sentinel-incident-evidence"
ALERT_INDEX_SCOPE = [
    "logs-suricata.alerts-so",
    "logs-detections.alerts-so",
]
PACK_INDEX_SCOPES = {
    "alert_context": ALERT_INDEX_SCOPE,
    "network_flow": [
        "logs-zeek.connection-*",
        "logs-endpoint.events.network-*",
        *ALERT_INDEX_SCOPE,
    ],
    "dns_activity": [
        "logs-zeek.dns-*",
        "logs-endpoint.events.network-*",
    ],
    "osquery_history": [
        "logs-endpoint.events.process-*",
        "logs-endpoint.events.file-*",
        "logs-endpoint.events.network-*",
        "logs-osquery_manager.result-*",
        "logs-osquery_manager.response-*",
    ],
    "cross_sensor_timeline": [
        *ALERT_INDEX_SCOPE,
        "logs-zeek.connection-*",
        "logs-zeek.dns-*",
        "logs-endpoint.events.network-*",
        "logs-endpoint.events.process-*",
        "logs-endpoint.events.file-*",
    ],
}
ALLOWED_PACKS = {
    "alert_context",
    "network_flow",
    "dns_activity",
    "osquery_history",
    "cross_sensor_timeline",
}
OSQUERY_PACKS = {
    "system_inventory": (
        "SELECT hostname, uuid, cpu_brand, cpu_physical_cores, "
        "cpu_logical_cores, physical_memory, hardware_vendor, hardware_model "
        "FROM system_info LIMIT 1;"
    ),
    "logged_in_users": (
        "SELECT user, tty, host, time, type, pid FROM logged_in_users "
        "ORDER BY time DESC LIMIT 100;"
    ),
    "listening_ports": (
        "SELECT lp.protocol, lp.address, lp.port, lp.pid, p.name, p.path "
        "FROM listening_ports AS lp LEFT JOIN processes AS p ON lp.pid = p.pid "
        "ORDER BY lp.port LIMIT 200;"
    ),
    "process_inventory": (
        "SELECT pid, parent, name, path, uid, gid, start_time FROM processes "
        "ORDER BY pid LIMIT 200;"
    ),
    "installed_packages": (
        "SELECT name, version, release, source, arch FROM rpm_packages "
        "ORDER BY name LIMIT 200;"
    ),
    "scheduled_tasks": (
        "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path "
        "FROM crontab ORDER BY path LIMIT 200;"
    ),
    "startup_items": (
        "SELECT name, path, args, type, status, source FROM startup_items "
        "ORDER BY name LIMIT 200;"
    ),
}
ALLOWED_STATUSES = {"ok", "timeout", "output_limit", "error", "invalid_response"}
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SAFE_ELASTIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=-]{1,512}$")
MAX_OSQUERY_ROWS = 200
MAX_ELASTIC_HITS = 200


class IncidentEvidenceContractError(ValueError):
    """The restricted incident-evidence chain could not be authenticated."""


def _require_mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IncidentEvidenceContractError(f"{label} must be an object")
    return value


def _require_nonempty_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise IncidentEvidenceContractError(f"{label} must be non-empty")
    return text


def _canonical_dsl_digest(query_dsl: dict[str, Any]) -> str:
    encoded = json.dumps(query_dsl, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _canonical_execution_digest(
    query_dsl: dict[str, Any],
    index_scope: list[str],
    query_endpoint: str,
) -> str:
    encoded = json.dumps(
        {
            "index_scope": index_scope,
            "query_endpoint": query_endpoint,
            "query_dsl": query_dsl,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _query_digest(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def _query_endpoint(index_scope: list[str]) -> str:
    return (
        f"{','.join(index_scope)}/_search"
        f"?ignore_unavailable=true&expand_wildcards=open&preference={QUERY_PREFERENCE}"
    )


def _index_matches_scope(index_name: str, index_scope: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(index_name, pattern)
        or fnmatch.fnmatchcase(index_name, f".ds-{pattern}-*")
        for pattern in index_scope
    )


def _validate_anchor(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    anchor = _require_mapping(value, "representative alert anchor")
    index_name = _require_nonempty_text(anchor.get("index"), "representative alert anchor index")
    document_id = _require_nonempty_text(anchor.get("id"), "representative alert anchor id")
    if (
        "*" in index_name
        or "?" in index_name
        or not _index_matches_scope(index_name, ALERT_INDEX_SCOPE)
    ):
        raise IncidentEvidenceContractError(
            "representative alert anchor index is outside the reviewed alert scope"
        )
    if not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
        raise IncidentEvidenceContractError("representative alert anchor id is invalid")
    return {"index": index_name, "id": document_id}


def _positive_control_dsl(anchor: dict[str, str]) -> dict[str, Any]:
    return {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {"ids": {"values": [anchor["id"]]}},
    }


def _negative_control_dsl(anchor: dict[str, str]) -> dict[str, Any]:
    return {
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


def _require_nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IncidentEvidenceContractError(f"{label} must be a non-negative integer")
    return value


def _validate_search_result(
    result: dict[str, Any],
    *,
    label: str,
    expected_scope: list[str],
    max_hits: int,
) -> bool:
    status = _require_nonempty_text(result.get("status"), f"{label} status")
    if status not in ALLOWED_STATUSES:
        raise IncidentEvidenceContractError(f"unsupported {label} status: {status}")

    index_scope = result.get("index_scope")
    if index_scope != expected_scope:
        raise IncidentEvidenceContractError(f"{label} index scope does not match its reviewed pack")
    endpoint = _require_nonempty_text(result.get("query_endpoint"), f"{label} query endpoint")
    if endpoint != _query_endpoint(expected_scope):
        raise IncidentEvidenceContractError(f"{label} query endpoint is outside its reviewed index scope")

    query_dsl = _require_mapping(result.get("query_dsl"), f"{label} exact query DSL")
    if not query_dsl:
        raise IncidentEvidenceContractError(f"{label} exact query DSL must be non-empty")
    digest = _require_nonempty_text(result.get("query_digest"), f"{label} query digest")
    if not SHA256_RE.fullmatch(digest) or _canonical_dsl_digest(query_dsl) != digest:
        raise IncidentEvidenceContractError(f"{label} exact query DSL does not match its wrapper digest")
    execution_digest = _require_nonempty_text(
        result.get("execution_digest"),
        f"{label} execution digest",
    )
    if (
        not SHA256_RE.fullmatch(execution_digest)
        or _canonical_execution_digest(query_dsl, index_scope, endpoint) != execution_digest
    ):
        raise IncidentEvidenceContractError(
            f"{label} query DSL/index execution manifest does not match its wrapper digest"
        )

    hits = result.get("hits")
    if not isinstance(hits, list) or len(hits) > max_hits:
        raise IncidentEvidenceContractError(f"{label} hits exceed their result contract")
    for item in hits:
        hit = _require_mapping(item, f"{label} hit")
        document_id = _require_nonempty_text(hit.get("id"), f"{label} hit id")
        index_name = _require_nonempty_text(hit.get("index"), f"{label} hit index")
        if not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
            raise IncidentEvidenceContractError(f"{label} hit id is invalid")
        if not _index_matches_scope(index_name, expected_scope):
            raise IncidentEvidenceContractError(f"{label} returned an out-of-scope hit index")
        _require_mapping(hit.get("source"), f"{label} hit source")

    returned_hits = _require_nonnegative_int(result.get("returned_hits"), f"{label} returned_hits")
    total_hits = _require_nonnegative_int(result.get("total_hits"), f"{label} total_hits")
    if returned_hits != len(hits) or total_hits < returned_hits:
        raise IncidentEvidenceContractError(f"{label} hit counts do not match its result set")
    relation = result.get("total_hits_relation")
    if relation not in {"eq", "gte"}:
        raise IncidentEvidenceContractError(f"{label} total_hits_relation is invalid")
    expected_truncated = relation != "eq" or total_hits > returned_hits
    if result.get("truncated") is not expected_truncated:
        raise IncidentEvidenceContractError(f"{label} truncated flag does not match its hit counts")
    projection = result.get("prompt_projection")
    if projection is not None:
        projection = _require_mapping(projection, f"{label} prompt projection")
        if projection.get("version") != 1:
            raise IncidentEvidenceContractError(f"{label} prompt projection version is invalid")
        source_returned = _require_nonnegative_int(
            projection.get("source_returned_hits"),
            f"{label} prompt projection source_returned_hits",
        )
        source_total = _require_nonnegative_int(
            projection.get("source_total_hits"),
            f"{label} prompt projection source_total_hits",
        )
        if (
            source_returned <= returned_hits
            or source_returned > max_hits
            or source_total != total_hits
            or source_total < source_returned
        ):
            raise IncidentEvidenceContractError(
                f"{label} prompt projection source counts are inconsistent"
            )
        source_truncated = projection.get("source_truncated")
        expected_source_truncated = relation != "eq" or source_total > source_returned
        if source_truncated is not expected_source_truncated:
            raise IncidentEvidenceContractError(
                f"{label} prompt projection source truncated flag is inconsistent"
            )
        source_digest = projection.get("source_hits_sha256")
        if not isinstance(source_digest, str) or not SHA256_RE.fullmatch(source_digest):
            raise IncidentEvidenceContractError(
                f"{label} prompt projection source digest is invalid"
            )
        retained_hits = _require_nonnegative_int(
            projection.get("retained_hits"),
            f"{label} prompt projection retained_hits",
        )
        reasons = projection.get("reasons")
        if (
            retained_hits != returned_hits
            or not isinstance(reasons, list)
            or not reasons
            or any(
                not isinstance(reason, str)
                or not reason.strip()
                or len(reason) > 100
                for reason in reasons
            )
        ):
            raise IncidentEvidenceContractError(
                f"{label} prompt projection metadata is inconsistent"
            )

    _require_nonnegative_int(result.get("duration_ms"), f"{label} duration_ms")
    timed_out = result.get("timed_out")
    if not isinstance(timed_out, bool):
        raise IncidentEvidenceContractError(f"{label} timed_out must be boolean")
    _require_nonnegative_int(result.get("took_ms"), f"{label} took_ms")
    shards = _require_mapping(result.get("shards"), f"{label} shards")
    total_shards = _require_nonnegative_int(shards.get("total"), f"{label} shard total")
    successful_shards = _require_nonnegative_int(
        shards.get("successful"),
        f"{label} successful shards",
    )
    failed_shards = _require_nonnegative_int(shards.get("failed"), f"{label} failed shards")
    _require_nonnegative_int(shards.get("skipped"), f"{label} skipped shards")
    failures = shards.get("failures")
    if not isinstance(failures, list) or any(not isinstance(item, dict) for item in failures):
        raise IncidentEvidenceContractError(f"{label} shard failures must be an array of objects")
    if failed_shards > total_shards or successful_shards > total_shards:
        raise IncidentEvidenceContractError(f"{label} shard counts are inconsistent")

    expected_semantic_valid = (
        status == "ok"
        and not timed_out
        and failed_shards == 0
        and total_shards > 0
        and successful_shards > 0
    )
    if result.get("semantic_valid") is not expected_semantic_valid:
        raise IncidentEvidenceContractError(f"{label} semantic_valid flag is inconsistent")
    if status != "ok" and hits:
        raise IncidentEvidenceContractError(f"{label} failed response must not expose partial hits")
    return expected_semantic_valid


def _validate_controls(
    request_anchor: dict[str, str] | None,
    response: dict[str, Any],
) -> bool:
    controls = _require_mapping(response.get("controls"), "query controls")
    if controls.get("anchor") != request_anchor:
        raise IncidentEvidenceContractError("query control anchor does not match the request")
    positive = _require_mapping(controls.get("positive_anchor"), "positive anchor control")
    negative = _require_mapping(controls.get("negative_filter"), "negative filter control")

    if request_anchor is None:
        for label, control in (
            ("positive anchor control", positive),
            ("negative filter control", negative),
        ):
            if (
                control.get("status") != "not_requested"
                or control.get("passed") is not False
                or control.get("semantic_valid") is not False
            ):
                raise IncidentEvidenceContractError(f"{label} must fail closed without an anchor")
        return False

    positive_valid = _validate_search_result(
        positive,
        label="positive anchor control",
        expected_scope=ALERT_INDEX_SCOPE,
        max_hits=1,
    )
    if positive.get("query_dsl") != _positive_control_dsl(request_anchor):
        raise IncidentEvidenceContractError("positive anchor control query is not the reviewed query")
    exact_hits = [
        item for item in positive["hits"]
        if item["id"] == request_anchor["id"] and item["index"] == request_anchor["index"]
    ]
    expected_positive_pass = (
        positive_valid
        and positive["total_hits_relation"] == "eq"
        and positive["total_hits"] == 1
        and len(exact_hits) == 1
    )
    if positive.get("passed") is not expected_positive_pass:
        raise IncidentEvidenceContractError("positive anchor control passed flag is inconsistent")

    negative_valid = _validate_search_result(
        negative,
        label="negative filter control",
        expected_scope=ALERT_INDEX_SCOPE,
        max_hits=1,
    )
    if negative.get("query_dsl") != _negative_control_dsl(request_anchor):
        raise IncidentEvidenceContractError("negative filter control query is not the reviewed query")
    expected_negative_pass = (
        negative_valid
        and negative["total_hits_relation"] == "eq"
        and negative["total_hits"] == 0
        and negative["returned_hits"] == 0
    )
    if negative.get("passed") is not expected_negative_pass:
        raise IncidentEvidenceContractError("negative filter control passed flag is inconsistent")
    return expected_positive_pass and expected_negative_pass


def _validate_osquery_results(
    request: dict[str, Any],
    response: dict[str, Any],
) -> list[str]:
    requested = request.get("osquery_packs")
    if not isinstance(requested, list) or not requested:
        raise IncidentEvidenceContractError("incident evidence request has no OSquery packs")
    requested_names = [str(item) for item in requested]
    if len(requested_names) != len(set(requested_names)):
        raise IncidentEvidenceContractError("incident evidence request contains duplicate OSquery packs")
    if any(name not in OSQUERY_PACKS for name in requested_names):
        raise IncidentEvidenceContractError("incident evidence request contains an unsupported OSquery pack")

    results = response.get("osquery_results")
    if not isinstance(results, list) or len(results) != len(requested_names):
        raise IncidentEvidenceContractError(
            f"incident evidence response must contain {len(requested_names)} OSquery result(s)"
        )

    observed: set[str] = set()
    statuses: list[str] = []
    for result_index, raw_result in enumerate(results):
        result = _require_mapping(raw_result, f"OSquery result {result_index + 1}")
        pack = _require_nonempty_text(result.get("pack"), "OSquery pack")
        if pack not in requested_names or pack in observed:
            raise IncidentEvidenceContractError("OSquery pack coverage is invalid or duplicated")
        observed.add(pack)
        status = _require_nonempty_text(result.get("status"), "OSquery status")
        if status not in ALLOWED_STATUSES:
            raise IncidentEvidenceContractError(f"unsupported OSquery status: {status}")
        target = _require_nonempty_text(result.get("target"), "OSquery target")
        if target != "security-onion-local-host":
            raise IncidentEvidenceContractError("OSquery target is not the Security Onion local host")

        query = _require_nonempty_text(result.get("query"), "exact OSquery SQL")
        if query != OSQUERY_PACKS[pack]:
            raise IncidentEvidenceContractError("exact OSquery SQL does not match its reviewed pack")
        digest = _require_nonempty_text(result.get("query_digest"), "OSquery digest")
        if not SHA256_RE.fullmatch(digest) or _query_digest(query) != digest:
            raise IncidentEvidenceContractError("exact OSquery SQL does not match its wrapper digest")

        rows = result.get("rows")
        if not isinstance(rows, list) or len(rows) > MAX_OSQUERY_ROWS:
            raise IncidentEvidenceContractError("OSquery rows exceed their result contract")
        if any(not isinstance(row, dict) for row in rows):
            raise IncidentEvidenceContractError("OSquery rows must contain objects")
        returned_rows = result.get("returned_rows")
        if isinstance(returned_rows, bool) or not isinstance(returned_rows, int):
            raise IncidentEvidenceContractError("OSquery returned_rows must be an integer")
        if returned_rows != len(rows):
            raise IncidentEvidenceContractError("OSquery returned_rows does not match its row set")
        total_rows = result.get("total_rows")
        if isinstance(total_rows, bool) or not isinstance(total_rows, int) or total_rows < returned_rows:
            raise IncidentEvidenceContractError("OSquery total_rows is invalid")
        if result.get("truncated") is not (total_rows > returned_rows):
            raise IncidentEvidenceContractError("OSquery truncated flag does not match its row counts")
        duration_ms = result.get("duration_ms")
        if isinstance(duration_ms, bool) or not isinstance(duration_ms, int) or duration_ms < 0:
            raise IncidentEvidenceContractError("OSquery duration_ms must be a non-negative integer")
        statuses.append(status)

    if observed != set(requested_names):
        raise IncidentEvidenceContractError("OSquery result coverage is incomplete")
    return statuses


def validate_incident_evidence_artifact(artifact: object) -> dict[str, Any]:
    """Return a validated evidence artifact or raise a contract error.

    The validator intentionally does not require every query to succeed.
    Timeouts and bounded-output failures are useful, explicit evidence gaps as
    long as the wrapper-issued KQL, DSL, digest, and requested window survive.
    """
    artifact_map = _require_mapping(artifact, "incident evidence artifact")
    schema = artifact_map.get("schema")
    if schema not in {INCIDENT_EVIDENCE_CONTRACT, LEGACY_INCIDENT_EVIDENCE_CONTRACT}:
        raise IncidentEvidenceContractError("incident evidence schema is unsupported")

    request = _require_mapping(artifact_map.get("request"), "incident evidence request")
    response = _require_mapping(
        artifact_map.get("security_onion_response"),
        "Security Onion incident evidence response",
    )
    if response.get("ok") is not True:
        raise IncidentEvidenceContractError("Security Onion evidence response is not successful")
    if response.get("read_only") is not True:
        raise IncidentEvidenceContractError("Security Onion evidence response is not read-only")
    if response.get("query_contract") != schema:
        raise IncidentEvidenceContractError("Security Onion query contract is unsupported")

    packs = request.get("packs")
    windows = request.get("windows")
    if not isinstance(packs, list) or not packs:
        raise IncidentEvidenceContractError("incident evidence request has no query packs")
    if not isinstance(windows, list) or not windows:
        raise IncidentEvidenceContractError("incident evidence request has no time windows")
    if len(packs) != len(set(str(item) for item in packs)):
        raise IncidentEvidenceContractError("incident evidence request contains duplicate packs")
    if any(str(pack) not in ALLOWED_PACKS for pack in packs):
        raise IncidentEvidenceContractError("incident evidence request contains an unsupported pack")

    observables = _require_mapping(request.get("observables"), "incident evidence observables")
    if response.get("observables") != observables:
        raise IncidentEvidenceContractError("response observables do not match the request")
    request_anchor = _validate_anchor(request.get("anchor")) if schema == INCIDENT_EVIDENCE_CONTRACT else None
    request_size = request.get("size")
    if schema == INCIDENT_EVIDENCE_CONTRACT:
        if (
            isinstance(request_size, bool)
            or not isinstance(request_size, int)
            or request_size < 1
            or request_size > MAX_ELASTIC_HITS
        ):
            raise IncidentEvidenceContractError("incident evidence request size is invalid")

    results = response.get("results")
    expected_count = len(packs) * len(windows)
    if not isinstance(results, list) or len(results) != expected_count:
        raise IncidentEvidenceContractError(
            f"incident evidence response must contain {expected_count} query result(s)"
        )

    expected_pairs = {(index, str(pack)) for index in range(len(windows)) for pack in packs}
    observed_pairs: set[tuple[int, str]] = set()
    statuses: list[str] = []
    elastic_semantic_results: list[bool] = []
    for result_index, raw_result in enumerate(results):
        result = _require_mapping(raw_result, f"query result {result_index + 1}")
        pack = _require_nonempty_text(result.get("pack"), "query pack")
        status = _require_nonempty_text(result.get("status"), "query status")
        if status not in ALLOWED_STATUSES:
            raise IncidentEvidenceContractError(f"unsupported query status: {status}")
        window_index = result.get("window_index")
        if isinstance(window_index, bool) or not isinstance(window_index, int):
            raise IncidentEvidenceContractError("query window_index must be an integer")
        pair = (window_index, pack)
        if pair not in expected_pairs or pair in observed_pairs:
            raise IncidentEvidenceContractError("query pack/window coverage is invalid or duplicated")
        observed_pairs.add(pair)

        window = _require_mapping(result.get("window"), "query window")
        requested_window = _require_mapping(windows[window_index], "requested query window")
        if window != requested_window:
            raise IncidentEvidenceContractError("query result window does not match the request")

        kql = _require_nonempty_text(result.get("kql_equivalent"), "query KQL equivalent")
        if len(kql) > 64 * 1024:
            raise IncidentEvidenceContractError("query KQL equivalent exceeds its byte contract")
        query_dsl = _require_mapping(result.get("query_dsl"), "exact query DSL")
        if not query_dsl:
            raise IncidentEvidenceContractError("exact query DSL must be non-empty")
        digest = _require_nonempty_text(result.get("query_digest"), "query digest")
        if not SHA256_RE.fullmatch(digest):
            raise IncidentEvidenceContractError("query digest is not a SHA-256 value")
        if _canonical_dsl_digest(query_dsl) != digest:
            raise IncidentEvidenceContractError("exact query DSL does not match its wrapper digest")
        if schema == INCIDENT_EVIDENCE_CONTRACT:
            elastic_semantic_results.append(
                _validate_search_result(
                    result,
                    label=f"{pack} query result",
                    expected_scope=PACK_INDEX_SCOPES[pack],
                    max_hits=request_size,
                )
            )
        statuses.append(status)

    if observed_pairs != expected_pairs:
        raise IncidentEvidenceContractError("query result coverage is incomplete")
    if schema == INCIDENT_EVIDENCE_CONTRACT:
        osquery_statuses = _validate_osquery_results(request, response)
        statuses.extend(osquery_statuses)
        controls_valid = _validate_controls(request_anchor, response)
        query_execution_valid = all(elastic_semantic_results)
        coverage_valid = query_execution_valid and all(
            status == "ok" for status in osquery_statuses
        )
        expected_complete = controls_valid and coverage_valid
        validity = _require_mapping(response.get("semantic_validity"), "semantic validity")
        expected_validity = {
            "transport_valid": True,
            "controls_valid": controls_valid,
            "query_execution_valid": query_execution_valid,
            "coverage_valid": coverage_valid,
            "semantic_valid": expected_complete,
        }
        for key, expected in expected_validity.items():
            if validity.get(key) is not expected:
                raise IncidentEvidenceContractError(
                    f"semantic validity {key} flag is inconsistent"
                )
        reasons = validity.get("reasons")
        if (
            not isinstance(reasons, list)
            or any(not isinstance(item, str) or not item.strip() for item in reasons)
            or (expected_complete and reasons)
            or (not expected_complete and not reasons)
        ):
            raise IncidentEvidenceContractError("semantic validity reasons are inconsistent")
    else:
        expected_complete = all(status == "ok" for status in statuses)
    if response.get("complete") is not expected_complete:
        raise IncidentEvidenceContractError("response complete flag does not match query results")
    if response.get("partial") is not (not expected_complete):
        raise IncidentEvidenceContractError("response partial flag does not match query results")
    return artifact_map
