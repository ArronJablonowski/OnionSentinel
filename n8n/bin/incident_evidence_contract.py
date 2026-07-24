#!/usr/bin/env python3
"""Validate restricted Security Onion incident-evidence artifacts.

The Security Onion wrapper is the only component allowed to construct and
execute Elasticsearch Query DSL.  Downstream workers use this module to make
sure the immutable artifact still contains every requested pack/window pair,
the human-readable KQL equivalent, and the exact digest-matched DSL that ran.
Partial query results are valid evidence gaps; missing query provenance is not.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any


INCIDENT_EVIDENCE_CONTRACT = "onion-sentinel-incident-evidence-v2"
LEGACY_INCIDENT_EVIDENCE_CONTRACT = "onion-sentinel-incident-evidence-v1"
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
MAX_OSQUERY_ROWS = 200


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


def _query_digest(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


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

    results = response.get("results")
    expected_count = len(packs) * len(windows)
    if not isinstance(results, list) or len(results) != expected_count:
        raise IncidentEvidenceContractError(
            f"incident evidence response must contain {expected_count} query result(s)"
        )

    expected_pairs = {(index, str(pack)) for index in range(len(windows)) for pack in packs}
    observed_pairs: set[tuple[int, str]] = set()
    statuses: list[str] = []
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
        statuses.append(status)

    if observed_pairs != expected_pairs:
        raise IncidentEvidenceContractError("query result coverage is incomplete")
    if schema == INCIDENT_EVIDENCE_CONTRACT:
        statuses.extend(_validate_osquery_results(request, response))
    expected_complete = all(status == "ok" for status in statuses)
    if response.get("complete") is not expected_complete:
        raise IncidentEvidenceContractError("response complete flag does not match query results")
    if response.get("partial") is not (not expected_complete):
        raise IncidentEvidenceContractError("response partial flag does not match query results")
    return artifact_map
