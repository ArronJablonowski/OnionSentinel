"""Reviewed scopes, query identities, and anchor primitives."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from typing import Any

from incident_evidence_validation import (
    IncidentEvidenceContractError,
    require_mapping,
    require_nonempty_text,
)


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
        "logs-zeek-so",
        "logs-endpoint.events.network-*",
        *ALERT_INDEX_SCOPE,
    ],
    "dns_activity": [
        "logs-zeek-so",
        "logs-endpoint.events.network-*",
    ],
    "osquery_history": [
        "logs-endpoint.events.process-*",
        "logs-endpoint.events.file-*",
        "logs-endpoint.events.network-*",
        "logs-osquery_manager.result-default",
        "logs-osquery_manager.action.responses-default",
    ],
    "cross_sensor_timeline": [
        *ALERT_INDEX_SCOPE,
        "logs-zeek-so",
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
SAFE_ELASTIC_INDEX_RE = re.compile(r"^[A-Za-z0-9._-]{1,255}$")
MAX_OSQUERY_ROWS = 200
MAX_ELASTIC_HITS = 200
ELASTIC_PROMPT_PROJECTION_FIELDS = {
    "version",
    "source_returned_hits",
    "source_total_hits",
    "source_truncated",
    "source_hits_bytes",
    "source_hits_sha256",
    "retained_hits",
    "retained_hits_bytes",
    "retained_hits_sha256",
    "reasons",
}
OSQUERY_PROMPT_PROJECTION_FIELDS = {
    "version",
    "source_returned_rows",
    "source_total_rows",
    "source_truncated",
    "source_rows_bytes",
    "source_rows_sha256",
    "retained_rows",
    "retained_rows_bytes",
    "retained_rows_sha256",
    "max_retained_rows",
    "max_retained_bytes",
    "max_row_bytes",
    "reasons",
}


def canonical_dsl_digest(query_dsl: dict[str, Any]) -> str:
    encoded = json.dumps(query_dsl, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def canonical_execution_digest(
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


def query_digest(query: str) -> str:
    return hashlib.sha256(query.encode("utf-8")).hexdigest()


def query_endpoint(index_scope: list[str]) -> str:
    return (
        f"{','.join(index_scope)}/_search"
        f"?ignore_unavailable=true&expand_wildcards=open&preference={QUERY_PREFERENCE}"
    )


def index_matches_scope(index_name: str, index_scope: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(index_name, pattern)
        or fnmatch.fnmatchcase(index_name, f".ds-{pattern}-*")
        for pattern in index_scope
    )


def validate_anchor(value: object) -> dict[str, str] | None:
    if value is None:
        return None
    anchor = require_mapping(value, "representative alert anchor")
    index_name = require_nonempty_text(
        anchor.get("index"), "representative alert anchor index"
    )
    document_id = require_nonempty_text(
        anchor.get("id"), "representative alert anchor id"
    )
    if (
        not SAFE_ELASTIC_INDEX_RE.fullmatch(index_name)
        or not index_matches_scope(index_name, ALERT_INDEX_SCOPE)
    ):
        raise IncidentEvidenceContractError(
            "representative alert anchor index is outside the reviewed alert scope"
        )
    if not SAFE_ELASTIC_ID_RE.fullmatch(document_id):
        raise IncidentEvidenceContractError(
            "representative alert anchor id is invalid"
        )
    return {"index": index_name, "id": document_id}


def positive_control_dsl(anchor: dict[str, str]) -> dict[str, Any]:
    return {
        "size": 1,
        "track_total_hits": True,
        "timeout": "30s",
        "_source": ["@timestamp", "event.dataset"],
        "query": {"ids": {"values": [anchor["id"]]}},
    }


def negative_control_dsl(anchor: dict[str, str]) -> dict[str, Any]:
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
