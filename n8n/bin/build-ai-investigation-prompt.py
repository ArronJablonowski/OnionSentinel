#!/usr/bin/env python3
"""Build a local-first AI investigation prompt package from alert-store SQLite.

The script does not call an LLM. It prepares a bounded evidence bundle and a
strict JSON response contract that can be sent to Hermes, Ollama, or a hosted
frontier model depending on the escalation policy.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from agent_memory import (
    MEMORY_ROLES,
    build_agent_memory_context,
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)
from incident_evidence_contract import validate_incident_evidence_artifact
from asset_inventory import load_asset_inventory, resolve_asset_context
from detection_validation import (
    build_detection_validation,
    extract_group_packet_features,
    extract_rule_context,
    load_detection_playbooks,
    marker_specs,
    resolve_detection_playbook,
)
from investigation_skills import (
    load_investigation_skills,
    resolve_investigation_skills,
)
from prompt_incident_evidence_projection import (
    project_incident_evidence_hits as project_evidence_hits,
    project_incident_evidence_osquery_rows as project_evidence_osquery_rows,
    reject_preprojected_incident_evidence_source as reject_preprojected_source,
)
from prompt_incident_grounding import (
    IncidentGroundingSources,
    immutable_query_provenance,
    mandatory_grounding_digest,
)
from prompt_builder_cli import (
    PromptBuilderCliDefaults,
    PromptBuilderCliSources,
    parse_prompt_builder_args,
)
from prompt_authorization_context import (
    AuthorizationContextSources,
    authorized_activity_context as project_authorized_activity_context,
    canonical_authorized_activity_entry as canonical_authorization_entry,
)
from prompt_correlation_context import (
    CorrelationContextSources,
    build_correlated_alert_context,
)
from prompt_correlation_facts import (
    COMMUNITY_ID_V1_RE,
    CORRELATION_MAX_RAW_JSON_BYTES,
    CorrelationFactSources,
    correlation_observable_weight,
    correlation_relationships,
    correlation_row_facts,
    correlation_time_bonus,
    parse_project_datetime,
)
from prompt_investigation_query_context import (
    QueryContextPolicy,
    QueryContextSources,
    build_investigation_query_context,
)
from prompt_detection_context import (
    DetectionContextRequest,
    DetectionContextSources,
    prepare_detection_context,
)
from prompt_evidence_admission import (
    PromptEvidenceAdmissionRequest,
    PromptEvidenceAdmissionSources,
    blind_model_authored_context,
    prepare_prompt_evidence_admission,
)
from prompt_evidence_snapshot import (
    CoreEvidenceSnapshotRequest,
    CoreEvidenceSnapshotSources,
    HistoricalEvidenceSnapshotRequest,
    HistoricalEvidenceSnapshotSources,
    collect_core_evidence_snapshot,
    collect_historical_evidence_snapshot,
)
from prompt_package_compactor import (
    PackageCompactionSources,
    compact_package_to_budget as compact_prompt_package,
)
from prompt_package_view_model import (
    PromptPackageView,
    assemble_prompt_package,
)
from prompt_response_contract import (
    PromptContractRequest,
    build_prompt_contract,
)
import investigation_query_contract as INVESTIGATION_CONTRACT


INVESTIGATION_CONTRACT_PACKS = INVESTIGATION_CONTRACT.PACKS
INVESTIGATION_EVENT_TUPLE_ATOM_RE = INVESTIGATION_CONTRACT.SAFE_ATOM_RE
EVENT_TUPLE_PATHS = getattr(
    INVESTIGATION_CONTRACT,
    "EVENT_TUPLE_PATHS",
    {
        field: (path,)
        for field, path in INVESTIGATION_CONTRACT.EVENT_TUPLE_FIELDS.items()
    },
)
PACK_ROLE_MODE = getattr(INVESTIGATION_CONTRACT, "PACK_ROLE_MODE", {})


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ROLLUPS = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_SYSTEM_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
DEFAULT_SECOND_OPINION_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_second_opinion_prompt.md"
DEFAULT_AGENT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_AI_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_DETECTION_PLAYBOOKS_FILE = HOME / "n8n-local" / "config" / "detection_playbooks.json"
DEFAULT_INVESTIGATION_SKILLS_FILE = HOME / "n8n-local" / "config" / "investigation_skills.json"
DEFAULT_ASSET_INVENTORY_FILE = (
    HOME
    / "n8n-local"
    / "config"
    / "asset_inventory.database-export.json"
)
DEFAULT_SOC_ANALYST_MEMORY_FILE = DEFAULT_AGENT_MEMORY_DIR / "soc-analyst-memory.md"
DEFAULT_SHARED_AGENT_MEMORY_FILE = DEFAULT_AGENT_MEMORY_DIR / "shared-agent-memory.md"
DEFAULT_SYSTEM_PROMPT = "You are a careful SOC analyst assisting with Security Onion alerts."
TEST_PREFIXES = ("phase%", "config-%", "internal-test-%", "sqlite-%", "policy-%", "codex-%")
ESCALATE_LEVELS = {"critical", "high"}
DEFAULT_MAX_PACKAGE_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_MAX_PROMPT_PACKAGE_BYTES", str(4 * 1024 * 1024))))
MAX_ARTIFACT_JSON_BYTES = max(64 * 1024, int(os.environ.get("SOC_AI_MAX_ARTIFACT_JSON_BYTES", str(2 * 1024 * 1024))))
MAX_INCIDENT_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_SYSTEM_PROMPT_BYTES = max(8 * 1024, int(os.environ.get("SOC_AI_MAX_SYSTEM_PROMPT_BYTES", str(64 * 1024))))
LEGACY_ARTIFACT_SCAN_LIMIT = max(10, int(os.environ.get("SOC_AI_LEGACY_ARTIFACT_SCAN_LIMIT", "200")))
INVESTIGATION_QUERY_CONTRACT = INVESTIGATION_CONTRACT.INVESTIGATION_QUERY_CONTRACT
INVESTIGATION_QUERY_V2 = (
    INVESTIGATION_QUERY_CONTRACT
    == "onion-sentinel-investigation-pivots-v2"
)
INVESTIGATION_QUERY_MAX_ROUNDS = 3
INVESTIGATION_QUERY_MAX_TOTAL = 12
INVESTIGATION_QUERY_MAX_PER_ROUND = 4
INVESTIGATION_QUERY_PACKS = (
    "alert_context",
    "network_flow",
    "dns_activity",
    "system_auth",
    "zeek_tls",
    "zeek_http",
    "zeek_files",
    "zeek_ssh",
    "zeek_stun",
    "zeek_quic",
    "zeek_anomalies",
    "osquery_history",
    "cross_sensor_timeline",
)
INVESTIGATION_QUERY_PACK_DESCRIPTIONS = {
    "alert_context": "Suricata and Sigma detection records.",
    "network_flow": "Zeek connection, endpoint network, and alert flow metadata.",
    "dns_activity": "Zeek DNS and endpoint network DNS metadata.",
    "system_auth": "System authentication outcomes, exact users, hosts, and source IPs.",
    "zeek_tls": "Zeek TLS/SSL metadata, SNI, validation, versions, ciphers, and JA fingerprints.",
    "zeek_http": "Zeek HTTP methods, hosts, URIs, status, sizes, and user agents.",
    "zeek_files": "Zeek file-transfer metadata, MIME types, sizes, analyzers, and hashes.",
    "zeek_ssh": "Zeek SSH authentication, versions, algorithms, and HASSH metadata.",
    "zeek_stun": "Zeek STUN and STUN NAT metadata.",
    "zeek_quic": "Zeek QUIC protocol, version, connection IDs, and server-name metadata.",
    "zeek_anomalies": "Zeek notice, weird, and analyzer anomaly metadata.",
    "osquery_history": "Historical endpoint and osquery-manager events stored in Elastic.",
    "cross_sensor_timeline": "Bounded alert, Zeek connection/DNS, and endpoint event timeline.",
}
INVESTIGATION_SECURITY_ONION_PURPOSES = (
    "validate_detection",
    "establish_timeline",
    "correlate_observable",
    "measure_prevalence",
    "identify_related_activity",
    "test_benign_hypothesis",
)
INVESTIGATION_DERIVED_OPERATIONS = (
    "coverage",
    "connections",
    "dns",
    "tls",
    "http",
    "files",
    "notices",
    "weird",
    "protocols",
    "packet_facts",
    "icmp_facts",
    "icmp_anomalies",
    "user_agents",
    "tls_versions",
    "geoip",
)
INVESTIGATION_DERIVED_FILTERS = {
    "common_flow": [
        "source_ip",
        "destination_ip",
        "endpoint_ip",
        "source_port",
        "destination_port",
        "port",
        "transport",
        "protocol",
        "start_epoch",
        "end_epoch",
    ],
    "connections": ["service", "connection_state"],
    "dns": ["query", "answer", "answer_type", "qtype", "rcode"],
    "tls": ["sni", "version", "cipher", "established"],
    "http": ["host", "uri", "uri_prefix", "method", "status_code", "user_agent"],
    "files": ["mime_type", "filename", "sha256"],
    "notices": ["note", "message"],
    "weird": ["name", "additional"],
    "packet_facts": [
        "query",
        "answer",
        "rcode",
        "sni",
        "version",
        "host",
        "uri",
        "uri_prefix",
        "user_agent",
        "frame_length_min",
        "frame_length_max",
        "icmp_type",
        "icmp_code",
    ],
    "icmp_facts": [
        "family",
        "icmp_type",
        "icmp_code",
        "identifier",
        "sequence",
        "frame_length_min",
        "frame_length_max",
        "payload_length_min",
        "payload_length_max",
        "selected_scope_match",
    ],
    "geoip": ["ip", "country_iso_code", "asn"],
}
ALERT_INDEX_RE = re.compile(
    r"^(?:"
    r"logs-(?:suricata\.alerts|detections\.alerts)-so"
    r"|\.ds-logs-(?:suricata\.alerts|detections\.alerts)-so-\d{4}\.\d{2}\.\d{2}-\d{6}"
    r")$"
)
SAFE_ELASTIC_ID_RE = re.compile(r"^[A-Za-z0-9_.:@+=-]{1,512}$")
SAFE_PIVOT_ATOM_RE = re.compile(r"^[A-Za-z0-9_.:@+-]{1,255}$")
SAFE_PIVOT_DOMAIN_RE = re.compile(
    r"(?i)^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
MAX_DETECTION_GROUP_ROWS = 5000


def project_incident_evidence_hits(
    incident_evidence: dict,
    *,
    limit: int,
    reason: str,
) -> int:
    """Compatibility delegate for bounded Elastic evidence projection."""
    return project_evidence_hits(
        incident_evidence,
        limit=limit,
        reason=reason,
    )


def project_incident_evidence_osquery_rows(
    incident_evidence: dict,
    *,
    limit: int,
    max_retained_bytes: int,
    max_row_bytes: int,
    reason: str,
) -> int:
    """Compatibility delegate for bounded OSQuery evidence projection."""
    return project_evidence_osquery_rows(
        incident_evidence,
        limit=limit,
        max_retained_bytes=max_retained_bytes,
        max_row_bytes=max_row_bytes,
        reason=reason,
    )


def reject_preprojected_incident_evidence_source(
    incident_evidence: dict,
) -> None:
    """Compatibility delegate for rejecting preprojected source evidence."""
    reject_preprojected_source(incident_evidence)


def parse_args() -> argparse.Namespace:
    return parse_prompt_builder_args(
        PromptBuilderCliDefaults(
            db=DEFAULT_DB,
            rollup_dir=DEFAULT_ROLLUPS,
            out_dir=DEFAULT_OUT,
            system_prompt_file=DEFAULT_SYSTEM_PROMPT_FILE,
            second_opinion_prompt_file=DEFAULT_SECOND_OPINION_PROMPT_FILE,
            agent_memory_dir=DEFAULT_AGENT_MEMORY_DIR,
            agent_memory_file=DEFAULT_SOC_ANALYST_MEMORY_FILE,
            shared_memory_file=DEFAULT_SHARED_AGENT_MEMORY_FILE,
            pcap_analysis_dir=DEFAULT_PCAP_ANALYSIS_DIR,
            analysis_dir=DEFAULT_AI_ANALYSIS_DIR,
            detection_playbooks=DEFAULT_DETECTION_PLAYBOOKS_FILE,
            investigation_skills=DEFAULT_INVESTIGATION_SKILLS_FILE,
            asset_inventory_file=DEFAULT_ASSET_INVENTORY_FILE,
            max_package_bytes=DEFAULT_MAX_PACKAGE_BYTES,
        ),
        PromptBuilderCliSources(
            memory_roles=frozenset(MEMORY_ROLES),
            role_prompt_file=role_prompt_file,
            role_second_opinion_prompt_file=role_second_opinion_prompt_file,
            role_memory_file=role_memory_file,
        ),
    )


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$", value)
    if match:
        year, month, day, hour, minute, second, zone = match.groups()
        return f"{year}{month}{day}-{hour}{minute}{second}{zone.replace(':', '')}"
    return safe_filename(value)


def safe_filename(value: str) -> str:
    return (
        str(value or "alert")
        .replace(":", "")
        .replace("/", "-")
        .replace("\\", "-")
        .replace("|", "-")
        .replace(" ", "-")
    )[:180]


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def row(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> sqlite3.Row | None:
    return conn.execute(sql, tuple(params)).fetchone()


def test_filter_sql(prefix: str = "alert_id") -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    for pattern in TEST_PREFIXES:
        clauses.append(f"{prefix} NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def parse_alert_json(value: str | None) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def parse_json_object(value: str | None) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def safe_int(value: object, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def read_bytes_bounded(path: Path, max_bytes: int) -> bytes:
    """Read a trusted runtime artifact only when it satisfies its size contract."""
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"artifact exceeds {max_bytes} byte limit: {path.name}")
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"artifact grew beyond {max_bytes} byte limit: {path.name}")
    return data


def load_json_bounded(path: Path, max_bytes: int = MAX_ARTIFACT_JSON_BYTES) -> dict:
    parsed = json.loads(read_bytes_bounded(path, max_bytes).decode("utf-8", errors="strict"))
    if not isinstance(parsed, dict):
        raise ValueError(f"JSON artifact root must be an object: {path.name}")
    return parsed


def load_system_prompt(path: Path) -> str:
    """Load the analyst-editable system prompt used by the AI runner."""
    try:
        prompt = read_bytes_bounded(path, MAX_SYSTEM_PROMPT_BYTES).decode("utf-8", errors="replace").strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SYSTEM_PROMPT


def sqlite_value(row_value: sqlite3.Row, key: str, default: object = None) -> object:
    return row_value[key] if key in row_value.keys() else default


def alert_group_key(row_value: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the dashboard and AI scheduler."""
    suppression_key = str(sqlite_value(row_value, "suppression_key") or "").strip()
    if suppression_key:
        return suppression_key
    return "|".join(
        [
            str(sqlite_value(row_value, "triage_level") or "unscored"),
            str(sqlite_value(row_value, "rule_name") or "unknown-rule"),
            str(sqlite_value(row_value, "source_ip") or "unknown-source"),
            str(sqlite_value(row_value, "destination_ip") or "unknown-destination"),
            str(sqlite_value(row_value, "filter_status") or "accepted"),
        ]
    )


def alert_group_id(group_key: str) -> str:
    return hashlib.sha1(str(group_key or "").encode("utf-8")).hexdigest()[:12]


def execution_lineage(
    selected: Any,
    *,
    blind_reanalysis: bool,
) -> dict[str, Any]:
    """Return collector-owned identifiers used by the durable harness trace."""

    stable_group_id = str(
        sqlite_value(selected, "stable_group_id") or ""
    ).strip().lower()
    if not stable_group_id:
        stable_group_id = alert_group_id(alert_group_key(selected))
    return {
        "group_id": stable_group_id,
        "manual_reanalysis": bool(blind_reanalysis),
    }


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {str(item["name"]) for item in rows(conn, f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def alert_group_rows(
    conn: sqlite3.Connection,
    selected: sqlite3.Row,
    *,
    include_tests: bool,
    extra_columns: Iterable[str] = (),
    row_limit: int | None = None,
) -> list[sqlite3.Row]:
    """Fetch one duplicate group through indexed identity columns.

    Older disaster-recovery databases may predate ``stable_group_id``. The
    exact-column fallback preserves compatibility without scanning every alert
    in Python for each model invocation.
    """
    available = table_columns(conn, "alerts")
    base_columns = [
        "alert_id", "first_seen", "last_seen", "seen_count", "rule_name",
        "source_ip", "destination_ip", "destination_port", "triage_level",
        "triage_score", "filter_status", "suppression_key", "stable_group_id",
    ]
    selected_columns = [name for name in [*base_columns, *extra_columns] if name in available]
    if not selected_columns:
        return [selected]

    params: list[object] = []
    stable_group_id = str(sqlite_value(selected, "stable_group_id") or "").strip()
    suppression_key = str(sqlite_value(selected, "suppression_key") or "").strip()
    if stable_group_id and "stable_group_id" in available:
        identity_sql = "stable_group_id = ?"
        params.append(stable_group_id)
    elif suppression_key and "suppression_key" in available:
        identity_sql = "suppression_key = ?"
        params.append(suppression_key)
    else:
        identity_columns = [
            name for name in ("triage_level", "rule_name", "source_ip", "destination_ip", "filter_status")
            if name in available
        ]
        identity_sql = " AND ".join(f"COALESCE({name}, '') = ?" for name in identity_columns)
        params.extend(str(sqlite_value(selected, name) or "") for name in identity_columns)
    if not identity_sql:
        return [selected]

    conditions = [identity_sql]
    if "filter_status" in available:
        conditions.append("COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'unknown', 'suppressed')")
    if not include_tests and "alert_id" in available:
        test_sql, test_params = test_filter_sql("alert_id")
        conditions.append(test_sql)
        params.extend(test_params)
    try:
        limit_sql = ""
        if row_limit is not None:
            bounded_limit = max(1, min(int(row_limit), MAX_DETECTION_GROUP_ROWS + 1))
            limit_sql = f" LIMIT {bounded_limit}"
        return rows(
            conn,
            f"SELECT {', '.join(selected_columns)} FROM alerts "
            f"WHERE {' AND '.join(f'({item})' for item in conditions)} "
            f"ORDER BY last_seen DESC, alert_id DESC{limit_sql}",
            params,
        ) or [selected]
    except sqlite3.Error:
        return [selected]


def analyst_state_context(conn: sqlite3.Connection, selected: sqlite3.Row) -> dict:
    group_key = alert_group_key(selected)
    group_id = alert_group_id(group_key)
    try:
        state = row(
            conn,
            """SELECT status, repeat_count, reason, updated_at, updated_by
               FROM analyst_alert_group_state WHERE group_id = ? OR group_key = ?
               ORDER BY updated_at DESC LIMIT 1""",
            [group_id, group_key],
        )
    except sqlite3.OperationalError:
        state = None
    return {
        "group_id": group_id,
        "group_key": group_key,
        "status": state["status"] if state else "open",
        "repeat_count_at_decision": state["repeat_count"] if state else 0,
        "reason": state["reason"] if state else None,
        "updated_at": state["updated_at"] if state else None,
        "updated_by": state["updated_by"] if state else None,
    }


def prior_analysis_context(
    conn: sqlite3.Connection,
    analysis_dir: Path,
    selected: sqlite3.Row,
    limit: int = 3,
) -> list[dict]:
    alert_id = str(selected["alert_id"] or "")
    found: list[dict] = []
    stable_group_id = str(sqlite_value(selected, "stable_group_id") or "").strip()
    try:
        indexed = rows(
            conn,
            """
            SELECT analysis_id, generated_at, model, model_path,
                   detection_outcome, bluf, summary, confidence, artifact_path
            FROM ai_analysis_runs
            WHERE alert_id = ? OR (? <> '' AND group_id = ?)
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            [alert_id, stable_group_id, stable_group_id, limit],
        )
    except sqlite3.Error:
        indexed = []
    for item in indexed:
        found.append({
            "analysis_id": item["analysis_id"],
            "artifact": item["artifact_path"],
            "generated_at": item["generated_at"],
            "model": item["model"],
            "model_path": item["model_path"],
            "detection_outcome": item["detection_outcome"],
            "bluf": item["bluf"],
            "summary": item["summary"],
            "confidence": item["confidence"],
        })
    if found:
        return found
    if not analysis_dir.exists():
        return found
    # Compatibility path for pre-index artifacts. The scan and each file read
    # are bounded so a large historical corpus cannot monopolize one worker.
    for path in sorted(analysis_dir.glob("*-local-ai-analysis.json"), reverse=True)[:LEGACY_ARTIFACT_SCAN_LIMIT]:
        try:
            payload = load_json_bounded(path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            continue
        text = json.dumps(payload, sort_keys=True)
        if alert_id not in text:
            continue
        result = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else payload
        found.append({
            "artifact": str(path),
            "generated_at": payload.get("generated_at") or result.get("generated_at"),
            "model": payload.get("analysis_model") or payload.get("model"),
            "detection_outcome": result.get("detection_outcome"),
            "bluf": result.get("bluf"),
            "summary": result.get("summary"),
            "confidence": result.get("confidence"),
            "tuning_recommendation": result.get("tuning_recommendation"),
        })
        if len(found) >= limit:
            break
    return found


def compact_pcap_analysis(record: dict) -> dict:
    """Keep PCAP evidence prompt-safe by including summaries, not packet bodies."""
    zeek = record.get("zeek") if isinstance(record.get("zeek"), dict) else {}
    tshark = record.get("tshark") if isinstance(record.get("tshark"), dict) else {}
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    local_query_index: dict[str, list] = {}
    for parser in (zeek, tshark):
        index = parser.get("_local_query_index") if isinstance(parser.get("_local_query_index"), dict) else {}
        for operation, values in index.items():
            if not isinstance(values, list):
                continue
            current = local_query_index.setdefault(str(operation), [])
            current.extend(item for item in values if isinstance(item, dict))
            del current[192:]
    return {
        "analysis_artifact": record.get("_analysis_path"),
        "evidence_relationship": record.get("_evidence_relationship"),
        "generated_at": record.get("generated_at"),
        "request_id": request.get("request_id"),
        "alert_id": request.get("alert_id"),
        "group_id": request.get("group_id"),
        "artifact_state": record.get("artifact_state"),
        "coverage": record.get("coverage") if isinstance(record.get("coverage"), dict) else {},
        "evidence_security": record.get("evidence_security") if isinstance(record.get("evidence_security"), dict) else {},
        "pcap_files": [
            {
                "name": item.get("name"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
            }
            for item in (record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else [])[:5]
            if isinstance(item, dict)
        ],
        "tool_paths": record.get("tool_paths") if isinstance(record.get("tool_paths"), dict) else {},
        "zeek": {
            "available": bool(zeek.get("available")),
            "reason": zeek.get("reason"),
            "record_counts": zeek.get("record_counts") if isinstance(zeek.get("record_counts"), dict) else {},
            "coverage": zeek.get("coverage") if isinstance(zeek.get("coverage"), dict) else {},
            "sampling": zeek.get("sampling") if isinstance(zeek.get("sampling"), dict) else {},
            "top_connections": zeek.get("top_connections") if isinstance(zeek.get("top_connections"), list) else [],
            "dns_queries": zeek.get("dns_queries") if isinstance(zeek.get("dns_queries"), list) else [],
            "tls_sni": zeek.get("tls_sni") if isinstance(zeek.get("tls_sni"), list) else [],
            "http_hosts": zeek.get("http_hosts") if isinstance(zeek.get("http_hosts"), list) else [],
            "files": zeek.get("files") if isinstance(zeek.get("files"), list) else [],
            "notices": zeek.get("notices") if isinstance(zeek.get("notices"), list) else [],
            "weird": zeek.get("weird") if isinstance(zeek.get("weird"), list) else [],
        },
        "tshark": {
            "available": bool(tshark.get("available")),
            "reason": tshark.get("reason"),
            "coverage": tshark.get("coverage") if isinstance(tshark.get("coverage"), dict) else {},
            "sampling": tshark.get("sampling") if isinstance(tshark.get("sampling"), dict) else {},
            "protocol_counts": (tshark.get("protocol_counts") if isinstance(tshark.get("protocol_counts"), list) else [])[:20],
            "top_conversations": (tshark.get("top_conversations") if isinstance(tshark.get("top_conversations"), list) else [])[:20],
            "icmp_size_review": tshark.get("icmp_size_review") if isinstance(tshark.get("icmp_size_review"), dict) else {},
            "icmp_semantics": tshark.get("icmp_semantics") if isinstance(tshark.get("icmp_semantics"), dict) else {},
            "dns_activity": tshark.get("dns_activity") if isinstance(tshark.get("dns_activity"), dict) else {},
            "http_user_agents": tshark.get("http_user_agents") if isinstance(tshark.get("http_user_agents"), dict) else {},
            "tls_versions": tshark.get("tls_versions") if isinstance(tshark.get("tls_versions"), dict) else {},
            "geoip": tshark.get("geoip") if isinstance(tshark.get("geoip"), dict) else {},
            "packet_samples": (tshark.get("packet_samples") if isinstance(tshark.get("packet_samples"), list) else [])[:20],
            "samples": [
                {
                    "pcap": Path(str(sample.get("pcap") or "capture")).name,
                    "protocol_hierarchy": str(sample.get("protocol_hierarchy") or "")[:4000],
                    "conversations": str(sample.get("conversations") or "")[:4000],
                    "field_sample_tsv": str(sample.get("field_sample_tsv") or "")[:4000],
                }
                for sample in (tshark.get("samples") if isinstance(tshark.get("samples"), list) else [])[:2]
                if isinstance(sample, dict)
            ],
        },
        "detection_context": (
            record.get("detection_context")
            if isinstance(record.get("detection_context"), dict)
            else {}
        ),
        # This is a local runtime capability index, not model context. The LLM
        # runner removes it from every model request and exposes it only through
        # the fixed read-only PCAP query operations.
        "_local_query_index": local_query_index,
    }


def compact_public_enrichment_record(record: dict) -> dict:
    """Expose provider evidence under an explicit, deterministic prompt budget.

    The complete accepted response remains in the enrichment cache.  Small
    responses are supplied intact; large responses carry an exact digest and a
    bounded JSON prefix so the model never mistakes a prompt projection for
    the complete provider artifact.
    """
    compact = {
        "source": record.get("source"),
        "indicator": record.get("indicator"),
        "indicator_type": record.get("indicator_type"),
        "verdict": record.get("verdict"),
        "confidence": record.get("confidence"),
        "tags": record.get("tags") if isinstance(record.get("tags"), list) else [],
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "cached_at": record.get("cached_at"),
        "raw_response_sha256": record.get("raw_response_sha256"),
        "raw_response_size_bytes": record.get("raw_response_size_bytes"),
        "raw_response_complete": record.get("raw_response_complete"),
    }
    raw = record.get("raw_response")
    serialized = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), default=str
    )
    raw_bytes = serialized.encode("utf-8")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    compact["provider_evidence"] = {
        "response_sha256": record.get("raw_response_sha256") or digest,
        "response_size_bytes": record.get("raw_response_size_bytes") or len(raw_bytes),
        "cache_response_complete": record.get("raw_response_complete", True),
        "prompt_projection_complete": len(raw_bytes) <= 16 * 1024,
        **(
            {"response": raw}
            if len(raw_bytes) <= 16 * 1024
            else {"response_json_prefix": raw_bytes[: 16 * 1024].decode("utf-8", "ignore")}
        ),
    }
    return compact


def public_enrichment_context(conn: sqlite3.Connection, selected: sqlite3.Row, limit: int, include_tests: bool) -> dict:
    """Collect normalized public enrichment for the selected duplicate group."""
    group_rows = alert_group_rows(
        conn,
        selected,
        include_tests=include_tests,
        extra_columns=("enrichment_json",),
    )
    records: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    indicators: dict[str, list[str]] = {}
    seen_records: set[tuple[str, str, str]] = set()

    for item in group_rows:
        bundle = parse_json_object(str(sqlite_value(item, "enrichment_json") or ""))
        external = bundle.get("external_intel") if isinstance(bundle.get("external_intel"), dict) else bundle
        for record in external.get("records", []) if isinstance(external.get("records"), list) else []:
            if not isinstance(record, dict):
                continue
            compact = compact_public_enrichment_record(record)
            key = (
                str(compact.get("source") or ""),
                str(compact.get("indicator_type") or ""),
                str(compact.get("indicator") or ""),
            )
            if key in seen_records:
                continue
            seen_records.add(key)
            records.append(compact)
            if len(records) >= limit:
                break
        for item_list, target in ((external.get("skipped"), skipped), (external.get("errors"), errors)):
            if isinstance(item_list, list):
                for entry in item_list[:limit]:
                    if isinstance(entry, dict):
                        target.append({key: entry.get(key) for key in ("source", "reason", "indicator", "indicator_type") if key in entry})
                    else:
                        target.append({"reason": str(entry)})
        raw_indicators = external.get("indicators") if isinstance(external.get("indicators"), dict) else {}
        for key, value in raw_indicators.items():
            if isinstance(value, list):
                indicators[str(key)] = [str(item) for item in value[:limit]]
        if len(records) >= limit:
            break

    verdict_counts: dict[str, int] = {}
    for record in records:
        verdict = str(record.get("verdict") or "unknown").lower()
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    return {
        "records": records,
        "record_limit": limit,
        "verdict_counts": verdict_counts,
        "indicators": indicators,
        "skipped": skipped[:limit],
        "errors": errors[:limit],
        "usage_guidance": (
            "Use public enrichment records as reputation/context evidence, not as sole proof of compromise. "
            "Mention malicious, suspicious, benign, scanner/noise, and unknown verdicts when they affect assessment, "
            "false-positive reasoning, escalation, or SIEM tuning."
        ),
    }


def pcap_request_context(conn: sqlite3.Connection, selected: sqlite3.Row) -> list[dict]:
    alert_id = str(selected["alert_id"] or "")
    stable_group_id = str(
        sqlite_value(selected, "stable_group_id") or ""
    ).strip()
    try:
        found = rows(
            conn,
            """
            SELECT p.*,
                   CASE
                     WHEN p.alert_id = ? THEN 'exact_alert'
                     ELSE 'stable_group_related'
                   END AS evidence_relationship
            FROM pcap_requests p
            LEFT JOIN alert_group_alias a
              ON a.legacy_group_id = p.group_id
            WHERE p.alert_id = ?
               OR (
                 ? <> ''
                 AND COALESCE(a.stable_group_id, p.group_id) = ?
               )
            ORDER BY created_at DESC
            LIMIT 10
            """,
            [alert_id, alert_id, stable_group_id, stable_group_id],
        )
    except sqlite3.Error:
        # Disaster-recovery and test databases can predate stable group
        # aliases. Preserve the exact-alert evidence path in that case.
        try:
            found = rows(
                conn,
                """
                SELECT p.*, 'exact_alert' AS evidence_relationship
                FROM pcap_requests p
                WHERE p.alert_id = ?
                ORDER BY created_at DESC
                LIMIT 10
                """,
                [alert_id],
            )
        except sqlite3.Error:
            return []
    return [dict(item) for item in found]


def pcap_evidence_context(conn: sqlite3.Connection, selected: sqlite3.Row, analysis_dir: Path, limit: int) -> dict:
    requests = pcap_request_context(conn, selected)
    request_ids = [
        str(item.get("request_id") or "")
        for item in requests
        if str(item.get("request_id") or "")
    ]
    request_id_set = set(request_ids)
    request_order = {
        request_id: position
        for position, request_id in enumerate(request_ids)
    }
    request_relationships = {
        str(item.get("request_id") or ""): str(
            item.get("evidence_relationship") or "exact_alert"
        )
        for item in requests
        if str(item.get("request_id") or "")
    }
    alert_id = str(selected["alert_id"])
    evidence = []
    loaded_paths: set[Path] = set()
    if analysis_dir.exists():
        # Broker artifacts use request_id-derived names, so normal lookups are
        # direct and O(number of requests) instead of O(all historical PCAPs).
        direct_paths = [
            analysis_dir / f"{re.sub(r'[^A-Za-z0-9_.-]+', '-', request_id).strip('-')[:140]}-pcap-analysis.json"
            for request_id in request_ids
            if request_id
        ]
        candidates = [path for path in direct_paths if path.exists()]
        # A bounded legacy scan retains compatibility with manually named or
        # pre-request-id artifacts without reintroducing an unbounded walk.
        if len(candidates) < limit:
            try:
                legacy = sorted(
                    analysis_dir.glob("*-pcap-analysis.json"),
                    key=lambda item: item.stat().st_mtime,
                    reverse=True,
                )[:LEGACY_ARTIFACT_SCAN_LIMIT]
            except OSError:
                legacy = []
            candidates.extend(path for path in legacy if path not in candidates)
        for path in candidates:
            if path in loaded_paths:
                continue
            loaded_paths.add(path)
            try:
                record = load_json_bounded(path)
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict):
                continue
            request = record.get("request") if isinstance(record.get("request"), dict) else {}
            if request.get("alert_id") != alert_id and request.get("request_id") not in request_id_set:
                continue
            record["_analysis_path"] = str(path)
            record["_evidence_relationship"] = request_relationships.get(
                str(request.get("request_id") or ""),
                "exact_alert",
            )
            evidence.append(compact_pcap_analysis(record))
            if len(evidence) >= limit:
                break
    # Exact selected-alert packet evidence must survive later package-budget
    # truncation ahead of merely related historical captures.  The secondary
    # key preserves the database's newest-request-first order.
    evidence.sort(
        key=lambda item: (
            0
            if item.get("evidence_relationship") == "exact_alert"
            else 1,
            request_order.get(
                str(item.get("request_id") or ""),
                len(request_order),
            ),
        )
    )
    return {
        "pcap_requests": requests,
        "parsed_evidence": evidence,
        "exact_alert_evidence_count": sum(
            1
            for item in evidence
            if item.get("evidence_relationship") == "exact_alert"
        ),
        "stable_group_related_evidence_count": sum(
            1
            for item in evidence
            if item.get("evidence_relationship") == "stable_group_related"
        ),
        "analysis_dir": str(analysis_dir),
        "usage_guidance": (
            "Use parsed_evidence when present. Zeek is the primary structured network evidence; "
            "TShark corroborates packet-level conversations and protocol hierarchy. If parsed_evidence is empty, "
            "treat PCAP as unavailable and list it as an evidence gap instead of inferring packet contents. "
            "Evidence marked exact_alert can support the selected event. Evidence marked stable_group_related "
            "is historical context for a related group event and must not be represented as packet proof for "
            "the selected alert."
        ),
    }


def select_alert(conn: sqlite3.Connection, args: argparse.Namespace) -> sqlite3.Row:
    if args.alert_id:
        selected = row(conn, "SELECT * FROM alerts WHERE alert_id = ?", [args.alert_id])
        if not selected:
            raise SystemExit(f"alert_id not found: {args.alert_id}")
        return selected

    levels = [level.strip().lower() for level in args.levels.split(",") if level.strip()]
    if not levels:
        raise SystemExit("--levels must contain at least one level")
    since = (dt.datetime.now().astimezone() - dt.timedelta(hours=args.hours)).replace(microsecond=0).isoformat().replace("T", "  ")
    filter_sql = ""
    filter_params: list[object] = []
    if not args.include_tests:
        test_sql, filter_params = test_filter_sql()
        filter_sql = f"AND {test_sql}"
    placeholders = ", ".join("?" for _ in levels)
    selected = row(
        conn,
        f"""
        SELECT *
        FROM alerts
        WHERE replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
          AND triage_level IN ({placeholders})
          AND COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'unknown')
          {filter_sql}
        ORDER BY
          CASE triage_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          triage_score DESC,
          replace(replace(last_seen, 'T', ' '), 'Z', '') DESC
        LIMIT 1
        """,
        [since, *levels, *filter_params],
    )
    if not selected:
        raise SystemExit("no matching alert found")
    return selected


def related_alerts(conn: sqlite3.Connection, selected: sqlite3.Row, limit: int, include_tests: bool) -> list[dict]:
    filter_sql = ""
    filter_params: list[object] = []
    if not include_tests:
        test_sql, filter_params = test_filter_sql("alert_id")
        filter_sql = f"AND {test_sql}"
    found = rows(
        conn,
        f"""
        SELECT alert_id, last_seen, rule_name, source_ip, destination_ip,
               triage_level, triage_score, filter_status, routing, seen_count
        FROM alerts
        WHERE alert_id != ?
          AND (
            rule_name = ?
            OR source_ip = ?
            OR destination_ip = ?
            OR (source_ip = ? AND destination_ip = ?)
          )
          {filter_sql}
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        [
            selected["alert_id"],
            selected["rule_name"],
            selected["source_ip"],
            selected["destination_ip"],
            selected["source_ip"],
            selected["destination_ip"],
            *filter_params,
            limit,
        ],
    )
    return [dict(item) for item in found]


def _authorization_context_sources() -> AuthorizationContextSources:
    return AuthorizationContextSources(
        row_value=sqlite_value,
        parse_alert_json=parse_alert_json,
        parse_datetime=parse_project_datetime,
        query_row=row,
        query_rows=rows,
    )


def authorized_activity_context(
    conn: sqlite3.Connection,
    selected: sqlite3.Row,
    limit: int = 500,
) -> dict[str, Any] | None:
    """Compatibility delegate for exact operator authorization evidence."""
    return project_authorized_activity_context(
        _authorization_context_sources(),
        conn,
        selected,
        limit,
    )


def canonical_authorized_activity_entry(
    selected: Any,
    authorization: Any,
    *,
    policy_id: Any,
) -> dict[str, Any] | None:
    """Compatibility delegate for exact authorization tuple binding."""
    return canonical_authorization_entry(
        _authorization_context_sources(),
        selected,
        authorization,
        policy_id=policy_id,
    )


def _correlation_row_facts(
    row_value: sqlite3.Row | dict,
) -> dict[str, Any]:
    return correlation_row_facts(
        CorrelationFactSources(
            row_value=sqlite_value,
            parse_json_object=parse_json_object,
        ),
        row_value,
    )


def _correlation_relationships(
    selected_facts: dict[str, Any],
    related_facts: dict[str, Any],
) -> list[dict[str, Any]]:
    return correlation_relationships(selected_facts, related_facts)

def correlated_alert_context(
    conn: sqlite3.Connection,
    selected: sqlite3.Row,
    limit: int,
    min_score: int,
) -> dict:
    """Return bounded deterministic cross-alert context with provenance."""
    return build_correlated_alert_context(
        CorrelationContextSources(
            rows=rows,
            table_columns=table_columns,
            row_value=sqlite_value,
            observable_weight=correlation_observable_weight,
            time_bonus=correlation_time_bonus,
            row_facts=_correlation_row_facts,
            relationships=_correlation_relationships,
            safe_int=safe_int,
            max_raw_json_bytes=CORRELATION_MAX_RAW_JSON_BYTES,
        ),
        conn,
        selected,
        limit,
        min_score,
    )


def grouped_alert_context(conn: sqlite3.Connection, selected: sqlite3.Row, limit: int, include_tests: bool) -> dict:
    """Summarize the dashboard duplicate group so AI weighs alert frequency."""
    selected_group_key = alert_group_key(selected)
    group_rows = alert_group_rows(conn, selected, include_tests=include_tests)
    total_observations = sum(max(1, safe_int(sqlite_value(item, "seen_count"))) for item in group_rows)
    first_seen_values = [str(sqlite_value(item, "first_seen") or "") for item in group_rows if sqlite_value(item, "first_seen")]
    last_seen_values = [str(sqlite_value(item, "last_seen") or "") for item in group_rows if sqlite_value(item, "last_seen")]
    timeline = [
        {
            "alert_id": item["alert_id"],
            "first_seen": sqlite_value(item, "first_seen"),
            "last_seen": sqlite_value(item, "last_seen"),
            "seen_count": max(1, safe_int(sqlite_value(item, "seen_count"))),
            "source_ip": sqlite_value(item, "source_ip"),
            "destination_ip": sqlite_value(item, "destination_ip"),
            "destination_port": sqlite_value(item, "destination_port"),
            "triage_level": sqlite_value(item, "triage_level"),
            "triage_score": sqlite_value(item, "triage_score"),
            "filter_status": sqlite_value(item, "filter_status"),
        }
        for item in group_rows[:limit]
    ]
    return {
        "group_key": selected_group_key,
        "raw_alert_rows": len(group_rows),
        "total_observations": total_observations,
        "first_seen": min(first_seen_values) if first_seen_values else sqlite_value(selected, "first_seen"),
        "last_seen": max(last_seen_values) if last_seen_values else sqlite_value(selected, "last_seen"),
        "timeline_sample": timeline,
        "timeline_sample_limit": limit,
        "frequency_guidance": (
            "Use total_observations and raw_alert_rows to judge urgency, recurrence, and tuning. "
            "A high count may indicate active behavior, noisy expected software, or a rule that needs suppression/drop/tuning."
        ),
    }


def compact_alert(row_value: sqlite3.Row) -> dict:
    alert = parse_alert_json(row_value["alert_json"])
    triage = alert.get("triage") if isinstance(alert.get("triage"), dict) else {}
    raw_event = parse_json_object(str(sqlite_value(row_value, "raw_event_json") or ""))
    rule_context = extract_rule_context(
        alert,
        raw_event,
        sqlite_value(row_value, "rule_id"),
    )
    parsed_rule = (
        rule_context.get("parsed_rule")
        if isinstance(rule_context.get("parsed_rule"), dict)
        else {}
    )
    message = alert.get("message")
    if isinstance(message, str) and len(message) <= 2000 and '"packet"' not in message:
        safe_message = message
    else:
        safe_message = None
    safe_contents = []
    for item in parsed_rule.get("contents", []) if isinstance(parsed_rule.get("contents"), list) else []:
        if not isinstance(item, dict):
            continue
        modifiers = item.get("modifiers") if isinstance(item.get("modifiers"), dict) else {}
        safe_contents.append(
            {
                "id": item.get("id"),
                "sha256": item.get("sha256"),
                "length": item.get("length"),
                "negated": bool(item.get("negated")),
                "modifiers": {
                    key: value
                    for key, value in modifiers.items()
                    if key in {"offset", "depth", "distance", "within", "startswith", "endswith", "nocase", "rawbytes"}
                    and (isinstance(value, bool) or re.fullmatch(r"\d{1,8}", str(value or "")))
                },
            }
        )
    return {
        "alert_id": row_value["alert_id"],
        "timestamp": row_value["timestamp"],
        "first_seen": row_value["first_seen"],
        "last_seen": row_value["last_seen"],
        "seen_count": row_value["seen_count"],
        "total_seen_count": sqlite_value(row_value, "total_seen_count"),
        "rule_name": row_value["rule_name"],
        "event_dataset": row_value["event_dataset"],
        "severity": row_value["severity"],
        "severity_label": row_value["severity_label"],
        "source_ip": row_value["source_ip"],
        "source_port": sqlite_value(row_value, "source_port"),
        "destination_ip": row_value["destination_ip"],
        "destination_port": sqlite_value(row_value, "destination_port"),
        "transport_protocol": sqlite_value(row_value, "transport_protocol"),
        "network_protocol": sqlite_value(row_value, "network_protocol"),
        "rule_id": sqlite_value(row_value, "rule_id"),
        "traffic_direction": row_value["traffic_direction"],
        "triage_score": row_value["triage_score"],
        "triage_level": row_value["triage_level"],
        "routing": row_value["routing"],
        "filter_status": row_value["filter_status"],
        "filter_reason": row_value["filter_reason"],
        "suppression_key": row_value["suppression_key"],
        "triage_reasons": triage.get("reasons", []),
        "rule_context": {
            "sid": rule_context.get("sid"),
            "record_rule_id": rule_context.get("record_rule_id"),
            "revision": rule_context.get("revision"),
            "name": rule_context.get("name"),
            "ruleset": rule_context.get("ruleset"),
            "category": rule_context.get("category"),
            "rule_sha256": parsed_rule.get("rule_sha256"),
            "deployed_rule": {
                "protocol": parsed_rule.get("protocol"),
                "packet_predicates": parsed_rule.get("predicates") or [],
                "content_predicates": safe_contents,
                "state_preconditions": [
                    {
                        "kind": item.get("kind"),
                        "operation": item.get("operation"),
                    }
                    for item in parsed_rule.get("state_operations", [])
                    if isinstance(item, dict)
                    and str(item.get("operation") or "").lower() in {"isset", "isnotset"}
                ],
                "unsupported_constraint_count": len(parsed_rule.get("unsupported_match_options") or []),
            },
        },
        "raw_alert_subset": {
            "source": alert.get("source"),
            "destination": alert.get("destination"),
            "network": alert.get("network"),
            "event": alert.get("event"),
            "observer": alert.get("observer"),
            "message": safe_message,
            "rule_category": alert.get("rule_category"),
            "rule_ruleset": alert.get("rule_ruleset"),
            "signature_id": alert.get("signature_id"),
        },
    }


def _nested_alert_value(alert: dict, dotted_path: str) -> object:
    current: object = alert
    for part in dotted_path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def asset_observables_and_events(group_rows: list[sqlite3.Row]) -> tuple[list[dict], list[dict]]:
    """Extract only explicit endpoint identifiers; never recursively promote sensor fields."""
    observables: list[dict] = []
    events: list[dict] = []
    for item in group_rows[:5000]:
        alert = parse_alert_json(str(sqlite_value(item, "alert_json") or ""))
        explicit_values = [
            ("ip", sqlite_value(item, "source_ip"), "source"),
            ("ip", sqlite_value(item, "destination_ip"), "destination"),
            ("ip", _nested_alert_value(alert, "client.ip"), "client"),
            ("ip", _nested_alert_value(alert, "server.ip"), "server"),
            ("ip", _nested_alert_value(alert, "host.ip"), "host"),
            ("mac", _nested_alert_value(alert, "source.mac"), "source"),
            ("mac", _nested_alert_value(alert, "destination.mac"), "destination"),
            ("mac", _nested_alert_value(alert, "client.mac"), "client"),
            ("mac", _nested_alert_value(alert, "server.mac"), "server"),
            ("hostname", _nested_alert_value(alert, "source.domain"), "source"),
            ("hostname", _nested_alert_value(alert, "destination.domain"), "destination"),
            ("hostname", _nested_alert_value(alert, "client.domain"), "client"),
            ("hostname", _nested_alert_value(alert, "server.domain"), "server"),
            ("hostname", _nested_alert_value(alert, "host.hostname"), "host"),
            ("hostname", _nested_alert_value(alert, "host.name"), "host"),
        ]
        observables.extend(
            {"type": observable_type, "value": value, "role": role}
            for observable_type, value, role in explicit_values
            if value not in (None, "")
        )
        events.append(
            {
                "source_ip": sqlite_value(item, "source_ip"),
                "destination_ip": sqlite_value(item, "destination_ip"),
                "destination_port": sqlite_value(item, "destination_port"),
                "protocol": sqlite_value(item, "transport_protocol"),
            }
        )
    return observables, events


def investigation_query_context(
    selected: sqlite3.Row,
    group_rows: list[sqlite3.Row],
    group_id: str,
    actor_role: str,
    pcap_available: bool,
) -> tuple[dict, dict]:
    """Compatibility delegate for broker query-context projection."""
    return build_investigation_query_context(
        investigation_query_context_policy(),
        investigation_query_context_sources(),
        selected,
        group_rows,
        group_id,
        actor_role,
        pcap_available,
    )


def investigation_query_context_policy() -> QueryContextPolicy:
    return QueryContextPolicy(
        query_contract=INVESTIGATION_QUERY_CONTRACT,
        query_v2=INVESTIGATION_QUERY_V2,
        query_packs=tuple(INVESTIGATION_QUERY_PACKS),
        pack_descriptions=INVESTIGATION_QUERY_PACK_DESCRIPTIONS,
        security_onion_purposes=INVESTIGATION_SECURITY_ONION_PURPOSES,
        derived_operations=INVESTIGATION_DERIVED_OPERATIONS,
        derived_filters=INVESTIGATION_DERIVED_FILTERS,
        contract_packs=INVESTIGATION_CONTRACT_PACKS,
        event_tuple_paths=EVENT_TUPLE_PATHS,
        pack_role_mode=PACK_ROLE_MODE,
        allowed_actor_roles=frozenset(
            INVESTIGATION_CONTRACT.ALLOWED_ACTOR_ROLES
        ),
        event_tuple_atom_pattern=INVESTIGATION_EVENT_TUPLE_ATOM_RE,
        alert_index_pattern=ALERT_INDEX_RE,
        elastic_id_pattern=SAFE_ELASTIC_ID_RE,
        pivot_atom_pattern=SAFE_PIVOT_ATOM_RE,
        pivot_domain_pattern=SAFE_PIVOT_DOMAIN_RE,
        max_rounds=INVESTIGATION_QUERY_MAX_ROUNDS,
        max_queries_total=INVESTIGATION_QUERY_MAX_TOTAL,
        max_queries_per_round=INVESTIGATION_QUERY_MAX_PER_ROUND,
    )


def investigation_query_context_sources() -> QueryContextSources:
    return QueryContextSources(
        parse_alert=parse_alert_json,
        parse_json_object=parse_json_object,
        row_value=sqlite_value,
        nested_value=_nested_alert_value,
        parse_datetime=parse_project_datetime,
        now_utc=lambda: dt.datetime.now(dt.timezone.utc),
    )


def exact_detection_group_rows(
    group_rows: list[sqlite3.Row],
    selected_rule_context: dict,
) -> tuple[list[sqlite3.Row], dict]:
    """Keep packet copies bound to the selected SID, revision, and rule digest."""
    selected_parsed = (
        selected_rule_context.get("parsed_rule")
        if isinstance(selected_rule_context.get("parsed_rule"), dict)
        else {}
    )
    selected_sid = str(selected_rule_context.get("sid") or "")
    selected_revision = selected_rule_context.get("revision")
    selected_digest = str(selected_parsed.get("rule_sha256") or "")
    exact: list[sqlite3.Row] = []
    excluded = 0
    input_truncated = len(group_rows) > MAX_DETECTION_GROUP_ROWS
    for item in group_rows[:MAX_DETECTION_GROUP_ROWS]:
        alert = parse_alert_json(str(sqlite_value(item, "alert_json") or ""))
        raw = parse_json_object(str(sqlite_value(item, "raw_event_json") or ""))
        context = extract_rule_context(alert, raw, sqlite_value(item, "rule_id"))
        parsed = context.get("parsed_rule") if isinstance(context.get("parsed_rule"), dict) else {}
        conflicts = context.get("identity_conflicts")
        identity_conflict = bool(
            isinstance(conflicts, dict)
            and any(conflicts.get(key) for key in ("sid", "revision"))
        )
        same = not identity_conflict
        if selected_sid:
            same = same and str(context.get("sid") or "") == selected_sid
        if selected_revision is not None:
            same = same and context.get("revision") == selected_revision
        if selected_digest:
            same = same and str(parsed.get("rule_sha256") or "") == selected_digest
        if same:
            exact.append(item)
        else:
            excluded += 1
    return exact, {
        "input_rows": min(len(group_rows), MAX_DETECTION_GROUP_ROWS),
        "exact_rule_rows": len(exact),
        "excluded_nonmatching_rows": excluded,
        "input_truncated": input_truncated,
        "identity": {
            "sid": selected_sid,
            "revision": selected_revision,
            "rule_sha256": selected_digest,
        },
    }


def model_policy(level: str | None) -> dict:
    normalized = str(level or "").lower()
    return {
        "default_model_path": "local_llm",
        "hosted_second_opinion_allowed": normalized in ESCALATE_LEVELS,
        "hosted_second_opinion_rule": "Only use hosted GPT-class analysis for critical/high alerts or when local analysis requests escalation.",
        "privacy_rule": "Do not send raw packet payloads, packet samples, local PCAP query results, credentials, tokens, or unnecessary internal notes to hosted models.",
    }


def agent_task(agent_role: str, *, blind_reanalysis: bool = False) -> str:
    """Return the bounded objective for the selected role.

    Every role receives the same immutable evidence contract. Only the decision
    objective changes, which prevents role routing from creating divergent or
    incomplete evidence collectors.
    """
    if agent_role == "incident-responder":
        historical_context = (
            "human analyst adjudications and operator-confirmed context"
            if blind_reanalysis
            else "prior SOC analyses"
        )
        return (
            "Produce a senior incident-response investigation report for the complete alert group. "
            f"Use its full timeline and frequency, {historical_context}, public enrichment, "
            "parsed PCAP evidence, analyst notes, correlations, memory, and the supplied "
            "read-only Security Onion query results. Build a fact-grounded timeline and "
            "determine scope, affected systems, likely impact, containment, eradication, "
            "recovery, evidence gaps, and safe next actions. Clearly distinguish observed "
            "facts from hypotheses. Never claim a query or response action occurred unless "
            "the supplied evidence records it."
        )
    if agent_role == "siem-engineer":
        return (
            "Produce a detection-engineering assessment of this alert group. "
            "Evaluate the exact deployed rule predicates, evidence coverage, false-positive "
            "drivers, severity and scoring, then propose bounded tuning or validation steps "
            "with expected impact and rollback criteria. Preserve detection coverage and "
            "never claim a rule change or query execution occurred unless supplied evidence "
            "records it."
        )
    if agent_role == "cyber-threat-intel":
        return (
            "Produce a threat-intelligence assessment for this alert group. Separate observed "
            "telemetry from external reporting and hypotheses; assess indicator relevance, "
            "confidence, recency, likely behaviors, collection gaps, and defensible pivots. "
            "Avoid unsupported attribution and never claim enrichment or query results that "
            "are not present in the supplied evidence."
        )
    if agent_role == "threat-hunter":
        return (
            "Produce a threat-hunting assessment for this alert group. Develop prioritized, "
            "falsifiable hypotheses from observed facts, identify expected corroborating and "
            "disconfirming evidence, and recommend bounded read-only pivots using the supplied "
            "query contract. Clearly distinguish proposed queries from executed queries and "
            "never claim results that are absent from the evidence."
        )
    return (
        "Explain likely meaning, repeat frequency, false positive possibilities, urgency, "
        "next investigative steps, tuning actions, and whether an independent second-model "
        "opinion is warranted."
    )


def _detection_context_sources() -> DetectionContextSources:
    return DetectionContextSources(
        row_value=sqlite_value,
        alert_group_rows=alert_group_rows,
        parse_alert_json=parse_alert_json,
        parse_json_object=parse_json_object,
        extract_rule_context=extract_rule_context,
        load_investigation_skills=load_investigation_skills,
        resolve_investigation_skills=resolve_investigation_skills,
        exact_detection_group_rows=exact_detection_group_rows,
        load_detection_playbooks=load_detection_playbooks,
        resolve_detection_playbook=resolve_detection_playbook,
        marker_specs=marker_specs,
        extract_group_packet_features=extract_group_packet_features,
        build_detection_validation=build_detection_validation,
        load_asset_inventory=load_asset_inventory,
        asset_observables_and_events=asset_observables_and_events,
        resolve_asset_context=resolve_asset_context,
    )


def build_package(conn: sqlite3.Connection, selected: sqlite3.Row, args: argparse.Namespace) -> dict:
    snapshot = collect_core_evidence_snapshot(
        CoreEvidenceSnapshotSources(
            grouped_alert_context=grouped_alert_context,
            pcap_evidence_context=pcap_evidence_context,
            public_enrichment_context=public_enrichment_context,
            authorized_activity_context=authorized_activity_context,
            analyst_state_context=analyst_state_context,
            correlated_alert_context=correlated_alert_context,
            compact_alert=compact_alert,
        ),
        CoreEvidenceSnapshotRequest(
            connection=conn,
            selected=selected,
            rollup_dir=args.rollup_dir,
            rollup_bytes=args.rollup_bytes,
            related_limit=args.related_limit,
            include_tests=bool(args.include_tests),
            pcap_analysis_dir=args.pcap_analysis_dir,
            pcap_analysis_limit=args.pcap_analysis_limit,
            correlation_limit=args.correlation_limit,
            correlation_min_score=args.correlation_min_score,
        ),
    )
    detection_context = prepare_detection_context(
        _detection_context_sources(),
        DetectionContextRequest(
            connection=conn,
            selected=selected,
            include_tests=bool(args.include_tests),
            agent_role=str(args.agent_role),
            investigation_skills_path=Path(
                getattr(
                    args,
                    "investigation_skills",
                    DEFAULT_INVESTIGATION_SKILLS_FILE,
                )
            ),
            detection_playbooks_path=Path(
                getattr(
                    args,
                    "detection_playbooks",
                    DEFAULT_DETECTION_PLAYBOOKS_FILE,
                )
            ),
            asset_inventory_path=Path(
                getattr(
                    args,
                    "asset_inventory_file",
                    DEFAULT_ASSET_INVENTORY_FILE,
                )
            ),
            maximum_group_rows=MAX_DETECTION_GROUP_ROWS,
        ),
    )
    admitted_evidence = prepare_prompt_evidence_admission(
        PromptEvidenceAdmissionSources(
            investigation_query_context=investigation_query_context,
            build_agent_memory_context=build_agent_memory_context,
            blind_model_authored_context=blind_model_authored_context,
            load_json_bounded=load_json_bounded,
            validate_incident_evidence=validate_incident_evidence_artifact,
            reject_preprojected_incident_evidence=(
                reject_preprojected_incident_evidence_source
            ),
            project_incident_evidence_hits=project_incident_evidence_hits,
        ),
        PromptEvidenceAdmissionRequest(
            selected=selected,
            agent_role=str(args.agent_role),
            group_id=str(snapshot.analyst_state.get("group_id") or ""),
            exact_validation_rows=detection_context.exact_validation_rows,
            pcap_context=snapshot.pcap_evidence,
            enrichment_context=snapshot.public_enrichment,
            compact_alert=snapshot.alert,
            grouped_alert_context=snapshot.grouped_alert_context,
            detection_validation=detection_context.detection_validation,
            asset_context=detection_context.asset_context,
            authorization_evidence=snapshot.authorization_evidence,
            analyst_state=snapshot.analyst_state,
            correlation_context=snapshot.correlated_alert_context,
            role_memory_file=args.agent_memory_file,
            shared_memory_file=args.shared_memory_file,
            memory_bytes=args.memory_bytes,
            blind_reanalysis=bool(args.blind_reanalysis),
            incident_evidence_file=args.incident_evidence_file,
            maximum_incident_evidence_bytes=MAX_INCIDENT_EVIDENCE_BYTES,
        ),
    )
    prompt_contract = build_prompt_contract(
        PromptContractRequest(
            agent_role=str(args.agent_role),
            blind_reanalysis=bool(args.blind_reanalysis),
            role_prompt=load_system_prompt(args.system_prompt_file),
            task=agent_task(
                args.agent_role,
                blind_reanalysis=args.blind_reanalysis,
            ),
            query_packs=tuple(INVESTIGATION_QUERY_PACKS),
            query_v2=INVESTIGATION_QUERY_V2,
        )
    )
    history = collect_historical_evidence_snapshot(
        HistoricalEvidenceSnapshotSources(
            prior_analysis_context=prior_analysis_context,
            related_alerts=related_alerts,
            query_rows=rows,
        ),
        HistoricalEvidenceSnapshotRequest(
            connection=conn,
            selected=selected,
            analysis_dir=args.analysis_dir,
            related_limit=args.related_limit,
            include_tests=bool(args.include_tests),
            blind_reanalysis=bool(args.blind_reanalysis),
        ),
    )
    return assemble_prompt_package(
        PromptPackageView(
            agent_role=str(args.agent_role),
            blind_reanalysis=bool(args.blind_reanalysis),
            lineage=execution_lineage(
                selected,
                blind_reanalysis=args.blind_reanalysis,
            ),
            generated_at=project_now(),
            analysis_policy=model_policy(selected["triage_level"]),
            runtime_files={
                "system_prompt_file": str(args.system_prompt_file),
                "second_opinion_system_prompt_file": str(
                    args.second_opinion_prompt_file
                ),
                "agent_memory_file": str(args.agent_memory_file),
                "shared_memory_file": str(args.shared_memory_file),
            },
            prompt_contract=prompt_contract,
            evidence_sections={
                "alert": snapshot.alert,
                "grouped_alert_context": snapshot.grouped_alert_context,
                "public_enrichment": snapshot.public_enrichment,
                "pcap_evidence": snapshot.pcap_evidence,
                "investigation_query_capability": (
                    admitted_evidence.investigation_capability
                ),
                "_local_investigation_query_context": (
                    admitted_evidence.local_investigation_query_context
                ),
                "investigation_skills": detection_context.investigation_skills,
                "detection_validation": detection_context.detection_validation,
                "asset_context": detection_context.asset_context,
                "authorization_evidence": snapshot.authorization_evidence,
                "analyst_state": snapshot.analyst_state,
                "prior_analyses": history.prior_analyses,
                "related_alerts": history.related_alerts,
                "correlated_alert_context": admitted_evidence.correlation_context,
                "recent_notifications": history.recent_notifications,
                "agent_memory": admitted_evidence.memory_context,
                "latest_daily_rollup": snapshot.latest_daily_rollup,
            },
            incident_evidence=admitted_evidence.incident_evidence,
        )
    )


def incident_prompt_immutable_query_provenance(incident: dict) -> dict:
    """Compatibility delegate for immutable incident query provenance."""
    return immutable_query_provenance(incident)


def incident_prompt_mandatory_grounding_digest(package: dict) -> str:
    """Compatibility delegate for mandatory incident prompt grounding."""
    return mandatory_grounding_digest(
        IncidentGroundingSources(
            validate_incident_evidence=validate_incident_evidence_artifact,
        ),
        package,
    )

def compact_package_to_budget(package: dict, max_bytes: int) -> tuple[dict, str]:
    """Compatibility delegate for deterministic package compaction."""
    return compact_prompt_package(
        PackageCompactionSources(
            mandatory_grounding_digest=(
                incident_prompt_mandatory_grounding_digest
            ),
            project_hits=project_incident_evidence_hits,
            project_osquery_rows=project_incident_evidence_osquery_rows,
            validate_incident_evidence=validate_incident_evidence_artifact,
        ),
        package,
        max_bytes,
    )


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        raise SystemExit(f"SQLite DB not found: {args.db}")
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        selected = select_alert(conn, args)
        package = build_package(conn, selected, args)
    finally:
        conn.close()

    package, output = compact_package_to_budget(package, args.max_package_bytes)
    if args.stdout:
        print(output)
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = filename_timestamp(project_now())
    alert_id = safe_filename(str(package["alert"]["alert_id"]))
    out_path = args.out_dir / f"{stamp}-{alert_id}-ai-prompt.json"
    out_path.write_text(output + "\n", encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
