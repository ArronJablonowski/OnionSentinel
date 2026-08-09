"""Page-bounded SOC alert evidence metadata composition."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable, Union


JsonObject = dict[str, object]
Row = Union[sqlite3.Row, dict]


@dataclass(frozen=True)
class SocEvidenceDependencies:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]
    dashboard_group_id: Callable[[str], str]
    outcome_label: Callable[[object], str]
    incident_defaults: Callable[[], JsonObject]
    review_defaults: Callable[[], JsonObject]
    apply_review: Callable[[sqlite3.Connection, list[Row], dict[str, JsonObject], dict[str, str]], None]
    apply_incident: Callable[[sqlite3.Connection, list[Row], dict[str, JsonObject], dict[str, str]], None]


def _row_value(row: Row, key: str) -> str:
    if isinstance(row, dict):
        return str(row.get(key) or "").strip()
    return str(row[key] or "").strip() if key in row.keys() else ""


def _initialize_metadata(rows: list[Row], deps: SocEvidenceDependencies) -> tuple[
    dict[str, JsonObject], dict[str, str], dict[str, str]
]:
    metadata: dict[str, JsonObject] = {}
    group_by_key: dict[str, str] = {}
    group_by_alert: dict[str, str] = {}
    for row in rows:
        group_key = _row_value(row, "group_key")
        group_id = deps.dashboard_group_id(group_key) if group_key else _row_value(row, "group_id")
        if not group_id:
            continue
        alert_id = _row_value(row, "alert_id") or _row_value(row, "representative_alert_id")
        metadata[group_id] = {
            "pcap_size_bytes": 0,
            "detection_outcome": "",
            "detection_outcome_label": "n/a",
            **deps.incident_defaults(),
            **deps.review_defaults(),
        }
        if group_key:
            group_by_key[group_key] = group_id
        if alert_id:
            group_by_alert[alert_id] = group_id
    return metadata, group_by_key, group_by_alert


def _mapping(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _apply_artifact_outcomes(metadata: dict[str, JsonObject], artifacts: object,
                             deps: SocEvidenceDependencies) -> None:
    outcomes = _mapping(artifacts).get("detection_outcome_by_group_id")
    if not isinstance(outcomes, dict):
        return
    for group_id, record in metadata.items():
        outcome = str(outcomes.get(group_id) or "").strip()
        if outcome:
            record["detection_outcome"] = outcome
            record["detection_outcome_label"] = deps.outcome_label(outcome)


def _alert_fallback_size(group_id: str, sizes: dict, group_by_alert: dict[str, str]) -> int:
    return sum(
        int(sizes.get(alert_id, 0) or 0)
        for alert_id, alert_group_id in group_by_alert.items()
        if alert_group_id == group_id
    )


def _apply_artifact_pcap_sizes(metadata: dict[str, JsonObject], pcap_analysis: object,
                               group_by_alert: dict[str, str]) -> None:
    analysis = _mapping(pcap_analysis)
    sizes_by_group = _mapping(analysis.get("size_by_group_id"))
    sizes_by_alert = _mapping(analysis.get("size_by_alert_id"))
    for group_id, record in metadata.items():
        fallback_size = int(sizes_by_group.get(group_id, 0) or 0)
        if fallback_size <= 0:
            fallback_size = _alert_fallback_size(group_id, sizes_by_alert, group_by_alert)
        record["pcap_size_bytes"] = max(0, fallback_size)


def _where_terms(columns: list[tuple[str, list[str]]]) -> tuple[str, list[str]]:
    clauses: list[str] = []
    arguments: list[str] = []
    for column, values in columns:
        if values:
            clauses.append(f"{column} IN ({','.join('?' for _ in values)})")
            arguments.extend(values)
    return " OR ".join(clauses), arguments


def _pcap_rows(conn: sqlite3.Connection, group_ids: list[str], group_keys: list[str],
               alert_ids: list[str]) -> list[sqlite3.Row]:
    where_sql, arguments = _where_terms([
        ("group_id", group_ids), ("group_key", group_keys), ("alert_id", alert_ids),
    ])
    if not where_sql:
        return []
    try:
        return conn.execute(
            "SELECT request_id, alert_id, group_id, group_key, artifact_path, "
            "artifact_sha256, artifact_size_bytes FROM pcap_requests "
            f"WHERE ({where_sql}) AND COALESCE(artifact_size_bytes, 0) > 0",
            arguments,
        ).fetchall()
    except sqlite3.Error:
        return []


def _pcap_group_id(item: sqlite3.Row, metadata: dict[str, JsonObject],
                   group_by_key: dict[str, str], group_by_alert: dict[str, str]) -> str:
    stored_group_id = str(item["group_id"] or "").strip()
    if stored_group_id in metadata:
        return stored_group_id
    return (
        group_by_key.get(str(item["group_key"] or "").strip())
        or group_by_alert.get(str(item["alert_id"] or "").strip())
        or ""
    )


def _artifact_identity(item: sqlite3.Row) -> str:
    for column in ("artifact_sha256", "artifact_path", "request_id"):
        value = str(item[column] or "").strip()
        if value:
            return value
    return ""


def _apply_database_pcap_sizes(conn: sqlite3.Connection, metadata: dict[str, JsonObject],
                               group_by_key: dict[str, str], group_by_alert: dict[str, str]) -> None:
    rows = _pcap_rows(conn, sorted(metadata), sorted(group_by_key), sorted(group_by_alert))
    sizes: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for item in rows:
        group_id = _pcap_group_id(item, metadata, group_by_key, group_by_alert)
        identity = _artifact_identity(item)
        artifact_key = (group_id, identity)
        if not group_id or not identity or artifact_key in seen:
            continue
        seen.add(artifact_key)
        sizes[group_id] = sizes.get(group_id, 0) + max(0, int(item["artifact_size_bytes"] or 0))
    for group_id, size_bytes in sizes.items():
        metadata[group_id]["pcap_size_bytes"] = size_bytes


def _analysis_rows(conn: sqlite3.Connection, group_ids: list[str], alert_ids: list[str],
                   columns: set[str]) -> list[sqlite3.Row]:
    where_sql, arguments = _where_terms([("group_id", group_ids), ("alert_id", alert_ids)])
    if not where_sql:
        return []
    role_filter = ""
    if "agent_role" in columns:
        role_filter = " AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = 'soc-analyst'"
    try:
        return conn.execute(
            "SELECT group_id, alert_id, detection_outcome, generated_at, created_at "
            "FROM ai_analysis_runs "
            f"WHERE ({where_sql}) AND COALESCE(detection_outcome, '') <> ''{role_filter} "
            "ORDER BY COALESCE(NULLIF(generated_at, ''), created_at) DESC, rowid DESC",
            arguments,
        ).fetchall()
    except sqlite3.Error:
        return []


def _apply_database_outcomes(conn: sqlite3.Connection, metadata: dict[str, JsonObject],
                             group_by_alert: dict[str, str], deps: SocEvidenceDependencies) -> None:
    rows = _analysis_rows(
        conn, sorted(metadata), sorted(group_by_alert), deps.table_columns(conn, "ai_analysis_runs"),
    )
    resolved: set[str] = set()
    for item in rows:
        stored_group_id = str(item["group_id"] or "").strip()
        stored_alert_id = str(item["alert_id"] or "").strip()
        group_id = stored_group_id if stored_group_id in metadata else group_by_alert.get(stored_alert_id, "")
        outcome = str(item["detection_outcome"] or "").strip()
        if not group_id or group_id in resolved or not outcome:
            continue
        resolved.add(group_id)
        metadata[group_id]["detection_outcome"] = outcome
        metadata[group_id]["detection_outcome_label"] = deps.outcome_label(outcome)


def compose_soc_evidence_metadata(conn: sqlite3.Connection | None, rows: list[Row],
                                  ai_artifacts: object, pcap_analysis: object,
                                  dependencies: SocEvidenceDependencies) -> dict[str, JsonObject]:
    """Compose PCAP, SOC outcome, review, and incident metadata for one page."""
    metadata, group_by_key, group_by_alert = _initialize_metadata(rows, dependencies)
    _apply_artifact_outcomes(metadata, ai_artifacts, dependencies)
    _apply_artifact_pcap_sizes(metadata, pcap_analysis, group_by_alert)
    if conn is None or not metadata:
        return metadata
    if dependencies.table_exists(conn, "pcap_requests"):
        _apply_database_pcap_sizes(conn, metadata, group_by_key, group_by_alert)
    if dependencies.table_exists(conn, "ai_analysis_runs"):
        _apply_database_outcomes(conn, metadata, group_by_alert, dependencies)
    dependencies.apply_review(conn, rows, metadata, group_by_alert)
    dependencies.apply_incident(conn, rows, metadata, group_by_alert)
    return metadata
