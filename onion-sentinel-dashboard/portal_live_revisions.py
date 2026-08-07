"""Bounded live-revision hashing and Incident Responder state repository."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Callable


JsonObject = dict[str, object]


@dataclass(frozen=True)
class RevisionSchemaDependencies:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    table_columns: Callable[[sqlite3.Connection, str], set[str]]


def revision_digest(value: object) -> str:
    """Return an opaque, deterministic live-update token."""
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def bounded_file_revision(path: Path, maximum_bytes: int) -> str:
    """Fingerprint bounded file identity without exposing path or contents."""
    try:
        metadata = path.stat()
        if not path.is_file() or metadata.st_size > maximum_bytes:
            return revision_digest(("invalid",))
        return revision_digest((metadata.st_mtime_ns, metadata.st_size))
    except FileNotFoundError:
        return revision_digest(("missing",))
    except OSError:
        return revision_digest(("unavailable",))


def revision_rows(
    conn: sqlite3.Connection,
    table: str,
    columns: tuple[str, ...],
    schema: RevisionSchemaDependencies,
    *,
    where_sql: str = "",
    arguments: tuple[object, ...] = (),
    order_sql: str = "",
    limit: int | None = None,
) -> list[JsonObject]:
    """Read a schema-tolerant, bounded table slice for revision hashing."""
    if not schema.table_exists(conn, table):
        return []
    available = schema.table_columns(conn, table)
    selected = [column for column in columns if column in available]
    if not selected:
        return []
    query = f"SELECT {', '.join(selected)} FROM {table}"
    if where_sql:
        query += f" WHERE {where_sql}"
    if order_sql:
        query += f" ORDER BY {order_sql}"
    query_arguments = list(arguments)
    if limit is not None:
        query += " LIMIT ?"
        query_arguments.append(limit)
    return [dict(row) for row in conn.execute(query, query_arguments).fetchall()]


def _values(rows: list[JsonObject], key: str) -> tuple[str, ...]:
    return tuple(str(row[key]) for row in rows if row.get(key))


def _related_rows(
    conn: sqlite3.Connection,
    schema: RevisionSchemaDependencies,
    table: str,
    columns: tuple[str, ...],
    key: str,
    values: tuple[str, ...],
) -> list[JsonObject]:
    if not values:
        return []
    placeholders = ",".join("?" for _ in values)
    return revision_rows(
        conn,
        table,
        columns,
        schema,
        where_sql=f"{key} IN ({placeholders})",
        arguments=values,
        order_sql=key,
    )


def incident_response_revision_state(
    conn: sqlite3.Connection,
    schema: RevisionSchemaDependencies,
) -> JsonObject:
    """Load only records capable of changing the Incident Responder UI."""
    cases = revision_rows(
        conn,
        "incident_response_cases",
        (
            "case_id", "group_id", "dashboard_group_id",
            "representative_alert_id", "status", "agent_status",
            "escalated_at", "updated_at", "latest_analysis_id",
            "latest_model", "latest_generated_at", "latest_error",
            "resolution_reason", "resolved_at", "resolved_by",
        ),
        schema,
        order_sql="case_id",
    )
    dashboard_group_ids = _values(cases, "dashboard_group_id")
    representative_alert_ids = _values(cases, "representative_alert_id")
    analysis_ids = _values(cases, "latest_analysis_id")
    case_ids = _values(cases, "case_id")
    state: JsonObject = {"cases": cases}
    state["groups"] = _related_rows(
        conn, schema, "alert_group_summary",
        (
            "group_id", "rule_name", "severity", "severity_label",
            "triage_level", "source_ip", "destination_ip",
            "destination_port", "raw_alert_count", "total_seen_count",
            "first_seen", "last_seen",
        ),
        "group_id", dashboard_group_ids,
    )
    state["alerts"] = _related_rows(
        conn, schema, "alerts",
        (
            "alert_id", "rule_name", "severity", "severity_label",
            "triage_level", "source_ip", "destination_ip",
            "destination_port", "seen_count", "first_seen", "last_seen",
        ),
        "alert_id", representative_alert_ids,
    )
    state["analyses"] = _related_rows(
        conn, schema, "ai_analysis_runs",
        (
            "analysis_id", "generated_at", "model", "detection_outcome",
            "confidence", "evidence_hash", "response_json",
        ),
        "analysis_id", analysis_ids,
    )
    state["reviews"] = _related_rows(
        conn, schema, "ai_second_opinion_runs",
        (
            "analysis_id", "status", "reviewer_outcome",
            "reviewer_confidence", "agreement", "material_disagreement",
            "disputed_fields_json", "generated_at",
        ),
        "analysis_id", analysis_ids,
    )
    state["adjudications"] = _related_rows(
        conn, schema, "analyst_adjudications",
        (
            "case_id", "analysis_id", "outcome_override", "confidence",
            "event_status", "detection_validity", "activity_disposition",
            "handling", "case_resolution_reason", "created_at",
        ),
        "case_id", case_ids,
    )
    latest_runs = revision_rows(
        conn,
        "incident_reanalysis_runs",
        (
            "run_id", "release_id", "scope", "status", "total_count",
            "created_at", "updated_at", "completed_at",
        ),
        schema,
        order_sql="created_at DESC",
        limit=1,
    )
    state["reanalysis_runs"] = latest_runs
    if latest_runs:
        state["reanalysis_cases"] = _related_rows(
            conn, schema, "incident_reanalysis_run_cases",
            (
                "run_id", "case_id", "status", "skip_reason",
                "latest_error", "analysis_id", "result_generated_at",
                "updated_at",
            ),
            "run_id", (str(latest_runs[0].get("run_id") or ""),),
        )
    return state


def incident_response_revision(
    conn: sqlite3.Connection,
    schema: RevisionSchemaDependencies,
) -> str:
    """Return the deterministic digest for the public incident view state."""
    return revision_digest(incident_response_revision_state(conn, schema))
