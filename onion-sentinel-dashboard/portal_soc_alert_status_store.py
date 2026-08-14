"""Schema and SQLite repository for durable SOC analyst alert status."""
from __future__ import annotations

import sqlite3
import json
import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class SocAlertStatusStoreSources:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    group_key_sql: Callable[[], str]
    group_id: Callable[[object], str]
    now_iso: Callable[[], str]


def soc_alert_group_summary_available(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
) -> bool:
    if not sources.table_exists(conn, "alert_group_summary"):
        return False
    try:
        row = conn.execute("SELECT COUNT(*) FROM alert_group_summary").fetchone()
    except sqlite3.Error:
        return False
    return bool(row and int(row[0] or 0) > 0)


def load_soc_alert_group_counts(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
) -> dict[str, int]:
    """Return current grouped repeat counts keyed by dashboard group ID."""
    if soc_alert_group_summary_available(sources, conn):
        try:
            rows = conn.execute(
                """
                SELECT group_id,
                       MAX(raw_alert_count, COALESCE(total_seen_count, 0))
                         AS repeat_count
                FROM alert_group_summary
                """
            ).fetchall()
            return {
                row["group_id"]: int(row["repeat_count"] or 0)
                for row in rows
            }
        except sqlite3.Error:
            pass
    group_expr = sources.group_key_sql()
    try:
        rows = conn.execute(
            f"""
            SELECT {group_expr} AS group_key,
                   MAX(
                     COUNT(*),
                     COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0)
                   ) AS repeat_count
            FROM alerts
            GROUP BY group_key
            """
        ).fetchall()
    except sqlite3.Error:
        return {}
    return {
        sources.group_id(row["group_key"]): int(row["repeat_count"] or 0)
        for row in rows
    }


def _valid_dashboard_group_id(value: object) -> str:
    group_id = str(value or "").strip().lower()
    return group_id if re.fullmatch(r"[a-f0-9]{12}", group_id) else ""


def load_manually_escalated_group_ids(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
) -> set[str]:
    """Return dashboard aliases moved manually to Incident Responder."""
    if not all(sources.table_exists(conn, table) for table in (
        "incident_response_cases", "incident_response_events"
    )):
        return set()
    try:
        rows = conn.execute(
            """
            SELECT c.dashboard_group_id, c.group_id AS stable_group_id,
                   e.detail_json
            FROM incident_response_cases AS c
            JOIN incident_response_events AS e ON e.case_id = c.case_id
            WHERE e.event_type = 'escalated'
            """
        ).fetchall()
    except sqlite3.Error:
        return set()
    dashboard_ids, stable_ids = _escalated_row_ids(rows)
    if stable_ids and sources.table_exists(conn, "alert_group_alias"):
        dashboard_ids.update(_alias_group_ids(conn, stable_ids))
    return dashboard_ids


def _escalated_row_ids(rows: list) -> tuple[set[str], set[str]]:
    dashboard_ids = set()
    stable_ids = set()
    for row in rows:
        if group_id := _valid_dashboard_group_id(row["dashboard_group_id"]):
            dashboard_ids.add(group_id)
        if stable_id := str(row["stable_group_id"] or "").strip():
            stable_ids.add(stable_id)
        try:
            detail = json.loads(row["detail_json"] or "{}")
        except (TypeError, json.JSONDecodeError):
            detail = {}
        if isinstance(detail, dict):
            if group_id := _valid_dashboard_group_id(
                detail.get("dashboard_group_id")
            ):
                dashboard_ids.add(group_id)
    return dashboard_ids, stable_ids


def _alias_group_ids(
    conn: sqlite3.Connection,
    stable_ids: set[str],
) -> set[str]:
    aliases = set()
    sorted_ids = sorted(stable_ids)
    for start in range(0, len(sorted_ids), 500):
        chunk = sorted_ids[start:start + 500]
        placeholders = ",".join("?" for _ in chunk)
        try:
            rows = conn.execute(
                "SELECT legacy_group_id FROM alert_group_alias "
                f"WHERE stable_group_id IN ({placeholders})",
                chunk,
            ).fetchall()
        except sqlite3.Error:
            continue
        aliases.update(
            group_id
            for row in rows
            if (group_id := _valid_dashboard_group_id(row["legacy_group_id"]))
        )
    return aliases


def load_active_soc_group_ids(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
    statuses: object,
    manually_escalated_group_ids: set[str] | None = None,
) -> set[str]:
    """Return grouped detections visible in the default active view."""
    hidden = _hidden_active_soc_group_ids(
        sources,
        conn,
        statuses,
        manually_escalated_group_ids,
    )
    if soc_alert_group_summary_available(sources, conn):
        try:
            rows = conn.execute(
                """
                SELECT group_id
                FROM alert_group_summary
                WHERE lower(coalesce(filter_status, 'accepted')) != 'suppressed'
                """
            ).fetchall()
            return {row["group_id"] for row in rows if row["group_id"] not in hidden}
        except sqlite3.Error:
            pass
    group_expr = sources.group_key_sql()
    try:
        rows = conn.execute(
            f"""
            SELECT {group_expr} AS group_key,
                   lower(coalesce(filter_status, 'accepted')) AS filter_status
            FROM alerts
            GROUP BY group_key, filter_status
            HAVING filter_status != 'suppressed'
            """
        ).fetchall()
    except sqlite3.Error:
        return set()
    return {
        group_id
        for row in rows
        if (group_id := sources.group_id(row["group_key"])) not in hidden
    }


def _hidden_active_soc_group_ids(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
    statuses: object,
    manually_escalated_group_ids: set[str] | None,
) -> set[str]:
    current = statuses if isinstance(statuses, dict) else {}
    hidden = {
        group_id
        for group_id, meta in current.items()
        if isinstance(meta, dict)
        and meta.get("status") in {"acknowledged", "suppressed"}
    }
    hidden.update(
        manually_escalated_group_ids
        if manually_escalated_group_ids is not None
        else load_manually_escalated_group_ids(sources, conn)
    )
    return hidden


def normalize_soc_alert_status_meta(
    value: object,
    *,
    now_iso: Callable[[], str],
    now: str | None = None,
) -> dict | None:
    if not isinstance(value, dict):
        return None
    status = str(value.get("status") or "open").strip().lower()
    if status not in {"open", "acknowledged", "suppressed"}:
        return None
    try:
        repeat_count = max(
            0,
            int(
                value.get("repeat_count")
                or value.get("acknowledged_count")
                or 0
            ),
        )
    except (TypeError, ValueError, OverflowError):
        repeat_count = 0
    return {
        "status": status,
        "repeat_count": repeat_count,
        "reason": str(value.get("reason") or "").strip()[:140],
        "updated_at": str(value.get("updated_at") or now or now_iso()),
    }


def _ensure_legacy_status_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_alert_status (
          alert_id TEXT PRIMARY KEY,
          status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
          repeat_count INTEGER NOT NULL DEFAULT 0,
          reason TEXT,
          updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_alert_status_status "
        "ON analyst_alert_status(status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_alert_status_updated_at "
        "ON analyst_alert_status(updated_at)"
    )


def _ensure_group_status_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_alert_group_state (
          group_id TEXT PRIMARY KEY,
          group_key TEXT,
          status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
          repeat_count INTEGER NOT NULL DEFAULT 0,
          reason TEXT,
          updated_at TEXT NOT NULL,
          updated_by TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_group_state_status "
        "ON analyst_alert_group_state(status)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_group_state_updated_at "
        "ON analyst_alert_group_state(updated_at)"
    )


def _ensure_adjudication_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_adjudications (
          adjudication_id TEXT PRIMARY KEY,
          dashboard_group_id TEXT NOT NULL,
          stable_group_id TEXT NOT NULL,
          case_id TEXT,
          analysis_id TEXT NOT NULL,
          outcome_override TEXT NOT NULL,
          confidence TEXT NOT NULL,
          rationale TEXT NOT NULL,
          evidence_gap TEXT,
          next_action TEXT,
          reviewer TEXT NOT NULL,
          event_status TEXT,
          detection_validity TEXT,
          activity_disposition TEXT,
          handling TEXT,
          duplicate_of TEXT,
          case_resolution_reason TEXT,
          created_at TEXT NOT NULL
        )
        """
    )


def _migrate_adjudication_schema(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in conn.execute(
            "PRAGMA table_info(analyst_adjudications)"
        ).fetchall()
    }
    for column in (
        "event_status",
        "detection_validity",
        "activity_disposition",
        "handling",
        "duplicate_of",
    ):
        if column not in columns:
            conn.execute(
                f"ALTER TABLE analyst_adjudications ADD COLUMN {column} TEXT"
            )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_group_created "
        "ON analyst_adjudications(dashboard_group_id, created_at DESC)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_analyst_adjudications_analysis_created "
        "ON analyst_adjudications(analysis_id, created_at DESC)"
    )


def ensure_soc_alert_status_schema(conn: sqlite3.Connection) -> None:
    _ensure_legacy_status_schema(conn)
    _ensure_group_status_schema(conn)
    _ensure_adjudication_schema(conn)
    _migrate_adjudication_schema(conn)


def load_soc_group_statuses(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
) -> dict:
    if not sources.table_exists(conn, "analyst_alert_group_state"):
        return {}
    counts = load_soc_alert_group_counts(sources, conn)
    rows = conn.execute(
        """
        SELECT group_id, group_key, status, repeat_count, reason,
               updated_at, updated_by
        FROM analyst_alert_group_state
        WHERE status IN ('acknowledged', 'suppressed')
        """
    ).fetchall()
    statuses = {}
    for row in rows:
        group_id = row["group_id"]
        repeat_count = int(row["repeat_count"] or 0)
        if (
            row["status"] == "acknowledged"
            and counts.get(group_id, repeat_count) > repeat_count
        ):
            continue
        statuses[group_id] = {
            "status": row["status"],
            "repeat_count": repeat_count,
            "reason": row["reason"] or "",
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"] or "",
            "group_key": row["group_key"] or "",
        }
    return statuses


def _status_identity(raw_meta: object) -> tuple[str, str]:
    current = raw_meta if isinstance(raw_meta, dict) else {}
    return (
        str(current.get("group_key") or ""),
        str(current.get("updated_by") or "")[:80],
    )


def write_soc_group_status(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
    group_id: str,
    raw_meta: object,
) -> None:
    meta = normalize_soc_alert_status_meta(
        raw_meta, now_iso=sources.now_iso
    )
    if not meta or meta["status"] == "open":
        conn.execute(
            "DELETE FROM analyst_alert_group_state WHERE group_id = ?",
            (str(group_id),),
        )
        return
    group_key, updated_by = _status_identity(raw_meta)
    conn.execute(
        """
        INSERT INTO analyst_alert_group_state (
          group_id, group_key, status, repeat_count, reason,
          updated_at, updated_by
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(group_id) DO UPDATE SET
          group_key = excluded.group_key,
          status = excluded.status,
          repeat_count = excluded.repeat_count,
          reason = excluded.reason,
          updated_at = excluded.updated_at,
          updated_by = excluded.updated_by
        """,
        (
            str(group_id),
            group_key,
            meta["status"],
            meta["repeat_count"],
            meta["reason"],
            meta["updated_at"],
            updated_by,
        ),
    )


def write_soc_group_statuses(
    sources: SocAlertStatusStoreSources,
    conn: sqlite3.Connection,
    statuses: object,
) -> None:
    current = statuses if isinstance(statuses, dict) else {}
    for group_id, raw_meta in current.items():
        write_soc_group_status(sources, conn, str(group_id), raw_meta)
