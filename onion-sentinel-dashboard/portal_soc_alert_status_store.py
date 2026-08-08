"""Schema and SQLite repository for durable SOC analyst alert status."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class SocAlertStatusStoreSources:
    table_exists: Callable[[sqlite3.Connection, str], bool]
    group_counts: Callable[[sqlite3.Connection], dict[str, int]]
    now_iso: Callable[[], str]


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
    counts = sources.group_counts(conn)
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
