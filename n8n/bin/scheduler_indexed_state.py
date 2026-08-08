"""Indexed scheduler schema capability and committed-result reconciliation."""
from __future__ import annotations

import sqlite3


ALERT_COLUMNS = {"stable_group_id", "stable_group_key"}
JOB_COLUMNS = {
    "id", "job_type", "dedupe_key", "status", "payload_json", "priority",
    "attempt_count", "max_attempts", "next_attempt_at",
    "processing_started_at", "rerun_requested", "requested_at",
}
RUN_COLUMNS = {"group_id", "generated_at"}


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def indexed_scheduler_available(conn: sqlite3.Connection) -> bool:
    """Return whether durable jobs and analysis results can drive scheduling."""
    if not {"alerts", "durable_jobs", "ai_analysis_runs"}.issubset(
        _table_names(conn)
    ):
        return False
    return (
        ALERT_COLUMNS.issubset(_table_columns(conn, "alerts"))
        and JOB_COLUMNS.issubset(_table_columns(conn, "durable_jobs"))
        and RUN_COLUMNS.issubset(_table_columns(conn, "ai_analysis_runs"))
    )


def _committed_pending_group_ids(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            """
            SELECT j.dedupe_key
            FROM durable_jobs AS j
            WHERE j.job_type = 'ai_analysis' AND j.status = 'pending'
              AND COALESCE(j.rerun_requested, 0) = 0
              AND j.processing_started_at IS NOT NULL
              AND EXISTS (
                SELECT 1 FROM ai_analysis_runs AS r
                WHERE r.group_id = j.dedupe_key
                  AND julianday(replace(r.generated_at, '  ', 'T')) >=
                      julianday(replace(j.processing_started_at, '  ', 'T'))
              )
            """
        ).fetchall()
        if str(row[0] or "").strip()
    }


def _orphaned_pending_group_ids(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            """
            SELECT j.dedupe_key
            FROM durable_jobs AS j
            WHERE j.job_type = 'ai_analysis' AND j.status = 'pending'
              AND NOT EXISTS (
                SELECT 1 FROM alerts AS a WHERE a.stable_group_id = j.dedupe_key
              )
            """
        ).fetchall()
        if str(row[0] or "").strip()
    }


def indexed_reconcilable_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return pending jobs proven complete or orphaned by indexed state."""
    if not indexed_scheduler_available(conn):
        return set()
    return _committed_pending_group_ids(conn) | _orphaned_pending_group_ids(conn)
