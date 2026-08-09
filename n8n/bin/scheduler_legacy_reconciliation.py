"""Read-only reconciliation policy for legacy artifact-backed AI jobs."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from scheduler_artifact_repository import completed_analysis_group_ids


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        str(row[1])
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return coalesced durable AI intents that still require a model run."""
    if "durable_jobs" not in _table_names(conn):
        return set()
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            """
            SELECT dedupe_key FROM durable_jobs
            WHERE job_type = 'ai_analysis' AND status = 'pending'
            """
        ).fetchall()
        if str(row[0] or "").strip()
    }


def _active_group_ids(
    conn: sqlite3.Connection,
    tables: set[str],
) -> set[str]:
    active = {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT group_id FROM alert_group_summary"
        ).fetchall()
        if str(row[0] or "").strip()
    }
    if "alert_group_alias" not in tables:
        return active
    aliases = conn.execute(
        "SELECT legacy_group_id, stable_group_id FROM alert_group_alias"
    ).fetchall()
    for legacy_id, stable_id in aliases:
        if str(legacy_id or "").strip() in active:
            active.add(str(stable_id or "").strip())
    return active


def orphaned_pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return pending AI queue keys that no longer map to an active group."""
    tables = _table_names(conn)
    if "durable_jobs" not in tables:
        return set()
    pending_ids = pending_ai_job_ids(conn)
    if not pending_ids:
        return set()
    return pending_ids - _active_group_ids(conn, tables)


def reconcilable_completed_ai_job_ids(
    conn: sqlite3.Connection,
    group_ids: set[str],
) -> set[str]:
    """Return completed jobs without erasing fresh evidence or rerun intent."""
    if not group_ids or "durable_jobs" not in _table_names(conn):
        return set()
    columns = _column_names(conn, "durable_jobs")
    if not {"processing_started_at", "rerun_requested"} <= columns:
        return group_ids
    placeholders = ", ".join("?" for _ in group_ids)
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            f"""
            SELECT dedupe_key FROM durable_jobs
            WHERE job_type = 'ai_analysis' AND status = 'pending'
              AND COALESCE(rerun_requested, 0) = 0
              AND processing_started_at IS NOT NULL
              AND dedupe_key IN ({placeholders})
            """,
            sorted(group_ids),
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_ai_job_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Combine artifact-complete and obsolete durable AI queue intents."""
    completed = completed_analysis_group_ids(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    return (
        reconcilable_completed_ai_job_ids(conn, completed)
        | orphaned_pending_ai_job_ids(conn)
    )
