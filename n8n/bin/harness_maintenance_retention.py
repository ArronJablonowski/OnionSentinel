"""Bounded retention, checkpoint, vacuum, and disk maintenance."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
import sqlite3
import stat
from typing import Any

from harness_maintenance_contract import (
    TERMINAL_STATUSES,
    MaintenanceError,
    timestamp_text,
)
from harness_maintenance_integrity import database_snapshot


def select_prunable_runs(
    connection: sqlite3.Connection,
    *,
    now: dt.datetime,
    retention_days: int,
    max_terminal_runs: int,
    min_terminal_runs: int,
    max_delete_runs: int,
    live_page_bytes: int,
    max_live_bytes: int,
) -> tuple[list[str], dict[str, int | bool]]:
    cutoff = timestamp_text(now - dt.timedelta(days=retention_days))
    terminal_count = int(
        connection.execute(
            "SELECT COUNT(*) FROM harness_runs WHERE status IN (?, ?, ?)",
            TERMINAL_STATUSES,
        ).fetchone()[0]
    )
    selected: list[str] = []
    selected_set: set[str] = set()

    def add(rows: list[sqlite3.Row]) -> None:
        for row in rows:
            run_id = str(row["run_id"])
            if run_id not in selected_set and len(selected) < max_delete_runs:
                selected.append(run_id)
                selected_set.add(run_id)

    expired = connection.execute(
        """
        SELECT run_id FROM harness_runs
        WHERE status IN (?, ?, ?)
          AND datetime(replace(COALESCE(completed_at, updated_at), '  ', 'T'))
              < datetime(?)
        ORDER BY datetime(
            replace(COALESCE(completed_at, updated_at), '  ', 'T')
        ), run_id
        LIMIT ?
        """,
        (*TERMINAL_STATUSES, cutoff, max_delete_runs),
    ).fetchall()
    add(expired)

    overflow = max(0, terminal_count - max_terminal_runs)
    if overflow and len(selected) < max_delete_runs:
        add(
            connection.execute(
                """
                SELECT run_id FROM harness_runs
                WHERE status IN (?, ?, ?)
                ORDER BY datetime(
                    replace(COALESCE(completed_at, updated_at), '  ', 'T')
                ), run_id
                LIMIT ?
                """,
                (*TERMINAL_STATUSES, min(overflow, max_delete_runs)),
            ).fetchall()
        )

    over_live_budget = live_page_bytes > max_live_bytes
    if over_live_budget and len(selected) < max_delete_runs:
        pressure_limit = min(
            max(0, terminal_count - min_terminal_runs),
            max_delete_runs,
        )
        add(
            connection.execute(
                """
                SELECT run_id FROM harness_runs
                WHERE status IN (?, ?, ?)
                ORDER BY datetime(
                    replace(COALESCE(completed_at, updated_at), '  ', 'T')
                ), run_id
                LIMIT ?
                """,
                (*TERMINAL_STATUSES, pressure_limit),
            ).fetchall()
        )

    return selected, {
        "expired_candidates": len(expired),
        "terminal_overflow": overflow,
        "over_live_byte_budget": over_live_budget,
        "selected": len(selected),
    }


def maintain_database(
    db_path: Path,
    *,
    now: dt.datetime,
    retention_days: int,
    max_terminal_runs: int,
    min_terminal_runs: int,
    max_delete_runs: int,
    max_live_bytes: int,
    incremental_vacuum_pages: int,
    apply: bool,
    backup: dict[str, Any] | None,
) -> dict[str, Any]:
    absent = _validate_database_path(db_path)
    if absent:
        return absent
    connection = _connect(db_path, apply=apply)
    try:
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        if not apply:
            connection.execute("PRAGMA query_only = ON")
        before = database_snapshot(connection, db_path)
        selected, candidates = select_prunable_runs(
            connection,
            now=now,
            retention_days=retention_days,
            max_terminal_runs=max_terminal_runs,
            min_terminal_runs=min_terminal_runs,
            max_delete_runs=max_delete_runs,
            live_page_bytes=int(before["live_page_bytes"]),
            max_live_bytes=max_live_bytes,
        )
        selected = _limit_to_backup(selected, candidates, apply, backup)
        deleted, checkpoint, vacuumed_pages_limit = _apply_maintenance(
            connection,
            selected=selected,
            apply=apply,
            before=before,
            incremental_vacuum_pages=incremental_vacuum_pages,
        )
        after = database_snapshot(connection, db_path)
    except sqlite3.Error as exc:
        raise MaintenanceError(
            f"harness SQLite maintenance failed: {exc}"
        ) from None
    finally:
        connection.close()

    follow_up = (
        int(after["run_counts"]["terminal"]) > max_terminal_runs
        or int(after["live_page_bytes"]) > max_live_bytes
        or int(after["allocated_disk_bytes"]) > max_live_bytes
        or candidates["selected"] >= max_delete_runs
        or int(checkpoint["busy"]) > 0
    )
    return {
        "status": "follow-up-required" if follow_up else "ok",
        "applied": apply,
        "database_present": True,
        "policy": {
            "retention_days": retention_days,
            "max_terminal_runs": max_terminal_runs,
            "min_terminal_runs_under_byte_pressure": min_terminal_runs,
            "max_delete_runs_per_pass": max_delete_runs,
            "max_live_bytes": max_live_bytes,
            "incremental_vacuum_pages_per_pass": incremental_vacuum_pages,
        },
        "backup": {
            key: value
            for key, value in (backup or {"verified": False}).items()
            if not key.startswith("_")
        },
        "candidates": candidates,
        "_candidate_run_ids": tuple(selected),
        "deleted_runs": deleted,
        "checkpoint": checkpoint,
        "incremental_vacuum_page_limit_applied": vacuumed_pages_limit,
        "before": before,
        "after": after,
        "follow_up_required": follow_up,
    }


def _validate_database_path(db_path: Path) -> dict[str, Any] | None:
    if db_path.is_symlink():
        raise MaintenanceError("harness SQLite database must not be a symlink")
    if not db_path.exists():
        return {
            "status": "absent",
            "applied": False,
            "database_present": False,
            "deleted_runs": 0,
        }
    if not db_path.is_file():
        raise MaintenanceError("harness SQLite database is not a regular file")
    if stat.S_IMODE(db_path.stat().st_mode) & 0o077:
        raise MaintenanceError("harness SQLite database must be owner-only")
    return None


def _connect(db_path: Path, *, apply: bool) -> sqlite3.Connection:
    if apply:
        connection = sqlite3.connect(db_path, timeout=10.0)
    else:
        uri = f"{db_path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


def _limit_to_backup(
    selected: list[str],
    candidates: dict[str, int | bool],
    apply: bool,
    backup: dict[str, Any] | None,
) -> list[str]:
    if not selected or not apply:
        return selected
    if not backup:
        raise MaintenanceError(
            "retention is blocked until a recent verified harness backup exists"
        )
    covered = {str(value) for value in backup.get("_covered_run_ids", ())}
    limited = [run_id for run_id in selected if run_id in covered]
    candidates["selected"] = len(limited)
    return limited


def _apply_maintenance(
    connection: sqlite3.Connection,
    *,
    selected: list[str],
    apply: bool,
    before: dict[str, Any],
    incremental_vacuum_pages: int,
) -> tuple[int, dict[str, int | bool], int]:
    checkpoint: dict[str, int | bool] = {
        "attempted": False,
        "busy": 0,
        "wal_pages": 0,
        "checkpointed_pages": 0,
    }
    if not apply:
        return 0, checkpoint, 0
    deleted = _delete_runs(connection, selected)
    connection.execute("PRAGMA optimize")
    vacuumed_pages_limit = 0
    if int(before["auto_vacuum"]) == 2 and incremental_vacuum_pages:
        connection.execute(
            f"PRAGMA incremental_vacuum({incremental_vacuum_pages})"
        )
        vacuumed_pages_limit = incremental_vacuum_pages
    if str(before["journal_mode"]) == "wal":
        row = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        checkpoint = {
            "attempted": True,
            "busy": int(row[0]),
            "wal_pages": int(row[1]),
            "checkpointed_pages": int(row[2]),
        }
    return deleted, checkpoint, vacuumed_pages_limit


def _delete_runs(connection: sqlite3.Connection, selected: list[str]) -> int:
    if not selected:
        return 0
    connection.execute("BEGIN IMMEDIATE")
    try:
        placeholders = ",".join("?" for _ in selected)
        cursor = connection.execute(
            f"""
            DELETE FROM harness_runs
            WHERE run_id IN ({placeholders}) AND status IN (?, ?, ?)
            """,
            (*selected, *TERMINAL_STATUSES),
        )
        connection.commit()
        return int(cursor.rowcount)
    except Exception:
        connection.rollback()
        raise
