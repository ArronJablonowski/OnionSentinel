"""Crash recovery for stale investigation-harness runs."""

from __future__ import annotations

from contextlib import closing
import datetime as dt
import fcntl
import os
from pathlib import Path
import sqlite3
from typing import Any

from harness_maintenance_contract import (
    RECONCILABLE_JOB_TYPES,
    MaintenanceError,
    load_harness_runtime,
    timestamp_text,
)
from harness_maintenance_integrity import (
    owner_readable_regular_file,
    table_names,
)


def select_stale_running_reconciliations(
    harness_db: Path,
    alert_db: Path,
    *,
    now: dt.datetime,
    stale_running_seconds: int,
    limit: int,
) -> list[dict[str, Any]]:
    """Select stale runs whose durable owner can no longer be executing."""
    if not owner_readable_regular_file(alert_db):
        raise MaintenanceError(
            "alert-store SQLite database must be an owner-owned regular "
            "file without group/world write access"
        )
    cutoff = timestamp_text(
        now - dt.timedelta(seconds=stale_running_seconds)
    )
    harness_uri = f"{harness_db.resolve().as_uri()}?mode=ro"
    alert_uri = f"{alert_db.resolve().as_uri()}?mode=ro"
    try:
        with closing(
            sqlite3.connect(harness_uri, uri=True, timeout=10.0)
        ) as harness_connection, closing(
            sqlite3.connect(alert_uri, uri=True, timeout=10.0)
        ) as alert_connection:
            harness_connection.row_factory = sqlite3.Row
            alert_connection.row_factory = sqlite3.Row
            harness_connection.execute("PRAGMA query_only = ON")
            alert_connection.execute("PRAGMA query_only = ON")
            if "durable_jobs" not in table_names(alert_connection):
                raise MaintenanceError(
                    "alert-store SQLite is missing durable_jobs"
                )
            candidates = _stale_running_candidates(
                harness_connection,
                cutoff,
                limit,
            )
            return _match_durable_jobs(
                harness_connection,
                alert_connection,
                candidates,
            )
    except sqlite3.Error as exc:
        raise MaintenanceError(
            f"stale harness reconciliation query failed: {exc}"
        ) from None


def _stale_running_candidates(
    harness_connection: sqlite3.Connection,
    cutoff: str,
    limit: int,
) -> list[sqlite3.Row]:
    return harness_connection.execute(
        """
        SELECT run_id, correlation_id, case_id, role, started_at,
               updated_at
        FROM harness_runs
        WHERE status = 'running'
          AND role IN ('soc-analyst', 'incident-responder')
          AND datetime(replace(updated_at, '  ', 'T')) <= datetime(?)
        ORDER BY datetime(replace(updated_at, '  ', 'T')), run_id
        LIMIT ?
        """,
        (cutoff, limit),
    ).fetchall()


def _match_durable_jobs(
    harness_connection: sqlite3.Connection,
    alert_connection: sqlite3.Connection,
    candidates: list[sqlite3.Row],
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    for candidate in candidates:
        job_type = RECONCILABLE_JOB_TYPES[str(candidate["role"])]
        durable = alert_connection.execute(
            """
            SELECT id, status, attempt_count, updated_at
            FROM durable_jobs
            WHERE job_type = ? AND dedupe_key = ?
            ORDER BY id DESC LIMIT 1
            """,
            (job_type, str(candidate["correlation_id"])),
        ).fetchone()
        if durable is None or str(durable["status"]) == "processing":
            continue
        successor = harness_connection.execute(
            """
            SELECT run_id, status, started_at
            FROM harness_runs
            WHERE correlation_id = ? AND case_id = ? AND run_id != ?
              AND datetime(replace(started_at, '  ', 'T')) >
                  datetime(replace(?, '  ', 'T'))
            ORDER BY datetime(replace(started_at, '  ', 'T')) DESC,
                     run_id DESC
            LIMIT 1
            """,
            (
                str(candidate["correlation_id"]),
                str(candidate["case_id"]),
                str(candidate["run_id"]),
                str(candidate["started_at"]),
            ),
        ).fetchone()
        selected.append(
            {
                "run_id": str(candidate["run_id"]),
                "durable_job_id": int(durable["id"]),
                "durable_job_type": job_type,
                "durable_status": str(durable["status"]),
                "durable_attempt_count": int(durable["attempt_count"] or 0),
                "successor_run_id": str(successor["run_id"]) if successor else "",
                "successor_status": str(successor["status"]) if successor else "",
            }
        )
    return selected


def reconcile_stale_running_runs(
    harness_db: Path,
    alert_db: Path,
    *,
    worker_lock_paths: tuple[Path, Path],
    now: dt.datetime,
    stale_running_seconds: int,
    limit: int,
    apply: bool,
) -> dict[str, Any]:
    """Terminalize stale ledgers only while both inference lanes are idle."""
    result: dict[str, Any] = {
        "enabled": True,
        "applied": apply,
        "status": "preview",
        "selected": 0,
        "reconciled": 0,
        "runs": [],
    }
    if not harness_db.exists():
        result["status"] = "absent"
        return result
    if not alert_db.exists():
        result["status"] = "alert-store-absent"
        return result
    handles = []
    try:
        if apply:
            status = _acquire_worker_locks(worker_lock_paths, handles)
            if status:
                result["status"] = status
                return result
        selected = select_stale_running_reconciliations(
            harness_db,
            alert_db,
            now=now,
            stale_running_seconds=stale_running_seconds,
            limit=limit,
        )
        result["selected"] = len(selected)
        result["runs"] = selected
        if not apply:
            return result
        result["reconciled"] = _reconcile_selected(harness_db, selected)
        result["status"] = "ok"
        return result
    finally:
        for handle in reversed(handles):
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()


def _acquire_worker_locks(worker_lock_paths: tuple[Path, Path], handles: list) -> str:
    for lock_path in worker_lock_paths:
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle = lock_path.open("a+", encoding="utf-8")
        os.chmod(lock_path, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            return "active-worker"
        handles.append(handle)
    return ""


def _reconcile_selected(harness_db: Path, selected: list[dict[str, Any]]) -> int:
    harness_runtime = load_harness_runtime()
    store = harness_runtime.HarnessStore(harness_db)
    reconciled = 0
    for item in selected:
        current = store.snapshot(item["run_id"])
        if str(current.get("status") or "") != "running":
            continue
        store.finish(
            item["run_id"],
            status=harness_runtime.RunStatus.FAILED.value,
            reason=(
                "stale harness run recovered after its durable owner "
                "stopped processing"
            ),
            summary={
                "recovery": "stale_durable_owner_reconciled",
                "durable_job_id": item["durable_job_id"],
                "durable_job_type": item["durable_job_type"],
                "durable_status": item["durable_status"],
                "durable_attempt_count": item["durable_attempt_count"],
                "successor_run_id": item["successor_run_id"],
                "successor_status": item["successor_status"],
            },
        )
        reconciled += 1
    return reconciled
