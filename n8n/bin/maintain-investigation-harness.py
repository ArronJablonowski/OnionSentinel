#!/usr/bin/env python3
"""Bound and verify the local Onion Sentinel investigation trace store.

The maintenance pass never creates a missing harness database. Terminal traces
are eligible for deletion by age, count, or live-page budget, while active runs
are always retained. Destructive retention is allowed only after a recent,
hash-verified recovery bundle contains a restorable harness snapshot.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import datetime as dt
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from typing import Any


DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_TERMINAL_RUNS = 10_000
DEFAULT_MIN_TERMINAL_RUNS = 1_000
DEFAULT_MAX_DELETE_RUNS = 1_000
DEFAULT_MAX_LIVE_BYTES = 2 * 1024**3
DEFAULT_INCREMENTAL_VACUUM_PAGES = 4_096
DEFAULT_MAX_BACKUP_AGE_SECONDS = 26 * 60 * 60
DEFAULT_STALE_RUNNING_SECONDS = 60 * 60
DEFAULT_MAX_RECONCILE_RUNS = 100
TERMINAL_STATUSES = ("succeeded", "failed", "cancelled")
REQUIRED_TABLES = frozenset(
    {
        "harness_metadata",
        "harness_runs",
        "harness_events",
        "harness_evidence",
        "harness_hypotheses",
        "harness_decisions",
        "harness_model_calls",
        "harness_tool_calls",
        "harness_budget_reservations",
    }
)
MAX_BACKUP_MANIFEST_BYTES = 1024 * 1024
RECONCILABLE_JOB_TYPES = {
    "soc-analyst": "ai_analysis",
    "incident-responder": "incident_response_analysis",
}


class MaintenanceError(RuntimeError):
    """A safe, concise maintenance failure."""


def load_harness_runtime():
    """Load the sibling harness API without depending on the caller's cwd."""
    module_name = "onion_sentinel_harness_maintenance_runtime"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    module_path = Path(__file__).with_name("onion_sentinel_harness.py")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise MaintenanceError("could not load the harness runtime API")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    script_dir = str(module_path.parent)
    inserted = script_dir not in sys.path
    if inserted:
        sys.path.insert(0, script_dir)
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    finally:
        if inserted:
            sys.path.remove(script_dir)
    return module


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp_text(value: dt.datetime) -> str:
    return (
        value.astimezone(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    )


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _owner_only_regular_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        and metadata.st_uid == os.getuid()
    )


def _owner_readable_regular_file(path: Path) -> bool:
    """Accept read-only source databases that only their owner may modify."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o022 == 0
        and metadata.st_uid == os.getuid()
    )


def _owner_only_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and not stat.S_ISLNK(metadata.st_mode)
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
        and metadata.st_uid == os.getuid()
    )


def sqlite_file_accounting(path: Path) -> dict[str, int]:
    logical = 0
    allocated = 0
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise MaintenanceError(
                f"harness SQLite sidecar is not a regular file: {candidate}"
            )
        logical += int(metadata.st_size)
        allocated += int(getattr(metadata, "st_blocks", 0) or 0) * 512
    return {
        "logical_file_bytes": logical,
        "allocated_disk_bytes": allocated or logical,
    }


def _table_names(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
    }


def verify_event_chains(
    connection: sqlite3.Connection,
    run_ids: tuple[str, ...],
) -> bool:
    """Verify the hash-chained event ledger for exact retention candidates."""
    if not run_ids:
        return True
    events_by_run: dict[str, list[sqlite3.Row]] = {
        run_id: [] for run_id in run_ids
    }
    status_by_run: dict[str, str] = {}
    for offset in range(0, len(run_ids), 400):
        batch = run_ids[offset : offset + 400]
        placeholders = ",".join("?" for _ in batch)
        status_by_run.update(
            {
                str(row["run_id"]): str(row["status"])
                for row in connection.execute(
                    f"""
                    SELECT run_id, status FROM harness_runs
                    WHERE run_id IN ({placeholders})
                    """,
                    batch,
                ).fetchall()
            }
        )
        rows = connection.execute(
            f"""
            SELECT * FROM harness_events
            WHERE run_id IN ({placeholders})
            ORDER BY run_id, sequence
            """,
            batch,
        ).fetchall()
        for row in rows:
            events_by_run.setdefault(str(row["run_id"]), []).append(row)
    for run_id in run_ids:
        rows = events_by_run.get(run_id) or []
        if not rows:
            return False
        status = status_by_run.get(run_id, "")
        if (
            status not in TERMINAL_STATUSES
            or str(rows[-1]["event_type"]) != f"run.{status}"
        ):
            return False
        previous = "0" * 64
        for expected_sequence, row in enumerate(rows, start=1):
            try:
                sequence = int(row["sequence"])
                payload_json = str(row["payload_json"])
                payload_digest = hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest()
                body = {
                    "run_id": run_id,
                    "sequence": sequence,
                    "idempotency_key": row["idempotency_key"],
                    "event_type": row["event_type"],
                    "stage": row["stage"],
                    "created_at": row["created_at"],
                    "payload_sha256": row["payload_sha256"],
                    "previous_event_sha256": row[
                        "previous_event_sha256"
                    ],
                }
                event_digest = digest_json(body)
            except (IndexError, KeyError, TypeError, ValueError, OverflowError):
                return False
            if (
                sequence != expected_sequence
                or str(row["payload_sha256"]) != payload_digest
                or str(row["previous_event_sha256"]) != previous
                or str(row["event_sha256"]) != event_digest
                or str(row["event_id"]) != f"evt-{event_digest[:32]}"
            ):
                return False
            previous = str(row["event_sha256"])
    return True


def database_snapshot(
    connection: sqlite3.Connection,
    path: Path,
) -> dict[str, Any]:
    quick_check = str(connection.execute("PRAGMA quick_check").fetchone()[0])
    if quick_check != "ok":
        raise MaintenanceError(
            f"harness SQLite quick_check failed: {quick_check}"
        )
    missing = sorted(REQUIRED_TABLES.difference(_table_names(connection)))
    if missing:
        raise MaintenanceError(
            "harness SQLite is missing table(s): " + ", ".join(missing)
        )
    foreign_key_errors = len(
        connection.execute("PRAGMA foreign_key_check").fetchall()
    )
    if foreign_key_errors:
        raise MaintenanceError(
            "harness SQLite foreign_key_check failed: "
            f"{foreign_key_errors} row(s)"
        )
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
    freelist_count = int(
        connection.execute("PRAGMA freelist_count").fetchone()[0]
    )
    journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
    auto_vacuum = int(connection.execute("PRAGMA auto_vacuum").fetchone()[0])
    counts = connection.execute(
        """
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status IN (?, ?, ?) THEN 1 ELSE 0 END) AS terminal,
          SUM(CASE WHEN status NOT IN (?, ?, ?) THEN 1 ELSE 0 END) AS active
        FROM harness_runs
        """,
        (*TERMINAL_STATUSES, *TERMINAL_STATUSES),
    ).fetchone()
    accounting = sqlite_file_accounting(path)
    return {
        "quick_check": quick_check,
        "foreign_key_check_rows": foreign_key_errors,
        "journal_mode": journal_mode.lower(),
        "auto_vacuum": auto_vacuum,
        "page_size": page_size,
        "page_count": page_count,
        "freelist_pages": freelist_count,
        "live_page_bytes": max(0, page_count - freelist_count) * page_size,
        "reclaimable_page_bytes": freelist_count * page_size,
        "run_counts": {
            "total": int(counts[0] or 0),
            "terminal": int(counts[1] or 0),
            "active": int(counts[2] or 0),
        },
        **accounting,
    }


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
            """
            SELECT COUNT(*) FROM harness_runs
            WHERE status IN (?, ?, ?)
            """,
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
        rows = connection.execute(
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
        add(rows)

    over_live_budget = live_page_bytes > max_live_bytes
    if over_live_budget and len(selected) < max_delete_runs:
        pressure_limit = min(
            max(0, terminal_count - min_terminal_runs),
            max_delete_runs,
        )
        rows = connection.execute(
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
        add(rows)

    return selected, {
        "expired_candidates": len(expired),
        "terminal_overflow": overflow,
        "over_live_byte_budget": over_live_budget,
        "selected": len(selected),
    }


def verify_recent_harness_backup(
    backup_root: Path,
    *,
    now: dt.datetime,
    max_age_seconds: int,
    required_run_ids: tuple[str, ...] = (),
) -> dict[str, Any]:
    if not _owner_only_directory(backup_root):
        raise MaintenanceError(
            "recovery backup directory must be owner-only and not a symlink"
        )
    bundles = sorted(
        (
            path
            for path in backup_root.iterdir()
            if _owner_only_directory(path) and not path.name.startswith(".")
        ),
        reverse=True,
    )
    for bundle in bundles:
        manifest_path = bundle / "manifest.json"
        harness_path = bundle / "investigation-harness.sqlite3"
        if (
            not _owner_only_regular_file(manifest_path)
            or not _owner_only_regular_file(harness_path)
            or manifest_path.stat().st_size > MAX_BACKUP_MANIFEST_BYTES
        ):
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            created = parse_timestamp(manifest.get("created_at"))
            harness_manifest = dict(
                dict(manifest.get("sqlite") or {}).get(
                    "investigation_harness"
                )
                or {}
            )
            file_manifest = dict(
                dict(manifest.get("files") or {}).get(
                    "investigation-harness.sqlite3"
                )
                or {}
            )
        except (OSError, ValueError, TypeError):
            continue
        age_seconds = (
            int((now - created).total_seconds())
            if created is not None
            else max_age_seconds + 1
        )
        if (
            created is None
            or not bool(harness_manifest.get("present"))
            or age_seconds < -300
            or age_seconds > max_age_seconds
        ):
            continue
        expected_digest = str(file_manifest.get("sha256") or "")
        if len(expected_digest) != 64 or sha256_file(harness_path) != expected_digest:
            continue
        try:
            uri = f"{harness_path.resolve().as_uri()}?mode=ro&immutable=1"
            with closing(
                sqlite3.connect(uri, uri=True, timeout=5.0)
            ) as connection:
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA query_only = ON")
                quick_check = str(
                    connection.execute("PRAGMA quick_check").fetchone()[0]
                )
                missing_tables = REQUIRED_TABLES.difference(
                    _table_names(connection)
                )
                runs = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM harness_runs"
                    ).fetchone()[0]
                )
                covered_run_ids: set[str] = set()
                for offset in range(0, len(required_run_ids), 400):
                    batch = required_run_ids[offset : offset + 400]
                    placeholders = ",".join("?" for _ in batch)
                    covered_run_ids.update(
                        str(row[0])
                        for row in connection.execute(
                            f"""
                            SELECT run_id FROM harness_runs
                            WHERE run_id IN ({placeholders})
                              AND status IN (?, ?, ?)
                            """,
                            (*batch, *TERMINAL_STATUSES),
                        ).fetchall()
                    )
                candidate_chains_valid = verify_event_chains(
                    connection,
                    required_run_ids,
                )
        except sqlite3.Error:
            continue
        if (
            quick_check != "ok"
            or missing_tables
            or runs != int(harness_manifest.get("rows", -1))
            or runs != int(manifest.get("harness_runs", -1))
            or covered_run_ids != set(required_run_ids)
            or not candidate_chains_valid
        ):
            continue
        return {
            "verified": True,
            "bundle": bundle.name,
            "age_seconds": max(0, age_seconds),
            "sha256": expected_digest,
            "run_rows": runs,
            "covered_retention_candidates": len(covered_run_ids),
            "candidate_event_chains_valid": candidate_chains_valid,
            "_covered_run_ids": tuple(sorted(covered_run_ids)),
        }
    raise MaintenanceError(
        "no recent hash-verified harness recovery snapshot is available"
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
    if not _owner_readable_regular_file(alert_db):
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
            if "durable_jobs" not in _table_names(alert_connection):
                raise MaintenanceError(
                    "alert-store SQLite is missing durable_jobs"
                )
            candidates = harness_connection.execute(
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
                        "durable_attempt_count": int(
                            durable["attempt_count"] or 0
                        ),
                        "successor_run_id": (
                            str(successor["run_id"]) if successor else ""
                        ),
                        "successor_status": (
                            str(successor["status"]) if successor else ""
                        ),
                    }
                )
            return selected
    except sqlite3.Error as exc:
        raise MaintenanceError(
            f"stale harness reconciliation query failed: {exc}"
        ) from None


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
            for lock_path in worker_lock_paths:
                lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                handle = lock_path.open("a+", encoding="utf-8")
                os.chmod(lock_path, 0o600)
                try:
                    fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    handle.close()
                    result["status"] = "active-worker"
                    return result
                handles.append(handle)
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
            result["status"] = "preview"
            return result
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
                    "durable_attempt_count": item[
                        "durable_attempt_count"
                    ],
                    "successor_run_id": item["successor_run_id"],
                    "successor_status": item["successor_status"],
                },
            )
            reconciled += 1
        result["reconciled"] = reconciled
        result["status"] = "ok"
        return result
    finally:
        for handle in reversed(handles):
            fcntl.flock(handle, fcntl.LOCK_UN)
            handle.close()


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

    if apply:
        connection = sqlite3.connect(db_path, timeout=10.0)
    else:
        uri = f"{db_path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=10.0)
    connection.row_factory = sqlite3.Row
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
        if selected and apply:
            if not backup:
                raise MaintenanceError(
                    "retention is blocked until a recent verified harness "
                    "backup exists"
                )
            covered = {
                str(value)
                for value in backup.get("_covered_run_ids", ())
            }
            selected = [run_id for run_id in selected if run_id in covered]
            candidates["selected"] = len(selected)
        deleted = 0
        checkpoint = {
            "attempted": False,
            "busy": 0,
            "wal_pages": 0,
            "checkpointed_pages": 0,
        }
        vacuumed_pages_limit = 0
        if apply:
            if selected:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    placeholders = ",".join("?" for _ in selected)
                    cursor = connection.execute(
                        f"""
                        DELETE FROM harness_runs
                        WHERE run_id IN ({placeholders})
                          AND status IN (?, ?, ?)
                        """,
                        (*selected, *TERMINAL_STATUSES),
                    )
                    deleted = int(cursor.rowcount)
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            connection.execute("PRAGMA optimize")
            if int(before["auto_vacuum"]) == 2 and incremental_vacuum_pages:
                connection.execute(
                    f"PRAGMA incremental_vacuum({incremental_vacuum_pages})"
                )
                vacuumed_pages_limit = incremental_vacuum_pages
            if str(before["journal_mode"]) == "wal":
                row = connection.execute(
                    "PRAGMA wal_checkpoint(TRUNCATE)"
                ).fetchone()
                checkpoint = {
                    "attempted": True,
                    "busy": int(row[0]),
                    "wal_pages": int(row[1]),
                    "checkpointed_pages": int(row[2]),
                }
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
        "status": "ok" if not follow_up else "follow-up-required",
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
        "backup": (
            {
                key: value
                for key, value in (backup or {"verified": False}).items()
                if not key.startswith("_")
            }
        ),
        "candidates": candidates,
        "_candidate_run_ids": tuple(selected),
        "deleted_runs": deleted,
        "checkpoint": checkpoint,
        "incremental_vacuum_page_limit_applied": vacuumed_pages_limit,
        "before": before,
        "after": after,
        "follow_up_required": follow_up,
    }


def atomic_write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = Path(stream.name)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def bounded_int(
    value: int,
    *,
    name: str,
    minimum: int,
    maximum: int,
) -> int:
    if value < minimum or value > maximum:
        raise MaintenanceError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--alert-db", type=Path)
    parser.add_argument("--backup-root", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--retention-days", type=int, default=DEFAULT_RETENTION_DAYS)
    parser.add_argument(
        "--max-terminal-runs",
        type=int,
        default=DEFAULT_MAX_TERMINAL_RUNS,
    )
    parser.add_argument(
        "--min-terminal-runs",
        type=int,
        default=DEFAULT_MIN_TERMINAL_RUNS,
    )
    parser.add_argument(
        "--max-delete-runs",
        type=int,
        default=DEFAULT_MAX_DELETE_RUNS,
    )
    parser.add_argument(
        "--max-live-bytes",
        type=int,
        default=DEFAULT_MAX_LIVE_BYTES,
    )
    parser.add_argument(
        "--incremental-vacuum-pages",
        type=int,
        default=DEFAULT_INCREMENTAL_VACUUM_PAGES,
    )
    parser.add_argument(
        "--max-backup-age-seconds",
        type=int,
        default=DEFAULT_MAX_BACKUP_AGE_SECONDS,
    )
    parser.add_argument(
        "--stale-running-seconds",
        type=int,
        default=DEFAULT_STALE_RUNNING_SECONDS,
    )
    parser.add_argument(
        "--max-reconcile-runs",
        type=int,
        default=DEFAULT_MAX_RECONCILE_RUNS,
    )
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    stack_dir = args.stack_dir.expanduser()
    db_path = (
        args.db.expanduser()
        if args.db
        else stack_dir / "alert_store_data/investigation-harness.sqlite3"
    )
    alert_db_path = (
        args.alert_db.expanduser()
        if args.alert_db
        else stack_dir / "alert_store_data/alerts.sqlite3"
    )
    backup_root = (
        args.backup_root.expanduser()
        if args.backup_root
        else stack_dir / "recovery_backups"
    )
    report_path = (
        args.report.expanduser()
        if args.report
        else stack_dir / "logs/investigation-harness-maintenance.json"
    )
    report: dict[str, Any] = {
        "generated_at": timestamp_text(utc_now()),
        "status": "running",
        "database": str(db_path),
    }
    return_code = 0
    try:
        retention_days = bounded_int(
            args.retention_days,
            name="retention days",
            minimum=1,
            maximum=3_650,
        )
        max_terminal_runs = bounded_int(
            args.max_terminal_runs,
            name="maximum terminal runs",
            minimum=100,
            maximum=1_000_000,
        )
        min_terminal_runs = bounded_int(
            args.min_terminal_runs,
            name="minimum terminal runs",
            minimum=0,
            maximum=max_terminal_runs,
        )
        max_delete_runs = bounded_int(
            args.max_delete_runs,
            name="maximum deletions per pass",
            minimum=1,
            maximum=5_000,
        )
        max_live_bytes = bounded_int(
            args.max_live_bytes,
            name="maximum live bytes",
            minimum=64 * 1024**2,
            maximum=64 * 1024**3,
        )
        incremental_vacuum_pages = bounded_int(
            args.incremental_vacuum_pages,
            name="incremental vacuum pages",
            minimum=0,
            maximum=65_536,
        )
        max_backup_age_seconds = bounded_int(
            args.max_backup_age_seconds,
            name="maximum backup age",
            minimum=60,
            maximum=7 * 24 * 60 * 60,
        )
        stale_running_seconds = bounded_int(
            args.stale_running_seconds,
            name="stale running seconds",
            minimum=30 * 60,
            maximum=7 * 24 * 60 * 60,
        )
        max_reconcile_runs = bounded_int(
            args.max_reconcile_runs,
            name="maximum stale run reconciliations",
            minimum=1,
            maximum=1_000,
        )
        lock_path = db_path.parent / ".investigation-harness-maintenance.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lock_path.open("w", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            report["stale_run_reconciliation"] = (
                reconcile_stale_running_runs(
                    db_path,
                    alert_db_path,
                    worker_lock_paths=(
                        stack_dir / "run/ai-analysis-ollama-worker.lock",
                        stack_dir / "run/ai-analysis-cli-worker.lock",
                    ),
                    now=utc_now(),
                    stale_running_seconds=stale_running_seconds,
                    limit=max_reconcile_runs,
                    apply=args.apply,
                )
            )
            # Determine candidates first. If apply mode discovers destructive
            # work, verify backup and repeat selection under the write lock.
            preview = maintain_database(
                db_path,
                now=utc_now(),
                retention_days=retention_days,
                max_terminal_runs=max_terminal_runs,
                min_terminal_runs=min_terminal_runs,
                max_delete_runs=max_delete_runs,
                max_live_bytes=max_live_bytes,
                incremental_vacuum_pages=incremental_vacuum_pages,
                apply=False,
                backup=None,
            )
            backup = None
            if (
                args.apply
                and preview.get("database_present")
                and int(dict(preview.get("candidates") or {}).get("selected") or 0)
            ):
                backup = verify_recent_harness_backup(
                    backup_root,
                    now=utc_now(),
                    max_age_seconds=max_backup_age_seconds,
                    required_run_ids=tuple(
                        str(value)
                        for value in preview.get("_candidate_run_ids", ())
                    ),
                )
            result = (
                maintain_database(
                    db_path,
                    now=utc_now(),
                    retention_days=retention_days,
                    max_terminal_runs=max_terminal_runs,
                    min_terminal_runs=min_terminal_runs,
                    max_delete_runs=max_delete_runs,
                    max_live_bytes=max_live_bytes,
                    incremental_vacuum_pages=incremental_vacuum_pages,
                    apply=True,
                    backup=backup,
                )
                if args.apply
                else preview
            )
        report.update(result)
        report.pop("_candidate_run_ids", None)
        report["generated_at"] = timestamp_text(utc_now())
        if result.get("status") == "follow-up-required":
            return_code = 1
    except (MaintenanceError, BlockingIOError, OSError, ValueError) as exc:
        report.update(
            {
                "status": "blocked",
                "error": str(exc),
                "generated_at": timestamp_text(utc_now()),
            }
        )
        return_code = 2
    atomic_write_report(report_path, report)
    print(json.dumps({"ok": return_code == 0, **report}, sort_keys=True))
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
