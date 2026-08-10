"""SQLite schema, connection, audit-event, and hash-chain foundation."""
from __future__ import annotations

import contextlib
import hashlib
import os
import sqlite3
import stat
from pathlib import Path
from typing import Any, Iterable, Mapping

from security_jsonl_log import SecurityJsonlLogger

from harness_contracts import bounded_metadata
from harness_policy import (
    DEFAULT_DB_PATH,
    DEFAULT_HARNESS_LOG_PATH,
    HARNESS_SCHEMA,
    SQL_SCHEMA_VERSION,
    HarnessIntegrityError,
    RunStatus,
    canonical_json,
    digest_json,
    utc_now,
)


def _secure_sqlite_files(path: Path) -> None:
    for candidate in (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
    ):
        if candidate.exists() and not candidate.is_symlink():
            try:
                os.chmod(candidate, stat.S_IRUSR | stat.S_IWUSR)
            except FileNotFoundError:
                if candidate == path or candidate.exists():
                    raise


def _probe_existing_schema_version(path: Path) -> int | None:
    """Inspect an existing database without changing its journal or sidecars."""
    if path.is_symlink():
        raise HarnessIntegrityError("harness database must not be a symlink")
    if not path.exists():
        return None
    if not path.is_file():
        raise HarnessIntegrityError("harness database must be a regular file")
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=5.0)
    except sqlite3.Error as exc:
        raise HarnessIntegrityError(
            "harness database could not be inspected safely"
        ) from exc
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        has_metadata = connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table' AND name = 'harness_metadata'
            """
        ).fetchone()
        if has_metadata is None:
            return None
        row = connection.execute(
            """
            SELECT value
            FROM harness_metadata
            WHERE key = 'schema_version'
            """
        ).fetchone()
        if row is None:
            return None
        try:
            return int(row["value"])
        except (TypeError, ValueError) as exc:
            raise HarnessIntegrityError(
                "harness database schema version is invalid"
            ) from exc
    except sqlite3.Error as exc:
        raise HarnessIntegrityError(
            "harness database schema could not be read"
        ) from exc
    finally:
        connection.close()


@contextlib.contextmanager
def _connect(path: Path) -> Iterable[sqlite3.Connection]:
    if path.is_symlink():
        raise HarnessIntegrityError("harness database must not be a symlink")
    if path.exists() and not path.is_file():
        raise HarnessIntegrityError("harness database must be a regular file")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    new_database = not path.exists()
    connection = sqlite3.connect(path, timeout=30.0)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        if new_database:
            # This must be selected before any tables or WAL state exist.
            connection.execute("PRAGMA auto_vacuum = INCREMENTAL")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        _secure_sqlite_files(path)
        with connection:
            yield connection
    finally:
        connection.close()
        _secure_sqlite_files(path)


class HarnessStoreFoundation:
    """Owner-only SQLite schema and event-chain foundation."""

    def __init__(
        self,
        path: Path = DEFAULT_DB_PATH,
        *,
        log_path: Path | None = None,
    ):
        self.path = path.expanduser()
        resolved_default = DEFAULT_DB_PATH.expanduser()
        selected_log_path = (
            log_path.expanduser()
            if log_path is not None
            else (
                DEFAULT_HARNESS_LOG_PATH
                if self.path == resolved_default
                else self.path.with_suffix(".events.jsonl")
            )
        )
        self.logger = SecurityJsonlLogger(
            selected_log_path,
            service="onion-sentinel-investigation-harness",
        )
        existing_version = _probe_existing_schema_version(self.path)
        if (
            existing_version is not None
            and existing_version > SQL_SCHEMA_VERSION
        ):
            raise HarnessIntegrityError(
                "harness database was created by a newer runtime"
            )
        self.initialize()
        self.logger.log(
            "info",
            "harness.store.ready",
            database_path=str(self.path),
            schema=HARNESS_SCHEMA,
            schema_version=SQL_SCHEMA_VERSION,
        )

    def _audit_event(self, event: Mapping[str, Any]) -> None:
        """Mirror committed event metadata without duplicating evidence."""
        try:
            with _connect(self.path) as connection:
                run = connection.execute(
                    """
                    SELECT correlation_id, case_id, alert_id, role, task_kind,
                           assigned_route, assigned_reviewer_route, status
                    FROM harness_runs WHERE run_id = ?
                    """,
                    (str(event.get("run_id") or ""),),
                ).fetchone()
            identity = dict(run) if run is not None else {}
            self.logger.log(
                "error"
                if str(event.get("event_type") or "") == "run.failed"
                else "info",
                "harness.event",
                run_id=str(event.get("run_id") or ""),
                trace_sequence=int(event.get("sequence") or 0),
                harness_event_type=str(event.get("event_type") or ""),
                stage=str(event.get("stage") or ""),
                event_id=str(event.get("event_id") or ""),
                event_created_at=str(event.get("created_at") or ""),
                event_sha256=str(event.get("event_sha256") or ""),
                payload_sha256=str(event.get("payload_sha256") or ""),
                **identity,
            )
        except Exception:
            # SQLite remains the authoritative hash-chained audit ledger.
            # Troubleshooting log failure must not invalidate committed work.
            return

    def initialize(self) -> None:
        with _connect(self.path) as connection:
            has_metadata = connection.execute(
                """
                SELECT 1
                FROM sqlite_master
                WHERE type = 'table' AND name = 'harness_metadata'
                """
            ).fetchone()
            if has_metadata is not None:
                version_row = connection.execute(
                    """
                    SELECT value
                    FROM harness_metadata
                    WHERE key = 'schema_version'
                    """
                ).fetchone()
                if version_row is not None:
                    try:
                        existing_version = int(version_row["value"])
                    except (TypeError, ValueError) as exc:
                        raise HarnessIntegrityError(
                            "harness database schema version is invalid"
                        ) from exc
                    if existing_version > SQL_SCHEMA_VERSION:
                        raise HarnessIntegrityError(
                            "harness database was created by a newer runtime"
                        )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS harness_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS harness_runs (
                    run_id TEXT PRIMARY KEY,
                    trace_id TEXT NOT NULL UNIQUE,
                    correlation_id TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    task_kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    assigned_route TEXT NOT NULL,
                    assigned_reviewer_route TEXT NOT NULL DEFAULT '',
                    active_route TEXT NOT NULL DEFAULT '',
                    prompt_digest TEXT NOT NULL,
                    evidence_manifest_digest TEXT NOT NULL,
                    configuration_digest TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    policy_mode TEXT NOT NULL,
                    parent_run_id TEXT NOT NULL,
                    job_digest TEXT NOT NULL,
                    revision INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    terminal_reason TEXT NOT NULL DEFAULT '',
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_harness_runs_case
                    ON harness_runs(case_id, started_at DESC);
                CREATE INDEX IF NOT EXISTS idx_harness_runs_status
                    ON harness_runs(status, updated_at);

                CREATE TABLE IF NOT EXISTS harness_events (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    sequence INTEGER NOT NULL,
                    event_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    previous_event_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    PRIMARY KEY (run_id, sequence),
                    UNIQUE (run_id, event_id),
                    UNIQUE (run_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS harness_evidence (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    evidence_ref TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_class TEXT NOT NULL,
                    trust_tier TEXT NOT NULL,
                    corroborating INTEGER NOT NULL CHECK(corroborating IN (0, 1)),
                    status TEXT NOT NULL,
                    evidence_digest TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    PRIMARY KEY (run_id, evidence_ref)
                );

                CREATE TABLE IF NOT EXISTS harness_hypotheses (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    hypothesis_id TEXT NOT NULL,
                    statement TEXT NOT NULL,
                    statement_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    supporting_refs_json TEXT NOT NULL,
                    contradicting_refs_json TEXT NOT NULL,
                    next_discriminator TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, hypothesis_id)
                );

                CREATE TABLE IF NOT EXISTS harness_decisions (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    decision_id TEXT NOT NULL,
                    decision_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    confidence_score REAL,
                    evidence_refs_json TEXT NOT NULL,
                    rationale_digest TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, decision_id)
                );

                CREATE TABLE IF NOT EXISTS harness_model_calls (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    call_id TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    requested_route TEXT NOT NULL,
                    observed_model TEXT NOT NULL,
                    observed_model_path TEXT NOT NULL,
                    observed_provider TEXT NOT NULL,
                    observed_harness TEXT NOT NULL,
                    independent_review INTEGER NOT NULL
                        CHECK(independent_review IN (0, 1)),
                    status TEXT NOT NULL,
                    input_digest TEXT NOT NULL,
                    output_digest TEXT NOT NULL,
                    duration_ms INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, call_id)
                );

                CREATE TABLE IF NOT EXISTS harness_tool_calls (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    call_id TEXT NOT NULL,
                    round_number INTEGER NOT NULL,
                    backend TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    result_digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    read_only INTEGER NOT NULL CHECK(read_only IN (0, 1)),
                    coverage TEXT NOT NULL,
                    truncated INTEGER NOT NULL CHECK(truncated IN (0, 1)),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, call_id)
                );

                CREATE TABLE IF NOT EXISTS harness_budget_reservations (
                    run_id TEXT NOT NULL REFERENCES harness_runs(run_id)
                        ON DELETE CASCADE,
                    reservation_type TEXT NOT NULL,
                    reservation_id TEXT NOT NULL,
                    amount INTEGER NOT NULL CHECK(amount >= 0),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (run_id, reservation_type, reservation_id)
                );
                """
            )
            run_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(harness_runs)"
                ).fetchall()
            }
            if "policy_digest" not in run_columns:
                connection.execute(
                    """
                    ALTER TABLE harness_runs
                    ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''
                    """
                )
            if "assigned_reviewer_route" not in run_columns:
                connection.execute(
                    """
                    ALTER TABLE harness_runs
                    ADD COLUMN assigned_reviewer_route TEXT NOT NULL DEFAULT ''
                    """
                )
            connection.execute(
                """
                INSERT OR IGNORE INTO harness_budget_reservations(
                    run_id, reservation_type, reservation_id, amount, created_at
                )
                SELECT run_id, 'model-call', call_id, 1, created_at
                FROM harness_model_calls
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO harness_budget_reservations(
                    run_id, reservation_type, reservation_id, amount, created_at
                )
                SELECT run_id, 'query-round', CAST(round_number AS TEXT),
                       SUM(
                         CASE
                           WHEN lower(status) IN (
                             'rejected', 'denied', 'blocked',
                             'unauthorized', 'forbidden'
                           ) THEN 0
                           ELSE 1
                         END
                       ),
                       MIN(created_at)
                FROM harness_tool_calls
                GROUP BY run_id, round_number
                """
            )
            connection.execute(
                """
                INSERT INTO harness_metadata(key, value)
                VALUES('schema_version', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (str(SQL_SCHEMA_VERSION),),
            )
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def _append_event_tx(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        event_type: str,
        stage: str,
        payload: Mapping[str, Any],
        idempotency_key: str,
        created_at: str | None = None,
    ) -> dict[str, Any]:
        payload_value = bounded_metadata(payload)
        payload_json = canonical_json(payload_value)
        payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        existing = connection.execute(
            """
            SELECT * FROM harness_events
            WHERE run_id = ? AND idempotency_key = ?
            """,
            (run_id, idempotency_key),
        ).fetchone()
        if existing is not None:
            if (
                existing["event_type"] != event_type
                or existing["stage"] != stage
                or existing["payload_sha256"] != payload_sha256
            ):
                raise HarnessIntegrityError(
                    "idempotency key was reused with different event content"
                )
            return dict(existing)
        previous = connection.execute(
            """
            SELECT sequence, event_sha256
            FROM harness_events
            WHERE run_id = ?
            ORDER BY sequence DESC
            LIMIT 1
            """,
            (run_id,),
        ).fetchone()
        sequence = int(previous["sequence"]) + 1 if previous else 1
        previous_hash = str(previous["event_sha256"]) if previous else "0" * 64
        created_at = created_at or utc_now()
        body = {
            "run_id": run_id,
            "sequence": sequence,
            "idempotency_key": idempotency_key,
            "event_type": event_type,
            "stage": stage,
            "created_at": created_at,
            "payload_sha256": payload_sha256,
            "previous_event_sha256": previous_hash,
        }
        event_sha256 = digest_json(body)
        event_id = f"evt-{event_sha256[:32]}"
        connection.execute(
            """
            INSERT INTO harness_events(
                run_id, sequence, event_id, idempotency_key, event_type,
                stage, created_at, payload_json, payload_sha256,
                previous_event_sha256, event_sha256
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                sequence,
                event_id,
                idempotency_key,
                event_type,
                stage,
                created_at,
                payload_json,
                payload_sha256,
                previous_hash,
                event_sha256,
            ),
        )
        return {
            **body,
            "event_id": event_id,
            "payload_json": payload_json,
            "event_sha256": event_sha256,
        }

    @staticmethod
    def _require_mutable_run_tx(
        connection: sqlite3.Connection,
        run_id: str,
    ) -> sqlite3.Row:
        run = connection.execute(
            "SELECT status FROM harness_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if run is None:
            raise HarnessIntegrityError("unknown harness run")
        if run["status"] not in {
            RunStatus.RUNNING.value,
            RunStatus.WAITING_FOR_REVIEW.value,
        }:
            raise HarnessIntegrityError("terminal harness run is immutable")
        return run

    @staticmethod
    def _update_run_stage_tx(
        connection: sqlite3.Connection,
        *,
        run_id: str,
        stage: str,
        updated_at: str,
        active_route: str | None = None,
    ) -> None:
        if active_route is None:
            cursor = connection.execute(
                """
                UPDATE harness_runs
                SET stage = ?, updated_at = ?, revision = revision + 1
                WHERE run_id = ? AND status IN (?, ?)
                """,
                (
                    stage,
                    updated_at,
                    run_id,
                    RunStatus.RUNNING.value,
                    RunStatus.WAITING_FOR_REVIEW.value,
                ),
            )
        else:
            cursor = connection.execute(
                """
                UPDATE harness_runs
                SET stage = ?, active_route = ?, updated_at = ?,
                    revision = revision + 1
                WHERE run_id = ? AND status IN (?, ?)
                """,
                (
                    stage,
                    active_route[:256],
                    updated_at,
                    run_id,
                    RunStatus.RUNNING.value,
                    RunStatus.WAITING_FOR_REVIEW.value,
                ),
            )
        if cursor.rowcount != 1:
            raise HarnessIntegrityError(
                "unknown or terminal harness run cannot advance"
            )
