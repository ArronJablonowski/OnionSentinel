"""Versioned harness schema creation and additive migration phases."""
from __future__ import annotations

from typing import Any

from harness_policy import HarnessIntegrityError, SQL_SCHEMA_VERSION


SCHEMA_SQL = """
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


def initialize_schema(connection: Any) -> None:
    """Create or additively migrate the harness schema in exact order."""
    _validate_existing_version(connection)
    connection.executescript(_schema_sql())
    _add_compatibility_columns(connection)
    _backfill_budget_reservations(connection)
    _settle_schema_version(connection)


def _schema_sql() -> str:
    """Retain the historical sqlite_master SQL layout byte for byte."""
    return "\n".join(
        f"                {line}" if line else line
        for line in SCHEMA_SQL.splitlines()
    )


def _validate_existing_version(connection: Any) -> None:
    has_metadata = connection.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table' AND name = 'harness_metadata'
        """
    ).fetchone()
    if has_metadata is None:
        return
    version_row = connection.execute(
        """
        SELECT value
        FROM harness_metadata
        WHERE key = 'schema_version'
        """
    ).fetchone()
    if version_row is None:
        return
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


def _add_compatibility_columns(connection: Any) -> None:
    run_columns = {
        str(row["name"])
        for row in connection.execute("PRAGMA table_info(harness_runs)").fetchall()
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


def _backfill_budget_reservations(connection: Any) -> None:
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


def _settle_schema_version(connection: Any) -> None:
    connection.execute(
        """
        INSERT INTO harness_metadata(key, value)
        VALUES('schema_version', ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (str(SQL_SCHEMA_VERSION),),
    )
