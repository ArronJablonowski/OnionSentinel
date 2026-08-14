from __future__ import annotations

import contextlib
import inspect
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import harness_store_foundation as foundation
import harness_store_schema as schema_owner


class HarnessStoreSchemaArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "state" / "harness.sqlite3"
        self.log_path = self.root / "logs" / "harness.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def make_store(self):
        return foundation.HarnessStoreFoundation(
            self.db_path,
            log_path=self.log_path,
        )

    def test_initialize_signature_and_new_database_contract(self) -> None:
        self.assertEqual(
            str(inspect.signature(foundation.HarnessStoreFoundation.initialize)),
            "(self) -> 'None'",
        )
        self.make_store()
        self.assertEqual(stat.S_IMODE(self.db_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.db_path.parent.stat().st_mode), 0o700)
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            connection.row_factory = sqlite3.Row
            objects = {
                (str(row["type"]), str(row["name"]))
                for row in connection.execute(
                    """
                    SELECT type, name FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                    """
                ).fetchall()
            }
            self.assertEqual(
                objects,
                {
                    ("table", "harness_metadata"),
                    ("table", "harness_runs"),
                    ("table", "harness_events"),
                    ("table", "harness_evidence"),
                    ("table", "harness_hypotheses"),
                    ("table", "harness_decisions"),
                    ("table", "harness_model_calls"),
                    ("table", "harness_tool_calls"),
                    ("table", "harness_budget_reservations"),
                    ("index", "idx_harness_runs_case"),
                    ("index", "idx_harness_runs_status"),
                },
            )

            run_columns = [
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(harness_runs)"
                ).fetchall()
            ]
            self.assertEqual(
                run_columns,
                [
                    "run_id", "trace_id", "correlation_id", "case_id",
                    "alert_id", "role", "task_kind", "status", "stage",
                    "assigned_route", "assigned_reviewer_route", "active_route",
                    "prompt_digest", "evidence_manifest_digest",
                    "configuration_digest", "execution_contract_json",
                    "execution_contract_digest", "policy_version", "policy_digest",
                    "policy_mode", "parent_run_id", "job_digest", "revision",
                    "started_at", "updated_at", "completed_at",
                    "terminal_reason", "summary_json",
                ],
            )
            self.assertEqual(connection.execute("PRAGMA auto_vacuum").fetchone()[0], 2)
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM harness_metadata WHERE key='schema_version'"
                ).fetchone()[0],
                str(foundation.SQL_SCHEMA_VERSION),
            )

    def test_schema_owner_does_not_import_foundation(self) -> None:
        source = inspect.getsource(schema_owner)
        self.assertNotIn("import harness_store_foundation", source)
        self.assertNotIn("from harness_store_foundation", source)
        facade = inspect.getsource(foundation.HarnessStoreFoundation.initialize)
        self.assertLessEqual(len(facade.splitlines()), 5)

    def test_legacy_columns_and_reservations_are_migrated_exactly(self) -> None:
        self.db_path.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.executescript(
                    """
                    CREATE TABLE harness_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO harness_metadata VALUES('schema_version', '3');
                    CREATE TABLE harness_runs(
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
                        active_route TEXT NOT NULL DEFAULT '',
                        prompt_digest TEXT NOT NULL,
                        evidence_manifest_digest TEXT NOT NULL,
                        configuration_digest TEXT NOT NULL,
                        policy_version TEXT NOT NULL,
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
                    INSERT INTO harness_runs(
                        run_id, trace_id, correlation_id, case_id, alert_id,
                        role, task_kind, status, stage, assigned_route,
                        active_route, prompt_digest, evidence_manifest_digest,
                        configuration_digest, policy_version, policy_mode,
                        parent_run_id, job_digest, revision, started_at,
                        updated_at, completed_at, terminal_reason, summary_json
                    ) VALUES(
                        'run-1', 'trace-1', 'correlation-1', 'case-1', 'alert-1',
                        'soc-analyst', 'soc-alert-analysis', 'running', 'intake',
                        'codex-cli:gpt-5.6-sol:high', '', 'a', 'b', 'c', 'v3',
                        'shadow', '', 'd', 0, '2026-01-01T00:00:00Z',
                        '2026-01-01T00:00:00Z', NULL, '', '{}'
                    );
                    CREATE TABLE harness_model_calls(
                        run_id TEXT, call_id TEXT, created_at TEXT,
                        PRIMARY KEY(run_id, call_id)
                    );
                    INSERT INTO harness_model_calls VALUES
                        ('run-1', 'model-1', '2026-01-01T00:00:00Z'),
                        ('run-1', 'model-2', '2026-01-01T00:01:00Z');
                    CREATE TABLE harness_tool_calls(
                        run_id TEXT, call_id TEXT, round_number INTEGER,
                        status TEXT, created_at TEXT,
                        PRIMARY KEY(run_id, call_id)
                    );
                    INSERT INTO harness_tool_calls VALUES
                        ('run-1', 'q-1', 1, 'ok', '2026-01-01T00:02:00Z'),
                        ('run-1', 'q-2', 1, 'rejected', '2026-01-01T00:03:00Z'),
                        ('run-1', 'q-3', 2, 'FORBIDDEN', '2026-01-01T00:04:00Z'),
                        ('run-1', 'q-4', 2, 'timeout', '2026-01-01T00:05:00Z');
                    """
                )
        self.make_store()
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            connection.row_factory = sqlite3.Row
            columns = {
                str(row["name"]): str(row["dflt_value"])
                for row in connection.execute("PRAGMA table_info(harness_runs)")
            }
            self.assertEqual(columns["policy_digest"], "''")
            self.assertEqual(columns["assigned_reviewer_route"], "''")
            self.assertEqual(columns["execution_contract_json"], "''")
            self.assertEqual(columns["execution_contract_digest"], "''")
            reservations = [
                tuple(row)
                for row in connection.execute(
                    """
                    SELECT reservation_type, reservation_id, amount, created_at
                    FROM harness_budget_reservations
                    ORDER BY reservation_type, reservation_id
                    """
                ).fetchall()
            ]
            self.assertEqual(
                reservations,
                [
                    ("model-call", "model-1", 1, "2026-01-01T00:00:00Z"),
                    ("model-call", "model-2", 1, "2026-01-01T00:01:00Z"),
                    ("query-round", "1", 1, "2026-01-01T00:02:00Z"),
                    ("query-round", "2", 1, "2026-01-01T00:04:00Z"),
                ],
            )
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM harness_metadata WHERE key='schema_version'"
                ).fetchone()[0],
                str(foundation.SQL_SCHEMA_VERSION),
            )

    def test_invalid_existing_version_refuses_without_wal_sidecars(self) -> None:
        self.db_path.parent.mkdir(parents=True)
        with contextlib.closing(sqlite3.connect(self.db_path)) as connection:
            with connection:
                connection.execute(
                    "CREATE TABLE harness_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "INSERT INTO harness_metadata VALUES('schema_version', 'invalid')"
                )
        with self.assertRaisesRegex(
            foundation.HarnessIntegrityError,
            "schema version is invalid",
        ):
            self.make_store()
        self.assertFalse(Path(f"{self.db_path}-wal").exists())
        self.assertFalse(Path(f"{self.db_path}-shm").exists())
        self.assertEqual(os.stat(self.db_path).st_size > 0, True)


if __name__ == "__main__":
    unittest.main()
