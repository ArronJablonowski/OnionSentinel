from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_indexed_state import (  # noqa: E402
    indexed_reconcilable_ai_job_ids,
    indexed_scheduler_available,
)


class SchedulerIndexedStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")

    def tearDown(self) -> None:
        self.conn.close()

    def create_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                stable_group_id TEXT,
                stable_group_key TEXT
            );
            CREATE TABLE durable_jobs (
                id INTEGER PRIMARY KEY,
                job_type TEXT,
                dedupe_key TEXT,
                status TEXT,
                payload_json TEXT,
                priority INTEGER,
                attempt_count INTEGER,
                max_attempts INTEGER,
                next_attempt_at TEXT,
                processing_started_at TEXT,
                rerun_requested INTEGER,
                requested_at TEXT
            );
            CREATE TABLE ai_analysis_runs (
                group_id TEXT,
                generated_at TEXT
            );
            """
        )

    def insert_job(
        self,
        group_id: str,
        *,
        started_at: str | None = "2026-08-08T10:00:00Z",
        rerun_requested: int = 0,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO durable_jobs (
                job_type, dedupe_key, status, payload_json, priority,
                attempt_count, max_attempts, next_attempt_at,
                processing_started_at, rerun_requested, requested_at
            ) VALUES (
                'ai_analysis', ?, 'pending', '{}', 0, 0, 3,
                '2026-08-08T10:00:00Z', ?, ?, '2026-08-08T09:00:00Z'
            )
            """,
            (group_id, started_at, rerun_requested),
        )

    def test_partial_schema_disables_indexed_scheduler(self) -> None:
        self.conn.execute(
            "CREATE TABLE alerts (stable_group_id TEXT, stable_group_key TEXT)"
        )
        self.conn.execute("CREATE TABLE durable_jobs (id INTEGER)")
        self.conn.execute(
            "CREATE TABLE ai_analysis_runs (group_id TEXT, generated_at TEXT)"
        )
        self.assertFalse(indexed_scheduler_available(self.conn))
        self.assertEqual(indexed_reconcilable_ai_job_ids(self.conn), set())

    def test_current_committed_result_is_reconcilable(self) -> None:
        self.create_schema()
        self.conn.execute(
            "INSERT INTO alerts VALUES ('alert-1', 'group-1', 'key-1')"
        )
        self.insert_job("group-1")
        self.conn.execute(
            "INSERT INTO ai_analysis_runs VALUES "
            "('group-1', '2026-08-08T10:05:00Z')"
        )
        self.conn.commit()
        self.assertTrue(indexed_scheduler_available(self.conn))
        self.assertEqual(
            indexed_reconcilable_ai_job_ids(self.conn),
            {"group-1"},
        )

    def test_stale_result_and_manual_rerun_are_not_reconciled(self) -> None:
        self.create_schema()
        for group_id in ("stale", "rerun"):
            self.conn.execute(
                "INSERT INTO alerts VALUES (?, ?, ?)",
                (f"alert-{group_id}", group_id, f"key-{group_id}"),
            )
        self.insert_job("stale")
        self.insert_job("rerun", rerun_requested=1)
        self.conn.executemany(
            "INSERT INTO ai_analysis_runs VALUES (?, ?)",
            (
                ("stale", "2026-08-08T09:59:59Z"),
                ("rerun", "2026-08-08T10:05:00Z"),
            ),
        )
        self.conn.commit()
        self.assertEqual(indexed_reconcilable_ai_job_ids(self.conn), set())

    def test_orphaned_pending_group_is_reconcilable(self) -> None:
        self.create_schema()
        self.insert_job("orphaned", started_at=None)
        self.conn.commit()
        self.assertEqual(
            indexed_reconcilable_ai_job_ids(self.conn),
            {"orphaned"},
        )


if __name__ == "__main__":
    unittest.main()
