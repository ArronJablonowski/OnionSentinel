from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import scheduler_legacy_reconciliation as reconciliation  # noqa: E402


class SchedulerLegacyReconciliationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.execute(
            "CREATE TABLE alert_group_summary (group_id TEXT PRIMARY KEY)"
        )
        self.conn.execute(
            """
            CREATE TABLE alert_group_alias (
                legacy_group_id TEXT,
                stable_group_id TEXT
            )
            """
        )

    def create_modern_jobs(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT,
                status TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )

    def insert_job(
        self,
        group_id: str,
        *,
        job_type: str = "ai_analysis",
        status: str = "pending",
        started: str | None = None,
        rerun: int = 0,
    ) -> None:
        self.conn.execute(
            "INSERT INTO durable_jobs VALUES (?, ?, ?, ?, ?)",
            (job_type, group_id, status, started, rerun),
        )

    def test_missing_job_table_has_no_pending_or_orphaned_intent(self) -> None:
        self.assertEqual(reconciliation.pending_ai_job_ids(self.conn), set())
        self.assertEqual(
            reconciliation.orphaned_pending_ai_job_ids(self.conn), set()
        )

    def test_pending_ids_include_only_nonempty_pending_ai_jobs(self) -> None:
        self.create_modern_jobs()
        self.insert_job("pending-ai")
        self.insert_job("completed-ai", status="completed")
        self.insert_job("pending-pcap", job_type="pcap_analysis")
        self.insert_job("   ")
        self.conn.commit()

        self.assertEqual(
            reconciliation.pending_ai_job_ids(self.conn), {"pending-ai"}
        )

    def test_active_legacy_and_stable_alias_ids_are_not_orphaned(self) -> None:
        self.create_modern_jobs()
        self.conn.execute(
            "INSERT INTO alert_group_summary VALUES ('legacy-active')"
        )
        self.conn.execute(
            "INSERT INTO alert_group_alias VALUES (?, ?)",
            ("legacy-active", "stable-active"),
        )
        for group_id in (
            "legacy-active",
            "stable-active",
            "orphaned-group",
        ):
            self.insert_job(group_id)
        self.conn.commit()

        self.assertEqual(
            reconciliation.orphaned_pending_ai_job_ids(self.conn),
            {"orphaned-group"},
        )

    def test_modern_reconciliation_preserves_fresh_and_rerun_intent(self) -> None:
        self.create_modern_jobs()
        self.insert_job("fresh", started=None)
        self.insert_job("completed-callback", started="2026-08-08T00:00:00Z")
        self.insert_job(
            "explicit-rerun",
            started="2026-08-08T00:00:00Z",
            rerun=1,
        )
        self.insert_job(
            "already-terminal",
            status="completed",
            started="2026-08-08T00:00:00Z",
        )
        self.conn.commit()

        self.assertEqual(
            reconciliation.reconcilable_completed_ai_job_ids(
                self.conn,
                {
                    "fresh",
                    "completed-callback",
                    "explicit-rerun",
                    "already-terminal",
                    "not-a-job",
                },
            ),
            {"completed-callback"},
        )

    def test_legacy_schema_preserves_historical_group_set_behavior(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT,
                status TEXT NOT NULL
            )
            """
        )
        self.conn.commit()
        self.assertEqual(
            reconciliation.reconcilable_completed_ai_job_ids(
                self.conn, {"artifact-a", "artifact-b"}
            ),
            {"artifact-a", "artifact-b"},
        )

    def test_combined_reconciliation_unions_completed_and_orphaned(self) -> None:
        self.create_modern_jobs()
        self.conn.execute(
            "INSERT INTO alert_group_summary VALUES ('completed-artifact')"
        )
        self.insert_job("completed-artifact", started="2026-08-08T00:00:00Z")
        self.insert_job("orphaned-group")
        self.conn.commit()
        with mock.patch.object(
            reconciliation,
            "completed_analysis_group_ids",
            return_value={"completed-artifact"},
        ) as completed:
            result = reconciliation.reconcilable_ai_job_ids(
                self.conn,
                {"alert-a"},
                Path("analysis"),
                Path("pcap"),
                Path("prompts"),
            )

        self.assertEqual(result, {"completed-artifact", "orphaned-group"})
        completed.assert_called_once_with(
            self.conn,
            {"alert-a"},
            Path("analysis"),
            Path("pcap"),
            Path("prompts"),
        )


if __name__ == "__main__":
    unittest.main()
