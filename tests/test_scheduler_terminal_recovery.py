from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_terminal_recovery import (  # noqa: E402
    TerminalRecoverySources,
    reconcile_terminal_success,
    terminal_success_recovery_candidates,
)


class SchedulerTerminalRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def databases(
        self,
        *,
        paths: bool = False,
    ) -> tuple[sqlite3.Connection, sqlite3.Connection, Path, Path]:
        root = Path(self.tempdir.name)
        alert_path = root / "alerts.sqlite3"
        harness_path = root / "harness.sqlite3"
        alert_target = str(alert_path) if paths else ":memory:"
        harness_target = str(harness_path) if paths else ":memory:"
        alert_conn = sqlite3.connect(alert_target)
        harness_conn = sqlite3.connect(harness_target)
        alert_conn.row_factory = sqlite3.Row
        harness_conn.row_factory = sqlite3.Row
        alert_conn.executescript(
            """
            CREATE TABLE durable_jobs (
                id INTEGER PRIMARY KEY, job_type TEXT, dedupe_key TEXT,
                status TEXT, payload_json TEXT, lease_token TEXT,
                processing_started_at TEXT
            );
            CREATE TABLE ai_analysis_runs (
                analysis_id TEXT, group_id TEXT, alert_id TEXT,
                agent_role TEXT, generated_at TEXT
            );
            CREATE TABLE incident_response_cases (
                case_id TEXT, group_id TEXT, agent_status TEXT,
                latest_analysis_id TEXT, latest_error TEXT
            );
            """
        )
        harness_conn.executescript(
            """
            CREATE TABLE harness_runs (
                run_id TEXT, correlation_id TEXT, case_id TEXT,
                alert_id TEXT, role TEXT, status TEXT, stage TEXT,
                assigned_route TEXT, completed_at TEXT
            );
            """
        )
        return alert_conn, harness_conn, alert_path, harness_path

    def insert_fixture(
        self,
        alert_conn: sqlite3.Connection,
        harness_conn: sqlite3.Connection,
        *,
        job_type: str = "ai_analysis",
        payload_updates: dict[str, object] | None = None,
        route: str = "codex-cli:gpt-5.5:high",
        generated_at: str = "2026-08-08T10:05:00Z",
        latest_error: str | None = None,
    ) -> None:
        is_ir = job_type == "incident_response_analysis"
        role = "incident-responder" if is_ir else "soc-analyst"
        case_id = "ir-case" if is_ir else ""
        payload: dict[str, object] = {
            "agent_role": role,
            "group_id": "group-1",
            "alert_id": "alert-1",
            "expected_assigned_route": route,
        }
        if case_id:
            payload["case_id"] = case_id
        payload.update(payload_updates or {})
        alert_conn.execute(
            "INSERT INTO durable_jobs VALUES (1, ?, 'group-1', 'processing', ?, "
            "'lease-1', '2026-08-08T10:00:00Z')",
            (job_type, json.dumps(payload)),
        )
        alert_conn.execute(
            "INSERT INTO ai_analysis_runs VALUES "
            "('run-1', 'group-1', 'alert-1', ?, ?)",
            (role, generated_at),
        )
        if is_ir:
            alert_conn.execute(
                "INSERT INTO incident_response_cases VALUES "
                "('ir-case', 'group-1', 'analyzed', 'run-1', ?)",
                (latest_error,),
            )
        harness_conn.execute(
            "INSERT INTO harness_runs VALUES "
            "('run-1', 'group-1', ?, 'alert-1', ?, 'succeeded', "
            "'complete', ?, '2026-08-08T10:06:00Z')",
            (case_id, role, route),
        )
        alert_conn.commit()
        harness_conn.commit()

    def test_soc_success_requires_exact_lane_and_attempt_window(self) -> None:
        alert_conn, harness_conn, _, _ = self.databases()
        try:
            self.insert_fixture(alert_conn, harness_conn)
            candidates = terminal_success_recovery_candidates(
                alert_conn,
                harness_conn,
                "cli",
            )
            self.assertEqual(
                candidates,
                [{
                    "job_id": 1,
                    "job_type": "ai_analysis",
                    "group_id": "group-1",
                    "lease_token": "lease-1",
                    "analysis_id": "run-1",
                }],
            )
            self.assertEqual(
                terminal_success_recovery_candidates(
                    alert_conn,
                    harness_conn,
                    "ollama",
                ),
                [],
            )
        finally:
            harness_conn.close()
            alert_conn.close()

    def test_ir_success_requires_committed_case_pointer_without_error(self) -> None:
        alert_conn, harness_conn, _, _ = self.databases()
        try:
            self.insert_fixture(
                alert_conn,
                harness_conn,
                job_type="incident_response_analysis",
            )
            self.assertEqual(
                len(terminal_success_recovery_candidates(
                    alert_conn,
                    harness_conn,
                    "cli",
                )),
                1,
            )
            alert_conn.execute(
                "UPDATE incident_response_cases SET latest_error = 'write failed'"
            )
            alert_conn.commit()
            self.assertEqual(
                terminal_success_recovery_candidates(
                    alert_conn,
                    harness_conn,
                    "cli",
                ),
                [],
            )
        finally:
            harness_conn.close()
            alert_conn.close()

    def test_malformed_or_mismatched_identity_is_rejected(self) -> None:
        mutations = (
            {"group_id": "different-group"},
            {"agent_role": "incident-responder"},
            {"alert_id": "different-alert"},
            {"expected_assigned_route": "codex-cli:gpt-5.6-sol:xhigh"},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                alert_conn, harness_conn, _, _ = self.databases()
                try:
                    self.insert_fixture(
                        alert_conn,
                        harness_conn,
                        payload_updates=mutation,
                    )
                    self.assertEqual(
                        terminal_success_recovery_candidates(
                            alert_conn,
                            harness_conn,
                            "cli",
                        ),
                        [],
                    )
                finally:
                    harness_conn.close()
                    alert_conn.close()

    def test_missing_required_schema_returns_no_candidates(self) -> None:
        alert_conn = sqlite3.connect(":memory:")
        harness_conn = sqlite3.connect(":memory:")
        try:
            alert_conn.execute("CREATE TABLE durable_jobs (id INTEGER)")
            harness_conn.execute("CREATE TABLE harness_runs (run_id TEXT)")
            self.assertEqual(
                terminal_success_recovery_candidates(
                    alert_conn,
                    harness_conn,
                    "cli",
                ),
                [],
            )
        finally:
            harness_conn.close()
            alert_conn.close()

    def test_reconciliation_reports_only_truthy_exact_transitions(self) -> None:
        alert_conn, harness_conn, alert_path, harness_path = self.databases(paths=True)
        self.insert_fixture(alert_conn, harness_conn)
        harness_conn.close()
        alert_conn.close()
        report_status = mock.Mock(return_value=True)

        def connect_read_only(path: Path) -> sqlite3.Connection:
            conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            return conn

        sources = TerminalRecoverySources(
            connect_read_only=connect_read_only,
            path_exists=lambda path: path.exists(),
            load_candidates=terminal_success_recovery_candidates,
            report_status=report_status,
        )
        completed = reconcile_terminal_success(
            sources,
            alert_db=alert_path,
            harness_db=harness_path,
            provider_lane="cli",
            alert_store_url="http://127.0.0.1:8787",
        )
        self.assertEqual(completed, 1)
        report_status.assert_called_once_with(
            "http://127.0.0.1:8787",
            "group-1",
            "completed",
            lease_token="lease-1",
            job_type="ai_analysis",
        )

        missing = reconcile_terminal_success(
            sources,
            alert_db=alert_path,
            harness_db=Path(self.tempdir.name) / "missing.sqlite3",
            provider_lane="cli",
            alert_store_url="http://127.0.0.1:8787",
        )
        self.assertEqual(missing, 0)


if __name__ == "__main__":
    unittest.main()
