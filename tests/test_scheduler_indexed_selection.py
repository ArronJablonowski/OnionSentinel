from __future__ import annotations

import datetime as dt
import json
import sqlite3
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_indexed_selection import (  # noqa: E402
    IndexedSelectionRequest,
    IndexedSelectionSources,
    provider_lane_predicate,
    select_next_indexed_alert,
)


def alert_time_sql(alias: str) -> str:
    prefix = f"{alias}." if alias else ""
    return (
        f"COALESCE(NULLIF({prefix}last_seen, ''), "
        f"NULLIF({prefix}timestamp, ''), {prefix}first_seen)"
    )


def severity_priority_sql(column: str) -> str:
    return (
        f"CASE LOWER(COALESCE({column}, '')) "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
    )


class SchedulerIndexedSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.precise_now = "2026-08-08T10:30:00Z"
        self.conn.executescript(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                timestamp TEXT,
                rule_name TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                triage_level TEXT,
                triage_score INTEGER,
                filter_status TEXT,
                stable_group_id TEXT,
                stable_group_key TEXT,
                routing TEXT,
                suppression_key TEXT
            );
            CREATE TABLE durable_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                generated_at TEXT,
                agent_role TEXT
            );
            """
        )
        self.sources = IndexedSelectionSources(
            now=lambda: dt.datetime.fromisoformat("2026-08-08T10:30:00+00:00"),
            precise_now=lambda: self.precise_now,
            alert_time_sql=alert_time_sql,
            severity_priority_sql=severity_priority_sql,
            test_filter_sql=lambda column: (f"{column} NOT LIKE ?", ["test-%"]),
            eligible_filter_statuses=(
                "accepted", "escalated", "unknown", "suppressed",
            ),
            fairness_age_seconds=15 * 60,
        )

    def tearDown(self) -> None:
        self.conn.close()

    def request(
        self,
        *,
        only_group_id: str = "",
        lane_sql: str = "",
        lane_params: tuple[object, ...] = (),
    ) -> IndexedSelectionRequest:
        return IndexedSelectionRequest(
            levels="critical,high,medium,low,informational",
            hours=24,
            include_tests=True,
            only_group_id=only_group_id,
            lane_sql=lane_sql,
            lane_params=lane_params,
        )

    def insert_alert(
        self,
        alert_id: str,
        group_id: str,
        severity: str,
        seen_at: str,
        score: int = 50,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts VALUES (
                ?, ?, ?, ?, ?, '10.0.0.1', '10.0.0.2', ?, ?, 'accepted',
                ?, ?, '', ''
            )
            """,
            (
                alert_id, seen_at, seen_at, seen_at, alert_id, severity,
                score, group_id, f"key-{group_id}",
            ),
        )

    def insert_job(
        self,
        group_id: str,
        *,
        role: str = "soc-analyst",
        job_type: str = "ai_analysis",
        manual: bool = False,
        priority: int = 0,
        requested_at: str = "2026-08-08T10:25:00Z",
        next_attempt_at: str = "2026-08-08T10:00:00Z",
    ) -> None:
        payload = {"agent_role": role}
        if manual:
            payload["manual_reanalysis"] = True
        self.conn.execute(
            """
            INSERT INTO durable_jobs (
                job_type, dedupe_key, status, payload_json, priority,
                attempt_count, max_attempts, next_attempt_at,
                processing_started_at, rerun_requested, requested_at
            ) VALUES (?, ?, 'pending', ?, ?, 0, 3, ?, NULL, 0, ?)
            """,
            (
                job_type, group_id, json.dumps(payload), priority,
                next_attempt_at, requested_at,
            ),
        )

    def select(self, request: IndexedSelectionRequest | None = None) -> sqlite3.Row | None:
        self.conn.commit()
        return select_next_indexed_alert(
            self.conn,
            request or self.request(),
            self.sources,
        )

    def test_manual_rerun_preempts_automatic_critical(self) -> None:
        self.insert_alert("manual-low", "manual-group", "low", "2026-08-08T10:00:00Z")
        self.insert_alert("critical", "critical-group", "critical", "2026-08-08T10:20:00Z")
        self.insert_job("manual-group", manual=True)
        self.insert_job("critical-group")
        selected = self.select()
        self.assertEqual(selected["alert_id"], "manual-low")
        self.assertEqual(selected["request_bucket"], 0)

    def test_severity_precedes_score_and_cross_role_fairness(self) -> None:
        self.insert_alert("critical", "critical-group", "critical", "2026-08-08T10:20:00Z", 20)
        self.insert_alert("high", "high-group", "high", "2026-08-08T09:00:00Z", 100)
        self.insert_job("critical-group", role="incident-responder", job_type="incident_response_analysis")
        self.insert_job("high-group", requested_at="2026-08-08T09:00:00Z")
        self.assertEqual(self.select()["alert_id"], "critical")

    def test_age_fairness_prevents_same_severity_role_starvation(self) -> None:
        self.insert_alert("soc", "soc-group", "medium", "2026-08-08T09:00:00Z")
        self.insert_alert("ir", "ir-group", "medium", "2026-08-08T10:20:00Z")
        self.insert_job("soc-group", requested_at="2026-08-08T09:00:00Z")
        self.insert_job(
            "ir-group",
            role="incident-responder",
            job_type="incident_response_analysis",
            priority=100,
            requested_at="2026-08-08T10:20:00Z",
        )
        selected = self.select()
        self.assertEqual(selected["alert_id"], "soc")
        self.assertEqual(selected["fairness_bucket"], 0)

    def test_exact_group_target_rejects_other_higher_priority_group(self) -> None:
        target = "0123456789abcdefabcd"
        other = "fedcba9876543210abcd"
        self.insert_alert("target", target, "low", "2026-08-08T09:00:00Z")
        self.insert_alert("other", other, "critical", "2026-08-08T10:20:00Z")
        self.insert_job(target)
        self.insert_job(other, manual=True)
        self.assertEqual(
            self.select(self.request(only_group_id=target))["alert_id"],
            "target",
        )
        with self.assertRaisesRegex(SystemExit, "one exact 20-hex"):
            self.select(self.request(only_group_id="not-exact"))

    def test_subsecond_due_time_is_not_selected_early(self) -> None:
        self.insert_alert("subsecond", "subsecond-group", "high", "2026-08-08T10:20:00Z")
        self.insert_job(
            "subsecond-group",
            next_attempt_at="2026-08-08T10:30:00.438Z",
        )
        self.precise_now = "2026-08-08T10:30:00.437Z"
        self.assertIsNone(self.select())
        self.precise_now = "2026-08-08T10:30:00.500Z"
        self.assertEqual(self.select()["alert_id"], "subsecond")

    def test_provider_lane_predicate_isolates_agent_roles(self) -> None:
        self.insert_alert("soc", "soc-group", "high", "2026-08-08T10:20:00Z")
        self.insert_alert("ir", "ir-group", "high", "2026-08-08T10:10:00Z")
        self.insert_job("soc-group")
        self.insert_job(
            "ir-group",
            role="incident-responder",
            job_type="incident_response_analysis",
        )
        cli_sql, cli_params = provider_lane_predicate(
            "cli", ["incident-responder"]
        )
        ollama_sql, ollama_params = provider_lane_predicate(
            "ollama", ["incident-responder"]
        )
        cli = self.select(self.request(
            lane_sql=cli_sql,
            lane_params=tuple(cli_params),
        ))
        ollama = self.select(self.request(
            lane_sql=ollama_sql,
            lane_params=tuple(ollama_params),
        ))
        self.assertEqual(cli["alert_id"], "ir")
        self.assertEqual(ollama["alert_id"], "soc")
        self.assertEqual(provider_lane_predicate("cli", []), ("AND 0 = 1", []))


if __name__ == "__main__":
    unittest.main()
