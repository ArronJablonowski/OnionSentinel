#!/usr/bin/env python3
"""Regression checks for local AI alert scheduler queue ordering."""
from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEDULER_PATH = REPO_ROOT / "n8n" / "bin" / "auto-run-ai-analysis.py"


def load_scheduler():
    spec = importlib.util.spec_from_file_location("auto_run_ai_analysis", SCHEDULER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AiSchedulerPriorityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scheduler = load_scheduler()
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
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
                routing TEXT,
                suppression_key TEXT
            )
            """
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            self.args = SimpleNamespace(
                levels="critical,high,medium,low,informational",
                hours=87600,
                include_tests=True,
                analysis_dir=Path(tmpdir),
            )

    def tearDown(self) -> None:
        self.conn.close()

    def insert_alert(
        self,
        alert_id: str,
        severity: str,
        last_seen: str,
        score: int = 80,
        rule_name: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts (
                alert_id, first_seen, last_seen, timestamp, rule_name, source_ip,
                destination_ip, triage_level, triage_score, filter_status, routing,
                suppression_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', 'analyst-review', NULL)
            """,
            (
                alert_id,
                last_seen,
                last_seen,
                last_seen,
                rule_name or f"{severity} test detection {alert_id}",
                source_ip or f"192.0.2.{len(alert_id)}",
                destination_ip or f"198.51.100.{len(alert_id)}",
                severity,
                score,
            ),
        )

    def test_drains_each_severity_newest_first_before_lower_severity(self) -> None:
        self.insert_alert("medium-newest", "medium", "2026-07-03  00:50:00Z", 90)
        self.insert_alert("high-newer-than-critical", "high", "2026-07-03  00:55:00Z", 90)
        self.insert_alert("critical-old", "critical", "2026-07-03  00:10:00Z", 70)
        self.insert_alert("critical-new", "critical", "2026-07-03  00:20:00Z", 60)
        self.insert_alert("low-newest", "low", "2026-07-03  01:00:00Z", 100)
        self.conn.commit()

        selected_groups: set[str] = set()
        selected_ids: list[str] = []
        for _ in range(5):
            selected = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
            self.assertIsNotNone(selected)
            selected_ids.append(selected["alert_id"])
            selected_groups.add(self.scheduler.alert_group_key(selected))

        self.assertEqual(
            selected_ids,
            [
                "critical-new",
                "critical-old",
                "high-newer-than-critical",
                "medium-newest",
                "low-newest",
            ],
        )

    def test_duplicate_groups_use_newest_representative_before_next_group(self) -> None:
        for alert_id, last_seen in (
            ("critical-dup-old", "2026-07-03  00:10:00Z"),
            ("critical-dup-new", "2026-07-03  00:30:00Z"),
        ):
            self.insert_alert(
                alert_id,
                "critical",
                last_seen,
                rule_name="same critical duplicate group",
                source_ip="192.0.2.44",
                destination_ip="198.51.100.44",
            )
        self.insert_alert("critical-other", "critical", "2026-07-03  00:20:00Z")
        self.insert_alert("high-newer", "high", "2026-07-03  01:00:00Z")
        self.conn.commit()

        selected_groups: set[str] = set()
        first = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
        self.assertIsNotNone(first)
        selected_groups.add(first["queue_group_key"])
        second = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
        self.assertIsNotNone(second)

        self.assertEqual(first["alert_id"], "critical-dup-new")
        self.assertEqual(second["alert_id"], "critical-other")


if __name__ == "__main__":
    unittest.main()
