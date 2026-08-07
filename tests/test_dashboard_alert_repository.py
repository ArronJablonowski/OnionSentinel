#!/usr/bin/env python3
"""Contracts for the read-only SOC alert repository."""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_alert_repository.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("dashboard_alert_repository", MODULE_PATH)
assert SPEC and SPEC.loader
REPOSITORY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REPOSITORY
SPEC.loader.exec_module(REPOSITORY)


ALERT_SCHEMA = """
CREATE TABLE alerts (
  alert_id TEXT PRIMARY KEY, first_seen TEXT, last_seen TEXT, seen_count INTEGER,
  timestamp TEXT, rule_name TEXT, event_dataset TEXT, severity INTEGER,
  severity_label TEXT, source_ip TEXT, destination_ip TEXT, alert_json TEXT,
  traffic_direction TEXT, triage_score INTEGER, triage_level TEXT, routing TEXT,
  filter_status TEXT, filter_reason TEXT, suppression_key TEXT, enrichment_json TEXT
)
"""


def alert_values(
    alert_id: str,
    first_seen: str,
    last_seen: str,
    seen_count: int,
    *,
    source_ip: str = "10.0.0.1",
    suppression_key: str = "",
    enrichment_json: str = "{}",
) -> tuple[object, ...]:
    return (
        alert_id, first_seen, last_seen, seen_count, last_seen, "Example Rule",
        "suricata.alert", 2, "medium", source_ip, "203.0.113.8",
        '{"destination":{"port":443}}', "outbound", 50, "review", "soc",
        "accepted", "", suppression_key, enrichment_json,
    )


class DashboardAlertRepositoryTests(unittest.TestCase):
    def create_database(self, rows: list[tuple[object, ...]]) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = Path(directory.name) / "alerts.sqlite3"
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute(ALERT_SCHEMA)
            connection.executemany(
                "INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
        return database

    def test_legacy_schema_is_adapted_without_writes(self) -> None:
        database = self.create_database([
            alert_values("a1", "2026-08-01T01:00:00Z", "2026-08-01T01:01:00Z", 2),
        ])

        result = REPOSITORY.load_alert_repository(database)

        self.assertEqual(len(result.rows), 1)
        self.assertIsNone(result.rows[0]["source_port"])
        self.assertEqual(result.rows[0]["total_seen_count"], 2)
        with closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 1)

    def test_rows_group_without_rotating_source_port_and_keep_newest_representative(self) -> None:
        database = self.create_database([
            alert_values("old", "2026-08-01T01:00:00Z", "2026-08-01T01:05:00Z", 2),
            alert_values("new", "2026-08-01T01:06:00Z", "2026-08-01T01:10:00Z", 3),
        ])

        row = REPOSITORY.load_alert_repository(database).rows[0]

        self.assertEqual(row["alert_id"], "new")
        self.assertEqual(row["raw_alert_count"], 2)
        self.assertEqual(row["total_seen_count"], 5)
        self.assertEqual(row["member_alert_ids"], ["new", "old"])
        self.assertEqual(row["first_seen"], "2026-08-01T01:00:00Z")
        self.assertEqual(row["last_seen"], "2026-08-01T01:10:00Z")
        self.assertEqual(row["member_timeline"][0]["destination_port"], "443")

    def test_enrichment_is_carried_forward_from_an_older_group_member(self) -> None:
        enrichment = '{"external_intel":{"records":[{"source":"test"}]}}'
        database = self.create_database([
            alert_values(
                "old", "2026-08-01T01:00:00Z", "2026-08-01T01:05:00Z", 1,
                enrichment_json=enrichment,
            ),
            alert_values("new", "2026-08-01T01:06:00Z", "2026-08-01T01:10:00Z", 1),
        ])

        row = REPOSITORY.load_alert_repository(database).rows[0]

        self.assertEqual(row["enrichment_json"], enrichment)

    def test_suppression_keys_keep_otherwise_identical_alerts_separate(self) -> None:
        database = self.create_database([
            alert_values("a1", "2026-08-01T01:00:00Z", "2026-08-01T01:01:00Z", 1, suppression_key="one"),
            alert_values("a2", "2026-08-01T01:02:00Z", "2026-08-01T01:03:00Z", 1, suppression_key="two"),
        ])

        result = REPOSITORY.load_alert_repository(database)

        self.assertEqual({row["alert_group_key"] for row in result.rows}, {"one", "two"})

    def test_module_is_bounded_read_only_and_deployed_once(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 240)
        for forbidden in ("import subprocess", "INSERT INTO", "UPDATE alerts", "DELETE FROM", "CREATE TABLE", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_repository.py"), 2)


if __name__ == "__main__":
    unittest.main()
