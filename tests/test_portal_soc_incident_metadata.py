"""Direct contracts for modular SOC Incident Response routing metadata."""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_incident_metadata import (  # noqa: E402
    SocIncidentDependencies,
    apply_soc_incident_metadata,
    incident_defaults,
)


class SocIncidentMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.conn.close()

    def dependencies(self) -> SocIncidentDependencies:
        return SocIncidentDependencies(
            table_exists=lambda conn, table: bool(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()),
            table_columns=lambda conn, table: {
                str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")
            },
        )

    def create_current_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, stable_group_id TEXT);
            CREATE TABLE alert_group_alias (legacy_group_id TEXT, stable_group_id TEXT);
            CREATE TABLE incident_response_cases (
              case_id TEXT, group_id TEXT, dashboard_group_id TEXT, status TEXT,
              agent_status TEXT, escalated_at TEXT, escalated_by TEXT, reason TEXT,
              updated_at TEXT
            );
            """
        )

    def test_defaults_are_explicit_and_missing_table_is_non_mutating(self) -> None:
        metadata = {"dash": incident_defaults()}

        apply_soc_incident_metadata(self.conn, metadata, {}, self.dependencies())

        self.assertEqual(metadata["dash"], incident_defaults())
        self.assertEqual(metadata["dash"]["incident_status"], "not_escalated")
        self.assertEqual(metadata["dash"]["incident_agent_status"], "not_queued")

    def test_newest_direct_case_wins(self) -> None:
        self.create_current_schema()
        self.conn.executemany(
            "INSERT INTO incident_response_cases VALUES (?, 'stable', 'dash', ?, ?, ?, ?, ?, ?)",
            [
                ("ir-old", "open", "analyzed", "old-time", "auto", "old", "2026-08-07T16:00:00Z"),
                ("ir-new", "investigating", "analyzing", "new-time", "analyst", "new", "2026-08-07T17:00:00Z"),
            ],
        )
        metadata = {"dash": incident_defaults()}

        apply_soc_incident_metadata(self.conn, metadata, {}, self.dependencies())

        self.assertEqual(metadata["dash"]["incident_case_id"], "ir-new")
        self.assertEqual(metadata["dash"]["incident_status"], "investigating")
        self.assertEqual(metadata["dash"]["incident_agent_status"], "analyzing")
        self.assertEqual(metadata["dash"]["incident_reason"], "new")

    def test_stable_identity_matches_alias_and_alert_mapping_with_legacy_defaults(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, stable_group_id TEXT);
            CREATE TABLE alert_group_alias (legacy_group_id TEXT, stable_group_id TEXT);
            CREATE TABLE incident_response_cases (
              case_id TEXT, group_id TEXT, dashboard_group_id TEXT
            );
            INSERT INTO alert_group_alias VALUES ('legacy-a', 'stable-shared');
            INSERT INTO alerts VALUES ('alert-b', 'stable-shared');
            INSERT INTO incident_response_cases VALUES ('ir-stable', 'stable-shared', 'historic-id');
            """
        )
        metadata = {"legacy-a": incident_defaults(), "legacy-b": incident_defaults()}

        apply_soc_incident_metadata(
            self.conn, metadata, {"alert-b": "legacy-b"}, self.dependencies(),
        )

        for group_id in ("legacy-a", "legacy-b"):
            self.assertEqual(metadata[group_id]["incident_case_id"], "ir-stable")
            self.assertEqual(metadata[group_id]["incident_status"], "open")
            self.assertEqual(metadata[group_id]["incident_agent_status"], "queued")


if __name__ == "__main__":
    unittest.main()
