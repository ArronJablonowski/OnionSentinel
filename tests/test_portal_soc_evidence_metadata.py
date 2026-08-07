"""Direct contracts for the modular SOC evidence metadata composer."""
from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_evidence_metadata import (  # noqa: E402
    SocEvidenceDependencies,
    compose_soc_evidence_metadata,
)


class SocEvidenceMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.review_calls = 0
        self.incident_calls = 0

    def tearDown(self) -> None:
        self.conn.close()

    def dependencies(self) -> SocEvidenceDependencies:
        def columns(conn: sqlite3.Connection, table: str) -> set[str]:
            return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}

        def apply_review(_conn: sqlite3.Connection, _rows: list,
                         metadata: dict, _group_by_alert: dict) -> None:
            self.review_calls += 1
            for record in metadata.values():
                record["review_applied"] = True

        def apply_incident(_conn: sqlite3.Connection, _rows: list,
                           metadata: dict, _group_by_alert: dict) -> None:
            self.incident_calls += 1
            for record in metadata.values():
                record["incident_applied"] = True

        return SocEvidenceDependencies(
            table_exists=lambda conn, table: bool(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()),
            table_columns=columns,
            dashboard_group_id=lambda key: {"group-a": "dash-a", "group-b": "dash-b"}.get(key, ""),
            outcome_label=lambda value: f"label:{value}",
            incident_defaults=lambda: {"incident_status": "not_escalated"},
            review_defaults=lambda: {"reviewer_status": "not_requested"},
            apply_review=apply_review,
            apply_incident=apply_incident,
        )

    def test_artifact_fallbacks_work_without_database(self) -> None:
        rows = [{"group_key": "group-a", "alert_id": "alert-a"}]

        result = compose_soc_evidence_metadata(
            None,
            rows,
            {"detection_outcome_by_group_id": {"dash-a": "inconclusive"}},
            {"size_by_alert_id": {"alert-a": 128}},
            self.dependencies(),
        )

        self.assertEqual(result["dash-a"]["pcap_size_bytes"], 128)
        self.assertEqual(result["dash-a"]["detection_outcome"], "inconclusive")
        self.assertEqual(result["dash-a"]["detection_outcome_label"], "label:inconclusive")
        self.assertEqual(result["dash-a"]["incident_status"], "not_escalated")
        self.assertEqual(self.review_calls, 0)
        self.assertEqual(self.incident_calls, 0)

    def test_database_pcap_size_deduplicates_artifacts_and_overrides_fallback(self) -> None:
        self.conn.execute(
            "CREATE TABLE pcap_requests (request_id TEXT, alert_id TEXT, group_id TEXT, "
            "group_key TEXT, artifact_path TEXT, artifact_sha256 TEXT, artifact_size_bytes INTEGER)"
        )
        self.conn.executemany(
            "INSERT INTO pcap_requests VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("one", "alert-a", "", "group-a", "/one", "same", 100),
                ("duplicate", "alert-a", "dash-a", "", "/two", "same", 100),
                ("two", "alert-a", "dash-a", "", "/three", "different", 75),
            ],
        )

        result = compose_soc_evidence_metadata(
            self.conn,
            [{"group_key": "group-a", "alert_id": "alert-a"}],
            {},
            {"size_by_group_id": {"dash-a": 999}},
            self.dependencies(),
        )

        self.assertEqual(result["dash-a"]["pcap_size_bytes"], 175)
        self.assertTrue(result["dash-a"]["review_applied"])
        self.assertTrue(result["dash-a"]["incident_applied"])

    def test_latest_soc_outcome_wins_and_incident_responder_is_excluded(self) -> None:
        self.conn.execute(
            "CREATE TABLE ai_analysis_runs (group_id TEXT, alert_id TEXT, agent_role TEXT, "
            "detection_outcome TEXT, generated_at TEXT, created_at TEXT)"
        )
        self.conn.executemany(
            "INSERT INTO ai_analysis_runs VALUES ('dash-a', 'alert-a', ?, ?, ?, ?)",
            [
                ("soc-analyst", "true_positive_suspicious", "2026-08-07T17:00:00Z", ""),
                ("incident-responder", "false_positive_logic_rule", "2026-08-07T18:00:00Z", ""),
            ],
        )

        result = compose_soc_evidence_metadata(
            self.conn,
            [{"group_key": "group-a", "alert_id": "alert-a"}],
            {"detection_outcome_by_group_id": {"dash-a": "inconclusive"}},
            {},
            self.dependencies(),
        )

        self.assertEqual(result["dash-a"]["detection_outcome"], "true_positive_suspicious")
        self.assertEqual(result["dash-a"]["detection_outcome_label"], "label:true_positive_suspicious")
        self.assertEqual(self.review_calls, 1)
        self.assertEqual(self.incident_calls, 1)


if __name__ == "__main__":
    unittest.main()
