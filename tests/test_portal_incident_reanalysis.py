import sqlite3
import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_incident_reanalysis as reanalysis  # noqa: E402


class PortalIncidentReanalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.conn.close()

    def test_run_id_policy_normalizes_and_rejects_untrusted_values(self) -> None:
        self.assertEqual(
            reanalysis.parse_reanalysis_run_id(
                {"run_id": [" IRR-ABC-123 "]}
            ),
            "irr-abc-123",
        )
        self.assertEqual(reanalysis.parse_reanalysis_run_id({}), "")
        with self.assertRaises(reanalysis.IncidentReanalysisQueryError):
            reanalysis.parse_reanalysis_run_id(
                {"run_id": ["irr-valid'; DROP TABLE runs"]}
            )

    def test_missing_schema_has_an_explicit_empty_payload(self) -> None:
        progress = reanalysis.load_reanalysis_progress(self.conn, "")
        payload = reanalysis.compose_reanalysis_progress_payload(progress)
        self.assertFalse(payload["schema_ready"])
        self.assertIsNone(payload["latest_run"])
        self.assertEqual(payload["runs"], [])
        self.assertEqual(payload["cases"], [])

    def test_progress_aggregates_known_statuses_and_selects_requested_run(self) -> None:
        self.conn.executescript("""
        CREATE TABLE incident_reanalysis_runs (
          run_id TEXT PRIMARY KEY, release_id TEXT, scope TEXT, status TEXT,
          requested_by TEXT, reason TEXT, total_count INTEGER,
          created_at TEXT, updated_at TEXT, completed_at TEXT
        );
        CREATE TABLE incident_reanalysis_run_cases (
          run_id TEXT, case_id TEXT, group_id TEXT, dashboard_group_id TEXT,
          representative_alert_id TEXT, status TEXT, skip_reason TEXT,
          latest_error TEXT, queued_at TEXT, started_at TEXT,
          completed_at TEXT, updated_at TEXT
        );
        INSERT INTO incident_reanalysis_runs VALUES
          ('irr-new', 'release-new', 'all', 'running', 'qa', 'new', 3,
           '20', '20', NULL),
          ('irr-old', 'release-old', 'all', 'completed', 'qa', 'old', NULL,
           '10', '10', '11');
        INSERT INTO incident_reanalysis_run_cases VALUES
          ('irr-new', 'case-b', 'group-b', 'dash-b', 'alert-b', 'running',
           NULL, NULL, '20', '20', NULL, '20'),
          ('irr-new', 'case-a', 'group-a', 'dash-a', 'alert-a', 'queued',
           NULL, NULL, '20', NULL, NULL, '20'),
          ('irr-new', 'case-c', 'group-c', 'dash-c', 'alert-c', 'unknown',
           NULL, NULL, '20', NULL, NULL, '20'),
          ('irr-old', 'case-old', 'group-old', 'dash-old', 'alert-old',
           'completed', NULL, NULL, '10', '10', '11', '11');
        """)

        latest = reanalysis.load_reanalysis_progress(self.conn, "")
        self.assertEqual(latest.runs[0]["run_id"], "irr-new")
        self.assertEqual(
            latest.runs[0]["counts"],
            {
                "queued": 1,
                "running": 1,
                "completed": 0,
                "failed": 0,
                "skipped": 0,
            },
        )
        self.assertEqual([case["case_id"] for case in latest.cases], [
            "case-a", "case-b", "case-c"
        ])

        selected = reanalysis.load_reanalysis_progress(self.conn, "irr-old")
        self.assertEqual(len(selected.runs), 1)
        self.assertEqual(selected.runs[0]["total_count"], 0)
        self.assertEqual(selected.cases[0]["case_id"], "case-old")


if __name__ == "__main__":
    unittest.main()
