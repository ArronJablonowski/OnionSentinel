from __future__ import annotations

import sqlite3
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_adjudication_history import (  # noqa: E402
    SocAdjudicationHistorySources,
    read_soc_adjudication_history,
)


class SocAdjudicationHistoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.conn.close()

    def sources(self, *, connect=None):
        @contextmanager
        def connection():
            yield self.conn

        def table_exists(conn, table):
            return conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone() is not None

        def table_columns(conn, table):
            return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}

        return SocAdjudicationHistorySources(
            connect=connect or connection,
            table_exists=table_exists,
            table_columns=table_columns,
            review_defaults=lambda: {"final_review_status": "unreviewed"},
            alert_review_state=lambda conn, group: {
                "source": "alert", "group_id": group
            },
            current_incident_analysis=lambda conn, case: {
                "response_json": "{}", "analysis_id": "analysis-1"
            },
            parse_review_json=lambda value: {},
            incident_review_state=lambda conn, case, analysis, response: {
                "source": "incident", "case_id": case["case_id"]
            },
        )

    def create_history(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE analyst_adjudications (
              adjudication_id TEXT, dashboard_group_id TEXT,
              stable_group_id TEXT, case_id TEXT, analysis_id TEXT,
              outcome_override TEXT, confidence TEXT, rationale TEXT,
              evidence_gap TEXT, next_action TEXT, reviewer TEXT,
              event_status TEXT, detection_validity TEXT,
              activity_disposition TEXT, handling TEXT, duplicate_of TEXT,
              case_resolution_reason TEXT, created_at TEXT
            );
            """
        )

    def insert_history(self, identifier, dashboard, stable, case, created):
        self.conn.execute(
            "INSERT INTO analyst_adjudications VALUES "
            "(?, ?, ?, ?, 'analysis', 'inconclusive', 'low', 'rationale', "
            "'', '', 'analyst', NULL, NULL, NULL, NULL, NULL, '', ?)",
            (identifier, dashboard, stable, case, created),
        )
        self.conn.commit()

    def test_invalid_identifiers_are_rejected(self) -> None:
        self.assertEqual(read_soc_adjudication_history(self.sources(), "bad")[0], 400)
        self.assertEqual(
            read_soc_adjudication_history(
                self.sources(), "abcdef123456", case_id="case/escape"
            )[0],
            400,
        )

    def test_missing_history_table_returns_default_review(self) -> None:
        status, payload = read_soc_adjudication_history(
            self.sources(), "abcdef123456"
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["history"], [])
        self.assertEqual(payload["review"]["final_review_status"], "unreviewed")

    def test_dashboard_history_is_newest_first_and_bounded(self) -> None:
        self.create_history()
        self.insert_history("old", "abcdef123456", "", "", "2026-08-01T00:00:00Z")
        self.insert_history("new", "abcdef123456", "", "", "2026-08-02T00:00:00Z")
        status, payload = read_soc_adjudication_history(
            self.sources(), "abcdef123456", limit=1
        )
        self.assertEqual(status, 200)
        self.assertEqual([row["adjudication_id"] for row in payload["history"]], ["new"])
        self.assertEqual(payload["review"]["source"], "alert")

    def test_alias_resolves_stable_group_history(self) -> None:
        self.create_history()
        self.conn.execute(
            "CREATE TABLE alert_group_alias "
            "(legacy_group_id TEXT, stable_group_id TEXT)"
        )
        self.conn.execute(
            "INSERT INTO alert_group_alias VALUES ('abcdef123456', 'stable-1')"
        )
        self.insert_history("stable", "other", "stable-1", "", "2026-08-02T00:00:00Z")
        _, payload = read_soc_adjudication_history(
            self.sources(), "abcdef123456"
        )
        self.assertEqual(payload["history"][0]["adjudication_id"], "stable")

    def test_summary_representative_resolves_stable_group_history(self) -> None:
        self.create_history()
        self.conn.execute(
            "CREATE TABLE alert_group_summary "
            "(group_id TEXT, representative_alert_id TEXT)"
        )
        self.conn.execute(
            "CREATE TABLE alerts (alert_id TEXT, stable_group_id TEXT)"
        )
        self.conn.execute(
            "INSERT INTO alert_group_summary VALUES ('abcdef123456', 'alert-1')"
        )
        self.conn.execute("INSERT INTO alerts VALUES ('alert-1', 'stable-2')")
        self.insert_history("stable", "other", "stable-2", "", "2026-08-02T00:00:00Z")
        _, payload = read_soc_adjudication_history(
            self.sources(), "abcdef123456"
        )
        self.assertEqual(payload["history"][0]["adjudication_id"], "stable")

    def test_case_history_uses_incident_review_composition(self) -> None:
        self.create_history()
        self.conn.execute(
            "CREATE TABLE incident_response_cases (case_id TEXT, status TEXT)"
        )
        self.conn.execute(
            "INSERT INTO incident_response_cases VALUES ('ir-case-1', 'open')"
        )
        self.insert_history(
            "case", "abcdef123456", "stable", "ir-case-1",
            "2026-08-02T00:00:00Z",
        )
        _, payload = read_soc_adjudication_history(
            self.sources(), "abcdef123456", case_id="ir-case-1"
        )
        self.assertEqual(payload["review"], {
            "source": "incident", "case_id": "ir-case-1"
        })
        self.assertEqual(payload["history"][0]["adjudication_id"], "case")

    def test_connection_failure_is_service_unavailable(self) -> None:
        @contextmanager
        def missing():
            raise FileNotFoundError("missing database")
            yield

        status, payload = read_soc_adjudication_history(
            self.sources(connect=missing), "abcdef123456"
        )
        self.assertEqual(status, 503)
        self.assertIn("missing database", payload["error"])


if __name__ == "__main__":
    unittest.main()
