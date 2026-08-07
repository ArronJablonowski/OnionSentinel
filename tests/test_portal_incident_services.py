import sqlite3
import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_incident_actions as actions  # noqa: E402
import portal_incident_list_service as list_service  # noqa: E402
import portal_incident_read_model as read_model  # noqa: E402
import portal_incident_repository as repository  # noqa: E402


class PortalIncidentActionTests(unittest.TestCase):
    def test_status_payload_is_normalized_and_bounded(self) -> None:
        payload = actions.normalize_incident_status_payload(
            "case-1",
            {
                "status": " RESOLVED ",
                "resolution_reason": " done " + ("x" * 3000),
                "updated_by": " analyst " + ("y" * 200),
            },
        )
        self.assertEqual(payload["status"], "resolved")
        self.assertEqual(len(payload["resolution_reason"]), 2000)
        self.assertEqual(len(payload["updated_by"]), 100)
        self.assertEqual(payload["case_id"], "case-1")

    def test_reviewer_alias_and_dashboard_default_are_preserved(self) -> None:
        reviewer = actions.normalize_incident_status_payload(
            "case-1", {"status": "open", "reviewer": "qa"}
        )
        defaulted = actions.normalize_incident_status_payload(
            "case-1", {"status": "in_progress"}
        )
        self.assertEqual(reviewer["updated_by"], "qa")
        self.assertEqual(defaulted["updated_by"], "dashboard")

    def test_invalid_status_and_unexplained_resolution_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            actions.IncidentStatusPayloadError, "Invalid incident case status"
        ):
            actions.normalize_incident_status_payload("case-1", {"status": "deleted"})
        with self.assertRaisesRegex(
            actions.IncidentStatusPayloadError, "resolution reason"
        ):
            actions.normalize_incident_status_payload("case-1", {"status": "resolved"})


class PortalIncidentListServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
        CREATE TABLE ai_analysis_runs (
          analysis_id TEXT PRIMARY KEY, group_id TEXT, agent_role TEXT,
          generated_at TEXT, created_at TEXT, model TEXT,
          detection_outcome TEXT, bluf TEXT, summary TEXT, confidence TEXT,
          evidence_hash TEXT, response_json TEXT
        );
        INSERT INTO ai_analysis_runs VALUES (
          'current-ir', 'case-group', 'incident-responder', '20', '20',
          'gpt-current', 'suspicious', 'Current BLUF', 'Current summary',
          'high', 'hash', '{}'
        );
        """)

    def tearDown(self) -> None:
        self.conn.close()

    def callbacks(self):
        return read_model.IncidentRowCallbacks(
            epoch=lambda value: float(value or 0),
            embedded_reviewer=lambda response, analysis: {
                "status": "not_requested",
                "primary_outcome": analysis.get("detection_outcome") or "",
                "primary_confidence": analysis.get("confidence") or "",
                "automation_authorization": {},
            },
            final_review_status=lambda reviewer, material, adjudication: "unreviewed",
            outcome_label=lambda outcome: str(outcome or "Not analyzed"),
            agent_display_state=lambda status, analysis_id, reviewer_status: (
                str(status or "queued"), str(status or "queued")
            ),
            reviewer_authorization=lambda reviewer: {},
            resolve_asset_ip=lambda ip, observed, inventory: {
                "status": "resolved", "ip": ip
            },
        )

    def test_stale_pointer_uses_case_bound_fallback_analysis(self) -> None:
        row = {
            "case_id": "case-1",
            "group_id": "case-group",
            "latest_analysis_id": "wrong-analysis",
            "last_seen": "20",
            "agent_status": "analyzed",
            "source_ip": "10.0.0.1",
            "destination_ip": "10.0.0.2",
            "raw_alert_count": 1,
            "total_seen_count": 1,
        }
        records = repository.IncidentListRecords(
            total=1,
            page=1,
            pages=1,
            rows=[row],
            status_counts={"open": 1},
            agent_status_counts={"analyzed": 1},
            analyses={
                "wrong-analysis": {
                    "analysis_id": "wrong-analysis",
                    "group_id": "other-group",
                    "agent_role": "incident-responder",
                }
            },
            run_columns={"analysis_id", "group_id", "agent_role"},
            second_opinions={},
            adjudications={},
        )
        rows = list_service.compose_incident_list_rows(
            self.conn,
            records,
            {},
            None,
            {},
            self.callbacks(),
        )
        self.assertEqual(rows[0]["analysis_id"], "current-ir")
        self.assertEqual(rows[0]["analysis_model"], "gpt-current")
        self.assertEqual(rows[0]["analysis_bluf"], "Current BLUF")
        self.assertEqual(rows[0]["freshness_status"], "current")


if __name__ == "__main__":
    unittest.main()
