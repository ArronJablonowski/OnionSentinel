import sqlite3
import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_incident_read_model as read_model  # noqa: E402
import portal_incident_repository as repository  # noqa: E402


CASE_SCHEMA = """
CREATE TABLE incident_response_cases (
  case_id TEXT PRIMARY KEY, group_id TEXT, dashboard_group_id TEXT,
  representative_alert_id TEXT, status TEXT, agent_status TEXT,
  escalated_at TEXT, updated_at TEXT, escalated_by TEXT, reason TEXT,
  latest_analysis_id TEXT, latest_model TEXT, latest_generated_at TEXT,
  latest_error TEXT, resolution_reason TEXT, resolved_at TEXT, resolved_by TEXT
);
"""


class PortalIncidentRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

    def tearDown(self) -> None:
        self.conn.close()

    def request(self, query=None):
        return read_model.parse_incident_list_request(
            query or {}, max_per_page=100
        )

    def test_missing_incident_schema_is_reported_without_querying(self) -> None:
        self.assertFalse(repository.incident_schema_ready(self.conn))

    def test_repository_batches_summary_analysis_review_and_adjudication(self) -> None:
        self.conn.executescript(CASE_SCHEMA + """
        CREATE TABLE alert_group_summary (
          group_id TEXT PRIMARY KEY, rule_name TEXT, severity INTEGER,
          severity_label TEXT, triage_level TEXT, source_ip TEXT,
          destination_ip TEXT, destination_port INTEGER,
          raw_alert_count INTEGER, total_seen_count INTEGER,
          first_seen TEXT, last_seen TEXT
        );
        CREATE TABLE alerts (
          alert_id TEXT PRIMARY KEY, rule_name TEXT, severity INTEGER,
          severity_label TEXT, triage_level TEXT, source_ip TEXT,
          destination_ip TEXT, destination_port INTEGER, seen_count INTEGER,
          first_seen TEXT, last_seen TEXT
        );
        CREATE TABLE ai_analysis_runs (
          analysis_id TEXT PRIMARY KEY, group_id TEXT, agent_role TEXT,
          generated_at TEXT, created_at TEXT, model TEXT,
          detection_outcome TEXT, bluf TEXT, summary TEXT, confidence TEXT,
          evidence_hash TEXT, response_json TEXT
        );
        CREATE TABLE ai_second_opinion_runs (
          analysis_id TEXT, status TEXT, primary_outcome TEXT,
          primary_confidence TEXT, reviewer_outcome TEXT,
          reviewer_confidence TEXT, agreement TEXT,
          material_disagreement INTEGER, disputed_fields_json TEXT,
          generated_at TEXT
        );
        CREATE TABLE analyst_adjudications (
          adjudication_id TEXT, dashboard_group_id TEXT, case_id TEXT,
          analysis_id TEXT, outcome_override TEXT, confidence TEXT,
          rationale TEXT, evidence_gap TEXT, next_action TEXT, reviewer TEXT,
          event_status TEXT, detection_validity TEXT,
          activity_disposition TEXT, handling TEXT, duplicate_of TEXT,
          case_resolution_reason TEXT, created_at TEXT
        );
        INSERT INTO incident_response_cases VALUES (
          'case-open', 'stable-1', 'dashboard-1', 'alert-1', 'open', 'analyzed',
          '1', '2', 'analyst', 'review', 'analysis-1', 'gpt-test', '2', '',
          NULL, NULL, NULL
        );
        INSERT INTO incident_response_cases VALUES (
          'case-resolved', 'stable-2', 'dashboard-2', 'alert-2', 'resolved',
          'analyzed', '1', '3', 'analyst', 'done', NULL, NULL, NULL, '',
          'closed', '3', 'analyst'
        );
        INSERT INTO alert_group_summary VALUES (
          'dashboard-1', 'Summary rule', 4, 'critical', 'critical',
          '10.0.0.1', '10.0.0.2', 443, 5, 8, '1', '2'
        );
        INSERT INTO alerts VALUES (
          'alert-1', 'Fallback rule', 2, 'medium', 'medium',
          '192.0.2.1', '192.0.2.2', 80, 2, '1', '2'
        );
        INSERT INTO ai_analysis_runs VALUES (
          'analysis-1', 'stable-1', 'incident-responder', '2', '2',
          'gpt-test', 'suspicious', 'BLUF', 'Summary', 'high', 'hash', '{}'
        );
        INSERT INTO ai_second_opinion_runs VALUES (
          'analysis-1', 'completed', 'suspicious', 'high', 'suspicious',
          'high', 'agreement', 0, '[]', '2'
        );
        INSERT INTO analyst_adjudications VALUES (
          'old', 'dashboard-1', 'case-open', 'analysis-1', 'benign', 'low',
          '', '', '', '', '', '', '', '', NULL, '', '1'
        );
        INSERT INTO analyst_adjudications VALUES (
          'new', 'dashboard-1', 'case-open', 'analysis-1', 'suspicious', 'high',
          '', '', '', '', '', '', '', '', NULL, '', '2'
        );
        """)

        records = repository.load_incident_list_records(
            self.conn,
            self.request({"status": ["open"], "per_page": ["1"]}),
        )

        self.assertEqual(records.total, 1)
        self.assertEqual(records.status_counts, {"open": 1, "resolved": 1})
        self.assertEqual(records.agent_status_counts, {"analyzed": 2})
        self.assertEqual(dict(records.rows[0])["rule_name"], "Summary rule")
        self.assertEqual(dict(records.rows[0])["total_seen_count"], 8)
        self.assertEqual(records.analyses["analysis-1"]["model"], "gpt-test")
        self.assertIn("agent_role", records.run_columns)
        self.assertEqual(
            records.second_opinions["analysis-1"]["reviewer_error"], ""
        )
        self.assertEqual(
            records.adjudications[("case-open", "analysis-1")]["adjudication_id"],
            "new",
        )
        review_records = repository.load_incident_review_records(
            self.conn,
            {"case_id": "case-open", "dashboard_group_id": "dashboard-1"},
            {"analysis_id": "analysis-1"},
        )
        self.assertEqual(review_records.evidence_updated_at, "2")
        self.assertEqual(review_records.reviewer["status"], "completed")
        self.assertEqual(review_records.reviewer["reviewer_error"], "")
        self.assertEqual(review_records.adjudication["adjudication_id"], "new")

    def test_legacy_case_schema_returns_null_optional_columns(self) -> None:
        self.conn.executescript("""
        CREATE TABLE incident_response_cases (
          case_id TEXT PRIMARY KEY, group_id TEXT, dashboard_group_id TEXT,
          representative_alert_id TEXT, status TEXT, agent_status TEXT,
          escalated_at TEXT, updated_at TEXT, escalated_by TEXT, reason TEXT,
          latest_analysis_id TEXT, latest_model TEXT, latest_generated_at TEXT,
          latest_error TEXT
        );
        INSERT INTO incident_response_cases VALUES (
          'legacy', 'stable', 'dashboard', 'alert', 'open', 'queued',
          '1', '2', 'analyst', 'legacy', NULL, NULL, NULL, NULL
        );
        """)

        records = repository.load_incident_list_records(
            self.conn, self.request()
        )
        row = dict(records.rows[0])
        self.assertEqual(row["case_id"], "legacy")
        self.assertIsNone(row["resolution_reason"])
        self.assertIsNone(row["resolved_at"])
        self.assertIsNone(row["resolved_by"])
        self.assertEqual(records.analyses, {})
        self.assertEqual(records.second_opinions, {})
        self.assertEqual(records.adjudications, {})
        review_records = repository.load_incident_review_records(
            self.conn,
            {"case_id": "legacy", "dashboard_group_id": "missing"},
            {},
        )
        self.assertEqual(review_records.evidence_updated_at, "")
        self.assertEqual(review_records.reviewer, {})
        self.assertIsNone(review_records.adjudication)

    def test_current_analysis_rejects_stale_pointer_and_selects_latest_ir_run(self) -> None:
        self.conn.executescript("""
        CREATE TABLE ai_analysis_runs (
          analysis_id TEXT PRIMARY KEY, group_id TEXT, agent_role TEXT,
          generated_at TEXT, created_at TEXT, model TEXT,
          detection_outcome TEXT, bluf TEXT, summary TEXT, confidence TEXT,
          evidence_hash TEXT, response_json TEXT
        );
        INSERT INTO ai_analysis_runs VALUES (
          'wrong-pointer', 'other-group', 'incident-responder', '99', '99',
          'wrong', '', '', '', '', '', '{}'
        );
        INSERT INTO ai_analysis_runs VALUES (
          'older-ir', 'case-group', 'incident-responder', '10', '10',
          'older', '', '', '', '', '', '{}'
        );
        INSERT INTO ai_analysis_runs VALUES (
          'latest-ir', 'case-group', 'incident-responder', '20', '20',
          'latest', '', '', '', '', '', '{}'
        );
        INSERT INTO ai_analysis_runs VALUES (
          'newer-soc', 'case-group', 'soc-analyst', '30', '30',
          'soc', '', '', '', '', '', '{}'
        );
        """)
        selected = repository.load_current_incident_analysis(
            self.conn,
            {"group_id": "case-group", "latest_analysis_id": "wrong-pointer"},
        )
        self.assertEqual(selected["analysis_id"], "latest-ir")
        self.assertEqual(selected["model"], "latest")

        pointed = repository.load_current_incident_analysis(
            self.conn,
            {"group_id": "case-group", "latest_analysis_id": "older-ir"},
        )
        self.assertEqual(pointed["analysis_id"], "older-ir")

    def test_legacy_analysis_schema_supports_pointer_only_lookup(self) -> None:
        self.conn.executescript("""
        CREATE TABLE ai_analysis_runs (
          analysis_id TEXT PRIMARY KEY, model TEXT, confidence TEXT
        );
        INSERT INTO ai_analysis_runs VALUES ('legacy-analysis', 'legacy-model', 'low');
        """)
        selected = repository.load_current_incident_analysis(
            self.conn, {"latest_analysis_id": "legacy-analysis"}
        )
        self.assertEqual(selected["model"], "legacy-model")
        self.assertEqual(
            repository.load_current_incident_analysis(self.conn, {}), {}
        )


if __name__ == "__main__":
    unittest.main()
