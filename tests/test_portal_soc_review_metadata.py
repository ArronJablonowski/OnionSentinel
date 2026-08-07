"""Direct contracts for the modular SOC review metadata read model."""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_review_metadata import (  # noqa: E402
    SocReviewDependencies,
    apply_soc_review_metadata,
    review_defaults,
    review_final_status,
    reviewer_automation_authorization,
)


class SocReviewMetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE alerts (alert_id TEXT PRIMARY KEY, stable_group_id TEXT);
            CREATE TABLE alert_group_alias (legacy_group_id TEXT PRIMARY KEY, stable_group_id TEXT);
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT PRIMARY KEY, group_id TEXT, alert_id TEXT, agent_role TEXT,
              generated_at TEXT, created_at TEXT, model TEXT, detection_outcome TEXT,
              confidence TEXT, evidence_hash TEXT, response_json TEXT
            );
            """
        )

    def tearDown(self) -> None:
        self.conn.close()

    def dependencies(self) -> SocReviewDependencies:
        def columns(conn: sqlite3.Connection, table: str) -> set[str]:
            return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}

        return SocReviewDependencies(
            table_exists=lambda conn, table: bool(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()),
            table_columns=columns,
            dashboard_group_id=lambda group_key: "dash" if group_key else "",
            outcome_label=lambda value: f"label:{value}",
            parse_timestamp=lambda value: dt.datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            ),
        )

    def apply(self, metadata: dict[str, dict], rows: list[dict] | None = None) -> None:
        apply_soc_review_metadata(
            self.conn,
            rows or [{"group_key": "group-key", "group_last_seen": "2026-08-07T18:00:00Z"}],
            metadata,
            {"alert-1": "dash"},
            self.dependencies(),
        )

    def insert_analysis(self, analysis_id: str, generated_at: str, response: dict,
                        *, role: str = "soc-analyst") -> None:
        self.conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, 'stable', 'alert-1', ?, ?, ?, 'model', "
            "'true_positive_suspicious', 'high', 'hash', ?)",
            (analysis_id, role, generated_at, generated_at, json.dumps(response)),
        )

    def test_latest_soc_analysis_uses_embedded_reviewer_and_marks_stale_coverage(self) -> None:
        self.conn.execute("INSERT INTO alert_group_alias VALUES ('dash', 'stable')")
        self.insert_analysis("older", "2026-08-07T16:00:00Z", {})
        self.insert_analysis("ir-newer", "2026-08-07T17:30:00Z", {}, role="incident-responder")
        self.insert_analysis("current", "2026-08-07T17:00:00Z", {
            "event_status": "observed",
            "evidence_used": ["alert", "flow"],
            "evidence_gaps": ["endpoint"],
            "_second_opinion": {
                "status": "completed",
                "response": {"detection_outcome": "true_positive_suspicious", "confidence": "high"},
                "comparison": {"agreement": "agreement", "material_disagreement": False},
                "automation_authorization": {"authorized": True, "reason_code": "reviewed"},
            },
        })
        metadata = {"dash": review_defaults()}

        self.apply(metadata)

        review = metadata["dash"]
        self.assertEqual(review["analysis_id"], "current")
        self.assertEqual(review["freshness_status"], "stale")
        self.assertEqual(review["coverage_status"], "gaps")
        self.assertEqual(review["evidence_used_count"], 2)
        self.assertEqual(review["final_review_status"], "model_consensus")
        self.assertTrue(review["automation_authorization"]["authorized"])
        self.assertEqual(review["primary_event_status"], "observed")

    def test_persisted_disagreement_and_latest_human_adjudication_override_effective_result(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT PRIMARY KEY, status TEXT, primary_outcome TEXT,
              primary_confidence TEXT, reviewer_outcome TEXT, reviewer_confidence TEXT,
              agreement TEXT, material_disagreement INTEGER, disputed_fields_json TEXT,
              reviewer_error TEXT, generated_at TEXT
            );
            CREATE TABLE analyst_adjudications (
              adjudication_id TEXT PRIMARY KEY, dashboard_group_id TEXT, stable_group_id TEXT,
              analysis_id TEXT, outcome_override TEXT, confidence TEXT, rationale TEXT,
              evidence_gap TEXT, next_action TEXT, reviewer TEXT, event_status TEXT,
              detection_validity TEXT, activity_disposition TEXT, handling TEXT,
              duplicate_of TEXT, case_resolution_reason TEXT, created_at TEXT
            );
            INSERT INTO alert_group_alias VALUES ('dash', 'stable');
            """
        )
        self.insert_analysis("analysis", "2026-08-07T17:00:00Z", {
            "_second_opinion": {"automation_authorization": {"authorized": False}},
        })
        self.conn.execute(
            "INSERT INTO ai_second_opinion_runs VALUES ("
            "'analysis', 'completed', 'true_positive_suspicious', 'high', "
            "'false_positive_logic_rule', 'high', 'disagree', 1, "
            "'[\"detection_outcome\"]', '', '2026-08-07T17:01:00Z')"
        )
        for adjudication_id, created_at, outcome in (
            ("older", "2026-08-07T17:02:00Z", "inconclusive"),
            ("latest", "2026-08-07T17:03:00Z", "false_positive_logic_rule"),
        ):
            self.conn.execute(
                "INSERT INTO analyst_adjudications VALUES (?, 'wrong-dashboard', 'stable', "
                "'analysis', ?, 'high', 'reviewed', '', '', 'analyst', 'observed', "
                "'logic_error', 'benign', 'no_action', NULL, NULL, ?)",
                (adjudication_id, outcome, created_at),
            )
        metadata = {"dash": review_defaults()}

        self.apply(metadata)

        review = metadata["dash"]
        self.assertEqual(review["final_review_status"], "adjudicated")
        self.assertEqual(review["effective_outcome"], "false_positive_logic_rule")
        self.assertEqual(review["effective_outcome_label"], "label:false_positive_logic_rule")
        self.assertEqual(review["adjudication"]["adjudication_id"], "latest")
        self.assertEqual(review["disputed_fields"], ["detection_outcome"])
        self.assertFalse(review["automation_authorization"]["authorized"])

    def test_missing_analysis_table_and_authorization_fallbacks_are_explicit(self) -> None:
        self.conn.execute("DROP TABLE ai_analysis_runs")
        metadata = {"dash": review_defaults()}

        self.apply(metadata)

        self.assertEqual(metadata["dash"], review_defaults())
        denied = reviewer_automation_authorization({"reviewer_confidence": "medium"})
        allowed = reviewer_automation_authorization({"reviewer_confidence": "high"})
        explicit = reviewer_automation_authorization({
            "reviewer_confidence": "high", "automation_authorization": {"authorized": False},
        })
        self.assertFalse(denied["authorized"])
        self.assertTrue(denied["legacy_confidence_fallback"])
        self.assertTrue(allowed["authorized"])
        self.assertFalse(explicit["authorized"])
        self.assertEqual(review_final_status({"status": "failed"}, False, None), "review_required_failed")


if __name__ == "__main__":
    unittest.main()
