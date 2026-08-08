"""Behavior contracts for durable LLM history projection and reconciliation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_llm_history import (  # noqa: E402
    compose_llm_activity_snapshot,
    llm_analysis_run_timestamp,
    llm_reviewer_started_at,
    project_adjudication_rows,
    project_database_primary_rows,
    project_second_opinion_rows,
    reconcile_llm_primary_logs,
)


class LlmHistoryTests(unittest.TestCase):
    def test_database_primary_projection_uses_observed_completion_only(self) -> None:
        logs = project_database_primary_rows(
            [
                {
                    "analysis_id": "run-1",
                    "alert_id": "alert-1",
                    "generated_at": "2026-08-07  01:00:00+00:00",
                    "agent_role": "threat-hunter",
                    "model": "gpt-5.6-sol",
                    "model_path": "frontier-codex-cli",
                    "seen_count": "bad",
                }
            ]
        )
        self.assertEqual(logs[0]["started_at"], logs[0]["finished_at"])
        self.assertIsNone(logs[0]["runtime_seconds"])
        self.assertEqual(logs[0]["alert"]["alert_count"], 1)
        self.assertEqual(logs[0]["telemetry_source"], "analysis_run_database")

    def test_reconciliation_prefers_exact_id_then_five_second_legacy_window(self) -> None:
        telemetry = [
            {
                "log_id": "exact",
                "agent_role": "soc-analyst",
                "finished_at": "2026-08-07T01:00:00+00:00",
                "alert": {"primary_alert_id": "alert-1"},
            },
            {
                "log_id": "legacy",
                "agent_role": "incident_responder",
                "finished_at": "2026-08-07T02:00:00+00:00",
                "alert": {"primary_alert_id": "alert-2"},
            },
        ]
        database = [
            {"analysis_id": "exact", "agent_role": "soc-analyst"},
            {
                "analysis_id": "database-legacy",
                "agent_role": "incident-responder",
                "finished_at": "2026-08-07T02:00:04+00:00",
                "alert": {"primary_alert_id": "alert-2"},
            },
            {
                "analysis_id": "distinct",
                "agent_role": "incident-responder",
                "finished_at": "2026-08-07T02:01:00+00:00",
                "alert": {"primary_alert_id": "alert-2"},
            },
        ]
        merged, recovered = reconcile_llm_primary_logs(telemetry, database)
        self.assertEqual(recovered, 1)
        self.assertEqual(len(merged), 3)
        self.assertTrue(merged[0]["database_confirmed"])
        self.assertTrue(merged[1]["database_confirmed"])
        self.assertEqual(merged[1]["analysis_id"], "database-legacy")

    def test_second_opinion_projection_uses_exact_parent_and_own_model_fields(self) -> None:
        parents = [
            {
                "analysis_id": "run-1",
                "alert": {"primary_alert_id": "alert-1", "rule_name": "Detection"},
                "gpu_temperature_celsius_max": 48.5,
            }
        ]
        rows = [
            {
                "analysis_id": "run-1",
                "alert_id": "alert-1",
                "agent_role": "soc-analyst",
                "status": "completed",
                "reviewer_error": "",
                "reviewer_model": "reviewer-model",
                "reviewer_model_path": "frontier-codex-cli",
                "reviewer_outcome": "true_positive_suspicious",
                "agreement": "material_disagreement",
                "material_disagreement": 1,
                "reviewer_runtime_seconds": 45,
                "generated_at": "2026-08-07  01:01:45+00:00",
            }
        ]
        reviewer = project_second_opinion_rows(rows, parents)[0]
        self.assertEqual(reviewer["status"], "success")
        self.assertEqual(reviewer["mode"], "codex-cli")
        self.assertEqual(reviewer["started_at"], "2026-08-07  01:01:00+00:00")
        self.assertEqual(reviewer["alert"]["rule_name"], "Detection")
        self.assertEqual(reviewer["gpu_temperature_celsius_max"], 48.5)
        self.assertIn("material disagreement", reviewer["error"])

    def test_adjudication_projection_derives_mode_and_human_review_detail(self) -> None:
        row = {
            "analysis_id": "run-1",
            "alert_id": "alert-1",
            "status": "completed",
            "mode": "shadow",
            "model_route": "ollama:gemma4:31b",
            "decision": "unresolved",
            "human_adjudication_required": 1,
            "generated_at": "2026-08-07T01:01:00+00:00",
            "adjudicator_runtime_seconds": 30,
        }
        adjudicator = project_adjudication_rows([row], [])[0]
        self.assertEqual(adjudicator["status"], "success")
        self.assertEqual(adjudicator["mode"], "ollama")
        self.assertEqual(adjudicator["model_path"], "ollama")
        self.assertTrue(adjudicator["human_adjudication_required"])
        self.assertIn("Human adjudication required", adjudicator["error"])

    def test_timestamp_helpers_bound_invalid_values_and_runtime(self) -> None:
        self.assertEqual(llm_analysis_run_timestamp("bad"), 0.0)
        self.assertEqual(
            llm_reviewer_started_at("2026-08-07T01:00:30+00:00", 30),
            "2026-08-07  01:00:00+00:00",
        )
        self.assertEqual(llm_reviewer_started_at("bad", 30), "bad")

    def test_snapshot_orders_runs_counts_roles_and_marks_truncation(self) -> None:
        primary = [
            {"log_id": "old", "agent_role": "soc_analyst", "started_at": "2026-08-07T01:00:00+00:00"}
        ]
        reviewers = [
            {"log_id": "new", "agent_role": "soc-analyst", "started_at": "2026-08-07T02:00:00+00:00"}
        ]
        snapshot = compose_llm_activity_snapshot(
            10, 5, primary, 1, 2, reviewers, [], 5
        )
        self.assertEqual([row["log_id"] for row in snapshot["combined"]], ["new", "old"])
        self.assertEqual(snapshot["agent_totals"], {"soc-analyst": 2})
        self.assertEqual(snapshot["database_recovered_total"], 2)
        self.assertTrue(snapshot["history_truncated"])


if __name__ == "__main__":
    unittest.main()
