"""Direct contracts for SOC AI status precedence and reconciliation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_ai_status import (  # noqa: E402
    SocAiStatusPolicy,
    compose_soc_ai_status,
    severity_meets_threshold,
)


class SocAiStatusTests(unittest.TestCase):
    def policy(self, *, prompt: float = 0, analysis: float = 0,
               group_artifact: bool = False) -> SocAiStatusPolicy:
        return SocAiStatusPolicy(
            severity_order=("informational", "low", "medium", "high", "critical"),
            eligible_filter_statuses=frozenset({"accepted", "escalated", "unknown", "suppressed"}),
            test_prefixes=("phase", "internal-test-"),
            latest_prompt_mtime=lambda _alert: prompt,
            latest_analysis_mtime=lambda _alert: analysis,
            static_reports=lambda: {},
            group_has_artifact=lambda _row: group_artifact,
        )

    def test_pending_prompt_precedes_threshold_and_report_state(self) -> None:
        result = compose_soc_ai_status(
            {"alert_id": "alert", "triage_level": "low", "filter_status": "accepted"},
            "group", {"group": {"ai_status_key": "analyzed"}}, None, "critical",
            self.policy(prompt=20, analysis=10),
        )

        self.assertEqual(result["ai_status_key"], "queued")
        self.assertIn("reanalysis prompt package", result["ai_status_detail"])

    def test_existing_artifact_preserves_report_below_current_threshold(self) -> None:
        report = {"ai_status_key": "analyzed", "ai_status_label": "Analyzed", "ai_status_detail": "done"}
        result = compose_soc_ai_status(
            {"alert_id": "alert", "triage_level": "low", "filter_status": "accepted"},
            "group", {"group": report}, {"analysis_group_ids": {"group"}}, "medium",
            self.policy(),
        )

        self.assertEqual(result, report)

    def test_stale_report_states_requeue_eligible_missing_artifact(self) -> None:
        row = {"alert_id": "alert", "triage_level": "high", "filter_status": "accepted"}
        for key in ("analyzed", "skipped"):
            with self.subTest(key=key):
                result = compose_soc_ai_status(
                    row, "group", {"group": {"ai_status_key": key}},
                    {"analysis_group_ids": set()}, "medium", self.policy(),
                )
                self.assertEqual(result["ai_status_key"], "queued")
                self.assertIn("artifact", result["ai_status_detail"])

    def test_skip_reasons_and_default_queue_are_explicit(self) -> None:
        cases = (
            ({"alert_id": "alert", "triage_level": "mystery", "filter_status": "accepted"},
             "informational", "Unrecognized severity"),
            ({"alert_id": "alert", "triage_level": "low", "filter_status": "accepted"},
             "medium", "Below configured Medium"),
            ({"alert_id": "phase-test", "triage_level": "high", "filter_status": "accepted"},
             "medium", "Test/validation alert"),
            ({"alert_id": "alert", "triage_level": "high", "filter_status": "rejected"},
             "medium", "Filter status rejected"),
        )
        for row, threshold, expected in cases:
            with self.subTest(expected=expected):
                result = compose_soc_ai_status(row, "group", {}, {}, threshold, self.policy())
                self.assertEqual(result["ai_status_key"], "not-queued")
                self.assertIn(expected, result["ai_status_detail"])
        queued = compose_soc_ai_status(
            {"alert_id": "alert", "triage_level": "high", "filter_status": "accepted"},
            "group", {}, {}, "medium", self.policy(),
        )
        self.assertEqual(queued["ai_status_key"], "queued")

    def test_severity_threshold_normalization_is_compatible(self) -> None:
        order = self.policy().severity_order
        self.assertTrue(severity_meets_threshold("info", "informational", order))
        self.assertTrue(severity_meets_threshold("high", "medium", order))
        self.assertFalse(severity_meets_threshold("low", "medium", order))
        self.assertFalse(severity_meets_threshold("critical", "disabled", order))
        self.assertFalse(severity_meets_threshold("unknown", "informational", order))


if __name__ == "__main__":
    unittest.main()
