"""Direct contracts for reviewer disagreement, projection, and control gates."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import disagreement, gates, projection  # noqa: E402


class ReviewDecisionGatesPackageTests(unittest.TestCase):
    def test_tuning_only_disagreement_preserves_case_disposition(self) -> None:
        primary = {
            "detection_outcome": "informational_no_action",
            "activity_disposition": "benign", "handling": "no_action",
            "confidence": "medium", "confidence_score": 0.68,
            "escalation_needed": False, "bluf": "Benign activity.",
        }
        result = disagreement.apply(primary, {}, {
            "agreement": "material_disagreement",
            "disputed_fields": [{"field": "tuning_recommendation", "material": True}],
        })
        self.assertEqual(result["handling"], "no_action")
        self.assertEqual(result["confidence"], "medium")
        self.assertEqual(result["_material_disagreement_gate"]["scope"], "control_only")

    def test_case_disagreement_fails_closed_and_replaces_actions(self) -> None:
        primary = {
            "handling": "monitor", "confidence_score": 0.9,
            "recommended_next_steps": ["Close and suppress."],
        }
        result = disagreement.apply(primary, {"handling": "investigate"}, {
            "agreement": "material_disagreement",
            "disputed_fields": [{"field": "handling", "material": True}],
        })
        self.assertEqual(result["detection_outcome"], "inconclusive")
        self.assertEqual(result["handling"], "investigate")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertIn("Do not close", " ".join(result["recommended_next_steps"]))

    def test_shadow_projection_never_authorizes_automation(self) -> None:
        primary = {"handling": "monitor", "activity_disposition": "unknown"}
        reviewer = {"handling": "investigate", "activity_disposition": "suspicious"}
        applied = projection.apply(primary, reviewer, {
            "status": "completed", "mode": "shadow", "automation_authorized": False,
            "response": {
                "decision": "reviewer_supported", "resolved_fields": ["handling"],
                "remaining_disagreements": [],
                "_adjudication_contract_validation": {
                    "valid": True, "automation_authorized": False,
                },
            },
        })
        self.assertTrue(applied)
        self.assertEqual(primary["handling"], "investigate")
        self.assertFalse(primary["_analytical_adjudication_projection"]["automation_authorized"])

    def test_unresolved_shadow_adjudication_is_not_projected(self) -> None:
        primary = {"handling": "monitor"}
        applied = projection.apply(primary, {"handling": "investigate"}, {
            "status": "completed", "mode": "shadow", "automation_authorized": False,
            "response": {
                "decision": "reviewer_supported", "remaining_disagreements": ["handling"],
                "_adjudication_contract_validation": {
                    "valid": True, "automation_authorized": False,
                },
            },
        })
        self.assertFalse(applied)
        self.assertEqual(primary["handling"], "monitor")

    def test_required_review_failure_caps_confidence_and_blocks_controls(self) -> None:
        response = gates.required(
            {"handling": "contain", "confidence_score": 0.95,
             "memory_candidates": [{"finding": "unsafe"}]},
            status="review_required_failed", reason="reviewer unavailable",
        )
        self.assertEqual(response["handling"], "investigate")
        self.assertLessEqual(response["confidence_score"], 0.39)
        self.assertEqual(response["memory_candidates"], [])
        self.assertTrue(response["_automation_controls"]["requires_human_review"])

    def test_completed_unapproved_review_preserves_confidence_but_blocks_controls(self) -> None:
        response = gates.completed(
            {"handling": "contain", "confidence": "medium", "confidence_score": 0.66},
            reason="confidence below authorization threshold",
        )
        self.assertEqual(response["final_disposition_status"], "review_completed_not_authorized")
        self.assertEqual(response["handling"], "investigate")
        self.assertEqual(response["confidence_score"], 0.66)
        self.assertTrue(response["_automation_controls"]["automatic_closure_blocked"])


if __name__ == "__main__":
    unittest.main()
