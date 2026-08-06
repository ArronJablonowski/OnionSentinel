"""Direct contracts for second-opinion triggers and independent comparison."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import comparison  # noqa: E402


def trigger(response: dict, prompt: dict | None = None) -> str:
    return comparison.trigger(
        response, prompt, control_tuning_values={"suppress", "drop"},
        consequential_outcomes={"true_positive_authorized_benign"},
    )


def compare(primary: dict, reviewer: dict) -> dict:
    return comparison.compare(
        primary, reviewer, control_tuning_values={"suppress", "drop"},
        non_escalatory_values={"monitor", "no_action"},
        boolean_setting=lambda value: bool(value),
    )


class ReviewComparisonPackageTests(unittest.TestCase):
    def test_explicit_request_has_priority_and_preserves_bounded_reason(self) -> None:
        self.assertEqual(
            trigger({
                "second_opinion_recommended": True,
                "second_opinion_reason": "Review disputed endpoint attribution.",
                "confidence": "low",
            }),
            "Review disputed endpoint attribution.",
        )

    def test_manual_incident_reanalysis_always_requests_independent_review(self) -> None:
        reason = trigger(
            {"confidence": "high"},
            {"manual_reanalysis": True, "agent_role": "incident-responder"},
        )
        self.assertIn("Manual Incident Responder reanalysis", reason)

    def test_guard_override_precedes_generic_low_confidence_reason(self) -> None:
        reason = trigger({
            "confidence": "low",
            "_verdict_validation": {"deterministic_evidence_guard": {
                "rule_intent_match": "mismatch", "override_applied": True,
            }},
        })
        self.assertIn("overrode the model verdict", reason)

    def test_exact_positions_produce_agreement(self) -> None:
        position = {
            "detection_outcome": "inconclusive", "event_status": "observed",
            "detection_validity": "unknown", "activity_disposition": "unknown",
            "handling": "investigate", "duplicate_of": None,
            "confidence": "medium", "confidence_score": 0.65,
            "escalation_needed": False,
        }
        result = compare(position, dict(position))
        self.assertEqual(result["agreement"], "agreement")
        self.assertEqual(result["disputed_fields"], [])

    def test_non_escalatory_handling_difference_is_advisory(self) -> None:
        primary = {
            "detection_outcome": "informational_no_action",
            "activity_disposition": "benign", "handling": "monitor",
            "escalation_needed": False,
        }
        reviewer = {**primary, "handling": "no_action"}
        result = compare(primary, reviewer)
        self.assertEqual(result["agreement"], "partial_disagreement")
        self.assertFalse(result["material_disagreement"])
        self.assertFalse(result["disputed_fields"][0]["material"])

    def test_consequential_disposition_difference_remains_material(self) -> None:
        primary = {
            "detection_outcome": "true_positive_malicious",
            "activity_disposition": "malicious", "handling": "contain",
            "escalation_needed": True,
        }
        reviewer = {
            "detection_outcome": "inconclusive",
            "activity_disposition": "unknown", "handling": "investigate",
            "escalation_needed": False,
        }
        result = compare(primary, reviewer)
        self.assertEqual(result["agreement"], "material_disagreement")
        self.assertTrue(result["material_disagreement"])
        self.assertIn("activity_disposition", {
            item["field"] for item in result["disputed_fields"] if item["material"]
        })


if __name__ == "__main__":
    unittest.main()
