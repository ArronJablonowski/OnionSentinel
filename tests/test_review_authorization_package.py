"""Direct contracts for reviewer-derived automation authorization."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import authorization  # noqa: E402


def dependencies() -> authorization.Dependencies:
    return authorization.Dependencies(
        confidence_high_threshold=0.8,
        control_tuning_values=frozenset({"suppress", "drop"}),
        consequential_conclusion=lambda response: response.get("handling") == "contain",
    )


class ReviewAuthorizationPackageTests(unittest.TestCase):
    def test_memory_requires_completed_high_confidence_full_agreement(self) -> None:
        eligible, reason = authorization.memory_eligibility({
            "status": "completed",
            "response": {"confidence": "high"},
            "comparison": {"agreement": "agreement", "material_disagreement": False},
        })
        self.assertTrue(eligible)
        self.assertIn("high-confidence", reason)

    def test_material_disagreement_blocks_all_automation(self) -> None:
        result = authorization.automation_authorization(
            {"handling": "contain"},
            {"confidence": "high", "confidence_score": 0.95},
            {"agreement": "disagreement", "material_disagreement": True},
            dependencies(),
        )
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason_code"], "material_disagreement")
        self.assertFalse(result["containment_authorized"])

    def test_control_tuning_always_requires_human_approval(self) -> None:
        result = authorization.automation_authorization(
            {"tuning_recommendation": "needs_more_data", "_tuning_coherence_guard": {
                "requested_tuning": "suppress",
            }},
            {"confidence": "high", "confidence_score": 0.95},
            {"agreement": "agreement", "material_disagreement": False},
            dependencies(),
        )
        self.assertTrue(result["authorized"])
        self.assertTrue(result["automatic_closure_authorized"])
        self.assertFalse(result["tuning_authorized"])
        self.assertTrue(result["control_tuning_requested"])

    def test_low_reviewer_score_blocks_authorization_despite_high_label(self) -> None:
        result = authorization.automation_authorization(
            {}, {"confidence": "high", "confidence_score": 0.79},
            {"agreement": "agreement", "material_disagreement": False},
            dependencies(),
        )
        self.assertFalse(result["authorized"])
        self.assertEqual(
            result["reason_code"], "reviewer_confidence_below_automation_threshold"
        )


if __name__ == "__main__":
    unittest.main()
