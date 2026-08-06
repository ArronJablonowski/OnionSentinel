"""Direct contracts for evidence-quality confidence calibration."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import confidence  # noqa: E402


def calibrate(response: dict) -> dict:
    label = lambda score: confidence.label(
        score, low_threshold=0.4, high_threshold=0.8,
    )
    return confidence.calibrate(
        response,
        confidence_values={"low", "medium", "high"},
        score_by_label={"low": 0.3, "medium": 0.65, "high": 0.9},
        calibration_version="test-v1",
        critical_keys={"detection_outcome", "summary"},
        consequential_outcomes={"true_positive_authorized_benign"},
        outcome_normalizer=lambda value: str(value),
        label_for_score=label,
    )


class ConclusionConfidencePackageTests(unittest.TestCase):
    def test_multi_source_evidence_preserves_supported_high_score(self) -> None:
        result = calibrate({
            "confidence": "high", "confidence_score": 0.9,
            "_evidence_reference_validation": {
                "corroborating_refs": ["a", "b"],
                "corroborating_source_classes": ["suricata", "zeek"],
                "invalid_refs": [],
            },
        })
        self.assertEqual(result["confidence_score"], 0.9)
        self.assertEqual(result["_confidence_calibration"]["limiters"], [])

    def test_explicit_empty_validated_refs_apply_no_corroboration_cap(self) -> None:
        result = calibrate({
            "confidence": "high", "confidence_score": 0.9,
            "evidence_used": ["unvalidated-model-citation"],
            "_evidence_reference_validation": {
                "corroborating_refs": [], "corroborating_source_classes": [],
            },
        })
        self.assertEqual(result["confidence_score"], 0.69)
        self.assertIn("no_valid_corroborating_evidence", result["_confidence_calibration"]["limiters"])

    def test_invalid_reference_and_material_contradiction_cap_low(self) -> None:
        result = calibrate({
            "confidence": "high", "confidence_score": 0.95,
            "_evidence_reference_validation": {"invalid_refs": ["bad"]},
            "_verdict_validation": {"material_contradiction": True},
        })
        self.assertEqual(result["confidence_score"], 0.39)
        self.assertEqual(result["confidence"], "low")
        self.assertIn("material_verdict_contradiction", result["_confidence_calibration"]["limiters"])

    def test_incident_and_deterministic_caps_preserve_auditable_reasons(self) -> None:
        result = calibrate({
            "confidence": "high", "confidence_score": 0.95,
            "_evidence_reference_validation": {
                "corroborating_refs": ["a", "b"],
                "corroborating_source_classes": ["zeek", "endpoint"],
            },
            "_verdict_validation": {"deterministic_evidence_guard": {
                "confidence_cap": 0.79,
                "confidence_cap_reasons": ["rule_intent_unknown"],
            }},
            "_incident_evidence_completeness": {
                "confidence_cap": 0.69, "limiters": ["timeline_incomplete"],
            },
        })
        self.assertEqual(result["confidence_score"], 0.69)
        self.assertEqual(
            result["_confidence_calibration"]["limiters"],
            ["rule_intent_unknown", "timeline_incomplete"],
        )

    def test_consequential_closure_with_gaps_cannot_remain_high(self) -> None:
        result = calibrate({
            "confidence": "high", "confidence_score": 0.95,
            "detection_outcome": "true_positive_authorized_benign",
            "evidence_gaps": ["endpoint telemetry unavailable"],
            "_evidence_reference_validation": {
                "corroborating_refs": ["a", "b"],
                "corroborating_source_classes": ["zeek", "suricata"],
            },
        })
        self.assertEqual(result["confidence_score"], 0.79)
        self.assertIn("consequential_outcome_with_evidence_gaps", result["_confidence_calibration"]["limiters"])


if __name__ == "__main__":
    unittest.main()
