"""Direct contracts for deterministic rule-intent conclusion reconciliation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import evidence_guard  # noqa: E402


def dependencies(*, endpoint=False) -> evidence_guard.Dependencies:
    return evidence_guard.Dependencies(
        bounded_text=lambda value, limit: str(value or "")[:limit],
        bounded_text_list=lambda value, **_kwargs: list(value or []),
        normalized_outcome=lambda value: str(value or "").strip().lower(),
        has_trusted_endpoint_evidence=lambda _package: endpoint,
        derive_legacy_outcome=lambda value: f"legacy:{value.get('detection_validity')}",
        control_tuning_values=frozenset({"suppress", "drop"}),
        factored_verdict_keys=frozenset({"detection_validity"}),
    )


def response() -> dict:
    return {
        "detection_outcome": "true_positive_malicious",
        "event_status": "observed",
        "detection_validity": "valid",
        "activity_disposition": "malicious",
        "handling": "contain",
        "duplicate_of": "case-old",
        "escalation_needed": True,
        "tuning_recommendation": "suppress",
        "recommended_tuning_actions": ["suppress rule"],
    }


class ConclusionEvidenceGuardPackageTests(unittest.TestCase):
    def test_mismatch_blocks_controls_and_caps_unsupported_maliciousness(self) -> None:
        result = evidence_guard.apply(
            response(),
            {"detection_validation": {"rule_intent_match": "mismatch", "event_status": "observed"}},
            dependencies(),
        )
        audit = result["_verdict_validation"]["deterministic_evidence_guard"]
        self.assertEqual(result["detection_validity"], "logic_error")
        self.assertEqual(result["activity_disposition"], "unknown")
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["tuning_recommendation"], "needs_more_data")
        self.assertEqual(audit["confidence_cap"], 0.39)
        self.assertTrue(result["_automation_controls"]["containment_blocked"])

    def test_trusted_endpoint_evidence_keeps_standard_mismatch_cap(self) -> None:
        result = evidence_guard.apply(
            response(),
            {"detection_validation": {"rule_intent_match": "mismatch"}},
            dependencies(endpoint=True),
        )
        audit = result["_verdict_validation"]["deterministic_evidence_guard"]
        self.assertEqual(audit["confidence_cap"], 0.79)

    def test_unknown_intent_caps_consequential_conclusion_without_override(self) -> None:
        result = evidence_guard.apply(
            response(),
            {"detection_validation": {"rule_intent_match": "unknown"}},
            dependencies(),
        )
        audit = result["_verdict_validation"]["deterministic_evidence_guard"]
        self.assertEqual(audit["confidence_cap"], 0.79)
        self.assertFalse(audit["override_applied"])

    def test_legacy_true_event_observed_is_positive_only(self) -> None:
        value = response()
        value["detection_outcome"] = "inconclusive"
        value["handling"] = "monitor"
        value["escalation_needed"] = False
        value["tuning_recommendation"] = "needs_more_data"
        result = evidence_guard.apply(
            value,
            {"detection_validation": {"rule_intent_match": "match", "event_observed": True}},
            dependencies(),
        )
        audit = result["_verdict_validation"]["deterministic_evidence_guard"]
        self.assertEqual(audit["event_status"], "observed")
        self.assertIsNone(audit["confidence_cap"])


if __name__ == "__main__":
    unittest.main()
