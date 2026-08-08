from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_adjudication_policy import (  # noqa: E402
    SOC_ANALYST_ADJUDICATION_OUTCOMES,
    adjudication_verdict_contradictions,
    derive_legacy_detection_outcome,
    legacy_verdict_factors,
    normalize_soc_adjudication_payload,
)


class SocAdjudicationPolicyTest(unittest.TestCase):
    def valid_payload(self, **updates):
        payload = {
            "outcome_override": "true_positive_suspicious",
            "confidence": "high",
            "rationale": "Observed behavior matches the detection intent.",
            "reviewer": "analyst",
        }
        payload.update(updates)
        return payload

    def test_every_legacy_factor_mapping_round_trips(self) -> None:
        for outcome in SOC_ANALYST_ADJUDICATION_OUTCOMES:
            factors = legacy_verdict_factors(outcome)
            if outcome == "duplicate":
                factors["duplicate_of"] = "canonical-alert"
            self.assertEqual(
                derive_legacy_detection_outcome(factors), outcome, outcome
            )

    def test_minimal_payload_is_normalized_and_bounded(self) -> None:
        ok, result = normalize_soc_adjudication_payload(
            self.valid_payload(
                rationale="x" * 5000,
                reviewer="r" * 120,
                evidence_gap="g" * 5000,
                next_action="n" * 5000,
                analysis_id="a" * 200,
            ),
            group_id="ABCDEF123456",
        )
        self.assertTrue(ok)
        self.assertEqual(result["group_id"], "abcdef123456")
        self.assertIsNone(result["case_id"])
        self.assertEqual(len(result["rationale"]), 4000)
        self.assertEqual(len(result["reviewer"]), 100)
        self.assertEqual(len(result["evidence_gap"]), 4000)
        self.assertEqual(len(result["next_action"]), 4000)
        self.assertEqual(len(result["analysis_id"]), 160)
        self.assertIsNone(result["event_status"])

    def test_identifiers_and_required_fields_are_validated(self) -> None:
        for group_id, case_id, message in (
            ("bad", "", "Invalid SOC alert group id"),
            ("abcdef123456", "case/escape", "Invalid incident case id"),
        ):
            ok, result = normalize_soc_adjudication_payload(
                self.valid_payload(), group_id=group_id, case_id=case_id
            )
            self.assertFalse(ok)
            self.assertEqual(result["error"], message)
        ok, result = normalize_soc_adjudication_payload(
            self.valid_payload(reviewer=""), group_id="abcdef123456"
        )
        self.assertFalse(ok)
        self.assertIn("required", result["error"])

    def test_factored_enums_and_duplicate_identifier_are_validated(self) -> None:
        for updates, phrase in (
            ({"event_status": "guessed"}, "event status"),
            ({"detection_validity": "maybe"}, "detection validity"),
            ({"activity_disposition": "evil"}, "activity disposition"),
            ({"handling": "delete"}, "handling"),
            ({"duplicate_of": ""}, "non-empty"),
            ({"duplicate_of": 7}, "string identifier"),
        ):
            ok, result = normalize_soc_adjudication_payload(
                self.valid_payload(**updates), group_id="abcdef123456"
            )
            self.assertFalse(ok)
            self.assertIn(phrase, result["error"])

    def test_explicit_contradictions_are_rejected(self) -> None:
        payload = self.valid_payload(
            outcome_override="false_positive_logic_rule",
            event_status="observed",
            detection_validity="logic_error",
            activity_disposition="malicious",
            handling="contain",
        )
        ok, result = normalize_soc_adjudication_payload(
            payload, group_id="abcdef123456"
        )
        self.assertFalse(ok)
        self.assertIn("explicit verdict factors", result["error"])
        self.assertIn("false-positive label", result["error"])

    def test_no_explicit_factors_preserves_legacy_compatibility(self) -> None:
        self.assertEqual(
            adjudication_verdict_contradictions(
                "duplicate",
                {"event_status": None, "duplicate_of": None},
            ),
            [],
        )

    def test_case_resolution_requires_boolean_and_reason(self) -> None:
        ok, result = normalize_soc_adjudication_payload(
            self.valid_payload(resolve_case="yes"),
            group_id="abcdef123456",
            case_id="ir-case-1",
        )
        self.assertFalse(ok)
        self.assertIn("JSON boolean", result["error"])
        ok, result = normalize_soc_adjudication_payload(
            self.valid_payload(resolve_case=True),
            group_id="abcdef123456",
            case_id="ir-case-1",
        )
        self.assertFalse(ok)
        self.assertIn("resolution reason", result["error"])
        ok, result = normalize_soc_adjudication_payload(
            self.valid_payload(
                resolve_case=True,
                case_resolution_reason="Evidence-backed closure.",
            ),
            group_id="abcdef123456",
            case_id="IR-CASE-1",
        )
        self.assertTrue(ok)
        self.assertTrue(result["resolve_case"])
        self.assertEqual(result["case_id"], "ir-case-1")


if __name__ == "__main__":
    unittest.main()
