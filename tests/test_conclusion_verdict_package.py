"""Direct contracts for deterministic factored-verdict normalization."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import verdict  # noqa: E402


OUTCOMES = {
    "true_positive_malicious", "true_positive_suspicious",
    "true_positive_authorized_benign", "false_positive_logic_rule",
    "false_positive_data_parser", "false_positive_bad_intel_ioc",
    "false_negative", "duplicate", "informational_no_action", "inconclusive",
}
EVENTS = {"observed", "not_observed", "unknown"}
VALIDITY = {"matched_intent", "logic_error", "parser_error", "intel_error", "not_applicable", "unknown"}
DISPOSITIONS = {"malicious", "suspicious", "authorized_benign", "benign", "unknown"}
HANDLING = {"contain", "escalate", "investigate", "monitor", "no_action"}
KEYS = {"event_status", "detection_validity", "activity_disposition", "handling", "duplicate_of"}


def normalize(response: dict) -> dict:
    return verdict.normalize(
        response, outcome_values=OUTCOMES, event_status_values=EVENTS,
        validity_values=VALIDITY, disposition_values=DISPOSITIONS,
        handling_values=HANDLING, factored_keys=KEYS,
        boolean_setting=lambda value: bool(value),
    )


class ConclusionVerdictPackageTests(unittest.TestCase):
    def test_legacy_alias_derives_authorized_benign_dimensions(self) -> None:
        response = normalize({"detection_outcome": "true-positive-benign"})
        self.assertEqual(response["detection_outcome"], "true_positive_authorized_benign")
        self.assertEqual(response["activity_disposition"], "authorized_benign")
        self.assertEqual(response["handling"], "no_action")
        self.assertEqual(response["_verdict_validation"]["source"], "legacy_derived")

    def test_complete_factored_verdict_is_authoritative_with_warning(self) -> None:
        response = normalize({
            "detection_outcome": "inconclusive",
            "event_status": "observed", "detection_validity": "matched_intent",
            "activity_disposition": "malicious", "handling": "contain",
            "duplicate_of": None,
        })
        audit = response["_verdict_validation"]
        self.assertEqual(response["detection_outcome"], "true_positive_malicious")
        self.assertEqual(audit["source"], "model_factored")
        self.assertEqual(audit["contradictions"], [])
        self.assertIn("factored verdict derives", audit["warnings"][0])

    def test_partial_mismatch_remains_material_contradiction(self) -> None:
        response = normalize({
            "detection_outcome": "true_positive_malicious",
            "handling": "monitor",
        })
        audit = response["_verdict_validation"]
        self.assertTrue(audit["material_contradiction"])
        self.assertTrue(any("malicious activity" in item for item in audit["contradictions"]))

    def test_duplicate_must_identify_canonical_record(self) -> None:
        response = normalize({"detection_outcome": "duplicate"})
        self.assertTrue(response["_verdict_validation"]["material_contradiction"])
        self.assertIn("must identify", response["_verdict_validation"]["contradictions"][0])

    def test_invalid_model_fields_fail_closed_to_inconclusive(self) -> None:
        response = normalize({"detection_outcome": "invented", "event_status": "definitely"})
        self.assertEqual(response["detection_outcome"], "inconclusive")
        self.assertEqual(set(response["_verdict_validation"]["invalid_fields"]), {"detection_outcome", "event_status"})
        self.assertTrue(response["_verdict_validation"]["material_contradiction"])


if __name__ == "__main__":
    unittest.main()
