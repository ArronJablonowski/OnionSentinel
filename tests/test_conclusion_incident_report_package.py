"""Direct contracts for durable Incident Responder report policy."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import incident_report  # noqa: E402


def dependencies() -> incident_report.Dependencies:
    def values(value, **kwargs):
        limit = kwargs.get("limit", 50)
        return [str(item)[:kwargs.get("item_limit", 4000)] for item in (value or [])][:limit]

    return incident_report.Dependencies(
        is_incident_responder=lambda package: bool(package and package.get("ir")),
        bounded_text=lambda value, limit: str(value or "")[:limit],
        bounded_text_list=values,
        normalized_outcome=lambda value: str(value or "inconclusive"),
        outcome_labels={"false_positive_logic_rule": "False Positive - Rule Logic"},
        confidence_values=frozenset({"low", "medium", "high"}),
        confidence_score_by_label={"low": 0.3, "medium": 0.6, "high": 0.9},
        required_fields=frozenset({"executive_bluf", "factual_timeline", "confidence"}),
        text_fields=frozenset({"executive_bluf"}),
        list_fields=frozenset({"factual_timeline"}),
    )


class ConclusionIncidentReportPackageTests(unittest.TestCase):
    def test_shape_reports_missing_and_malformed_fields(self) -> None:
        result = incident_report.validate_shape(
            {"executive_bluf": "", "factual_timeline": "bad"}, dependencies()
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["missing_fields"], ["confidence"])
        self.assertEqual(result["invalid_fields"], ["executive_bluf", "factual_timeline"])

    def test_normalization_orders_timeline_and_bounds_confidence(self) -> None:
        result = incident_report.normalize({
            "confidence": "invalid",
            "factual_timeline": [
                {"timestamp": "2026-01-02T00:00:00Z", "event": "later", "source_pack": "a", "confidence": "high"},
                {"timestamp": "2026-01-01T00:00:00Z", "event": "earlier", "source_pack": "b", "confidence": "medium"},
            ],
        }, dependencies())
        self.assertEqual([item["event"] for item in result["factual_timeline"]], ["earlier", "later"])
        self.assertEqual(result["confidence"], "low")

    def test_rule_mismatch_reconciles_durable_and_compatibility_narrative(self) -> None:
        response = {
            "detection_outcome": "false_positive_logic_rule",
            "event_status": "observed", "detection_validity": "logic_error",
            "activity_disposition": "unknown", "handling": "investigate",
            "confidence": "low", "confidence_score": 0.3,
            "incident_response_report": {"executive_bluf": "malicious", "conclusion": "contain"},
            "_incident_response_report_validation": {"valid": True},
            "_verdict_validation": {"deterministic_evidence_guard": {
                "override_applied": True, "rule_intent_match": "mismatch",
            }},
        }
        result = incident_report.reconcile(response, {"ir": True}, dependencies())
        validation = result["_incident_response_report_validation"]
        self.assertTrue(validation["narrative_reconciled"])
        self.assertEqual(result["bluf"], result["incident_response_report"]["executive_bluf"])
        self.assertIn("rule_intent_match=mismatch", result["likely_meaning"])

    def test_soc_response_is_unchanged(self) -> None:
        response = {"incident_response_report": {}}
        self.assertIs(incident_report.reconcile(response, {}, dependencies()), response)


if __name__ == "__main__":
    unittest.main()
