"""Direct contracts for Incident Responder evidence completeness scoring."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import incident_completeness  # noqa: E402


def dependencies() -> incident_completeness.Dependencies:
    return incident_completeness.Dependencies(
        is_incident_responder=lambda package: bool(package and package.get("ir")),
        safe_nonnegative_int=lambda value: max(0, int(value or 0)),
        success_statuses=frozenset({"ok", "success"}),
        report_text_fields=frozenset({"executive_bluf", "conclusion"}),
        confidence_high_threshold=0.8,
    )


def complete_package() -> dict:
    return {
        "ir": True,
        "incident_response_evidence": {
            "coverage_note": "complete",
            "security_onion_response": {
                "complete": True,
                "partial": False,
                "semantic_validity": {"controls_valid": True, "semantic_valid": True},
                "results": [{"status": "ok", "semantic_valid": True}],
            },
        },
    }


class ConclusionIncidentCompletenessPackageTests(unittest.TestCase):
    def test_missing_required_collector_evidence_caps_low(self) -> None:
        response = {"_incident_response_report_validation": {"valid": True}}
        result = incident_completeness.apply(response, {"ir": True}, dependencies())
        audit = result["_incident_evidence_completeness"]
        self.assertEqual(audit["confidence_cap"], 0.39)
        self.assertIn("required_incident_evidence_missing", audit["limiters"])

    def test_complete_evidence_has_no_cap(self) -> None:
        response = {"_incident_response_report_validation": {"valid": True}}
        result = incident_completeness.apply(response, complete_package(), dependencies())
        audit = result["_incident_evidence_completeness"]
        self.assertIsNone(audit["confidence_cap"])
        self.assertTrue(audit["complete_for_high_confidence"])

    def test_partial_and_truncated_sources_record_distinct_limiters(self) -> None:
        package = complete_package()
        collector = package["incident_response_evidence"]["security_onion_response"]
        collector["partial"] = True
        collector["results"][0]["truncated"] = True
        package["live_osquery_evidence"] = {
            "complete": False, "results": [{"status": "timeout", "truncated": True}],
        }
        result = incident_completeness.apply({}, package, dependencies())
        audit = result["_incident_evidence_completeness"]
        self.assertEqual(audit["confidence_cap"], 0.69)
        self.assertIn("incident_evidence_partial", audit["limiters"])
        self.assertIn("incident_evidence_query_truncated", audit["limiters"])
        self.assertIn("live_endpoint_osquery_query_failed", audit["limiters"])

    def test_resolved_retry_does_not_preserve_superseded_failure_cap(self) -> None:
        package = complete_package()
        package["investigation_query_results"] = {
            "outcomes": {
                "unresolved_non_success_attempts": 0,
                "resolved_retry_query_ids": ["q1"],
            },
            "rounds": [{"results": [{"query_id": "q1", "status": "timeout"}]}],
        }
        result = incident_completeness.apply({}, package, dependencies())
        self.assertNotIn(
            "investigation_pivot_failed_or_partial",
            result["_incident_evidence_completeness"]["limiters"],
        )


if __name__ == "__main__":
    unittest.main()
