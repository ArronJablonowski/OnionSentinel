"""Direct contracts for collector-owned evidence citation validation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import validation  # noqa: E402


DEPS = validation.Dependencies(
    bounded_reference=lambda value: " ".join(str(value or "").split())[:256]
)


class EvidenceValidationPackageTests(unittest.TestCase):
    def test_invalid_refs_are_removed_and_audited(self) -> None:
        response = {"evidence_used": ["alert:1", "model:invented"]}
        validation.apply(response, {
            "evidence_reference_contract": {"references": [{
                "ref": "alert:1", "corroborating": True,
                "source_class": "security_onion_detection",
            }]}
        }, DEPS)
        self.assertEqual(response["evidence_used"], ["alert:1"])
        audit = response["_evidence_reference_validation"]
        self.assertEqual(audit["invalid_refs"], ["model:invented"])
        self.assertEqual(audit["corroborating_refs"], ["alert:1"])
        self.assertIn("did not resolve", response["evidence_gaps"][0])

    def test_zero_row_reference_remains_citeable_but_not_corroborating(self) -> None:
        response = {"evidence_used": ["query:" + "a" * 64]}
        validation.apply(response, {
            "evidence_reference_contract": {"references": [{
                "ref": "query:" + "a" * 64, "corroborating": False,
                "source_class": "security_onion_investigation_query",
                "returned": 0,
            }]}
        }, DEPS)
        audit = response["_evidence_reference_validation"]
        self.assertEqual(audit["valid_refs"], response["evidence_used"])
        self.assertEqual(audit["corroborating_refs"], [])
        self.assertEqual(audit["non_corroborating_refs"], response["evidence_used"])

    def test_duplicate_citations_and_source_classes_are_deduplicated(self) -> None:
        response = {"evidence_used": ["alert", "alert"]}
        validation.apply(response, {
            "evidence_reference_contract": {"references": [{
                "ref": "alert", "corroborating": True,
                "source_class": "security_onion_detection",
            }]}
        }, DEPS)
        self.assertEqual(response["evidence_used"], ["alert"])
        self.assertEqual(
            response["_evidence_reference_validation"]["corroborating_source_classes"],
            ["security_onion_detection"],
        )


if __name__ == "__main__":
    unittest.main()
