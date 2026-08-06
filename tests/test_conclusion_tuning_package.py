"""Direct contracts for advisory tuning coherence policy."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import tuning  # noqa: E402


def dependencies(*, authorized=False) -> tuning.Dependencies:
    return tuning.Dependencies(
        bounded_text_list=lambda value, **kwargs: list(value or [])[:kwargs.get("limit", 50)],
        has_authorization_evidence=lambda _package: authorized,
        control_tuning_values=frozenset({"suppress", "drop"}),
    )


class ConclusionTuningPackageTests(unittest.TestCase):
    def test_unsafe_control_tuning_is_downgraded_with_all_blockers(self) -> None:
        response = {
            "tuning_recommendation": "suppress",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "evidence_gaps": ["missing endpoint evidence"],
            "_second_opinion": {"comparison": {"material_disagreement": True}},
        }
        result = tuning.apply(response, {}, dependencies())
        guard = result["_tuning_coherence_guard"]
        self.assertEqual(result["tuning_recommendation"], "needs_more_data")
        self.assertTrue(guard["downgrade_applied"])
        self.assertEqual(set(guard["blocking_reasons"]), {
            "detection_validity_unknown", "activity_disposition_unknown",
            "material_evidence_gaps", "structured_authorization_missing",
            "reviewer_material_disagreement_unresolved",
        })

    def test_coherent_authorized_recommendation_remains_advisory(self) -> None:
        response = {
            "tuning_recommendation": "drop",
            "detection_validity": "valid",
            "activity_disposition": "malicious",
            "evidence_gaps": [],
        }
        result = tuning.apply(response, {}, dependencies(authorized=True))
        self.assertEqual(result["tuning_recommendation"], "drop")
        self.assertFalse(result["_tuning_coherence_guard"]["downgrade_applied"])
        self.assertFalse(result["_automation_controls"]["automatic_tuning_authorized"])
        self.assertTrue(result["_automation_controls"]["tuning_requires_human_approval"])

    def test_previous_requested_control_is_preserved_across_revalidation(self) -> None:
        response = {
            "tuning_recommendation": "needs_more_data",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "_tuning_coherence_guard": {"requested_tuning": "suppress"},
        }
        result = tuning.apply(response, {}, dependencies())
        self.assertEqual(result["_tuning_coherence_guard"]["requested_tuning"], "suppress")

    def test_non_control_recommendation_is_unchanged(self) -> None:
        response = {"tuning_recommendation": "monitor"}
        self.assertIs(tuning.apply(response, {}, dependencies()), response)
        self.assertNotIn("_tuning_coherence_guard", response)


if __name__ == "__main__":
    unittest.main()
