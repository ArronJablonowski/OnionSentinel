from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))

from onion_sentinel.analysis.conclusions import correlation  # noqa: E402


CONFIDENCE = frozenset({"low", "medium", "high"})


class ConclusionCorrelationPackageTests(unittest.TestCase):
    def test_normalizes_groups_and_derives_order_independent_episode(self) -> None:
        first = correlation.normalize({
            "correlation_found": True,
            "confidence": "HIGH",
            "related_groups": [
                {"group_id": " Group-B ", "reason": "same process"},
                "GROUP-A",
            ],
        }, confidence_values=CONFIDENCE)
        second = correlation.normalize({
            "correlation_found": True,
            "episode_id": "untrusted-model-episode",
            "related_groups": ["group-a", "group-b"],
        }, confidence_values=CONFIDENCE)

        self.assertEqual(first["confidence"], "high")
        self.assertEqual(first["episode_id"], second["episode_id"])
        self.assertRegex(first["episode_id"], r"^episode-[a-f0-9]{20}$")
        self.assertEqual(first["episode_basis"], [
            "related_group:group-a",
            "related_group:group-b",
        ])

    def test_correlation_requires_at_least_one_admitted_group(self) -> None:
        value = correlation.normalize({
            "correlation_found": True,
            "related_groups": [None, {}, {"group_id": "  "}],
        }, confidence_values=CONFIDENCE)
        self.assertFalse(value["correlation_found"])
        self.assertEqual(value["related_groups"], [])
        self.assertEqual(value["episode_id"], "")

    def test_bounds_model_controlled_fields_and_repairs_confidence(self) -> None:
        value = correlation.normalize({
            "confidence": "invented",
            "related_groups": [
                {"group_id": f"GROUP-{number}", "reason": "r" * 1200}
                for number in range(25)
            ],
            "shared_evidence": list(range(25)),
            "contradicting_evidence": "single",
            "recommended_pivots": list(range(25)),
            "attack_chain_hypothesis": "h" * 5000,
        }, confidence_values=CONFIDENCE)

        self.assertEqual(value["confidence"], "low")
        self.assertEqual(len(value["related_groups"]), 20)
        self.assertEqual(len(value["related_groups"][0]["reason"]), 1000)
        self.assertEqual(len(value["shared_evidence"]), 20)
        self.assertEqual(value["contradicting_evidence"], ["single"])
        self.assertEqual(len(value["recommended_pivots"]), 20)
        self.assertEqual(len(value["attack_chain_hypothesis"]), 4000)


if __name__ == "__main__":
    unittest.main()
