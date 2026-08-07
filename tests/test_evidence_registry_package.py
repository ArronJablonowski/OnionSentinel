"""Direct contracts for the bounded evidence-reference registry."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import registry  # noqa: E402


def canonical_count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def make_registry(maximum=4):
    return registry.Registry(maximum_references=maximum, deps=registry.Dependencies(
        bounded_reference=lambda value: " ".join(str(value or "").split())[:256],
        source_class=lambda value: str(value or "").split(".", 1)[0],
        canonical_count=canonical_count,
    ))


class EvidenceRegistryPackageTests(unittest.TestCase):
    def test_zero_rows_are_non_corroborating_negative_evidence(self) -> None:
        catalog = make_registry()
        catalog.add("query:" + "a" * 64, source="query", returned=0)
        item = catalog.contract()["references"][0]
        self.assertFalse(item["corroborating"])
        self.assertEqual(item["returned"], 0)

    def test_invalid_required_count_is_audited_and_non_corroborating(self) -> None:
        catalog = make_registry()
        catalog.add("query:" + "b" * 64, source="query", returned="many", require_valid_count=True)
        item = catalog.contract()["references"][0]
        self.assertEqual(item["status"], "invalid_result_count")
        self.assertFalse(item["corroborating"])

    def test_stronger_duplicate_reference_upgrades_existing_entry(self) -> None:
        catalog = make_registry()
        catalog.add("alert", source="alert", corroborating=False)
        catalog.add("alert", source="alert", corroborating=True)
        self.assertTrue(catalog.contract()["references"][0]["corroborating"])

    def test_reference_cap_and_sorting_are_deterministic(self) -> None:
        catalog = make_registry(maximum=2)
        catalog.add("z", source="alert")
        catalog.add("a", source="alert")
        catalog.add("m", source="alert")
        self.assertEqual(
            [item["ref"] for item in catalog.contract()["references"]],
            ["a", "z"],
        )


if __name__ == "__main__":
    unittest.main()
