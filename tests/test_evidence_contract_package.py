"""Direct contracts for top-level evidence contract composition."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.evidence import contract, references, registry  # noqa: E402


class Harness:
    def __init__(self, *, columnar_claimed=False, authorized=False):
        self.columnar_claimed = columnar_claimed
        self.authorized = authorized
        self.traversed = []

    def registry(self):
        return registry.Registry(50, registry.Dependencies(
            bounded_reference=lambda value: str(value or "")[:256],
            source_class=references.source_class,
            canonical_count=lambda value: value if isinstance(value, int) else None,
        ))

    def traverse(self, value, path, sink):
        self.traversed.append(path)
        if isinstance(value, dict) and value.get("ref"):
            sink.add(value["ref"], source=path[0])

    def columnar(self, value, sink):
        if self.columnar_claimed:
            sink.add("query:" + "a" * 64, source="columnar")
        return self.columnar_claimed

    def authorization(self, _prompt):
        return self.authorized

    def deps(self):
        return contract.Dependencies(
            registry_factory=self.registry, traverse=self.traverse,
            process_columnar=self.columnar,
            has_structured_authorization=self.authorization,
        )


class EvidenceContractPackageTests(unittest.TestCase):
    def test_section_and_alert_references_have_expected_corroboration(self) -> None:
        harness = Harness()
        result = contract.build({
            "alert": {"alert_id": "alert-1"},
            "public_enrichment": {"provider": "failed"},
        }, harness.deps())
        refs = {item["ref"]: item for item in result["references"]}
        self.assertTrue(refs["alert"]["corroborating"])
        self.assertTrue(refs["alert:alert-1"]["corroborating"])
        self.assertFalse(refs["public_enrichment"]["corroborating"])

    def test_authorization_reference_requires_canonical_validator_success(self) -> None:
        prompt = {"authorization_evidence": {"entries": [{
            "evidence_ref": "authorized-activity:sha256:" + "b" * 64,
        }]}}
        denied = contract.build(prompt, Harness(authorized=False).deps())
        allowed = contract.build(prompt, Harness(authorized=True).deps())
        self.assertEqual(denied["references"], [])
        self.assertEqual(len(allowed["references"]), 1)

    def test_columnar_claim_prevents_ordinary_iterative_traversal(self) -> None:
        harness = Harness(columnar_claimed=True)
        contract.build({
            "investigation_query_results": {"ref": "must-not-be-traversed"},
        }, harness.deps())
        self.assertNotIn(("investigation_query_results",), harness.traversed)

    def test_attach_mutates_only_contract_field(self) -> None:
        prompt = {"alert": {"alert_id": "alert-1"}}
        returned = contract.attach(prompt, Harness().deps())
        self.assertIs(returned, prompt)
        self.assertIn("evidence_reference_contract", prompt)


if __name__ == "__main__":
    unittest.main()
