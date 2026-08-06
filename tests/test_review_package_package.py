"""Direct contracts for blind independent-review package construction."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.review import package  # noqa: E402


def build(source: dict, *, hosted: bool = False, hashes: list | None = None) -> dict:
    observed_hashes = hashes if hashes is not None else []

    def safe_copy(value, **kwargs):
        result = copy.deepcopy(value)
        if kwargs.get("hosted"):
            result.pop("hosted_private", None)
        return result

    def attach(value):
        value["evidence_reference_contract"] = {"references": [{"ref": "current:1"}]}

    def evidence_hash(value):
        observed_hashes.append(copy.deepcopy(value))
        return f"hash-{len(observed_hashes)}"

    return package.build(
        source, hosted=hosted, max_queries=4, model_safe_copy=safe_copy,
        attach_evidence_contract=attach, case_id=lambda _value: "case-1",
        observable_catalog=lambda value: value.get("observable_catalog", []),
        taxonomy_catalog=lambda _value: ["zeek.http"],
        artifact_catalog=lambda _value: ["document-id"],
        rule_shorthand_catalog=lambda _value: ["et-test"],
        evidence_hash=evidence_hash,
    )


class ReviewPackagePackageTests(unittest.TestCase):
    def test_blind_package_removes_anchoring_without_mutating_source(self) -> None:
        source = {
            "prior_analyses": [{"outcome": "malicious"}],
            "instructions": {
                "role": "primary analyst",
                "grounding": ["Use current evidence", "Use prior_analyses"],
            },
            "correlated_alert_context": {"candidates": [{
                "prior_analysis": {"outcome": "benign"},
                "correlation_reasons": ["shared IP", "previous correlation record exists"],
            }]},
            "agent_memory": {"role_memory": {"records": [
                {"status": "model-observed", "finding": "claim"},
                {"status": "operator-confirmed", "finding": "confirmed"},
            ]}},
        }
        result = build(source)
        self.assertNotIn("prior_analyses", result)
        self.assertNotIn("role", result["instructions"])
        self.assertEqual(result["instructions"]["grounding"], ["Use current evidence"])
        self.assertNotIn("prior_analysis", result["correlated_alert_context"]["candidates"][0])
        self.assertEqual(result["agent_memory"]["role_memory"]["records"], [
            {"status": "operator-confirmed", "finding": "confirmed"},
        ])
        self.assertIn("prior_analyses", source)

    def test_hosted_transport_boundary_precedes_observable_contract(self) -> None:
        source = {
            "hosted_private": {"ip": "203.0.113.5"},
            "observable_catalog": [{"kind": "ip", "value": "10.0.0.5"}],
        }
        result = build(source, hosted=True)
        self.assertNotIn("hosted_private", result)
        self.assertEqual(
            result["review_contract"]["allowed_observables"],
            [{"kind": "ip", "value": "10.0.0.5"}],
        )
        self.assertEqual(result["second_opinion_review"]["evidence_boundary"], "hosted-redacted")

    def test_supplemental_context_is_bound_by_recomputed_hash(self) -> None:
        hashes: list = []
        result = build({
            "reviewer_supplemental_context": {"initial_review_sha256": "a" * 64},
        }, hashes=hashes)
        self.assertEqual(len(hashes), 2)
        self.assertEqual(result["review_contract"]["evidence_hash"], "hash-2")
        self.assertIn("reviewer_supplemental_reconciliation", hashes[-1])
        self.assertTrue(result["second_opinion_review"]["primary_conclusion_withheld"])


if __name__ == "__main__":
    unittest.main()
