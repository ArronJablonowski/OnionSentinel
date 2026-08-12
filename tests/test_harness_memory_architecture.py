from __future__ import annotations

import dataclasses
import importlib
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

MEMORY = importlib.import_module("harness_memory")


class HarnessMemoryArchitectureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = MEMORY.HarnessPolicy.disabled_default()
        self.role = "soc-analyst"
        self.valid = {
            "confidence": "high",
            "confidence_score": 0.91,
            "_automation_controls": {
                "memory_writeback_blocked": False,
            },
            "_evidence_reference_validation": {
                "invalid_refs": [],
                "corroborating_source_classes": [
                    "suricata_alert",
                    "zeek_conn",
                ],
            },
            "_second_opinion": {
                "status": "completed",
                "comparison": {
                    "agreement": "agreement",
                    "material_disagreement": False,
                },
            },
        }

    def decide(self, response=None, **kwargs):
        return MEMORY.memory_promotion_decision(
            kwargs.pop("policy", self.policy),
            self.valid if response is None else response,
            role=kwargs.pop("role", self.role),
            has_shared_candidates=kwargs.pop("has_shared_candidates", False),
            human_approved=kwargs.pop("human_approved", False),
            **kwargs,
        )

    def test_stable_surface_signature_and_return_type(self) -> None:
        self.assertEqual(
            str(inspect.signature(MEMORY.memory_promotion_decision)),
            "(policy: 'HarnessPolicy', response: 'Mapping[str, Any]', *, role: 'str', has_shared_candidates: 'bool', human_approved: 'bool' = False) -> 'PolicyDecision'",
        )
        self.assertFalse(
            {"HarnessPolicy", "PolicyDecision", "bounded_metadata", "memory_promotion_decision"}
            .difference(vars(MEMORY))
        )
        self.assertIsInstance(self.decide(), MEMORY.PolicyDecision)

    def test_guardrail_has_first_refusal_precedence_and_exact_reason(self) -> None:
        response = {
            **self.valid,
            "confidence": "low",
            "_automation_controls": {
                "memory_writeback_blocked": True,
                "reason": "prompt injection guardrail",
            },
            "_evidence_reference_validation": {
                "invalid_refs": ["missing:1"],
                "corroborating_source_classes": [],
            },
            "_second_opinion": {"status": "not-run"},
        }
        self.assertEqual(
            self.decide(response),
            MEMORY.PolicyDecision(
                False,
                "memory.promote",
                "prompt injection guardrail",
            ),
        )
        response["_automation_controls"] = {"memory_writeback_blocked": True}
        self.assertEqual(
            self.decide(response).reason,
            "automation guardrail blocked memory",
        )

    def test_provenance_refusal_order_and_source_normalization_are_stable(self) -> None:
        invalid = {
            **self.valid,
            "_evidence_reference_validation": {
                "invalid_refs": ["bad"],
                "corroborating_source_classes": ["suricata_alert", "zeek_conn"],
            },
        }
        self.assertEqual(
            self.decide(invalid).reason,
            "memory candidate depends on unresolved evidence references",
        )
        for sources in (
            [],
            ["suricata_alert"],
            ["suricata_alert", "suricata_alert", ""],
            "suricata_alert,zeek_conn",
            None,
        ):
            with self.subTest(sources=sources):
                response = {
                    **self.valid,
                    "_evidence_reference_validation": {
                        "invalid_refs": [],
                        "corroborating_source_classes": sources,
                    },
                }
                self.assertEqual(
                    self.decide(response).reason,
                    "fewer than two corroborating evidence source classes",
                )

    def test_confidence_threshold_and_review_contract_are_stable(self) -> None:
        for confidence, score in (
            ("medium", 1.0),
            ("HIGH", 0.79),
            ("high", None),
            ("high", "invalid"),
        ):
            with self.subTest(confidence=confidence, score=score):
                response = {
                    **self.valid,
                    "confidence": confidence,
                    "confidence_score": score,
                }
                self.assertEqual(
                    self.decide(response).reason,
                    "analysis confidence is below the memory promotion threshold",
                )
        for review in (
            {},
            {"status": "not-run"},
            {"status": "completed", "comparison": {}},
            {
                "status": "completed",
                "comparison": {
                    "agreement": "agreement",
                    "material_disagreement": True,
                },
            },
        ):
            with self.subTest(review=review):
                response = {**self.valid, "_second_opinion": review}
                self.assertEqual(
                    self.decide(response).reason,
                    "independent reviewer did not fully corroborate the analysis",
                )
        no_review_policy = dataclasses.replace(
            self.policy,
            memory_require_independent_agreement=False,
        )
        response = {**self.valid, "_second_opinion": {"status": "not-run"}}
        self.assertEqual(
            self.decide(response, policy=no_review_policy).reason,
            "explicit human approval is required",
        )

    def test_shared_approval_and_role_authorization_results_are_exact(self) -> None:
        self.assertEqual(
            self.decide(has_shared_candidates=True),
            MEMORY.PolicyDecision(
                False,
                "memory.promote",
                "shared memory requires explicit human approval",
                requires_approval=True,
            ),
        )
        self.assertEqual(
            self.decide(has_shared_candidates=True, human_approved=True),
            MEMORY.PolicyDecision(
                True,
                "memory.promote",
                "authorized by exact role capability",
                requires_approval=True,
            ),
        )
        self.assertEqual(
            self.decide(role="unknown", human_approved=True),
            MEMORY.PolicyDecision(
                False,
                "memory.promote",
                "unknown agent role",
                requires_approval=True,
            ),
        )
        no_shared_approval = dataclasses.replace(
            self.policy,
            shared_memory_requires_human_approval=False,
        )
        self.assertEqual(
            self.decide(
                policy=no_shared_approval,
                has_shared_candidates=True,
            ).reason,
            "explicit human approval is required",
        )


if __name__ == "__main__":
    unittest.main()
