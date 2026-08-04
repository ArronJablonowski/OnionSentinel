#!/usr/bin/env python3
"""Regression checks for independent-review prompt contracts."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "n8n" / "config"
REVIEWER_PROMPTS = tuple(sorted(CONFIG.glob("*_second_opinion_prompt.md")))


class ReviewerPromptContractTests(unittest.TestCase):
    def test_all_role_reviewers_use_the_observable_ledger_contract(self) -> None:
        self.assertEqual(len(REVIEWER_PROMPTS), 5)
        required = (
            "Build `observables_used` after drafting every other response field.",
            "material IPv4 address",
            "For a bare host or user",
            "ordinary prose",
            "Do not copy unused allowed observables.",
            "perform a final observable-ledger consistency pass",
            "`review_contract.allowed_observables`",
        )
        for path in REVIEWER_PROMPTS:
            with self.subTest(path=path.name):
                prompt = path.read_text(encoding="utf-8")
                for phrase in required:
                    self.assertIn(phrase, prompt)

    def test_all_role_reviewers_distinguish_telemetry_labels_from_domains(self) -> None:
        required = (
            "ECS field paths",
            "Elastic index/document identifiers",
            "telemetry labels",
            "`event.dataset`",
            "`event.module`",
            "`data_stream.dataset`",
            "not domains, FQDNs, hosts, or Community IDs",
            "Never add telemetry metadata to `observables_used`.",
        )
        for path in REVIEWER_PROMPTS:
            with self.subTest(path=path.name):
                prompt = path.read_text(encoding="utf-8")
                for phrase in required:
                    self.assertIn(phrase, prompt)

    def test_all_role_reviewers_bind_identity_and_evidence_refs(self) -> None:
        required = (
            "`review_contract.case_id`",
            "`review_contract.evidence_hash`",
            "`review_case_id`",
            "`review_evidence_hash`",
            "`evidence_used`",
            "`evidence_reference_contract`",
        )
        for path in REVIEWER_PROMPTS:
            with self.subTest(path=path.name):
                prompt = path.read_text(encoding="utf-8")
                for phrase in required:
                    self.assertIn(phrase, prompt)

    def test_soc_and_ir_reviewers_allow_only_one_bounded_supplemental_pivot(
        self,
    ) -> None:
        for name in (
            "soc_analyst_second_opinion_prompt.md",
            "incident_responder_second_opinion_prompt.md",
        ):
            with self.subTest(prompt=name):
                prompt = (CONFIG / name).read_text(encoding="utf-8")
                self.assertIn(
                    "second_opinion_review.supplemental_pivot_policy.allowed",
                    prompt,
                )
                self.assertIn("at most one narrow read-only", prompt)
                self.assertIn("authorization envelope", prompt)
                self.assertIn("must not request another pivot", prompt)
                self.assertNotIn(
                    "Do not request additional investigation pivots.",
                    prompt,
                )


if __name__ == "__main__":
    unittest.main()
