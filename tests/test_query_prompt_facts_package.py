from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import prompt_facts


class QueryPromptFactsPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = prompt_facts.Policy(maximum_result_count=10_000)

    def test_canonical_bytes_and_bounded_facts_preserve_complete_semantics(self) -> None:
        self.assertEqual(
            prompt_facts.canonical_bytes({"b": 2, "a": 1}),
            b'{"a":1,"b":2}',
        )
        self.assertEqual(prompt_facts.bounded("  complete fact  "), "complete fact")
        self.assertEqual(prompt_facts.bounded("abcdef", maximum_bytes=5), "")
        self.assertEqual(
            prompt_facts.bounded({"a": 1}, maximum_bytes=7),
            '{"a":1}',
        )

    def test_counts_require_exact_bounded_non_boolean_integers(self) -> None:
        for invalid in (True, False, 1.0, "1", -1, 10_001):
            with self.subTest(invalid=invalid):
                self.assertIsNone(
                    prompt_facts.canonical_count(invalid, policy=self.policy)
                )
        self.assertEqual(prompt_facts.canonical_count(0, policy=self.policy), 0)
        self.assertEqual(
            prompt_facts.canonical_count(10_000, policy=self.policy), 10_000
        )

    def test_most_specific_present_invalid_count_blocks_outer_fallback(self) -> None:
        containers = ({"returned_hits": "7"}, {"returned_hits": 99})
        self.assertIsNone(
            prompt_facts.provenance_count(
                containers, ("returned_hits",), policy=self.policy
            )
        )
        self.assertEqual(
            prompt_facts.provenance_count(
                ({}, {"returned_hits": 99}),
                ("returned_hits",),
                policy=self.policy,
            ),
            99,
        )

    def test_query_semantics_requires_concrete_bounded_intent(self) -> None:
        self.assertEqual(
            prompt_facts.query_semantics(({"backend": "elastic", "pack": "dns"},)),
            "",
        )
        semantics = prompt_facts.query_semantics(
            (
                {
                    "backend": "elastic",
                    "pack": "zeek_dns",
                    "purpose": "Correlate the destination domain",
                    "observables": {"domains": ["example.test"]},
                },
            )
        )
        self.assertIn("Correlate the destination domain", semantics)
        self.assertIn("example.test", semantics)
        self.assertEqual(
            prompt_facts.query_semantics(
                ({"purpose": "x" * 181}, {"purpose": "short fallback"})
            ),
            "",
        )

    def test_result_summary_retains_exact_interpretive_facts(self) -> None:
        summary = prompt_facts.result_summary(
            (
                {
                    "total_hits": 50,
                    "semantic_valid": True,
                    "truncated": False,
                },
            ),
            status="success",
            returned=3,
            policy=self.policy,
        )
        self.assertIn('"returned":3', summary)
        self.assertIn('"total":50', summary)
        self.assertIn('"semantic_valid":true', summary)
        self.assertEqual(
            prompt_facts.result_summary(
                ({},), status="success", returned=None, policy=self.policy
            ),
            "",
        )
        self.assertEqual(
            prompt_facts.result_summary(
                ({"evidence_summary": "collector-confirmed empty result"},),
                status="success",
                returned=0,
                policy=self.policy,
            ),
            "collector-confirmed empty result",
        )


if __name__ == "__main__":
    unittest.main()
