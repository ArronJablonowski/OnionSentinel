from __future__ import annotations

import copy
import hashlib
import unittest

from n8n.onion_sentinel.analysis.query import prompt_budget, prompt_facts


class QueryPromptBudgetPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = prompt_budget.Policy(
            maximum_rows=3,
            result_schema="results-v1",
        )

    def dependencies(self, *, fallback=None) -> prompt_budget.Dependencies:
        def project(value, state):
            cloned = copy.deepcopy(value)
            for result in cloned.get("results", []) if isinstance(cloned, dict) else []:
                evidence = result.get("evidence") if isinstance(result, dict) else None
                rows = evidence.get("rows") if isinstance(evidence, dict) else None
                if isinstance(rows, list):
                    remaining = max(0, self.policy.maximum_rows - int(state["rows"]))
                    evidence["rows"] = rows[:remaining]
                    state["rows"] = int(state["rows"]) + len(evidence["rows"])
                    if len(evidence["rows"]) < len(rows):
                        state["truncated"] = True
            return cloned

        def compact(value):
            encoded = prompt_facts.canonical_bytes(value)
            return {
                "prompt_projection": "compacted_due_to_cumulative_byte_budget",
                "audit_bytes": len(encoded),
                "audit_sha256": hashlib.sha256(encoded).hexdigest(),
                "query_id": value.get("query_id", "") if isinstance(value, dict) else "",
            }

        return prompt_budget.Dependencies(
            project_rows=project,
            compact_audit=compact,
            columnar_payload=lambda _rounds, _maximum: fallback,
        )

    def rounds(self) -> list[dict]:
        return [{
            "round": 1,
            "requests": [{"purpose": "r" * 1200}],
            "audit": [{"broker": "a" * 1200}],
            "results": [{
                "query_id": "query-1",
                "trusted_query_audit": [{
                    "query_id": "query-1",
                    "query_dsl": {"payload": "q" * 1800},
                }],
                "evidence": {
                    "query_digest": "a" * 64,
                    "result_digest": "b" * 64,
                    "evidence_ref": "query:" + ("a" * 64) + ":" + ("b" * 64),
                    "rows": [{"value": "e" * 800} for _ in range(5)],
                },
            }],
        }]

    def test_invalid_budgets_fail_closed(self) -> None:
        for invalid in (True, False, 0, -1, 1.5, "100"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "positive integer"):
                    prompt_budget.payload(
                        [],
                        maximum_bytes=invalid,
                        policy=self.policy,
                        dependencies=self.dependencies(),
                    )

    def test_rich_payload_preserves_data_and_exact_size_accounting(self) -> None:
        payload = prompt_budget.payload(
            self.rounds(),
            maximum_bytes=20_000,
            policy=self.policy,
            dependencies=self.dependencies(),
        )
        metadata = payload["prompt_projection"]
        self.assertEqual(metadata["rows_included"], 3)
        self.assertTrue(metadata["truncated"])
        self.assertEqual(metadata["trusted_query_audits_compacted"], 0)
        self.assertEqual(metadata["encoded_bytes"], len(prompt_facts.canonical_bytes(payload)))
        self.assertLessEqual(metadata["encoded_bytes"], metadata["max_bytes"])

    def test_tight_budget_compacts_then_omits_with_digest_bindings(self) -> None:
        payload = prompt_budget.payload(
            self.rounds(),
            maximum_bytes=1_400,
            policy=self.policy,
            dependencies=self.dependencies(),
        )
        metadata = payload["prompt_projection"]
        self.assertGreaterEqual(metadata["trusted_query_audits_compacted"], 1)
        self.assertGreaterEqual(metadata["evidence_bodies_omitted"], 1)
        self.assertGreaterEqual(metadata["round_metadata_omitted"], 1)
        result = payload["rounds"][0]["results"][0]
        self.assertEqual(
            result["evidence"]["prompt_projection"],
            "omitted_due_to_cumulative_byte_budget",
        )
        self.assertEqual(len(result["evidence"]["evidence_sha256"]), 64)
        self.assertLessEqual(metadata["encoded_bytes"], 1_400)

    def test_columnar_fallback_is_used_only_when_projection_cannot_fit(self) -> None:
        fallback = {"schema": "columnar-floor", "rounds": [], "prompt_projection": {}}
        payload = prompt_budget.payload(
            self.rounds(),
            maximum_bytes=100,
            policy=self.policy,
            dependencies=self.dependencies(fallback=fallback),
        )
        self.assertIs(payload, fallback)
        with self.assertRaisesRegex(ValueError, "exceeds"):
            prompt_budget.payload(
                self.rounds(),
                maximum_bytes=100,
                policy=self.policy,
                dependencies=self.dependencies(fallback=None),
            )


if __name__ == "__main__":
    unittest.main()
