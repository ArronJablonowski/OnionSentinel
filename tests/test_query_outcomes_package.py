from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import outcomes


class QueryOutcomesPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = outcomes.Policy(
            success_statuses=frozenset(
                {"ok", "success", "completed", "complete", "succeeded"}
            )
        )

    def summary(self, rounds, admitted):
        return outcomes.summary(
            rounds, queries_admitted=admitted, policy=self.policy
        )

    def test_grouped_results_count_each_unique_logical_query(self) -> None:
        result = self.summary(
            [{"results": [{"query_ids": ["a", "a", "b"], "status": "ok"}]}],
            2,
        )
        self.assertEqual(result["successful_queries"], 2)
        self.assertEqual(result["queries_accounted"], 2)
        self.assertEqual(result["evidence_gaps"], [])

    def test_nested_batch_preserves_success_error_and_semantic_partial(self) -> None:
        result = self.summary(
            [{"results": [{
                "query_ids": ["ok", "invalid", "missing"],
                "status": "timeout",
                "evidence": {
                    "controls_valid": True,
                    "results": [
                        {"query_id": "ok", "status": "ok", "semantic_valid": True},
                        {"query_id": "invalid", "status": "ok", "semantic_valid": False},
                        {"query_id": "unknown", "status": "ok"},
                    ],
                },
            }]}],
            3,
        )
        self.assertEqual(result["successful_queries"], 1)
        self.assertEqual(result["partial_queries"], 1)
        self.assertEqual(result["timeout_queries"], 1)
        self.assertEqual(result["unresolved_non_success_attempts"], 2)

    def test_zero_success_and_unreported_queries_are_explicit_gaps(self) -> None:
        zero = self.summary([{"results": [{"status": "rejected"}]}], 1)
        unreported = self.summary([{"results": [{"status": "ok"}]}], 2)
        self.assertTrue(zero["zero_success"])
        self.assertIn("no follow-up query evidence", zero["evidence_gaps"][0])
        self.assertEqual(unreported["unreported_queries"], 1)
        self.assertIn("did not return complete", unreported["evidence_gaps"][0])

    def test_successful_retry_resolves_only_prior_attempts_for_same_id(self) -> None:
        result = self.summary(
            [
                {"results": [{"query_id": "q", "status": "rejected"}]},
                {"results": [{"query_id": "q", "status": "ok"}]},
            ],
            2,
        )
        self.assertEqual(result["resolved_retry_query_ids"], ["q"])
        self.assertEqual(result["resolved_non_success_attempts"], 1)
        self.assertEqual(result["unresolved_non_success_attempts"], 0)
        self.assertEqual(result["evidence_gaps"], [])

    def test_window_adjustment_is_counted_and_never_hidden_by_success(self) -> None:
        result = self.summary(
            [{
                "requests": [{"normalization": {"window_adjustment": {"hours": 24}}}],
                "results": [{"status": "ok"}],
            }],
            1,
        )
        self.assertEqual(result["adjusted_windows"], 1)
        self.assertIn("24-hour limit", result["evidence_gaps"][0])

    def test_append_gaps_is_deduplicated_bounded_and_report_aware(self) -> None:
        response = {
            "evidence_gaps": ["existing"],
            "incident_response_report": {"evidence_gaps": ["new"]},
        }
        outcomes.append_evidence_gaps(response, ["new", "new"])
        self.assertEqual(response["evidence_gaps"], ["existing", "new"])
        self.assertEqual(
            response["incident_response_report"]["evidence_gaps"], ["new"]
        )


if __name__ == "__main__":
    unittest.main()
