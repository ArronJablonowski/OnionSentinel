from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.query import prompt_facts, prompt_provenance


class QueryPromptProvenancePackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.columns = (
            "round", "query_id", "backend_index", "status_index", "read_only",
            "query_digest", "result_digest", "evidence_ref_or_empty", "returned",
            "semantics_index", "result_summary_index",
        )
        self.policy = prompt_provenance.Policy(
            maximum_queries=12,
            success_statuses=frozenset({"success", "ok"}),
            result_schema="results-v1",
            columnar_schema="columnar-v1",
            columns=self.columns,
            empty_ref_instruction="derive from adjacent digests",
            facts=prompt_facts.Policy(maximum_result_count=(2**63) - 1),
        )
        self.dependencies = prompt_provenance.Dependencies(
            result_bound_reference=lambda query, result: (
                f"query:{query}:{result}" if query and result else "",
                result or query,
            )
        )

    def result(self, query_id: str = "query-1") -> dict:
        query_digest = "a" * 64
        result_digest = "b" * 64
        return {
            "query_id": query_id,
            "backend": "elastic",
            "status": "success",
            "read_only": True,
            "trusted_query_audit": [{
                "query_id": query_id,
                "backend": "elastic",
                "purpose": "Correlate the trusted source and destination",
                "status": "success",
                "query_digest": query_digest,
                "result_digest": result_digest,
                "evidence_ref": f"query:{query_digest}:{result_digest}",
                "returned_hits": 0,
            }],
        }

    def test_query_ids_are_exact_and_unmodified(self) -> None:
        self.assertEqual(prompt_provenance.exact_query_id("query-1:@+="), "query-1:@+=")
        self.assertEqual(prompt_provenance.exact_query_id(" query-1"), "")
        self.assertEqual(prompt_provenance.exact_query_id("query id"), "")
        self.assertEqual(prompt_provenance.exact_query_id(7), "")

    def test_rows_preserve_zero_results_and_mark_invalid_success_partial(self) -> None:
        result = self.result()
        result["trusted_query_audit"][0]["semantic_valid"] = False
        rows = prompt_provenance.rows(
            [{"round": 2, "results": [result]}], policy=self.policy
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "partial")
        self.assertEqual(rows[0]["returned"], 0)
        self.assertTrue(rows[0]["read_only"])
        self.assertIn("Correlate the trusted source", rows[0]["semantics"])

    def test_grouped_results_require_exact_unique_child_coverage(self) -> None:
        first = self.result("query-1")["trusted_query_audit"][0]
        second = dict(first, query_id="query-2", query_digest="c" * 64)
        grouped = {
            "query_ids": ["query-1", "query-2"],
            "backend": "elastic",
            "status": "success",
            "read_only": True,
            "trusted_query_audit": [first],
        }
        self.assertIsNone(
            prompt_provenance.rows(
                [{"round": 1, "results": [grouped]}], policy=self.policy
            )
        )
        grouped["trusted_query_audit"] = [first, second]
        self.assertEqual(
            len(prompt_provenance.rows(
                [{"round": 1, "results": [grouped]}], policy=self.policy
            )),
            2,
        )
        grouped["trusted_query_audit"] = [first, second, second]
        self.assertIsNone(
            prompt_provenance.rows(
                [{"round": 1, "results": [grouped]}], policy=self.policy
            )
        )

    def test_columnar_payload_omits_only_canonical_reconstructable_reference(self) -> None:
        rounds = [{"round": 1, "results": [self.result()]}]
        payload = prompt_provenance.columnar_payload(
            rounds,
            maximum_bytes=4096,
            policy=self.policy,
            dependencies=self.dependencies,
        )
        self.assertIsNotNone(payload)
        columnar = payload["rounds"][0]
        row = dict(zip(columnar["columns"], columnar["rows"][0]))
        self.assertEqual(row["evidence_ref_or_empty"], "")
        self.assertEqual(columnar["omitted_rows"], 0)
        self.assertEqual(columnar["source_provenance_rows"], 1)
        self.assertLessEqual(payload["prompt_projection"]["encoded_bytes"], 4096)
        self.assertIsNone(
            prompt_provenance.columnar_payload(
                rounds,
                maximum_bytes=100,
                policy=self.policy,
                dependencies=self.dependencies,
            )
        )


if __name__ == "__main__":
    unittest.main()
