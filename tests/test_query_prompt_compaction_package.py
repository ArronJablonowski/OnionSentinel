from __future__ import annotations

import hashlib
import math
import unittest

from n8n.onion_sentinel.analysis.query import prompt_compaction, prompt_facts


class QueryPromptCompactionPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = prompt_compaction.Policy(maximum_rows=3)
        self.dependencies = prompt_compaction.Dependencies(
            error_category=lambda _value: "request_contract_rejection",
            error_digest=lambda value: hashlib.sha256(str(value).encode()).hexdigest(),
        )

    def test_projection_enforces_one_recursive_row_budget(self) -> None:
        state = {"rows": 0, "truncated": False}
        projected = prompt_compaction.project_rows(
            {
                "results": [
                    {"hits": [{"id": 1}, {"id": 2}]},
                    {"records": [{"id": 3}, {"id": 4}]},
                ]
            },
            state,
            policy=self.policy,
            dependencies=self.dependencies,
        )
        self.assertEqual(state["rows"], 3)
        self.assertTrue(state["truncated"])
        self.assertEqual(len(projected["results"][0]["hits"]), 2)
        self.assertEqual(len(projected["results"][1]["records"]), 1)
        self.assertTrue(projected["results"][1]["records_prompt_truncated"])

    def test_projection_replaces_query_errors_and_removes_untrusted_digests(self) -> None:
        state = {"rows": 0, "truncated": False}
        projected = prompt_compaction.project_rows(
            {
                "query_id": "query-1",
                "backend": "elastic",
                "status": "rejected",
                "error": "raw secret-bearing backend detail",
                "error_digest": "untrusted-model-value",
                "error_sha256": "also-untrusted",
            },
            state,
            policy=self.policy,
            dependencies=self.dependencies,
        )
        self.assertEqual(projected["error"], "request_contract_rejection")
        self.assertEqual(len(projected["error_sha256"]), 64)
        self.assertNotIn("raw secret-bearing backend detail", str(projected))
        self.assertNotIn("untrusted-model-value", str(projected))

    def test_compact_audit_binds_exact_source_and_keeps_finite_provenance(self) -> None:
        audit = {
            "query_id": "query-1",
            "backend": "elastic",
            "purpose": "Correlate trusted telemetry",
            "query_digest": "a" * 64,
            "result_digest": "b" * 64,
            "returned_hits": 0,
            "duration_ms": 12.5,
            "took_ms": math.inf,
            "error": "raw broker error",
            "window": {"start": "start", "end": "end", "extra": "drop"},
            "query_dsl": {"match_all": {}},
        }
        compact = prompt_compaction.compact_audit(
            audit, dependencies=self.dependencies
        )
        source = prompt_facts.canonical_bytes(audit)
        self.assertEqual(compact["audit_bytes"], len(source))
        self.assertEqual(compact["audit_sha256"], hashlib.sha256(source).hexdigest())
        self.assertEqual(compact["returned_hits"], 0)
        self.assertEqual(compact["duration_ms"], 12.5)
        self.assertNotIn("took_ms", compact)
        self.assertNotIn("query_dsl", compact)
        self.assertEqual(compact["error"], "request_contract_rejection")
        self.assertEqual(compact["window"], {"start": "start", "end": "end"})

    def test_non_object_audit_is_digest_bound_by_type(self) -> None:
        compact = prompt_compaction.compact_audit(
            ["unexpected"], dependencies=self.dependencies
        )
        self.assertEqual(compact["audit_type"], "list")
        self.assertEqual(len(compact["audit_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
