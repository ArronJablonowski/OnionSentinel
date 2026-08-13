"""Characterize exact result-source admission for prompt provenance."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.query import prompt_provenance


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", self.label, key, default))
        return super().get(key, default)


class QueryPromptProvenanceSourceTests(unittest.TestCase):
    def test_evidence_access_count_and_collection_order_are_exact(self) -> None:
        trace: list[object] = []
        evidence = TrackingDict(
            {"results": []}, trace=trace, label="evidence"
        )
        result = TrackingDict(
            {
                "query_id": "q-1",
                "evidence": evidence,
                "trusted_query_audit": [],
            },
            trace=trace,
            label="result",
        )

        resolved = prompt_provenance._result_sources(result)

        self.assertIs(resolved[0], evidence)
        self.assertEqual(resolved[1], [])
        self.assertIs(resolved[2][0], result)
        self.assertEqual(trace, [
            ("get", "result", "evidence", None),
            ("get", "result", "evidence", None),
            ("get", "evidence", "results", []),
            ("get", "result", "trusted_query_audit", []),
            ("get", "result", "query_id", None),
        ])

        trace.clear()
        malformed = TrackingDict(
            {"query_id": "q-1", "evidence": []},
            trace=trace,
            label="malformed",
        )
        resolved = prompt_provenance._result_sources(malformed)
        self.assertEqual(resolved[0], {})
        self.assertEqual(trace[:2], [
            ("get", "malformed", "evidence", None),
            ("get", "malformed", "trusted_query_audit", []),
        ])

    def test_invalid_collections_fail_before_coverage(self) -> None:
        cases = [
            {"query_id": "q-1", "evidence": {"results": [None]}},
            {"query_id": "q-1", "trusted_query_audit": ["audit"]},
            {"query_id": "invalid id", "trusted_query_audit": []},
            {"query_id": "q-1", "query_ids": ["q-1"]},
        ]
        for result in cases:
            with self.subTest(result=result):
                with patch.object(prompt_provenance, "_exact_coverage") as coverage:
                    self.assertIsNone(prompt_provenance._result_sources(result))
                    coverage.assert_not_called()

    def test_trusted_then_nested_coverage_and_source_precedence_are_exact(self) -> None:
        trusted = [{"query_id": "q-1"}]
        nested = [{"query_id": "q-1"}]
        evidence = {"results": nested}
        result = {
            "query_id": "q-1",
            "evidence": evidence,
            "trusted_query_audit": trusted,
        }
        calls: list[object] = []

        def coverage(candidates, declared):
            calls.append((candidates, declared))
            return True

        with patch.object(prompt_provenance, "_exact_coverage", coverage):
            resolved = prompt_provenance._result_sources(result)

        self.assertEqual(calls, [(trusted, ["q-1"]), (nested, ["q-1"])])
        self.assertIs(resolved[0], evidence)
        self.assertIs(resolved[1][0], nested[0])
        self.assertIs(resolved[2][0], trusted[0])

        calls.clear()
        with patch.object(
            prompt_provenance,
            "_exact_coverage",
            side_effect=lambda candidates, declared: calls.append(
                (candidates, declared)
            ) or False,
        ):
            self.assertIsNone(prompt_provenance._result_sources(result))
        self.assertEqual(calls, [(trusted, ["q-1"])])

    def test_grouped_empty_rejection_single_fallback_and_exceptions_are_exact(self) -> None:
        grouped = {
            "query_ids": ["q-1", "q-2"],
            "evidence": {"results": []},
            "trusted_query_audit": [],
        }
        self.assertIsNone(prompt_provenance._result_sources(grouped))

        single = {"query_id": "q-1"}
        snapshot = copy.deepcopy(single)
        evidence, nested, sources = prompt_provenance._result_sources(single)
        self.assertEqual(evidence, {})
        self.assertEqual(nested, [])
        self.assertIs(sources[0], single)
        self.assertEqual(single, snapshot)

        class ExplodingResult(dict):
            def get(self, key: object, default: object = None) -> object:
                if key == "trusted_query_audit":
                    raise RuntimeError("trusted access failed")
                return super().get(key, default)

        with self.assertRaisesRegex(RuntimeError, "trusted access failed"):
            prompt_provenance._result_sources(
                ExplodingResult(query_id="q-1", evidence={"results": []})
            )


if __name__ == "__main__":
    unittest.main()
