"""Characterize cumulative prompt-budget audit candidate selection."""
from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.query import prompt_budget


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", self.label, key, default))
        return super().get(key, default)


class QueryPromptAuditCandidateTests(unittest.TestCase):
    def dependencies(self, compact) -> prompt_budget.Dependencies:
        return prompt_budget.Dependencies(
            project_rows=lambda value, _state: value,
            compact_audit=compact,
            columnar_payload=lambda _rounds, _maximum: None,
        )

    def test_non_mapping_rounds_and_results_are_skipped_in_order(self) -> None:
        trace: list[object] = []
        round_item = TrackingDict(
            {"results": [None, "result", 7, [], {}]},
            trace=trace,
            label="round",
        )
        compact_calls: list[object] = []

        result = prompt_budget._audit_candidates(
            [None, "round", round_item, 9],
            self.dependencies(lambda audit: compact_calls.append(audit) or {}),
        )

        self.assertEqual(result, [])
        self.assertEqual(trace, [("get", "round", "results", None)])
        self.assertEqual(compact_calls, [])

    def test_traversal_skip_call_order_and_candidate_identities_are_exact(self) -> None:
        trace: list[object] = []
        compacted = TrackingDict(
            {"prompt_projection": "compacted_due_to_cumulative_byte_budget"},
            trace=trace,
            label="already-compacted",
        )
        scalar = "scalar-audit"
        audit = TrackingDict(
            {"query_id": "q-1", "payload": "large"},
            trace=trace,
            label="audit",
        )
        result_item = TrackingDict(
            {"trusted_query_audit": [compacted, scalar, audit]},
            trace=trace,
            label="result",
        )
        round_item = TrackingDict(
            {"results": [result_item]}, trace=trace, label="round"
        )
        scalar_compact = {"compact": "scalar"}
        audit_compact = {"compact": "audit"}

        def compact(value):
            trace.append(("compact", value))
            return scalar_compact if value is scalar else audit_compact

        sizes = {
            id(scalar): 8,
            id(scalar_compact): 3,
            id(audit): 20,
            id(audit_compact): 7,
        }

        def encoded_size(value):
            trace.append(("size", value))
            return sizes[id(value)]

        snapshot = copy.deepcopy([round_item])
        with patch.object(prompt_budget, "_encoded_size", encoded_size):
            candidates = prompt_budget._audit_candidates(
                [round_item], self.dependencies(compact)
            )

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0][0], 5)
        self.assertEqual(candidates[1][0], 13)
        self.assertIs(candidates[0][1], result_item)
        self.assertIs(candidates[1][1], result_item)
        self.assertEqual([item[2] for item in candidates], [1, 2])
        self.assertIs(candidates[0][3], scalar_compact)
        self.assertIs(candidates[1][3], audit_compact)
        self.assertEqual(trace, [
            ("get", "round", "results", None),
            ("get", "result", "trusted_query_audit", None),
            ("get", "already-compacted", "prompt_projection", None),
            ("compact", scalar),
            ("size", scalar),
            ("size", scalar_compact),
            ("get", "audit", "prompt_projection", None),
            ("compact", audit),
            ("size", audit),
            ("size", audit_compact),
        ])
        self.assertEqual([dict(round_item)], snapshot)

    def test_zero_and_negative_savings_are_excluded_without_reordering(self) -> None:
        audits = [{"id": "zero"}, {"id": "negative"}, {"id": "positive"}]
        compacts = [{"compact": item["id"]} for item in audits]

        def compact(value):
            return compacts[audits.index(value)]

        values = {
            id(audits[0]): 5,
            id(compacts[0]): 5,
            id(audits[1]): 4,
            id(compacts[1]): 9,
            id(audits[2]): 11,
            id(compacts[2]): 2,
        }
        with patch.object(
            prompt_budget, "_encoded_size", side_effect=lambda value: values[id(value)]
        ):
            candidates = prompt_budget._audit_candidates(
                [{"results": [{"trusted_query_audit": audits}]}],
                self.dependencies(compact),
            )

        self.assertEqual(candidates, [(9, candidates[0][1], 2, compacts[2])])

    def test_truthiness_iteration_and_dependency_exceptions_propagate(self) -> None:
        marker = RuntimeError("compaction failed")
        with self.assertRaisesRegex(TypeError, "iterable"):
            prompt_budget._audit_candidates(
                [{"results": 7}], self.dependencies(lambda _audit: {})
            )

        later = {"trusted_query_audit": [{"id": "later"}]}
        with self.assertRaisesRegex(RuntimeError, "compaction failed"):
            prompt_budget._audit_candidates(
                [{"results": [
                    {"trusted_query_audit": [{"id": "first"}]}, later
                ]}],
                self.dependencies(lambda _audit: (_ for _ in ()).throw(marker)),
            )

        compact = {"compact": True}
        with patch.object(
            prompt_budget,
            "_encoded_size",
            side_effect=ArithmeticError("original size failed"),
        ):
            with self.assertRaisesRegex(ArithmeticError, "original size failed"):
                prompt_budget._audit_candidates(
                    [{"results": [{"trusted_query_audit": [{"id": "audit"}]}]}],
                    self.dependencies(lambda _audit: compact),
                )


if __name__ == "__main__":
    unittest.main()
