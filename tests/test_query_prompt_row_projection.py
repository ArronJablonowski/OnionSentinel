"""Characterize recursive cumulative prompt-row projection."""
from __future__ import annotations

import copy
import unittest

from n8n.onion_sentinel.analysis.query import prompt_compaction


class StringKey:
    def __init__(self, value: str, trace: list[object], *, fail: bool = False) -> None:
        self.value = value
        self.trace = trace
        self.fail = fail

    def __str__(self) -> str:
        self.trace.append(("str", self.value))
        if self.fail:
            raise RuntimeError(f"key conversion failed: {self.value}")
        return self.value


class QueryPromptRowProjectionTests(unittest.TestCase):
    def dependencies(self, trace: list[object]) -> prompt_compaction.Dependencies:
        def category(value: object) -> str:
            trace.append(("category", value))
            return f"category:{value}"

        def digest(value: object) -> str:
            trace.append(("digest", value))
            return f"digest:{value}"

        return prompt_compaction.Dependencies(category, digest)

    def project(
        self,
        value: object,
        state: dict[str, int | bool],
        trace: list[object],
        *,
        maximum_rows: int = 3,
    ) -> object:
        return prompt_compaction.project_rows(
            value,
            state,
            policy=prompt_compaction.Policy(maximum_rows),
            dependencies=self.dependencies(trace),
        )

    def test_nested_lists_are_fresh_and_scalars_retain_identity(self) -> None:
        marker = object()
        source = [marker, [marker], (marker,), None, "value"]
        state = {"rows": 0, "truncated": False}

        projected = self.project(source, state, [])

        self.assertIsInstance(projected, list)
        self.assertIsNot(projected, source)
        self.assertIsNot(projected[1], source[1])
        self.assertIs(projected[0], marker)
        self.assertIs(projected[1][0], marker)
        self.assertIs(projected[2], source[2])
        self.assertEqual(state, {"rows": 0, "truncated": False})

    def test_cumulative_budget_slice_marker_and_key_collision_are_exact(self) -> None:
        trace: list[object] = []
        first_hits = [{"id": 1}, {"id": 2}]
        second_records = [{"id": 3}, {"id": 4}]
        source = {
            StringKey("Hits", trace): first_hits,
            "nested": {"ROWS": [{"id": 9}]},
            StringKey("records", trace): second_records,
            "records_prompt_truncated": "source-value",
        }
        snapshot = copy.deepcopy({
            "first_hits": first_hits,
            "nested": source["nested"],
            "second_records": second_records,
            "marker": source["records_prompt_truncated"],
        })
        state = {"rows": 1, "truncated": False}

        projected = self.project(source, state, trace, maximum_rows=4)

        self.assertEqual(trace, [("str", "Hits"), ("str", "records")])
        self.assertEqual(projected["Hits"], first_hits)
        self.assertEqual(projected["nested"]["ROWS"], [{"id": 9}])
        self.assertEqual(projected["records"], [])
        self.assertEqual(projected["records_prompt_truncated"], "source-value")
        self.assertEqual(state, {"rows": 4, "truncated": True})
        self.assertEqual(first_hits, snapshot["first_hits"])
        self.assertEqual(source["nested"], snapshot["nested"])
        self.assertEqual(second_records, snapshot["second_records"])
        self.assertEqual(
            source["records_prompt_truncated"], snapshot["marker"]
        )
        self.assertIsNot(projected["Hits"], first_hits)

    def test_query_error_redaction_and_dependency_order_are_exact(self) -> None:
        trace: list[object] = []
        state = {"rows": 0, "truncated": False}
        source = {
            "query_id": "q-1",
            "status": "error",
            "backend": "security_onion",
            "error": "raw-error",
            "ERROR": "case-variant-raw-error",
            "error_digest": "untrusted-digest",
            "error_sha256": "untrusted-sha",
            "kept": {"value": 1},
        }

        projected = self.project(source, state, trace)

        self.assertEqual(projected, {
            "query_id": "q-1",
            "status": "error",
            "backend": "security_onion",
            "kept": {"value": 1},
            "error": "category:raw-error",
            "error_sha256": "digest:raw-error",
        })
        self.assertEqual(
            trace, [("category", "raw-error"), ("digest", "raw-error")]
        )

    def test_error_detection_key_conversion_and_state_exceptions_propagate(self) -> None:
        trace: list[object] = []
        state = {"rows": 0, "truncated": False}
        source = {
            "before": {"value": 1},
            StringKey("explode", trace, fail=True): "never-projected",
            "after": "unreached",
        }
        with self.assertRaisesRegex(RuntimeError, "key conversion failed"):
            self.project(source, state, trace)
        self.assertEqual(trace, [("str", "explode")])
        self.assertEqual(state, {"rows": 0, "truncated": False})

        class ExplodingState(dict):
            def __getitem__(self, key: object) -> object:
                if key == "rows":
                    raise LookupError("row state unavailable")
                return super().__getitem__(key)

        with self.assertRaisesRegex(LookupError, "row state unavailable"):
            self.project(
                {"rows": [{"id": 1}]},
                ExplodingState(rows=0, truncated=False),
                [],
            )


if __name__ == "__main__":
    unittest.main()
