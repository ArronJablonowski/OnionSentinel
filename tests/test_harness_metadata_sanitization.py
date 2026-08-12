#!/usr/bin/env python3
"""Characterize bounded, secret-safe harness metadata projection."""
from __future__ import annotations

import ast
import copy
import math
import sys
import unittest
from collections.abc import Mapping, Sequence
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

import harness_contract_metadata as METADATA  # noqa: E402


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse((BIN_DIR / "harness_contract_metadata.py").read_text())
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class StringValue:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return self.value


class MaterializedMapping(Mapping):
    def __init__(self, values: list[tuple[str, object]]) -> None:
        self.values = values
        self.events: list[str] = []

    def __getitem__(self, key: str) -> object:
        raise AssertionError("items() owns mapping traversal")

    def __iter__(self):
        return (key for key, _value in self.values)

    def __len__(self) -> int:
        return len(self.values)

    def items(self):
        self.events.append("items")
        for key, value in self.values:
            self.events.append(f"yield:{key}")
            yield key, value


class MaterializedSequence(Sequence):
    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.events: list[str] = []

    def __getitem__(self, index: int) -> object:
        self.events.append(f"item:{index}")
        return self.values[index]

    def __len__(self) -> int:
        self.events.append("len")
        return len(self.values)


class HarnessMetadataSanitizationCharacterizationTests(unittest.TestCase):
    def test_sanitization_owners_stay_small_and_cohesive(self) -> None:
        for name in (
            "_is_metadata_scalar",
            "_is_metadata_sequence",
            "_sanitize_sequence",
            "sanitize_metadata",
            "_sanitize_mapping",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_scalar_types_and_nonfinite_floats_are_returned_unchanged(self) -> None:
        self.assertIsNone(METADATA.sanitize_metadata(None))
        self.assertIs(METADATA.sanitize_metadata(True), True)
        self.assertEqual(METADATA.sanitize_metadata(0), 0)
        self.assertEqual(METADATA.sanitize_metadata(-7), -7)
        self.assertEqual(METADATA.sanitize_metadata(1.25), 1.25)
        self.assertTrue(math.isnan(METADATA.sanitize_metadata(float("nan"))))
        self.assertEqual(METADATA.sanitize_metadata(float("inf")), float("inf"))

    def test_string_values_are_bounded_and_sensitive_patterns_are_redacted(self) -> None:
        self.assertEqual(METADATA.sanitize_metadata("safe"), "safe")
        self.assertEqual(
            METADATA.sanitize_metadata("x" * (METADATA.MAX_EVENT_STRING + 3)),
            "x" * METADATA.MAX_EVENT_STRING,
        )
        for value in (
            "Bearer abcdefghijklmnop",
            "api_key=abcdefghijklmnop",
            "token: abcdefghijklmnop",
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    METADATA.sanitize_metadata(value),
                    "[redacted-sensitive-value]",
                )

    def test_secret_mapping_keys_redact_children_without_spending_child_budget(self) -> None:
        budget = [3]
        result = METADATA.sanitize_metadata(
            {
                "token": {"deep": "secret"},
                "safe": "visible",
                "password": "hidden",
            },
            item_budget=budget,
        )

        self.assertEqual(
            result,
            {
                "token": "[redacted-sensitive-field]",
                "safe": "visible",
                "password": "[redacted-sensitive-field]",
            },
        )
        self.assertEqual(budget, [1])

    def test_mapping_budget_emits_marker_but_sequence_budget_silently_stops(self) -> None:
        mapping_budget = [3]
        sequence_budget = [3]

        self.assertEqual(
            METADATA.sanitize_metadata(
                {"a": 1, "b": 2, "c": 3},
                item_budget=mapping_budget,
            ),
            {"a": 1, "b": 2, "_truncated": True},
        )
        self.assertEqual(mapping_budget, [0])
        self.assertEqual(
            METADATA.sanitize_metadata(
                [1, 2, 3],
                item_budget=sequence_budget,
            ),
            [1, 2],
        )
        self.assertEqual(sequence_budget, [0])

    def test_depth_is_checked_before_budget_is_consumed(self) -> None:
        budget = [4]
        self.assertEqual(
            METADATA.sanitize_metadata("value", depth=9, item_budget=budget),
            "[truncated]",
        )
        self.assertEqual(budget, [4])
        self.assertEqual(
            METADATA.sanitize_metadata(
                {"a": {"b": 1}},
                depth=8,
                item_budget=budget,
            ),
            {"a": "[truncated]"},
        )
        self.assertEqual(budget, [3])

    def test_zero_budget_short_circuits_every_value_type(self) -> None:
        for value in (None, 1, "x", [1], {"a": 1}, b"x"):
            budget = [0]
            with self.subTest(value=value):
                self.assertEqual(
                    METADATA.sanitize_metadata(value, item_budget=budget),
                    "[truncated]",
                )
                self.assertEqual(budget, [0])

    def test_sequences_are_materialized_before_budgeted_projection(self) -> None:
        sequence = MaterializedSequence([1, 2, 3, 4])
        budget = [2]

        self.assertEqual(
            METADATA.sanitize_metadata(sequence, item_budget=budget),
            [1],
        )
        self.assertEqual(
            sequence.events,
            ["len"] * (2 if sys.version_info < (3, 10) else 1)
            + ["item:0", "item:1", "item:2", "item:3", "item:4"],
        )
        self.assertEqual(budget, [0])

    def test_mapping_items_are_materialized_before_budgeted_projection(self) -> None:
        mapping = MaterializedMapping([("a", 1), ("b", 2), ("c", 3)])
        budget = [2]

        self.assertEqual(
            METADATA.sanitize_metadata(mapping, item_budget=budget),
            {"a": 1, "_truncated": True},
        )
        self.assertEqual(
            mapping.events,
            ["items", "yield:a", "yield:b", "yield:c"],
        )
        self.assertEqual(budget, [0])

    def test_key_projection_preserves_order_and_last_collision_wins(self) -> None:
        prefix = "k" * 128
        result = METADATA.sanitize_metadata(
            {
                prefix + "first": "first",
                "middle": "kept",
                prefix + "second": "second",
            }
        )

        self.assertEqual(list(result), [prefix, "middle"])
        self.assertEqual(result, {prefix: "second", "middle": "kept"})

    def test_key_values_are_redacted_before_sensitive_field_detection(self) -> None:
        result = METADATA.sanitize_metadata(
            {
                "token": "hidden",
                "Bearer abcdefghijklmnop": "child-is-projected",
                None: "empty-key",
            }
        )

        self.assertEqual(
            result,
            {
                "token": "[redacted-sensitive-field]",
                "[redacted-sensitive-value]": "child-is-projected",
                "": "empty-key",
            },
        )

    def test_bytes_and_unsupported_objects_use_redacted_string_fallback(self) -> None:
        self.assertEqual(METADATA.sanitize_metadata(b"abc"), "b'abc'")
        self.assertEqual(
            METADATA.sanitize_metadata(bytearray(b"abc")),
            "bytearray(b'abc')",
        )
        self.assertTrue(
            METADATA.sanitize_metadata(memoryview(b"abc")).startswith("<memory at ")
        )
        self.assertEqual(
            METADATA.sanitize_metadata(StringValue("Bearer abcdefghijklmnop")),
            "[redacted-sensitive-value]",
        )

    def test_tuple_and_range_sequences_project_to_lists(self) -> None:
        self.assertEqual(METADATA.sanitize_metadata((1, "two")), [1, "two"])
        self.assertEqual(METADATA.sanitize_metadata(range(3)), [0, 1, 2])

    def test_malformed_external_budgets_keep_native_failures(self) -> None:
        with self.assertRaises(IndexError):
            METADATA.sanitize_metadata("value", item_budget=[])
        with self.assertRaises(TypeError):
            METADATA.sanitize_metadata("value", item_budget=(2,))
        with self.assertRaises(TypeError):
            METADATA.sanitize_metadata("value", item_budget=["2"])

    def test_recursive_metadata_is_bounded_by_depth(self) -> None:
        value: dict[str, object] = {}
        value["self"] = value

        result = METADATA.sanitize_metadata(value)
        current = result
        for _depth in range(8):
            current = current["self"]
        self.assertEqual(current, {"self": "[truncated]"})

    def test_input_is_not_mutated(self) -> None:
        value = {
            "safe": [1, {"token": "hidden"}],
            "nested": {"value": "ok"},
        }
        before = copy.deepcopy(value)

        METADATA.sanitize_metadata(value)

        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
