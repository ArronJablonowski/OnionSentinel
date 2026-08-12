from __future__ import annotations

import ast
import copy
import importlib
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
NORMALIZATION_PATH = DASHBOARD / "ac_hunter_normalization.py"


def load_module(name: str):
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module(name)


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(NORMALIZATION_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.IfExp):
            complexity += 1
        elif isinstance(
            node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)
        ):
            complexity += sum(1 + len(item.ifs) for item in node.generators)
    return target.end_lineno - target.lineno + 1, complexity


class TrackingDict(dict):
    def __init__(self, *args, trace: list[object], fail_key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.fail_key = fail_key

    def get(self, key, default=None):
        self.trace.append(["get", key])
        if key == self.fail_key:
            raise RuntimeError("synthetic get failure")
        return super().get(key, default)


class AcHunterRowsArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.normalization = load_module("ac_hunter_normalization")
        cls.scoring = load_module("ac_hunter_scoring")
        cls.collection = load_module("ac_hunter_collection_findings")

    def test_signature_current_debt_and_compatibility_exports_are_exact(self) -> None:
        signature = inspect.signature(self.normalization._rows)
        self.assertEqual(list(signature.parameters), ["value", "names"])
        self.assertEqual(signature.parameters["names"].default, ())
        self.assertEqual(
            str(signature.return_annotation), "List[Dict[str, Any]]"
        )
        self.assertEqual(function_metrics("_rows"), (34, 13))
        self.assertIs(self.scoring._rows, self.normalization._rows)
        self.assertIs(self.collection._rows, self.normalization._rows)
        self.assertLessEqual(
            len(NORMALIZATION_PATH.read_text().splitlines()), 600
        )

    def test_direct_list_is_bounded_filtered_and_preserves_row_identity(self) -> None:
        rows = []
        expected = []
        for index in range(130):
            if index % 3:
                row = {"index": index}
                rows.append(row)
                if index < 100:
                    expected.append(row)
            else:
                rows.append([index])
        before = copy.deepcopy(rows)
        result = self.normalization._rows(rows, ("ignored",))
        self.assertEqual(result, expected)
        self.assertTrue(all(output is source for output, source in zip(result, expected)))
        self.assertEqual(rows, before)

    def test_priority_duplicates_and_list_short_circuit_are_exact(self) -> None:
        trace: list[object] = []
        value = TrackingDict(
            {
                "custom": {"items": [["not-a-row"]]},
                "data": [["not-a-row"]],
                "results": [{"must_not": "be read"}],
            },
            trace=trace,
        )
        before = copy.deepcopy(dict(value))
        self.assertEqual(
            self.normalization._rows(value, ("custom", "data")), []
        )
        self.assertEqual(
            trace,
            [
                ["get", "custom"],
                ["get", "data"],
            ],
        )
        self.assertEqual(dict(value), before)

        trace = []
        duplicate = TrackingDict({"data": None}, trace=trace)
        self.assertEqual(self.normalization._rows(duplicate, ("data",)), [])
        self.assertEqual(
            trace,
            [
                ["get", "data"],
                ["get", "data"],
                ["get", "results"],
                ["get", "items"],
                ["get", "rows"],
                ["get", "records"],
                ["get", "findings"],
                ["get", "hosts"],
            ],
        )

    def test_nested_empty_falls_through_and_nonempty_returns_before_fallback(self) -> None:
        child = {"items": ["not-a-row"]}
        later_row = {"row": 1}
        value = {
            "first": child,
            "results": [later_row],
            "keyed": {"value": 2},
        }
        before = copy.deepcopy(value)
        result = self.normalization._rows(value, ("first",))
        self.assertEqual(result, [later_row])
        self.assertIs(result[0], later_row)
        self.assertEqual(value, before)

        nested_row = {"nested": True}
        nested = {"first": {"rows": [nested_row]}, "results": [{"later": True}]}
        result = self.normalization._rows(nested, ("first",))
        self.assertEqual(result, [nested_row])
        self.assertIs(result[0], nested_row)

    def test_keyed_object_projection_is_bounded_copied_and_ordered(self) -> None:
        value = {}
        original_rows = []
        for index in range(130):
            key = "host-%03d" % index
            if index % 4 == 0:
                value[key] = [index]
                continue
            row = {"value": index}
            if index % 5 == 0:
                row["host"] = "explicit-%03d" % index
            value[key] = row
            if index < 100:
                original_rows.append((key, row))
        before = copy.deepcopy(value)
        result = self.normalization._rows(value)
        self.assertEqual(len(result), len(original_rows))
        for output, (key, source) in zip(result, original_rows):
            self.assertIsNot(output, source)
            expected = dict(source)
            expected.setdefault("host", key)
            self.assertEqual(output, expected)
            self.assertEqual(list(output)[:-1], list(source)[:-1] if "host" in source else list(source))
        self.assertEqual(value, before)

    def test_type_and_get_errors_propagate_without_mutation(self) -> None:
        for value in (None, True, 1, 1.5, "text", (1,), {1, 2}):
            with self.subTest(value=repr(value)):
                self.assertEqual(self.normalization._rows(value), [])

        trace: list[object] = []
        value = TrackingDict(
            {"first": None, "keyed": {"value": 1}},
            trace=trace,
            fail_key="results",
        )
        before = copy.deepcopy(dict(value))
        with self.assertRaisesRegex(RuntimeError, "synthetic get failure") as raised:
            self.normalization._rows(value, ("first",))
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(trace, [["get", "first"], ["get", "data"], ["get", "results"]])
        self.assertEqual(dict(value), before)


if __name__ == "__main__":
    unittest.main()
