from __future__ import annotations

import ast
import datetime as dt
import importlib
import inspect
import math
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
CONFIG_PATH = DASHBOARD / "ac_hunter_config.py"


def load_module(name: str):
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module(name)


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(CONFIG_PATH.read_text(encoding="utf-8"))
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
    return target.end_lineno - target.lineno + 1, complexity


class ObservableValue:
    def __init__(self, truthy: bool, text: str, trace: list[str]) -> None:
        self.truthy = truthy
        self.text = text
        self.trace = trace

    def __bool__(self) -> bool:
        self.trace.append("bool")
        return self.truthy

    def __str__(self) -> str:
        self.trace.append("str")
        return self.text


class AcHunterTimestampArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_module("ac_hunter_config")
        cls.scoring = load_module("ac_hunter_scoring")
        cls.service = load_module("ac_hunter_service")

    def test_signature_current_debt_and_compatibility_exports_are_exact(self) -> None:
        signature = inspect.signature(self.config._parse_timestamp)
        self.assertEqual(list(signature.parameters), ["value"])
        self.assertEqual(str(signature.return_annotation), "Optional[float]")
        self.assertEqual(function_metrics("_parse_timestamp"), (20, 11))
        self.assertIs(self.scoring._parse_timestamp, self.config._parse_timestamp)
        self.assertIs(self.service._parse_timestamp, self.config._parse_timestamp)
        self.assertLessEqual(len(CONFIG_PATH.read_text().splitlines()), 600)

    def test_boolean_numeric_millisecond_and_boundary_policy_is_exact(self) -> None:
        cases = [
            (None, None),
            (False, None),
            (True, None),
            (0, None),
            (-1, None),
            (1, 1.0),
            (1.5, 1.5),
            (10_000_000_000, 10_000_000_000.0),
            (10_000_000_001, 10_000_000.001),
            (1_000_000_000_000, 1_000_000_000.0),
            (99_999_999_999_999, 99_999_999_999.999),
            (100_000_000_000_000, None),
            (float("nan"), None),
            (float("inf"), None),
            (float("-inf"), None),
        ]
        for value, expected in cases:
            with self.subTest(value=repr(value)):
                result = self.config._parse_timestamp(value)
                if expected is None:
                    self.assertIsNone(result)
                else:
                    self.assertIs(type(result), float)
                    self.assertEqual(result, expected)

        with self.assertRaises(OverflowError) as raised:
            self.config._parse_timestamp(10**1000)
        self.assertIsNone(raised.exception.__cause__)

    def test_text_digit_length_iso_timezone_and_offset_policy_is_exact(self) -> None:
        epoch = dt.datetime(
            2026, 8, 12, 16, 22, 33, 123456, tzinfo=dt.timezone.utc
        ).timestamp()
        cases = [
            ("", None),
            ("   ", None),
            ("1", 1.0),
            ("  1000  ", 1000.0),
            ("10000000001", 10_000_000.001),
            ("١٢٣", 123.0),
            ("-1", None),
            ("1.5", None),
            ("x" * 80, None),
            ("x" * 81, None),
            ("2026-08-12", None),
            ("2026-08-12T16:22:33", None),
            ("2026-08-12T16:22:33.123456Z", epoch),
            ("2026-08-12T10:22:33.123456-06:00", epoch),
            ("2026-08-12T16:22:33.123456+00:00", epoch),
            ("not-a-timestamp", None),
        ]
        for value, expected in cases:
            with self.subTest(value=repr(value)):
                result = self.config._parse_timestamp(value)
                if expected is None:
                    self.assertIsNone(result)
                else:
                    self.assertEqual(result, expected)
                    self.assertIs(type(result), float)

        with self.assertRaises(ValueError) as raised:
            self.config._parse_timestamp("²")
        self.assertIsNone(raised.exception.__cause__)

    def test_custom_object_conversion_order_and_input_nonmutation_are_exact(self) -> None:
        trace: list[str] = []
        false_value = ObservableValue(False, "1", trace)
        self.assertIsNone(self.config._parse_timestamp(false_value))
        self.assertEqual(trace, ["bool"])

        trace = []
        true_value = ObservableValue(True, " 42 ", trace)
        self.assertEqual(self.config._parse_timestamp(true_value), 42.0)
        self.assertEqual(trace, ["bool", "str"])

        class RaisingText:
            def __str__(self) -> str:
                raise RuntimeError("synthetic string failure")

        with self.assertRaisesRegex(RuntimeError, "synthetic string failure"):
            self.config._parse_timestamp(RaisingText())

        value = ["2026-08-12T16:22:33Z"]
        before = list(value)
        self.assertIsNone(self.config._parse_timestamp(value))
        self.assertEqual(value, before)

    def test_only_fromisoformat_value_error_is_suppressed(self) -> None:
        events: list[object] = []

        class Parsed:
            tzinfo = dt.timezone.utc

            def timestamp(self) -> float:
                events.append("timestamp")
                raise OverflowError("synthetic timestamp failure")

        class FakeDateTime:
            @classmethod
            def fromisoformat(cls, text: str):
                events.append(["fromisoformat", text])
                if text == "value-error":
                    raise ValueError("suppressed")
                if text == "type-error":
                    raise TypeError("propagated")
                return Parsed()

        with mock.patch.object(self.config.dt, "datetime", FakeDateTime):
            self.assertIsNone(self.config._parse_timestamp("value-error"))
            with self.assertRaisesRegex(TypeError, "propagated") as type_error:
                self.config._parse_timestamp("type-error")
            self.assertIsNone(type_error.exception.__cause__)
            with self.assertRaisesRegex(
                OverflowError, "synthetic timestamp failure"
            ) as timestamp_error:
                self.config._parse_timestamp("2026-01-01Z")
            self.assertIsNone(timestamp_error.exception.__cause__)
        self.assertEqual(
            events,
            [
                ["fromisoformat", "value-error"],
                ["fromisoformat", "type-error"],
                ["fromisoformat", "2026-01-01+00:00"],
                "timestamp",
            ],
        )


if __name__ == "__main__":
    unittest.main()
