from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

CONTRACT = importlib.import_module("dhcp_asset_contract")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse((BIN / "dhcp_asset_contract.py").read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TraceDict(dict):
    def __init__(self, trace, values):
        super().__init__(values)
        self.trace = trace

    def get(self, key, default=None):
        self.trace.append(("get", key, default))
        return super().get(key, default)

    def __iter__(self):
        self.trace.append(("iterate",))
        return super().__iter__()

    def __getitem__(self, key):
        self.trace.append(("getitem", key))
        return super().__getitem__(key)


class DhcpAssetContractValidationTests(unittest.TestCase):
    def test_signatures_and_current_complexity_debt_are_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(CONTRACT._validate_accounting)),
            "(payload: 'dict', observations: 'object') -> 'list[object]'",
        )
        self.assertEqual(
            str(inspect.signature(CONTRACT._validated_window)),
            "(payload: 'dict', expected_window: 'dict | None') -> "
            "'tuple[dt.datetime, dt.datetime]'",
        )
        self.assertEqual(function_metrics("_validate_accounting"), (21, 11))
        self.assertEqual(function_metrics("_validated_window"), (35, 13))

    def valid_accounting(self, observations=None):
        observations = [{"n": 1}] if observations is None else observations
        return {
            "status": "ok",
            "hits_total": len(observations) + 4,
            "returned": len(observations),
            "truncated": False,
        }, observations

    def test_accounting_returns_the_original_observation_list(self) -> None:
        payload, observations = self.valid_accounting([{"n": 1}, {"n": 2}])
        original = copy.deepcopy(payload)
        result = CONTRACT._validate_accounting(payload, observations)
        self.assertIs(result, observations)
        self.assertEqual(payload, original)

    def test_accounting_error_classes_and_precedence_are_exact(self) -> None:
        too_many = [None] * (CONTRACT.MAX_RESPONSE_OBSERVATIONS + 1)
        cases = [
            ({}, None, "invalid observation list"),
            ({}, {}, "invalid observation list"),
            ({}, too_many, "invalid observation list"),
            ({"status": "failed"}, [], "invalid status"),
            (
                {"status": "ok", "hits_total": True, "returned": 0, "truncated": False},
                [],
                "invalid result accounting",
            ),
            (
                {"status": "ok", "hits_total": 0, "returned": True, "truncated": False},
                [],
                "invalid result accounting",
            ),
            (
                {"status": "partial", "hits_total": 0, "returned": 1, "truncated": False},
                [],
                "invalid result accounting",
            ),
            (
                {"status": "ok", "hits_total": 0, "returned": 0, "truncated": 0},
                [],
                "invalid result accounting",
            ),
        ]
        for payload, observations, message in cases:
            with self.subTest(message=message, payload=payload):
                with self.assertRaisesRegex(ValueError, message):
                    CONTRACT._validate_accounting(payload, observations)

    def test_accounting_get_order_and_status_short_circuit_are_preserved(self) -> None:
        trace = []
        payload = TraceDict(
            trace,
            {
                "status": "ok",
                "hits_total": 2,
                "returned": 1,
                "truncated": False,
            },
        )
        observations = ["row"]
        self.assertIs(CONTRACT._validate_accounting(payload, observations), observations)
        self.assertEqual(
            trace,
            [
                ("get", "status", None),
                ("get", "hits_total", None),
                ("get", "returned", None),
                ("get", "truncated", None),
            ],
        )

        trace = []
        payload = TraceDict(trace, {"status": "failed"})
        with self.assertRaisesRegex(ValueError, "invalid status"):
            CONTRACT._validate_accounting(payload, [])
        self.assertEqual(trace, [("get", "status", None)])

    def valid_window(self):
        return {
            "query_audit": {
                "index": "logs-zeek-so",
                "dataset": "zeek.dhcp",
                "query_digest": "a" * 64,
            },
            "window": {
                "start": "2026-08-05T00:00:00Z",
                "end": "2026-08-06T00:00:00Z",
            },
        }

    def test_window_preserves_audit_parse_format_and_result_order(self) -> None:
        trace = []
        payload = TraceDict(trace, self.valid_window())
        expected = {
            "start": "expected-start",
            "end": "expected-end",
        }
        start = dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc)
        end = start + dt.timedelta(hours=24)

        def parse(value):
            trace.append(("parse", value))
            return {
                "2026-08-05T00:00:00Z": start,
                "2026-08-06T00:00:00Z": end,
                "expected-start": start,
                "expected-end": end,
            }[value]

        def format_time(value):
            trace.append(("format", value))
            return "start" if value == start else "end"

        with (
            mock.patch.object(CONTRACT, "parse_timestamp", side_effect=parse),
            mock.patch.object(CONTRACT, "format_timestamp", side_effect=format_time),
        ):
            result = CONTRACT._validated_window(payload, expected)

        self.assertEqual(result, (start, end))
        self.assertEqual(
            trace,
            [
                ("get", "query_audit", None),
                ("get", "window", None),
                ("parse", "2026-08-05T00:00:00Z"),
                ("parse", "2026-08-06T00:00:00Z"),
                ("format", start),
                ("parse", "expected-start"),
                ("format", start),
                ("format", end),
                ("parse", "expected-end"),
                ("format", end),
            ],
        )

    def test_window_audit_schema_and_bound_failures_are_exact(self) -> None:
        cases = []
        for audit in (
            None,
            {},
            {"index": "other", "dataset": "zeek.dhcp", "query_digest": "a" * 64},
            {"index": "logs-zeek-so", "dataset": "other", "query_digest": "a" * 64},
            {"index": "logs-zeek-so", "dataset": "zeek.dhcp", "query_digest": "A" * 64},
        ):
            payload = self.valid_window()
            payload["query_audit"] = audit
            cases.append((payload, "invalid fixed-query audit"))
        for window in (None, {}, {"start": "x"}, {"start": "x", "end": "y", "extra": 1}):
            payload = self.valid_window()
            payload["window"] = window
            cases.append((payload, "invalid query window"))
        for payload, message in cases:
            with self.subTest(message=message, payload=payload):
                with self.assertRaisesRegex(ValueError, message):
                    CONTRACT._validated_window(payload, None)

        start = dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc)
        for end in (start, start - dt.timedelta(seconds=1), start + dt.timedelta(hours=24, seconds=1)):
            with self.subTest(end=end), mock.patch.object(
                CONTRACT,
                "parse_timestamp",
                side_effect=[start, end],
            ), self.assertRaisesRegex(ValueError, "out of bounds"):
                CONTRACT._validated_window(self.valid_window(), None)

    def test_expected_window_mismatch_and_input_non_mutation_are_preserved(self) -> None:
        payload = self.valid_window()
        expected = {
            "start": "2026-08-05T00:00:01Z",
            "end": "2026-08-06T00:00:00Z",
        }
        before_payload = copy.deepcopy(payload)
        before_expected = copy.deepcopy(expected)
        with self.assertRaisesRegex(ValueError, "does not match the request"):
            CONTRACT._validated_window(payload, expected)
        self.assertEqual(payload, before_payload)
        self.assertEqual(expected, before_expected)


if __name__ == "__main__":
    unittest.main()
