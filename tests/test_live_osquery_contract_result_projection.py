"""Characterize provenance-bound live-OSQuery result admission."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
MODULE_PATH = BIN / "live_osquery_contract_result.py"


class _temporary_sys_path:
    def __enter__(self):
        sys.path.insert(0, str(BIN))

    def __exit__(self, exc_type, exc, traceback):
        sys.path.remove(str(BIN))


def load_result_module(name: str = "live_osquery_contract_result_projection"):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("live OSQuery result contract cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    with _temporary_sys_path():
        spec.loader.exec_module(module)
    return module


result_contract = load_result_module()


def request(
    *,
    alias: str = "host-a",
    query: str = "SELECT pid, name FROM processes LIMIT 2;",
    purpose: str = "Inspect process identity",
) -> dict[str, Any]:
    return {
        "target_alias": alias,
        "query": query,
        "purpose": purpose,
        "query_digest": hashlib.sha256(query.encode("utf-8")).hexdigest(),
    }


def raw_result(**overrides: Any) -> dict[str, Any]:
    value = {
        **request(),
        "status": "ok",
        "rows": [{"pid": 1, "name": "launchd"}],
        "total_rows": 1,
        "truncated": False,
        "duration_ms": 27,
        "error": "",
    }
    value.update(overrides)
    return value


def artifact(**overrides: Any) -> dict[str, Any]:
    value = {
        "schema": result_contract.SCHEMA,
        "case_id": "case-266",
        "generated_at": "2026-08-12T08:00:00Z",
        "read_only": True,
        "complete": True,
        "results": [raw_result()],
    }
    value.update(overrides)
    return value


class TrackingMapping(dict):
    def __init__(self, values: dict[str, Any]):
        super().__init__(values)
        self.trace: list[str] = []

    def get(self, key, default=None):
        self.trace.append(key)
        return super().get(key, default)


class OneShotIterable:
    def __init__(self, values: Iterable[Any]):
        self.values = list(values)
        self.iterations = 0

    def __iter__(self):
        self.iterations += 1
        if self.iterations > 1:
            raise AssertionError("expected requests were iterated more than once")
        return iter(self.values)


class LiveOsqueryResultProjectionTests(unittest.TestCase):
    def test_success_projection_key_order_and_input_immutability_are_exact(self):
        value = artifact()
        expected = [request()]
        before_value = copy.deepcopy(value)
        before_expected = copy.deepcopy(expected)

        normalized = result_contract.validate_result_artifact(
            value,
            expected_requests=expected,
        )

        self.assertEqual(value, before_value)
        self.assertEqual(expected, before_expected)
        self.assertEqual(
            list(normalized),
            [
                "schema",
                "case_id",
                "generated_at",
                "read_only",
                "complete",
                "partial",
                "results",
            ],
        )
        self.assertEqual(
            list(normalized["results"][0]),
            [
                "target_alias",
                "query",
                "purpose",
                "query_digest",
                "status",
                "rows",
                "total_rows",
                "truncated",
                "duration_ms",
                "error",
            ],
        )
        self.assertEqual(normalized["results"][0]["rows"], [{"pid": "1", "name": "launchd"}])
        self.assertIsNot(normalized["results"], value["results"])
        self.assertIsNot(normalized["results"][0]["rows"], value["results"][0]["rows"])

    def test_expected_requests_are_consumed_once_before_count_admission(self):
        expected = OneShotIterable([request()])
        normalized = result_contract.validate_result_artifact(
            artifact(),
            expected_requests=expected,
        )
        self.assertEqual(normalized["case_id"], "case-266")
        self.assertEqual(expected.iterations, 1)

        duplicate = OneShotIterable([request(), request()])
        with self.assertRaisesRegex(
            result_contract.LiveOsqueryContractError,
            "^expected request list contains duplicates$",
        ):
            result_contract.validate_result_artifact(
                artifact(results=[]),
                expected_requests=duplicate,
            )
        self.assertEqual(duplicate.iterations, 1)

    def test_mapping_access_order_is_frozen(self):
        tracked_result = TrackingMapping(raw_result())
        tracked_artifact = TrackingMapping(artifact(results=[tracked_result]))
        tracked_expected = TrackingMapping(request())

        result_contract.validate_result_artifact(
            tracked_artifact,
            expected_requests=[tracked_expected],
        )

        self.assertEqual(
            tracked_artifact.trace,
            ["schema", "case_id", "results", "read_only", "complete", "generated_at"],
        )
        self.assertEqual(
            tracked_expected.trace,
            ["target_alias", "query", "purpose"],
        )
        self.assertEqual(
            tracked_result.trace,
            [
                "target_alias",
                "query",
                "purpose",
                "rows",
                "status",
                "total_rows",
                "duration_ms",
                "truncated",
                "error",
            ],
        )

    def test_duplicate_observation_and_binding_mutation_order_are_frozen(self):
        expected_request = request()
        key = (expected_request["target_alias"], expected_request["query_digest"])

        observed = {key}
        with self.assertRaisesRegex(
            result_contract.LiveOsqueryContractError,
            "^live OSQuery result contains duplicates$",
        ):
            result_contract._normalize_result(
                raw_result(purpose="wrong"),
                expected={},
                observed=observed,
            )
        self.assertEqual(observed, {key})

        observed = set()
        with self.assertRaisesRegex(
            result_contract.LiveOsqueryContractError,
            "^result query or target does not match a submitted request$",
        ):
            result_contract._normalize_result(
                raw_result(),
                expected={},
                observed=observed,
            )
        self.assertEqual(observed, {key})

        observed = set()
        with self.assertRaisesRegex(
            result_contract.LiveOsqueryContractError,
            "^result purpose does not match its submitted request$",
        ):
            result_contract._normalize_result(
                raw_result(purpose="wrong"),
                expected={key: expected_request},
                observed=observed,
            )
        self.assertEqual(observed, {key})

    def test_artifact_failure_precedence_is_exact(self):
        cases = (
            (None, None, "live OSQuery result must be an object"),
            (
                {"schema": "bad", "case_id": "", "results": None},
                None,
                f"result schema must be {result_contract.SCHEMA}",
            ),
            (
                {"schema": result_contract.SCHEMA, "case_id": "", "results": None},
                None,
                "case_id is required",
            ),
            (
                artifact(results=None, read_only=False, complete=False),
                None,
                "result list is missing or exceeds its bound",
            ),
            (
                artifact(results=[None], read_only=False, complete=False),
                None,
                "each live OSQuery result must be an object",
            ),
            (
                artifact(read_only=False, complete=False),
                [request()],
                "live OSQuery result is not marked read-only",
            ),
            (
                artifact(complete=False),
                [request()],
                "result complete flag does not match individual query outcomes",
            ),
        )
        for value, expected, message in cases:
            with self.subTest(message=message):
                with self.assertRaises(result_contract.LiveOsqueryContractError) as raised:
                    result_contract.validate_result_artifact(
                        value,
                        expected_requests=expected,
                    )
                self.assertEqual(str(raised.exception), message)

    def test_result_failure_precedence_and_accounting_cause_are_exact(self):
        invalid_rows = raw_result(
            rows=[{"wrong": "value"}],
            status="unsupported",
            total_rows="bad",
        )
        with self.assertRaises(result_contract.LiveOsqueryContractError) as raised:
            result_contract._normalize_result(
                invalid_rows,
                expected=None,
                observed=set(),
            )
        self.assertEqual(
            str(raised.exception),
            "result row columns do not match the submitted query projection",
        )

        invalid_status = raw_result(status="unsupported", total_rows="bad")
        with self.assertRaises(result_contract.LiveOsqueryContractError) as raised:
            result_contract._normalize_result(
                invalid_status,
                expected=None,
                observed=set(),
            )
        self.assertEqual(str(raised.exception), "unsupported result status: unsupported")

        invalid_accounting = raw_result(total_rows="bad")
        with self.assertRaises(result_contract.LiveOsqueryContractError) as raised:
            result_contract._normalize_result(
                invalid_accounting,
                expected=None,
                observed=set(),
            )
        self.assertEqual(
            str(raised.exception),
            "result row count or duration is not an integer",
        )
        self.assertIsInstance(raised.exception.__cause__, ValueError)

    def test_empty_and_partial_completion_truth_conditions_are_frozen(self):
        empty = result_contract.validate_result_artifact(
            artifact(results=[], complete=True),
            expected_requests=[],
        )
        self.assertTrue(empty["complete"])
        self.assertFalse(empty["partial"])

        failed = raw_result(status="timeout", rows=[], total_rows=0, error="timed out")
        partial = result_contract.validate_result_artifact(
            artifact(results=[failed], complete=False),
            expected_requests=[request()],
        )
        self.assertFalse(partial["complete"])
        self.assertTrue(partial["partial"])

        truthy_complete = result_contract.validate_result_artifact(
            artifact(complete="yes"),
            expected_requests=[request()],
        )
        self.assertTrue(truthy_complete["complete"])


if __name__ == "__main__":
    unittest.main()
