from __future__ import annotations

import importlib
import inspect
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

PREFLIGHT = importlib.import_module("harness_run_model_preflight")


class TraceStore:
    def __init__(self, trace, reservation=None):
        self.trace = trace
        self.reservation = reservation or {
            "reserved": True,
            "total": 1,
            "operation_count": 1,
            "violations": [],
        }

    def append_event(self, run_id, event_type, stage, payload, **kwargs):
        self.trace.append(
            ("append_event", run_id, event_type, stage, payload, kwargs)
        )

    def reserve_budget_operation(self, run_id, **kwargs):
        self.trace.append(("reserve_budget_operation", run_id, kwargs))
        return dict(self.reservation)


class TraceRun:
    def __init__(
        self,
        trace,
        *,
        mode="shadow",
        primary_route="route:primary",
        reviewer_route="route:reviewer",
        reservation=None,
        model_calls=0,
        elapsed_seconds=3.5,
        enforce_error=None,
    ):
        self.trace = trace
        self.run_id = "run-1"
        self.store = TraceStore(trace, reservation)
        self.envelope = SimpleNamespace(
            assigned_route=primary_route,
            assigned_reviewer_route=reviewer_route,
        )
        self.policy = SimpleNamespace(
            mode=mode,
            budgets={
                "max_model_calls": 4,
                "max_prompt_evidence_bytes": 100,
                "max_prompt_evidence_rows": 10,
                "max_run_seconds": 60,
            },
        )
        self._model_calls = model_calls
        self.elapsed_seconds = elapsed_seconds
        self.enforce_error = enforce_error

    def _elapsed_seconds(self):
        self.trace.append(("elapsed_seconds",))
        return self.elapsed_seconds

    def _enforce_budget(self, **kwargs):
        self.trace.append(("enforce_budget", self._model_calls, kwargs))
        if self.enforce_error is not None:
            raise self.enforce_error


def traced_dependencies(trace, *, canonical='{"safe":true}', rows=2):
    def valid_identifier(value, label, limit):
        trace.append(("valid_identifier", value, label, limit))
        return str(value)

    def model_route(value, label):
        trace.append(("model_route", value, label))
        return str(value)

    def redacted_string(value, limit):
        trace.append(("redacted_string", value, limit))
        return f"redacted:{value}"

    def canonical_json(value):
        trace.append(("canonical_json", value))
        return canonical

    def approximate_evidence_rows(value):
        trace.append(("approximate_evidence_rows", value))
        return rows

    return {
        "valid_identifier": valid_identifier,
        "model_route": model_route,
        "redacted_string": redacted_string,
        "canonical_json": canonical_json,
        "approximate_evidence_rows": approximate_evidence_rows,
    }


def preflight(run, dependencies, **overrides):
    arguments = {
        "call_id": "model-1",
        "input_value": {"rows": [1, 2]},
        "requested_route": "route:primary",
        "purpose": "analyze safely",
        "independent_review": False,
        **dependencies,
    }
    arguments.update(overrides)
    return PREFLIGHT.preflight_model_call(run, **arguments)


class HarnessModelPreflightProjectionTests(unittest.TestCase):
    def test_public_signature_is_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(PREFLIGHT.preflight_model_call)),
            "(run: 'Any', *, call_id: 'str', input_value: 'Any', requested_route: 'str', purpose: 'str', independent_review: 'bool', valid_identifier: 'Callable[[Any, str, int], str]', model_route: 'Callable[[Any, str], str]', redacted_string: 'Callable[[Any, int], str]', canonical_json: 'Callable[[Any], str]', approximate_evidence_rows: 'Callable[[Any], int]') -> 'None'",
        )

    def test_success_preserves_dependency_event_reservation_and_enforcement_order(self) -> None:
        trace = []
        run = TraceRun(
            trace,
            model_calls=2,
            reservation={
                "reserved": True,
                "total": 3,
                "operation_count": 3,
                "violations": [],
            },
        )
        dependencies = traced_dependencies(trace)

        self.assertIsNone(preflight(run, dependencies))

        self.assertEqual(
            [entry[0] for entry in trace],
            [
                "valid_identifier",
                "model_route",
                "redacted_string",
                "append_event",
                "canonical_json",
                "approximate_evidence_rows",
                "elapsed_seconds",
                "reserve_budget_operation",
                "redacted_string",
                "enforce_budget",
            ],
        )
        self.assertEqual(run._model_calls, 3)
        self.assertEqual(trace[-1][1], 3)
        self.assertEqual(
            trace[-1][2],
            {
                "operation_id": "model:model-1",
                "operation": "model call",
                "stage": "primary-analysis",
                "observed": {
                    "call_id": "model-1",
                    "purpose": "redacted:analyze safely",
                    "requested_route": "route:primary",
                    "expected_route": "route:primary",
                    "route_allowed": True,
                    "independent_review": False,
                    "next_model_call": 3,
                    "prompt_bytes": len('{"safe":true}'.encode("utf-8")),
                    "approximate_evidence_rows": 2,
                    "reserved": True,
                },
                "violations": [],
            },
        )

    def test_enforced_route_refusal_stops_before_prompt_measurement(self) -> None:
        trace = []
        run = TraceRun(trace, mode="enforce")
        dependencies = traced_dependencies(trace)

        with self.assertRaisesRegex(
            PREFLIGHT.HarnessPolicyError,
            "does not match the immutable run assignment",
        ):
            preflight(
                run,
                dependencies,
                requested_route="route:unexpected",
            )

        self.assertEqual(
            [entry[0] for entry in trace],
            [
                "valid_identifier",
                "model_route",
                "redacted_string",
                "append_event",
            ],
        )
        self.assertFalse(trace[-1][4]["allowed"])
        self.assertEqual(run._model_calls, 0)

    def test_identifier_and_route_validation_failures_preserve_cutoffs(self) -> None:
        for failing_dependency, expected_order in (
            ("valid_identifier", ["valid_identifier"]),
            ("model_route", ["valid_identifier", "model_route"]),
        ):
            with self.subTest(failing_dependency=failing_dependency):
                trace = []
                run = TraceRun(trace)
                dependencies = traced_dependencies(trace)

                def fail(*args, **kwargs):
                    del args, kwargs
                    trace.append((failing_dependency,))
                    raise ValueError(failing_dependency)

                dependencies[failing_dependency] = fail
                with self.assertRaisesRegex(ValueError, failing_dependency):
                    preflight(run, dependencies)
                self.assertEqual(
                    [entry[0] for entry in trace],
                    expected_order,
                )
                self.assertEqual(run._model_calls, 0)

    def test_unicode_measurements_and_violation_order_flow_to_reservation(self) -> None:
        trace = []
        reservation = {
            "reserved": False,
            "total": 4,
            "operation_count": 5,
            "violations": [
                "max_prompt_evidence_bytes",
                "max_prompt_evidence_rows",
                "max_run_seconds",
                "max_model_calls",
            ],
        }
        run = TraceRun(
            trace,
            reservation=reservation,
            model_calls=2,
            elapsed_seconds=61,
        )
        run.policy.budgets["max_prompt_evidence_bytes"] = 1
        dependencies = traced_dependencies(
            trace,
            canonical='{"emoji":"🧅"}',
            rows=11,
        )

        preflight(run, dependencies)

        reserve = next(
            entry for entry in trace if entry[0] == "reserve_budget_operation"
        )
        self.assertEqual(
            reserve[2],
            {
                "reservation_type": "model-call",
                "reservation_id": "model-1",
                "amount": 1,
                "max_total": 4,
                "max_operations": 4,
                "enforce": False,
                "preexisting_violations": [
                    "max_prompt_evidence_bytes",
                    "max_prompt_evidence_rows",
                    "max_run_seconds",
                ],
            },
        )
        enforce = trace[-1][2]
        self.assertEqual(
            enforce["observed"]["prompt_bytes"],
            len('{"emoji":"🧅"}'.encode("utf-8")),
        )
        self.assertEqual(enforce["violations"], reservation["violations"])
        self.assertEqual(run._model_calls, 2)

    def test_enforcement_failure_keeps_reserved_counter_projection(self) -> None:
        trace = []
        run = TraceRun(
            trace,
            reservation={
                "reserved": True,
                "total": 7,
                "operation_count": 4,
                "violations": ["max_model_calls"],
            },
            model_calls=5,
            enforce_error=RuntimeError("enforcement failed"),
        )
        dependencies = traced_dependencies(trace)

        with self.assertRaisesRegex(RuntimeError, "enforcement failed"):
            preflight(run, dependencies)

        self.assertEqual(run._model_calls, 7)
        self.assertEqual(trace[-1][0:2], ("enforce_budget", 7))


if __name__ == "__main__":
    unittest.main()
