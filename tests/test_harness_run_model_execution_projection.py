#!/usr/bin/env python3
"""Characterize harness model-call persistence projection."""
from __future__ import annotations

import copy
import importlib
import inspect
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

EXECUTION = importlib.import_module("harness_run_model_execution")


class FakeResult:
    def __init__(self, row: Any) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, row: Any, events: list[Any]) -> None:
        self.row = row
        self.events = events

    def __enter__(self):
        self.events.append(("connect.enter",))
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.events.append((
            "connect.exit",
            None if exc_type is None else exc_type.__name__,
        ))
        return False

    def execute(self, sql: str, parameters: Any):
        self.events.append(("execute", " ".join(sql.split()), parameters))
        return FakeResult(self.row)


class FakeStore:
    def __init__(self, events: list[Any], reservation: dict[str, Any]) -> None:
        self.path = Path("/synthetic/harness.sqlite3")
        self.events = events
        self.reservation = reservation

    def append_event(self, run_id: str, *args: Any, **kwargs: Any) -> None:
        self.events.append((
            "append_event", run_id, copy.deepcopy(args), copy.deepcopy(kwargs),
        ))

    def reserve_budget_operation(self, run_id: str, **kwargs: Any):
        self.events.append((
            "reserve_budget", run_id, copy.deepcopy(kwargs),
        ))
        return copy.deepcopy(self.reservation)

    def record_model_call(self, run_id: str, **kwargs: Any) -> None:
        self.events.append((
            "record_model_call", run_id, copy.deepcopy(kwargs),
        ))


class SyntheticRun:
    def __init__(
        self,
        *,
        mode: str = "shadow",
        model_calls: int = 0,
        reservation: dict[str, Any] | None = None,
        enforce_error: bool = False,
    ) -> None:
        self.run_id = "run-1"
        self.events: list[Any] = []
        self.policy = SimpleNamespace(
            mode=mode,
            budgets={"max_model_calls": 4},
        )
        self._model_calls = model_calls
        self.store = FakeStore(
            self.events,
            reservation or {
                "reserved": True,
                "total": 1,
                "operation_count": 1,
                "violations": [],
            },
        )
        self.enforce_error = enforce_error

    def _enforce_budget(self, **kwargs: Any) -> None:
        self.events.append(("enforce_budget", copy.deepcopy(kwargs)))
        if self.enforce_error:
            raise EXECUTION.HarnessPolicyError("synthetic budget refusal")


class HarnessRunModelExecutionProjectionTests(unittest.TestCase):
    def invoke(
        self,
        run: SyntheticRun,
        *,
        row: Any,
        call_id: str = "model-1",
        requested_route: str = "codex-cli:gpt-5.6-sol:high",
        response: dict[str, Any] | None = None,
        input_value: Any = None,
        duration_seconds: float = 1.2345,
        independent_review: bool = False,
        status: str = "completed",
    ) -> None:
        response = (
            {"_analysis_model_route": requested_route, "answer": "bounded"}
            if response is None
            else response
        )
        connect = lambda path: FakeConnection(row, run.events)
        EXECUTION.record_model_call(
            run,
            call_id=call_id,
            purpose="primary analysis",
            requested_route=requested_route,
            response=response,
            input_value=input_value,
            duration_seconds=duration_seconds,
            independent_review=independent_review,
            status=status,
            connect=connect,
        )

    def authorization_row(
        self,
        *,
        route: str = "codex-cli:gpt-5.6-sol:high",
        independent_review: bool = False,
        allowed: bool = True,
    ) -> dict[str, Any]:
        return {"payload_json": json.dumps({
            "allowed": allowed,
            "requested_route": route,
            "independent_review": independent_review,
        })}

    def test_public_signature_is_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(EXECUTION.record_model_call)),
            "(run: 'Any', *, call_id: 'str', purpose: 'str', requested_route: 'str', response: 'Mapping[str, Any]', input_value: 'Any', duration_seconds: 'float', independent_review: 'bool', status: 'str', connect: 'Callable[[Any], Any]') -> 'None'",
        )

    def test_validation_precedes_authorization_connection(self) -> None:
        run = SyntheticRun()
        with self.assertRaisesRegex(
            EXECUTION.HarnessPolicyError,
            "model call_id is invalid",
        ):
            self.invoke(run, row=self.authorization_row(), call_id="")
        self.assertEqual(run.events, [])

        with self.assertRaises(EXECUTION.HarnessPolicyError):
            self.invoke(run, row=self.authorization_row(), requested_route="bad route")
        self.assertEqual(run.events, [])

    def test_authorization_lookup_preserves_query_and_json_failure(self) -> None:
        run = SyntheticRun()
        with self.assertRaises(json.JSONDecodeError):
            self.invoke(run, row={"payload_json": "{"})
        self.assertEqual(
            [event[0] for event in run.events],
            ["connect.enter", "execute", "connect.exit"],
        )
        query = run.events[1]
        self.assertIn("FROM harness_events", query[1])
        self.assertEqual(query[2], ("run-1", "policy.model-route:model-1"))
        self.assertEqual(run._model_calls, 0)

    def test_shadow_mismatch_continues_through_reservation_and_persistence(self) -> None:
        run = SyntheticRun(model_calls=7)
        response = {
            "_analysis_model_route": "ollama:other",
            "answer": "retained",
        }
        input_value = {"prompt": "not persisted", "index": 2}
        self.invoke(
            run,
            row=self.authorization_row(),
            response=response,
            input_value=input_value,
            duration_seconds=-0.25,
            status="failed",
        )
        self.assertEqual(
            [event[0] for event in run.events],
            [
                "connect.enter", "execute", "connect.exit", "append_event",
                "reserve_budget", "record_model_call",
            ],
        )
        observation = run.events[3]
        self.assertEqual(observation[2][0:2], (
            "policy.model-observation", "primary-analysis",
        ))
        self.assertFalse(observation[2][2]["allowed"])
        recorded = run.events[5][2]
        self.assertEqual(recorded["duration_ms"], 0)
        self.assertEqual(recorded["status"], "failed")
        self.assertEqual(recorded["input_digest"], EXECUTION.digest_json(input_value))
        self.assertEqual(recorded["response"], response)
        self.assertEqual(run._model_calls, 7)

    def test_success_preserves_review_stage_rounding_and_counter_update(self) -> None:
        run = SyntheticRun(model_calls=1, reservation={
            "reserved": True,
            "total": 5,
            "operation_count": 2,
            "violations": [],
        })
        route = "codex-cli:gpt-5.6-sol:high"
        self.invoke(
            run,
            row=self.authorization_row(independent_review=True),
            requested_route=route,
            independent_review=True,
            input_value=["bounded"],
            duration_seconds=1.2345,
        )
        append = run.events[3]
        self.assertEqual(append[2][1], "independent-review")
        recorded = run.events[5][2]
        self.assertEqual(recorded["duration_ms"], 1234)
        self.assertTrue(recorded["independent_review"])
        self.assertEqual(run._model_calls, 5)

    def test_enforce_observation_refusal_precedes_reservation(self) -> None:
        run = SyntheticRun(mode="enforce")
        with self.assertRaisesRegex(
            EXECUTION.HarnessPolicyError,
            "collector-observed route differs",
        ):
            self.invoke(
                run,
                row=self.authorization_row(),
                response={"_analysis_model_route": "ollama:other"},
            )
        self.assertEqual(
            [event[0] for event in run.events],
            ["connect.enter", "execute", "connect.exit", "append_event"],
        )
        self.assertEqual(run._model_calls, 0)

    def test_enforced_budget_refusal_precedes_persistence_and_counter(self) -> None:
        run = SyntheticRun(
            mode="enforce",
            model_calls=2,
            reservation={
                "reserved": False,
                "total": 2,
                "operation_count": 5,
                "violations": ["max_model_calls"],
            },
            enforce_error=True,
        )
        with self.assertRaisesRegex(
            EXECUTION.HarnessPolicyError,
            "synthetic budget refusal",
        ):
            self.invoke(run, row=self.authorization_row())
        self.assertEqual(
            [event[0] for event in run.events],
            [
                "connect.enter", "execute", "connect.exit", "append_event",
                "reserve_budget", "enforce_budget",
            ],
        )
        enforced = run.events[-1][1]
        self.assertEqual(enforced["operation_id"], "model:model-1")
        self.assertEqual(enforced["observed"], {
            "call_id": "model-1",
            "next_model_call": 5,
            "reserved": False,
        })
        self.assertEqual(run._model_calls, 2)


if __name__ == "__main__":
    unittest.main()
