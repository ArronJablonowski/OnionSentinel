#!/usr/bin/env python3
"""Characterize harness execution repository transaction phases."""
from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_repository():
    path = BIN / "harness_store_execution_repository.py"
    spec = importlib.util.spec_from_file_location(
        "harness_store_execution_repository_phases_characterization",
        path,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REPOSITORY = load_repository()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_store_execution_repository.py").read_text(
            encoding="utf-8"
        )
    )
    if "." in name:
        class_name, function_name = name.split(".", 1)
        owner = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        candidates = owner.body
    else:
        function_name = name
        candidates = tree.body
    target = next(
        node
        for node in candidates
        if isinstance(node, ast.FunctionDef) and node.name == function_name
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


class TracedRow:
    def __init__(self, names: tuple[str, ...], values: tuple[Any, ...]) -> None:
        self.names = names
        self.values = values
        self.accesses: list[Any] = []

    def __iter__(self):
        self.accesses.append("__iter__")
        return iter(self.values)

    def __getitem__(self, key: Any) -> Any:
        self.accesses.append(key)
        if isinstance(key, int):
            return self.values[key]
        return self.values[self.names.index(key)]


class FakeCursor:
    def __init__(self, row: Any = None) -> None:
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, rows: list[Any] | None = None) -> None:
        self.rows = list(rows or [])
        self.events: list[Any] = []

    def execute(self, query: str, parameters: Any = None):
        normalized = " ".join(query.split())
        self.events.append(("execute", normalized, parameters))
        row = self.rows.pop(0) if "SELECT" in normalized else None
        return FakeCursor(row)

    def commit(self) -> None:
        self.events.append(("commit",))


class FakeConnect:
    def __init__(self, connection: FakeConnection, events: list[Any]) -> None:
        self.connection = connection
        self.events = events

    def __enter__(self):
        self.events.append(("connect.enter",))
        return self.connection

    def __exit__(self, exc_type, exc, traceback):
        self.events.append(
            ("connect.exit", None if exc_type is None else exc_type.__name__)
        )
        return False


class FakeRepository:
    def __init__(self) -> None:
        self.path = Path("/synthetic/harness.sqlite3")
        self.events: list[Any] = []

    def _require_mutable_run_tx(self, connection: Any, run_id: str) -> None:
        self.events.append(("require_mutable", connection, run_id))

    def _append_event_tx(self, connection: Any, **kwargs: Any) -> dict[str, Any]:
        self.events.append(("append_event", connection, copy.deepcopy(kwargs)))
        return {
            "event_id": "event-1",
            "created_at": "event-time",
            "run_id": kwargs["run_id"],
        }

    def _update_run_stage_tx(self, connection: Any, **kwargs: Any) -> None:
        self.events.append(("update_stage", connection, copy.deepcopy(kwargs)))

    def _audit_event(self, event: Any) -> None:
        self.events.append(("audit", copy.deepcopy(event)))


class HarnessStoreExecutionRepositoryPhasesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = FakeRepository()
        self.connection = FakeConnection()
        self.connect_events: list[Any] = []
        self.connect_patch = mock.patch.object(
            REPOSITORY,
            "_connect",
            side_effect=lambda path: FakeConnect(
                self.connection,
                self.connect_events,
            ),
        )
        self.now_patch = mock.patch.object(
            REPOSITORY,
            "utc_now",
            return_value="fixed-now",
        )
        self.connect_patch.start()
        self.now_patch.start()
        self.addCleanup(self.connect_patch.stop)
        self.addCleanup(self.now_patch.stop)

    def test_changed_execution_phases_stay_within_architecture_budget(self) -> None:
        functions = (
            "_reservation_rows",
            "_existing_reservation_result",
            "_budget_violation",
            "_new_reservation_result",
            "_model_call_values",
            "_persist_model_call",
            "_append_model_event",
            "_tool_call_values",
            "_persist_tool_call",
            "_append_tool_event",
            "HarnessStoreExecutionRepository.reserve_budget_operation",
            "HarnessStoreExecutionRepository.record_model_call",
            "HarnessStoreExecutionRepository.record_tool_call",
        )
        for name in functions:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def invoke(self, name: str, *args: Any, **kwargs: Any):
        method = getattr(REPOSITORY.HarnessStoreExecutionRepository, name)
        return method(self.repo, *args, **kwargs)

    def test_public_signatures_are_stable(self) -> None:
        expected = {
            "reserve_budget_operation": "(self, run_id: 'str', *, reservation_type: 'str', reservation_id: 'str', amount: 'int', max_total: 'int', max_operations: 'int', enforce: 'bool', preexisting_violations: 'Sequence[str]' = ()) -> 'dict[str, Any]'",
            "record_model_call": "(self, run_id: 'str', *, call_id: 'str', purpose: 'str', requested_route: 'str', response: 'Mapping[str, Any]', independent_review: 'bool', input_digest: 'str', duration_ms: 'int', status: 'str' = 'completed') -> 'None'",
            "record_tool_call": "(self, run_id: 'str', *, call_id: 'str', round_number: 'int', backend: 'str', capability: 'str', purpose: 'str', request_digest: 'str', result_digest: 'str', status: 'str', read_only: 'bool', coverage: 'str', truncated: 'bool') -> 'None'",
        }
        for name, signature in expected.items():
            with self.subTest(name=name):
                self.assertEqual(
                    str(
                        inspect.signature(
                            getattr(
                                REPOSITORY.HarnessStoreExecutionRepository,
                                name,
                            )
                        )
                    ),
                    signature,
                )

    def test_unknown_budget_type_fails_before_identifier_or_connection(self) -> None:
        with (
            mock.patch.object(REPOSITORY, "_valid_identifier") as identifier,
            self.assertRaisesRegex(
                REPOSITORY.HarnessPolicyError,
                "^unknown budget reservation type$",
            ),
        ):
            self.invoke(
                "reserve_budget_operation",
                "run-1",
                reservation_type="other",
                reservation_id="reservation-1",
                amount=1,
                max_total=1,
                max_operations=1,
                enforce=True,
            )
        identifier.assert_not_called()
        self.assertEqual(self.connect_events, [])

    def test_existing_budget_reservation_is_replay_safe(self) -> None:
        existing = TracedRow(("amount",), (3,))
        totals = TracedRow(("operation_count", "total"), (2, 7))
        self.connection.rows = [existing, totals]
        violations = ["z", "a", "z"]
        original = copy.deepcopy(violations)
        result = self.invoke(
            "reserve_budget_operation",
            "run-1",
            reservation_type="model-call",
            reservation_id="reservation-1",
            amount=3,
            max_total=10,
            max_operations=5,
            enforce=True,
            preexisting_violations=violations,
        )
        self.assertEqual(
            result,
            {
                "reserved": True,
                "existing": True,
                "operation_count": 2,
                "total": 7,
                "violations": ["a", "z"],
            },
        )
        self.assertEqual(violations, original)
        self.assertEqual(existing.accesses, ["amount"])
        self.assertEqual(totals.accesses, ["operation_count", "total"])
        self.assertEqual(self.connection.events[-1], ("commit",))
        self.assertEqual(self.connect_events[-1], ("connect.exit", None))

    def test_existing_budget_collision_exits_without_commit(self) -> None:
        existing = TracedRow(("amount",), (4,))
        totals = TracedRow(("operation_count", "total"), (2, 7))
        self.connection.rows = [existing, totals]
        with self.assertRaisesRegex(
            REPOSITORY.HarnessIntegrityError,
            "^budget reservation collides with different amount$",
        ):
            self.invoke(
                "reserve_budget_operation",
                "run-1",
                reservation_type="query-round",
                reservation_id="reservation-1",
                amount=3,
                max_total=10,
                max_operations=5,
                enforce=True,
            )
        self.assertNotIn(("commit",), self.connection.events)
        self.assertEqual(
            self.connect_events[-1],
            ("connect.exit", "HarnessIntegrityError"),
        )

    def test_new_budget_reservation_preserves_enforcement_and_insert(self) -> None:
        totals = TracedRow(("operation_count", "total"), (2, 7))
        self.connection.rows = [None, totals]
        result = self.invoke(
            "reserve_budget_operation",
            "run-1",
            reservation_type="query-round",
            reservation_id="reservation-1",
            amount=-3,
            max_total=6,
            max_operations=2,
            enforce=False,
            preexisting_violations=("prior",),
        )
        self.assertEqual(
            result,
            {
                "reserved": True,
                "existing": False,
                "operation_count": 3,
                "total": 7,
                "violations": ["max_queries_total", "max_query_rounds", "prior"],
            },
        )
        insert = next(
            event
            for event in self.connection.events
            if event[0] == "execute" and event[1].startswith("INSERT INTO")
        )
        self.assertEqual(
            insert[2],
            ("run-1", "query-round", "reservation-1", 0, "fixed-now"),
        )
        self.assertEqual(self.connection.events[-1], ("commit",))

    def test_enforced_budget_refusal_commits_without_insert(self) -> None:
        totals = TracedRow(("operation_count", "total"), (1, 5))
        self.connection.rows = [None, totals]
        result = self.invoke(
            "reserve_budget_operation",
            "run-1",
            reservation_type="model-call",
            reservation_id="reservation-1",
            amount=1,
            max_total=5,
            max_operations=1,
            enforce=True,
        )
        self.assertFalse(result["reserved"])
        self.assertEqual(result["violations"], ["max_model_calls"])
        self.assertFalse(
            any(
                event[0] == "execute" and event[1].startswith("INSERT INTO")
                for event in self.connection.events
            )
        )
        self.assertEqual(self.connection.events[-1], ("commit",))

    def model_kwargs(self) -> dict[str, Any]:
        return {
            "call_id": "model-1",
            "purpose": "triage",
            "requested_route": "codex-cli:gpt-5.6-sol:high",
            "response": {
                "_analysis_model": "gpt-5.6-sol",
                "_analysis_model_path": "codex-cli",
                "_analysis_provider": "openai",
                "_analysis_harness": "codex",
                "result": "synthetic",
            },
            "independent_review": False,
            "input_digest": "f" * 64,
            "duration_ms": 42,
            "status": "completed",
        }

    def test_new_model_call_preserves_insert_event_stage_commit_and_audit(self) -> None:
        self.connection.rows = [None]
        kwargs = self.model_kwargs()
        original = copy.deepcopy(kwargs)
        self.invoke("record_model_call", "run-1", **kwargs)
        self.assertEqual(kwargs, original)
        insert = next(
            event
            for event in self.connection.events
            if event[0] == "execute" and event[1].startswith("INSERT INTO")
        )
        self.assertEqual(insert[2][0:2], ("run-1", "model-1"))
        self.assertEqual(insert[2][2], "triage")
        self.assertEqual(insert[2][3], "codex-cli:gpt-5.6-sol:high")
        self.assertEqual(insert[2][4:8], ("gpt-5.6-sol", "codex-cli", "openai", "codex"))
        self.assertEqual(insert[2][8:11], (0, "completed", "f" * 64))
        self.assertEqual(insert[2][-2:], (42, "fixed-now"))
        self.assertEqual(
            [event[0] for event in self.repo.events],
            ["append_event", "update_stage", "audit"],
        )
        payload = self.repo.events[0][2]["payload"]
        self.assertEqual(payload["duration_ms"], 42)
        self.assertEqual(payload["input_digest"], "f" * 64)
        self.assertEqual(
            self.repo.events[0][2]["idempotency_key"],
            "model.completed:model-1",
        )
        self.assertEqual(
            self.repo.events[1][2],
            {
                "run_id": "run-1",
                "stage": REPOSITORY.Stage.PRIMARY_ANALYSIS.value,
                "updated_at": "event-time",
                "active_route": "codex-cli:gpt-5.6-sol:high",
            },
        )
        self.assertEqual(self.connection.events[-1], ("commit",))
        self.assertEqual(self.connect_events[-1], ("connect.exit", None))

    def test_existing_model_call_reuses_observed_duration(self) -> None:
        kwargs = self.model_kwargs()
        values = (
            "triage",
            "codex-cli:gpt-5.6-sol:high",
            "gpt-5.6-sol",
            "codex-cli",
            "openai",
            "codex",
            0,
            "completed",
            "f" * 64,
            REPOSITORY.digest_json(kwargs["response"]),
            777,
            "original-time",
        )
        existing = TracedRow(
            (
                "purpose", "requested_route", "observed_model",
                "observed_model_path", "observed_provider", "observed_harness",
                "independent_review", "status", "input_digest", "output_digest",
                "duration_ms", "created_at",
            ),
            values,
        )
        self.connection.rows = [existing]
        self.invoke("record_model_call", "run-1", **kwargs)
        self.assertEqual(existing.accesses, ["__iter__", "duration_ms"])
        self.assertEqual(self.repo.events[0][2]["payload"]["duration_ms"], 777)
        self.assertFalse(
            any(
                event[0] == "execute" and event[1].startswith("INSERT INTO")
                for event in self.connection.events
            )
        )

    def test_model_collision_has_no_event_commit_or_audit(self) -> None:
        kwargs = self.model_kwargs()
        existing = TracedRow(tuple(f"field-{i}" for i in range(12)), tuple(range(12)))
        self.connection.rows = [existing]
        with self.assertRaisesRegex(
            REPOSITORY.HarnessIntegrityError,
            "^model call_id collides with different call content$",
        ):
            self.invoke("record_model_call", "run-1", **kwargs)
        self.assertEqual(self.repo.events, [])
        self.assertNotIn(("commit",), self.connection.events)
        self.assertEqual(
            self.connect_events[-1],
            ("connect.exit", "HarnessIntegrityError"),
        )

    def tool_kwargs(self) -> dict[str, Any]:
        return {
            "call_id": "tool-1",
            "round_number": -2,
            "backend": "elastic",
            "capability": "security-onion.events.query",
            "purpose": "corroborate",
            "request_digest": "1" * 64,
            "result_digest": "2" * 64,
            "status": "ok",
            "read_only": True,
            "coverage": "",
            "truncated": False,
        }

    def test_new_tool_call_preserves_insert_event_stage_commit_and_audit(self) -> None:
        self.connection.rows = [None]
        kwargs = self.tool_kwargs()
        original = copy.deepcopy(kwargs)
        self.invoke("record_tool_call", "run-1", **kwargs)
        self.assertEqual(kwargs, original)
        insert = next(
            event
            for event in self.connection.events
            if event[0] == "execute" and event[1].startswith("INSERT INTO")
        )
        self.assertEqual(
            insert[2],
            (
                "run-1", "tool-1", 0, "elastic",
                "security-onion.events.query", "corroborate", "1" * 64,
                "2" * 64, "ok", 1, "unknown", 0, "fixed-now",
            ),
        )
        event_kwargs = self.repo.events[0][2]
        self.assertEqual(event_kwargs["stage"], REPOSITORY.Stage.QUERY_EXECUTION.value)
        self.assertEqual(event_kwargs["payload"]["round"], 0)
        self.assertTrue(event_kwargs["payload"]["read_only"])
        self.assertEqual(event_kwargs["payload"]["coverage"], "unknown")
        self.assertEqual(event_kwargs["idempotency_key"], "tool.completed:tool-1")
        self.assertEqual(
            [event[0] for event in self.repo.events],
            ["append_event", "update_stage", "audit"],
        )
        self.assertEqual(self.connection.events[-1], ("commit",))

    def test_existing_tool_call_is_replay_safe_and_collision_fails_closed(self) -> None:
        kwargs = self.tool_kwargs()
        values = (
            0, "elastic", "security-onion.events.query", "corroborate",
            "1" * 64, "2" * 64, "ok", 1, "unknown", 0, "old-time",
        )
        names = (
            "round_number", "backend", "capability", "purpose",
            "request_digest", "result_digest", "status", "read_only",
            "coverage", "truncated", "created_at",
        )
        existing = TracedRow(names, values)
        self.connection.rows = [existing]
        self.invoke("record_tool_call", "run-1", **kwargs)
        self.assertEqual(existing.accesses, ["__iter__"])
        self.assertFalse(
            any(
                event[0] == "execute" and event[1].startswith("INSERT INTO")
                for event in self.connection.events
            )
        )

        self.connection = FakeConnection([TracedRow(names, (9, *values[1:]))])
        self.repo.events.clear()
        self.connect_events.clear()
        with self.assertRaisesRegex(
            REPOSITORY.HarnessIntegrityError,
            "^tool call_id collides with different call content$",
        ):
            self.invoke("record_tool_call", "run-1", **kwargs)
        self.assertEqual(self.repo.events, [])
        self.assertNotIn(("commit",), self.connection.events)
        self.assertEqual(
            self.connect_events[-1],
            ("connect.exit", "HarnessIntegrityError"),
        )

    def test_audit_runs_only_after_connection_scope_commits(self) -> None:
        self.connection.rows = [None]
        order: list[str] = []

        class OrderedConnect(FakeConnect):
            def __exit__(inner_self, exc_type, exc, traceback):
                order.append("connection_exit")
                return super().__exit__(exc_type, exc, traceback)

        with (
            mock.patch.object(
                REPOSITORY,
                "_connect",
                return_value=OrderedConnect(self.connection, self.connect_events),
            ),
            mock.patch.object(
                self.repo,
                "_audit_event",
                side_effect=lambda event: order.append("audit"),
            ),
        ):
            self.invoke("record_tool_call", "run-1", **self.tool_kwargs())
        self.assertEqual(order, ["connection_exit", "audit"])


if __name__ == "__main__":
    unittest.main()
