from __future__ import annotations

import ast
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

FOUNDATION = importlib.import_module("harness_store_foundation")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(
        (BIN / "harness_store_foundation.py").read_text(encoding="utf-8")
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


class TraceRow:
    def __init__(self, trace, values, *, fail=False):
        self.trace = trace
        self.values = dict(values)
        self.fail = fail

    def keys(self):
        self.trace.append(("row.keys",))
        if self.fail:
            raise RuntimeError("row conversion failed")
        return self.values.keys()

    def __getitem__(self, key):
        self.trace.append(("row.get", key))
        return self.values[key]


class Cursor:
    def __init__(self, trace, row, *, fail=False):
        self.trace = trace
        self.row = row
        self.fail = fail

    def fetchone(self):
        self.trace.append(("fetchone",))
        if self.fail:
            raise RuntimeError("fetch failed")
        return self.row


class Connection:
    def __init__(self, trace, row=None, *, execute_fail=False, fetch_fail=False):
        self.trace = trace
        self.row = row
        self.execute_fail = execute_fail
        self.fetch_fail = fetch_fail

    def execute(self, query, parameters):
        self.trace.append(("execute", " ".join(query.split()), parameters))
        if self.execute_fail:
            raise RuntimeError("execute failed")
        return Cursor(self.trace, self.row, fail=self.fetch_fail)


class Connect:
    def __init__(self, trace, connection, *, enter_fail=False, exit_fail=False):
        self.trace = trace
        self.connection = connection
        self.enter_fail = enter_fail
        self.exit_fail = exit_fail

    def __enter__(self):
        self.trace.append(("connect.enter",))
        if self.enter_fail:
            raise RuntimeError("connect enter failed")
        return self.connection

    def __exit__(self, exc_type, exc, traceback):
        self.trace.append(
            ("connect.exit", None if exc_type is None else exc_type.__name__)
        )
        if self.exit_fail:
            raise RuntimeError("connect exit failed")
        return False


class Logger:
    def __init__(self, trace, *, fail=False):
        self.trace = trace
        self.fail = fail

    def log(self, level, event_name, **kwargs):
        self.trace.append(("logger.log", level, event_name, kwargs))
        if self.fail:
            raise RuntimeError("logger failed")


class Event:
    def __init__(self, trace, values, *, fail_key=None):
        self.trace = trace
        self.values = dict(values)
        self.fail_key = fail_key

    def get(self, key, default=None):
        self.trace.append(("event.get", key, default))
        if key == self.fail_key:
            raise RuntimeError(f"event {key} failed")
        return self.values.get(key, default)


class HarnessStoreAuditProjectionTests(unittest.TestCase):
    def invoke(
        self,
        event,
        *,
        row=None,
        logger_fail=False,
        connect_call_fail=False,
        enter_fail=False,
        exit_fail=False,
        execute_fail=False,
        fetch_fail=False,
        trace=None,
    ):
        trace = [] if trace is None else trace
        connection = Connection(
            trace,
            row,
            execute_fail=execute_fail,
            fetch_fail=fetch_fail,
        )
        owner = type("Owner", (), {})()
        owner.path = Path("/synthetic/harness.sqlite3")
        owner.logger = Logger(trace, fail=logger_fail)

        def connect(path):
            trace.append(("connect.call", path))
            if connect_call_fail:
                raise RuntimeError("connect call failed")
            return Connect(
                trace,
                connection,
                enter_fail=enter_fail,
                exit_fail=exit_fail,
            )

        with mock.patch.object(FOUNDATION, "_connect", side_effect=connect):
            result = FOUNDATION.HarnessStoreFoundation._audit_event(
                owner,
                event,
            )
        return result, trace

    def test_public_signature_and_changed_functions_are_within_budget(self) -> None:
        self.assertEqual(
            str(
                inspect.signature(
                    FOUNDATION.HarnessStoreFoundation._audit_event
                )
            ),
            "(self, event: 'Mapping[str, Any]') -> 'None'",
        )
        for name in (
            "_audit_run_identity",
            "_audit_log_level",
            "_audit_log_fields",
            "HarnessStoreFoundation._audit_event",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_failed_event_preserves_query_lifetime_conversion_and_log_projection(self) -> None:
        trace = []
        identity = {
            "correlation_id": "corr-1",
            "case_id": "case-1",
            "alert_id": "alert-1",
            "role": "soc-analyst",
            "task_kind": "alert-triage",
            "assigned_route": "route:primary",
            "assigned_reviewer_route": "route:reviewer",
            "status": "failed",
        }
        row = TraceRow(trace, identity)
        event = Event(
            trace,
            {
                "run_id": 123,
                "sequence": "7",
                "event_type": "run.failed",
                "stage": "complete",
                "event_id": "evt-1",
                "created_at": "event-time",
                "event_sha256": "a" * 64,
                "payload_sha256": "b" * 64,
            },
        )

        result, trace = self.invoke(event, row=row, trace=trace)

        self.assertIsNone(result)
        execute = next(item for item in trace if item[0] == "execute")
        self.assertEqual(
            execute,
            (
                "execute",
                "SELECT correlation_id, case_id, alert_id, role, task_kind, assigned_route, assigned_reviewer_route, status FROM harness_runs WHERE run_id = ?",
                ("123",),
            ),
        )
        self.assertLess(
            trace.index(("connect.exit", None)),
            trace.index(("row.keys",)),
        )
        logged = next(item for item in trace if item[0] == "logger.log")
        self.assertEqual(
            logged,
            (
                "logger.log",
                "error",
                "harness.event",
                {
                    "run_id": "123",
                    "trace_sequence": 7,
                    "harness_event_type": "run.failed",
                    "stage": "complete",
                    "event_id": "evt-1",
                    "event_created_at": "event-time",
                    "event_sha256": "a" * 64,
                    "payload_sha256": "b" * 64,
                    **identity,
                },
            ),
        )

    def test_missing_run_uses_empty_identity_and_event_defaults(self) -> None:
        event_trace = []
        event = Event(event_trace, {})

        result, trace = self.invoke(event, row=None, trace=event_trace)

        self.assertIsNone(result)
        logged = next(item for item in trace if item[0] == "logger.log")
        self.assertEqual(logged[1:3], ("info", "harness.event"))
        self.assertEqual(
            logged[3],
            {
                "run_id": "",
                "trace_sequence": 0,
                "harness_event_type": "",
                "stage": "",
                "event_id": "",
                "event_created_at": "",
                "event_sha256": "",
                "payload_sha256": "",
            },
        )
        execute = next(item for item in trace if item[0] == "execute")
        self.assertEqual(execute[2], ("",))

    def test_every_mirror_failure_is_suppressed_with_no_follow_on_log(self) -> None:
        scenarios = (
            {"connect_call_fail": True},
            {"enter_fail": True},
            {"execute_fail": True},
            {"fetch_fail": True},
            {"exit_fail": True},
        )
        for options in scenarios:
            with self.subTest(options=options):
                result, trace = self.invoke(
                    {"run_id": "run-1"},
                    **options,
                )
                self.assertIsNone(result)
                self.assertNotIn("logger.log", [item[0] for item in trace])

        trace = []
        row = TraceRow(trace, {"status": "running"}, fail=True)
        result, trace = self.invoke(
            {"run_id": "run-1"},
            row=row,
            trace=trace,
        )
        self.assertIsNone(result)
        self.assertNotIn("logger.log", [item[0] for item in trace])

        result, trace = self.invoke(
            {"run_id": "run-1"},
            row={"status": "running"},
            logger_fail=True,
        )
        self.assertIsNone(result)
        self.assertIn("logger.log", [item[0] for item in trace])

    def test_event_projection_failure_occurs_after_identity_lookup_and_is_suppressed(self) -> None:
        event_trace = []
        event = Event(
            event_trace,
            {"run_id": "run-1", "sequence": object()},
        )
        result, trace = self.invoke(
            event,
            row={"status": "running"},
            trace=event_trace,
        )

        self.assertIsNone(result)
        self.assertIn("fetchone", [item[0] for item in trace])
        self.assertIn("connect.exit", [item[0] for item in trace])
        self.assertNotIn("logger.log", [item[0] for item in trace])

    def test_run_identity_lookup_failure_from_event_mapping_is_suppressed(self) -> None:
        event_trace = []
        event = Event(event_trace, {}, fail_key="run_id")
        result, trace = self.invoke(event, trace=event_trace)

        self.assertIsNone(result)
        self.assertIn("connect.enter", [item[0] for item in trace])
        self.assertNotIn("execute", [item[0] for item in trace])
        self.assertIn(("connect.exit", "RuntimeError"), trace)
        self.assertNotIn("logger.log", [item[0] for item in trace])


if __name__ == "__main__":
    unittest.main()
