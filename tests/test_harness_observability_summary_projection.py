from __future__ import annotations

import ast
import datetime as dt
import importlib.util
import inspect
import json
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "report-harness-observability.py"
SPEC = importlib.util.spec_from_file_location(
    "harness_observability_summary_projection",
    SCRIPT,
)
REPORT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(REPORT)


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
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


class Cursor:
    def __init__(self, trace, response):
        self.trace = trace
        self.response = response

    def fetchone(self):
        self.trace.append(("fetchone",))
        return self.response

    def fetchall(self):
        self.trace.append(("fetchall",))
        return self.response

    def __iter__(self):
        self.trace.append(("iterate",))
        return iter(self.response)


class Connection:
    def __init__(self, trace, responses):
        object.__setattr__(self, "trace", trace)
        object.__setattr__(self, "responses", dict(responses))
        object.__setattr__(self, "row_factory", None)

    def __setattr__(self, name, value):
        if name == "row_factory":
            self.trace.append(("row_factory", value))
        object.__setattr__(self, name, value)

    def execute(self, sql):
        normalized = " ".join(sql.split())
        self.trace.append(("execute", normalized))
        response = self.responses[normalized]
        if isinstance(response, BaseException):
            raise response
        return Cursor(self.trace, response)

    def close(self):
        self.trace.append(("close",))


class HarnessObservabilitySummaryProjectionTests(unittest.TestCase):
    maxDiff = None

    def queries(self):
        return {
            "PRAGMA query_only=ON": None,
            "PRAGMA quick_check(1)": ("ok",),
            "SELECT status, COUNT(*) count FROM harness_runs GROUP BY status ORDER BY status": [
                {"status": "failed", "count": 2},
                {"status": "running", "count": 1},
            ],
            "SELECT stage, COUNT(*) count FROM harness_runs WHERE status NOT IN ('succeeded','failed','cancelled') GROUP BY stage ORDER BY stage": [
                {"stage": "query-execution", "count": 1}
            ],
            "SELECT event_type, COUNT(*) count FROM harness_events GROUP BY event_type ORDER BY event_type": [
                {"event_type": "run.failed", "count": 2}
            ],
            "SELECT status, started_at, updated_at, completed_at, terminal_reason FROM harness_runs": [
                {
                    "status": "failed",
                    "started_at": "2026-08-05T00:00:00+00:00",
                    "updated_at": "2026-08-05T00:01:00+00:00",
                    "completed_at": "2026-08-05T00:01:00+00:00",
                    "terminal_reason": "provider timeout",
                },
                {
                    "status": "failed",
                    "started_at": "invalid",
                    "updated_at": "2026-08-05T00:02:00+00:00",
                    "completed_at": None,
                    "terminal_reason": "sqlite integrity",
                },
                {
                    "status": "running",
                    "started_at": "2026-08-05T00:01:00+00:00",
                    "updated_at": "2026-08-05T00:02:00+00:00",
                    "completed_at": None,
                    "terminal_reason": "",
                },
            ],
            "PRAGMA table_info(harness_model_calls)": [
                (0, "duration_ms"),
                (1, "input_tokens"),
                (2, "output_tokens"),
                (3, "attempt_count"),
            ],
            "SELECT observed_provider provider, observed_model model, observed_harness harness, status, COUNT(*) count, CAST(AVG(duration_ms) AS INTEGER) average_duration_ms FROM harness_model_calls GROUP BY observed_provider, observed_model, observed_harness, status ORDER BY observed_provider, observed_model, observed_harness, status": [
                {
                    "provider": "codex-cli",
                    "model": "gpt-test",
                    "harness": "native",
                    "status": "failed",
                    "count": 2,
                    "average_duration_ms": 50,
                }
            ],
            "SELECT duration_ms FROM harness_model_calls": [(10,), (-5,), (100,)],
            "SELECT backend, capability, status, COUNT(*) count, SUM(CASE WHEN truncated = 1 THEN 1 ELSE 0 END) truncated_count FROM harness_tool_calls GROUP BY backend, capability, status ORDER BY backend, capability, status": [
                {
                    "backend": "elastic",
                    "capability": "events.read",
                    "status": "ok",
                    "count": 3,
                    "truncated_count": 1,
                }
            ],
            "SELECT COUNT(*) FROM harness_runs": (3,),
            "SELECT COUNT(*) FROM harness_events": (4,),
            "SELECT COUNT(*) FROM harness_evidence": (5,),
            "SELECT COUNT(*) FROM harness_hypotheses": (6,),
            "SELECT COUNT(*) FROM harness_decisions": (7,),
            "SELECT COUNT(*) FROM harness_model_calls": (8,),
            "SELECT COUNT(*) FROM harness_tool_calls": (9,),
            "SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0) FROM harness_model_calls": (
                111,
                222,
            ),
            "SELECT COALESCE(SUM(MAX(attempt_count - 1, 0)),0) FROM harness_model_calls": (
                3,
            ),
        }

    def invoke(self, *, responses=None):
        trace = []
        connection = Connection(trace, responses or self.queries())
        path = Path("/synthetic/investigation-harness.sqlite3")
        now = dt.datetime(2026, 8, 5, 0, 3, tzinfo=dt.timezone.utc)

        def safe(value):
            trace.append(("safe", value))

        def connect(database_uri, *, uri: bool, timeout: float):
            trace.append(
                ("connect", database_uri, {"uri": uri, "timeout": timeout})
            )
            return connection

        original_percentile = REPORT.percentile

        def percentile(values, fraction):
            projected = list(values)
            trace.append(("percentile", projected, fraction))
            return original_percentile(projected, fraction)

        with (
            mock.patch.object(REPORT, "safe_regular_file", side_effect=safe),
            mock.patch.object(REPORT.sqlite3, "connect", side_effect=connect),
            mock.patch.object(REPORT, "percentile", side_effect=percentile),
        ):
            result = REPORT.summarize_database(path, now)
        return result, trace, connection, path

    def test_signature_and_changed_functions_are_within_budget(self) -> None:
        self.assertEqual(
            str(inspect.signature(REPORT.summarize_database)),
            "(path: 'Path', now: 'dt.datetime') -> 'dict[str, Any]'",
        )
        for name in (
            "summarize_database",
            "_open_observability_database",
            "_validate_observability_database",
            "_grouped_run_telemetry",
            "_run_time_telemetry",
            "_model_telemetry",
            "_tool_telemetry",
            "_entity_counts",
            "_usage_telemetry",
            "_database_summary",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_full_summary_preserves_admission_queries_close_and_projection(self) -> None:
        result, trace, connection, path = self.invoke()

        self.assertEqual(trace[0], ("safe", path))
        self.assertEqual(
            trace[1],
            (
                "connect",
                f"file:{path}?mode=ro",
                {"uri": True, "timeout": 5.0},
            ),
        )
        self.assertEqual(trace[2], ("row_factory", REPORT.sqlite3.Row))
        self.assertEqual(trace[3], ("execute", "PRAGMA query_only=ON"))
        queries = [item[1] for item in trace if item[0] == "execute"]
        self.assertEqual(queries, list(self.queries()))
        close_index = trace.index(("close",))
        percentile_indexes = [
            index for index, item in enumerate(trace) if item[0] == "percentile"
        ]
        self.assertTrue(percentile_indexes)
        self.assertTrue(all(close_index < index for index in percentile_indexes))
        self.assertIs(connection.row_factory, REPORT.sqlite3.Row)

        self.assertEqual(
            list(result),
            [
                "status_counts",
                "active_stage_counts",
                "active_run_age_seconds",
                "terminal_latency_ms",
                "model_latency_ms",
                "failure_classes",
                "counts",
                "event_counts",
                "model_routes",
                "tool_calls",
                "token_usage",
                "retry_usage",
            ],
        )
        self.assertEqual(
            result["active_run_age_seconds"],
            {"maximum": 120, "count": 1},
        )
        self.assertEqual(
            result["terminal_latency_ms"],
            {"p50": 60_000, "p95": 60_000, "maximum": 60_000},
        )
        self.assertEqual(
            result["model_latency_ms"],
            {"p50": 10, "p95": 10, "maximum": 100},
        )
        self.assertEqual(
            result["failure_classes"],
            [
                {"failure_class": "persistence_or_integrity", "count": 1},
                {"failure_class": "provider_or_model", "count": 1},
            ],
        )
        self.assertEqual(
            result["counts"],
            {
                "runs": 3,
                "events": 4,
                "evidence_refs": 5,
                "hypotheses": 6,
                "decisions": 7,
                "model_calls": 8,
                "tool_calls": 9,
            },
        )
        self.assertEqual(
            result["token_usage"],
            {"available": True, "input_tokens": 111, "output_tokens": 222},
        )
        self.assertEqual(
            result["retry_usage"],
            {"available": True, "retry_attempts": 3},
        )
        self.assertNotIn("provider timeout", json.dumps(result))
        self.assertNotIn("sqlite integrity", json.dumps(result))

    def test_optional_usage_queries_are_absent_without_columns(self) -> None:
        responses = self.queries()
        responses["PRAGMA table_info(harness_model_calls)"] = [(0, "duration_ms")]
        responses.pop(
            "SELECT COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0) FROM harness_model_calls"
        )
        responses.pop(
            "SELECT COALESCE(SUM(MAX(attempt_count - 1, 0)),0) FROM harness_model_calls"
        )
        result, trace, _, _ = self.invoke(responses=responses)
        self.assertEqual(result["token_usage"], {"available": False})
        self.assertEqual(result["retry_usage"], {"available": False})
        queries = [item[1] for item in trace if item[0] == "execute"]
        self.assertNotIn("SUM(input_tokens)", " ".join(queries))
        self.assertNotIn("attempt_count - 1", " ".join(queries))

    def test_safety_and_quick_check_fail_closed_with_exact_connection_boundary(
        self,
    ) -> None:
        path = Path("/synthetic/investigation-harness.sqlite3")
        now = dt.datetime(2026, 8, 5, tzinfo=dt.timezone.utc)
        with (
            mock.patch.object(
                REPORT,
                "safe_regular_file",
                side_effect=RuntimeError("unsafe input"),
            ),
            mock.patch.object(REPORT.sqlite3, "connect") as connect,
            self.assertRaisesRegex(RuntimeError, "unsafe input"),
        ):
            REPORT.summarize_database(path, now)
        connect.assert_not_called()

        trace = []
        responses = self.queries()
        responses["PRAGMA quick_check(1)"] = ("corrupt",)
        connection = Connection(trace, responses)
        with (
            mock.patch.object(REPORT, "safe_regular_file"),
            mock.patch.object(REPORT.sqlite3, "connect", return_value=connection),
            self.assertRaisesRegex(RuntimeError, "quick check failed"),
        ):
            REPORT.summarize_database(path, now)
        self.assertEqual(trace[-1], ("close",))
        self.assertEqual(
            [item[1] for item in trace if item[0] == "execute"],
            ["PRAGMA query_only=ON", "PRAGMA quick_check(1)"],
        )


if __name__ == "__main__":
    unittest.main()
