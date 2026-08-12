import ast
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/report-production-soak.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_module():
    spec = importlib.util.spec_from_file_location("production_soak_summary", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self) -> None:
            self.value = 1

        def visit_FunctionDef(self, node) -> None:
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node) -> None:
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node) -> None:
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node) -> None:
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_IfExp(self, node) -> None:
            self.value += 1
            self.generic_visit(node)

        def visit_ListComp(self, node) -> None:
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_ListComp
        visit_DictComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class ProductionSoakSummaryCharacterizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_module()

    @staticmethod
    def local_text(value: dt.datetime) -> str:
        return value.astimezone().replace(microsecond=0).isoformat().replace("T", "  ")

    @staticmethod
    def sample(
        when: dt.datetime,
        *,
        healthy_since: object,
        ok: object = True,
        failures: object = None,
        signals: object = None,
    ) -> dict[str, object]:
        return {
            "generated_at": when.isoformat().replace("T", "  "),
            "ok": ok,
            "failures": [] if failures is None else failures,
            "signals": {} if signals is None else signals,
            "soak": {"healthy_since": healthy_since},
        }

    def test_empty_and_last_sample_without_clock_return_exact_failures(self):
        self.assertEqual(
            self.module.summarize([]),
            {
                "status": "failed",
                "qualified": False,
                "reason": "no valid SLO samples",
                "sample_count": 0,
            },
        )
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        samples = [
            self.sample(start, healthy_since=start.isoformat()),
            self.sample(start + dt.timedelta(minutes=5), healthy_since=""),
        ]
        self.assertEqual(
            self.module.summarize(samples),
            {
                "status": "failed",
                "qualified": False,
                "reason": "current healthy soak clock is not running",
                "sample_count": 2,
            },
        )

    def test_summary_phases_meet_architecture_contract(self):
        self.assertLessEqual(len(SCRIPT.read_text().splitlines()), 250)
        for name in (
            "_current_healthy_since",
            "_soak_window",
            "_window_metrics",
            "_window_failures",
            "_signal_maxima",
            "_qualification_status",
            "summarize",
        ):
            lines, complexity = function_metrics(name)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "n8n/bin/report-production-soak.py::summarize",
            baseline["functions"],
        )

    def test_window_metrics_failures_maxima_and_field_order_are_exact(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        clock = start.isoformat()
        samples = [
            self.sample(
                start - dt.timedelta(minutes=5),
                healthy_since=clock,
                ok=False,
                failures=["pre-window"],
                signals={"ignored": 999},
            ),
            self.sample(
                start,
                healthy_since=clock,
                signals={"a": 1, "boolish": False, "text": "x", "none": None, "nested": {}},
            ),
            self.sample(
                start + dt.timedelta(minutes=5),
                healthy_since=clock,
                ok=False,
                failures=["z", "a", "z"],
                signals={"a": 2.5, "boolish": True, "extra": -4},
            ),
            self.sample(
                start + dt.timedelta(minutes=20),
                healthy_since=clock,
                failures=["ignored because sample is healthy"],
                signals={"a": -1, "extra": -2},
            ),
        ]
        original = copy.deepcopy(samples)

        summary = self.module.summarize(samples, required_hours=1)

        self.assertEqual(samples, original)
        self.assertEqual(
            list(summary),
            [
                "status",
                "qualified",
                "healthy_since",
                "first_sample",
                "last_sample",
                "required_hours",
                "elapsed_seconds",
                "remaining_seconds",
                "sample_count",
                "expected_sample_count",
                "sample_coverage_percent",
                "max_sample_gap_seconds",
                "failed_sample_count",
                "failure_reasons",
                "signal_maxima",
            ],
        )
        self.assertEqual(
            summary,
            {
                "status": "failed",
                "qualified": False,
                "healthy_since": self.local_text(start),
                "first_sample": self.local_text(start),
                "last_sample": self.local_text(start + dt.timedelta(minutes=20)),
                "required_hours": 1,
                "elapsed_seconds": 1200,
                "remaining_seconds": 2400,
                "sample_count": 3,
                "expected_sample_count": 5,
                "sample_coverage_percent": 60.0,
                "max_sample_gap_seconds": 900,
                "failed_sample_count": 1,
                "failure_reasons": ["a", "z"],
                "signal_maxima": {
                    "a": 2.5,
                    "boolish": True,
                    "extra": -2,
                    "nested": None,
                    "none": None,
                    "text": None,
                },
            },
        )

    def test_status_policy_preserves_duration_coverage_and_gap_edges(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        clock = start.isoformat()
        sparse = [
            self.sample(start, healthy_since=clock),
            self.sample(start + dt.timedelta(hours=1), healthy_since=clock),
        ]
        sparse_summary = self.module.summarize(sparse, required_hours=48)
        self.assertEqual(sparse_summary["status"], "in_progress")
        self.assertEqual(sparse_summary["sample_coverage_percent"], 15.4)
        self.assertEqual(sparse_summary["max_sample_gap_seconds"], 3600)

        twelve = [
            self.sample(start + dt.timedelta(seconds=(3600 * index / 11)), healthy_since=clock)
            for index in range(12)
        ]
        qualified = self.module.summarize(twelve, required_hours=1)
        self.assertEqual(qualified["status"], "passed")
        self.assertTrue(qualified["qualified"])
        self.assertEqual(qualified["sample_coverage_percent"], 92.3)
        self.assertLessEqual(qualified["max_sample_gap_seconds"], 720)

        eleven = [
            self.sample(start + dt.timedelta(seconds=(3600 * index / 10)), healthy_since=clock)
            for index in range(11)
        ]
        insufficient = self.module.summarize(eleven, required_hours=1)
        self.assertEqual(insufficient["status"], "failed")
        self.assertFalse(insufficient["qualified"])
        self.assertEqual(insufficient["sample_coverage_percent"], 84.6)

    def test_public_required_hours_zero_retains_current_policy(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        summary = self.module.summarize(
            [self.sample(start, healthy_since=start.isoformat())],
            required_hours=0,
        )
        self.assertEqual(summary["status"], "passed")
        self.assertTrue(summary["qualified"])
        self.assertEqual(summary["remaining_seconds"], 0)

    def test_future_clock_and_invalid_window_timestamp_keep_exceptions(self):
        start = dt.datetime(2026, 7, 14, tzinfo=dt.timezone.utc)
        with self.assertRaises(IndexError):
            self.module.summarize(
                [self.sample(start, healthy_since=(start + dt.timedelta(hours=1)).isoformat())]
            )

        invalid = self.sample(start, healthy_since=start.isoformat())
        invalid["generated_at"] = "not-a-timestamp"
        with self.assertRaises(TypeError):
            self.module.summarize([invalid])


if __name__ == "__main__":
    unittest.main()
