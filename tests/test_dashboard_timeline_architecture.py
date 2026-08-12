from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
TIMELINE_PATH = SCRIPTS / "dashboard_timeline_components.py"


def load_timeline():
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "dashboard_timeline_architecture", TIMELINE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(TIMELINE_PATH.read_text(encoding="utf-8"))
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
            complexity += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
    return target.end_lineno - target.lineno + 1, complexity


def event(**values):
    return {
        "alert_id": "alert:default",
        "timestamp": "2026-07-15T12:00:00-06:00",
        "first_seen": "2026-07-15T12:00:00-06:00",
        "last_seen": "2026-07-15T12:00:00-06:00",
        "seen_count": 1,
        "source_ip": "192.0.2.10",
        "destination_ip": "198.51.100.20",
        "destination_port": "443",
        **values,
    }


class FailingMapping(dict):
    def __init__(self, values, fail_key):
        super().__init__(values)
        self.fail_key = fail_key
        self.trace = []

    def get(self, key, default=None):
        self.trace.append(key)
        if key == self.fail_key:
            raise RuntimeError("synthetic mapping failure")
        return super().get(key, default)


class DashboardTimelineArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.timeline = load_timeline()

    def test_signature_current_debt_module_budget_and_callers_are_exact(self) -> None:
        signature = inspect.signature(self.timeline.alert_seen_timeline_html)
        self.assertEqual(list(signature.parameters), ["row"])
        self.assertEqual(str(signature.return_annotation), "str")
        self.assertEqual(function_metrics("alert_seen_timeline_html"), (171, 45))
        self.assertLessEqual(len(TIMELINE_PATH.read_text().splitlines()), 600)
        factory = (
            SCRIPTS / "dashboard_alert_report_factory.py"
        ).read_text(encoding="utf-8")
        contract = (SCRIPTS / "dashboard_builder_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "from dashboard_timeline_components import alert_seen_timeline_html",
            factory,
        )
        self.assertIn(
            "from dashboard_timeline_components import alert_seen_timeline_html",
            contract,
        )

    def test_empty_invalid_and_timestamp_fallback_filtering_is_exact(self) -> None:
        self.assertEqual(self.timeline.alert_seen_timeline_html({}), "")
        self.assertEqual(
            self.timeline.alert_seen_timeline_html({"member_timeline": []}),
            "",
        )
        row = {
            "member_timeline": [
                None,
                "not-an-event",
                {"alert_id": "invalid", "timestamp": "not-a-time"},
                event(
                    alert_id="alert:last-seen",
                    timestamp="",
                    fired_at="",
                    last_seen="2026-07-15T12:00:01-06:00",
                ),
                event(
                    alert_id="alert:fired-at",
                    timestamp="",
                    fired_at="2026-07-15T12:00:02-06:00",
                ),
            ]
        }
        before = copy.deepcopy(row)
        rendered = self.timeline.alert_seen_timeline_html(row)
        self.assertEqual(row, before)
        self.assertIn("2 alert row(s), 2 observation(s)", rendered)
        self.assertNotIn("invalid", rendered)
        self.assertLess(rendered.index("last-seen"), rendered.index("fired-at"))

    def test_sort_repeat_expansion_short_ids_and_escaping_are_exact(self) -> None:
        malicious = event(
            alert_id='prefix:alert<script>"',
            seen_count="2",
            source_ip='<script>alert("source")</script>',
            destination_ip='198.51.100.20" onmouseover="bad',
            destination_port="<443>",
        )
        row = {"member_timeline": [malicious]}
        before = copy.deepcopy(row)
        rendered = self.timeline.alert_seen_timeline_html(row)
        self.assertEqual(row, before)
        self.assertEqual(rendered.count("<tr data-timeline-row"), 2)
        self.assertIn('data-timeline-index="1"', rendered)
        self.assertIn('data-timeline-index="2"', rendered)
        self.assertIn("observation 1 of 2", rendered)
        self.assertIn("observation 2 of 2", rendered)
        self.assertIn("alert&lt;script&gt;&quot;", rendered)
        self.assertIn("&lt;script&gt;alert(&quot;source&quot;)&lt;/script&gt;", rendered)
        self.assertIn("198.51.100.20&quot; onmouseover=&quot;bad", rendered)
        self.assertNotIn("<script>", rendered)

    def test_marker_bucket_and_burst_labels_preserve_geometry_contract(self) -> None:
        rendered = self.timeline.alert_seen_timeline_html(
            {
                "member_timeline": [
                    event(
                        alert_id="alert:first",
                        timestamp="2026-07-15T12:00:00-06:00",
                    ),
                    event(
                        alert_id="alert:middle",
                        timestamp="2026-07-15T12:00:30-06:00",
                        first_seen="2026-07-15T12:00:30-06:00",
                        last_seen="2026-07-15T12:00:30-06:00",
                    ),
                    event(
                        alert_id="alert:last",
                        timestamp="2026-07-15T14:00:00-06:00",
                        first_seen="2026-07-15T14:00:00-06:00",
                        last_seen="2026-07-15T14:00:00-06:00",
                    ),
                ]
            }
        )
        self.assertIn('class="alert-timeline-marker marker-first"', rendered)
        self.assertIn('class="alert-timeline-marker marker-last"', rendered)
        self.assertIn("<span>First</span>", rendered)
        self.assertIn("<span>Last</span>", rendered)
        self.assertIn('class="alert-timeline-burst"', rendered)
        self.assertIn("Activity burst | events 2 | observations 2", rendered)
        self.assertIn("style=\"left:2.0%;width:4.0%\"", rendered)

    def test_seen_window_duration_and_pagination_boundaries_are_exact(self) -> None:
        twenty_five = self.timeline.alert_seen_timeline_html(
            {"member_timeline": [event(seen_count=25)]}
        )
        self.assertEqual(twenty_five.count("<tr data-timeline-row"), 25)
        self.assertNotIn("alert-timeline-pagination", twenty_five)
        twenty_six = self.timeline.alert_seen_timeline_html(
            {
                "member_timeline": [
                    event(
                        first_seen="2026-07-15T11:59:00-06:00",
                        last_seen="2026-07-15T12:01:00-06:00",
                        seen_count=26,
                    )
                ]
            }
        )
        self.assertEqual(twenty_six.count("<tr data-timeline-row"), 26)
        self.assertIn('data-timeline-page-size="25"', twenty_six)
        self.assertIn('data-timeline-total="26"', twenty_six)
        self.assertIn("Page 1 of 2 · Showing 1-25 of 26", twenty_six)
        self.assertIn("2 minutes, 0 seconds", twenty_six)
        self.assertTrue(twenty_six.startswith("\n<details"))
        self.assertTrue(twenty_six.endswith("</details>\n"))

    def test_row_and_event_get_failures_propagate_without_wrapping(self) -> None:
        row = FailingMapping({}, "member_timeline")
        with self.assertRaisesRegex(
            RuntimeError, "synthetic mapping failure"
        ) as raised:
            self.timeline.alert_seen_timeline_html(row)
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(row.trace, ["member_timeline"])

        bad_event = FailingMapping({}, "first_seen")
        with self.assertRaisesRegex(RuntimeError, "synthetic mapping failure"):
            self.timeline.alert_seen_timeline_html(
                {"member_timeline": [bad_event]}
            )
        self.assertEqual(bad_event.trace, ["first_seen"])

    def test_non_iterable_truthy_timeline_propagates_type_error(self) -> None:
        with self.assertRaisesRegex(TypeError, "not iterable") as raised:
            self.timeline.alert_seen_timeline_html({"member_timeline": 7})
        self.assertIsNone(raised.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
