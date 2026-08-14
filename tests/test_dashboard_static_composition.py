import sys
from pathlib import Path
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import dashboard_static_composition as composition  # noqa: E402


SHELL = """<!doctype html><html><head>
<title>Old</title><link href="dashboard-metrics.css?v=20260712-responsive-qa">
</head><body><div class="app-shell" data-view="overview">
<nav class="nav">old</nav>
<div class="health" id="system-health-tile" data-health-state="unknown"><span>x</span></div><div class="analyst byline">
<h1 id="page-title">SOC Overview</h1>
<div id="page-subtitle" class="subtitle">Resilient alert intake, evidence enrichment, and AI triage</div>
<section id="overview-view" class="view-section overview-view" aria-label="SOC Alerts overview">overview</section>
<section id="alerts-view" class="view-section alerts-view" aria-label="SOC alert table">alerts</section>
<div class="footer">footer</div>
<script>setView(appShell?.dataset.view||'overview');</script>
</div></body></html>"""


class DashboardStaticCompositionTests(unittest.TestCase):
    def test_common_shell_transformations_preserve_exact_call_order(self) -> None:
        trace = []
        original_sub = composition.re.sub
        original_escape = composition.html.escape

        class Text(str):
            def replace(self, old, new, count=-1):
                trace.append(("replace", old, new, count))
                return Text(super().replace(old, new, count))

        def escape(value, quote=True):
            trace.append(("escape", value, quote))
            return original_escape(value, quote=quote)

        def substitute(pattern, replacement, value, count=0, flags=0):
            trace.append(("sub", pattern, replacement, count, flags))
            return Text(original_sub(pattern, replacement, value, count=count, flags=flags))

        def replace_content(value, replacement):
            trace.append(("replace_content", value, replacement))
            return "FINAL"

        plan = composition.StaticPagePlan(
            page_key="logs",
            title="Logs <live>",
            subtitle="Safe & current",
            navigation_html='<nav class="nav">new</nav>',
            content_html='<section id="logs">content</section>',
        )
        with (
            mock.patch.object(composition.html, "escape", side_effect=escape),
            mock.patch.object(composition.re, "sub", side_effect=substitute),
            mock.patch.object(
                composition,
                "replace_main_page_content",
                side_effect=replace_content,
            ),
        ):
            result = composition.compose_static_page(Text(SHELL), plan)

        self.assertEqual(result, "FINAL")
        self.assertEqual(
            [(event[0],) + event[1:] for event in trace if event[0] in {"escape", "sub", "replace_content"}],
            [
                ("escape", "Logs <live>", True),
                (
                    "sub",
                    r'<title>.*?</title>',
                    '<title>Logs &lt;live&gt; - Onion Sentinel</title>',
                    1,
                    0,
                ),
                (
                    "sub",
                    r'<nav class="nav">.*?</nav>',
                    '<nav class="nav">new</nav>',
                    1,
                    composition.re.S,
                ),
                ("escape", "Logs <live>", True),
                ("escape", "Safe & current", True),
                (
                    "replace_content",
                    mock.ANY,
                    '<section id="logs">content</section>',
                ),
            ],
        )
        replacements = [event for event in trace if event[0] == "replace"]
        self.assertEqual(
            [(old, count) for _, old, _new, count in replacements],
            [
                ("dashboard-metrics.css?v=20260712-responsive-qa", -1),
                ('<div class="app-shell" data-view="overview">', 1),
                ('<div class="health" id="system-health-tile" data-health-state="unknown">', 1),
                ('</span></div><div class="analyst byline">', 1),
                ('<h1 id="page-title">SOC Overview</h1>', 1),
                (
                    '<div id="page-subtitle" class="subtitle">Resilient alert intake, '
                    'evidence enrichment, and AI triage</div>',
                    1,
                ),
                ("setView(appShell?.dataset.view||'overview');", -1),
            ],
        )

    def test_alert_contract_admission_preserves_iteration_and_short_circuit_order(self) -> None:
        trace = []

        class Text(str):
            def replace(self, old, new, count=-1):
                trace.append(("replace", old, str(new), count))
                return Text(super().replace(old, new, count))

            def __contains__(self, value):
                trace.append(("contains", str(value)))
                return super().__contains__(value)

        class Contract(str):
            def __bool__(self):
                trace.append(("contract_bool", str(self)))
                return super().__len__() > 0

            def __add__(self, other):
                trace.append(("contract_add", str(self), other))
                return super().__add__(other)

        class Contracts(tuple):
            def __iter__(self):
                trace.append(("contracts_iter",))
                return super().__iter__()

        first = Contract('<script id="first"></script>')
        empty = Contract("")
        duplicate = Contract('<script id="first"></script>')
        second = Contract('<script id="second"></script>')
        plan = composition.StaticPagePlan(
            page_key="alerts",
            title="Alerts",
            subtitle="Triage",
            navigation_html='<nav class="nav">alerts</nav>',
            alert_contracts=Contracts((first, empty, duplicate, second)),
        )
        original_remove = composition.remove_between_markers

        def remove(value, start, end):
            trace.append(("remove_between", start, end))
            return Text(original_remove(value, start, end))

        with mock.patch.object(
            composition,
            "remove_between_markers",
            side_effect=remove,
        ):
            page = composition.compose_static_page(Text(SHELL), plan)

        self.assertEqual(page.count(first), 1)
        self.assertEqual(page.count(second), 1)
        self.assertEqual(
            [event for event in trace if event[0] in {"remove_between", "contracts_iter", "contract_bool", "contains", "contract_add"}],
            [
                ("remove_between", composition.OVERVIEW_MARKER, composition.ALERTS_MARKER),
                ("contracts_iter",),
                ("contract_bool", str(first)),
                ("contains", str(first)),
                ("contract_add", str(first), "</body>"),
                ("contract_bool", ""),
                ("contract_bool", str(duplicate)),
                ("contains", str(duplicate)),
                ("contract_bool", str(second)),
                ("contains", str(second)),
                ("contract_add", str(second), "</body>"),
            ],
        )

    def test_content_page_escapes_labels_and_replaces_shell_content(self) -> None:
        page = composition.compose_static_page(
            SHELL,
            composition.StaticPagePlan(
                page_key="logs",
                title="Logs <live>",
                subtitle="Safe & current",
                navigation_html='<nav class="nav">new</nav>',
                content_html='<section id="logs">content</section>',
            ),
        )
        self.assertIn("<title>Logs &lt;live&gt; - Onion Sentinel</title>", page)
        self.assertIn("Safe &amp; current", page)
        self.assertIn('<nav class="nav">new</nav>', page)
        self.assertIn('<section id="logs">content</section>', page)
        self.assertNotIn('id="overview-view"', page)
        self.assertNotIn('id="alerts-view"', page)
        self.assertIn('<div class="footer">footer</div>', page)
        self.assertIn('href="system-health.html"', page)
        self.assertIn("static page navigation is rendered server-side", page)

    def test_alert_page_removes_overview_and_injects_each_contract_once(self) -> None:
        contract = '<script id="alert-contract"></script>'
        page = composition.compose_static_page(
            SHELL,
            composition.StaticPagePlan(
                page_key="alerts",
                title="SOC Alerts",
                subtitle="Triage",
                navigation_html='<nav class="nav">alerts</nav>',
                alert_contracts=(contract, contract),
            ),
        )
        self.assertNotIn('id="overview-view"', page)
        self.assertIn('class="view-section alerts-view active"', page)
        self.assertEqual(page.count(contract), 1)
        self.assertIn('data-view="alerts"', page)

    def test_missing_content_fails_closed_for_non_alert_route(self) -> None:
        with self.assertRaisesRegex(ValueError, "missing static page content"):
            composition.compose_static_page(
                SHELL,
                composition.StaticPagePlan(
                    page_key="logs",
                    title="Logs",
                    subtitle="Logs",
                    navigation_html="<nav></nav>",
                ),
            )


if __name__ == "__main__":
    unittest.main()
