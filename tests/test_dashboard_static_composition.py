import sys
from pathlib import Path
import unittest


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
