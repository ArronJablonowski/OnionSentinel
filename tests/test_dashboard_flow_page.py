#!/usr/bin/env python3
"""Contract tests for the analyst-facing Onion Sentinel data-flow page."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
MODULE_PATH = SCRIPT_DIR / "dashboard_flow_page.py"
INSTALLER_PATH = REPO_ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_builder():
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("build_soc_alerts_dashboard", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardFlowPageTests(unittest.TestCase):
    def setUp(self) -> None:
        spec = importlib.util.spec_from_file_location("dashboard_flow_page", MODULE_PATH)
        self.page = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[spec.name] = self.page
        spec.loader.exec_module(self.page)
        self.builder = load_builder()

    def render_flow(self) -> str:
        with (
            mock.patch.object(self.builder, "current_local_ai_model", return_value="test-model:latest"),
            mock.patch.object(self.builder, "count_ai_analysis_artifacts", return_value=0),
            mock.patch.object(
                self.builder,
                "telegram_sent_counts",
                return_value={"critical": 0, "high": 0},
            ),
        ):
            return self.builder.flow_page_section([])

    def test_flow_page_models_independent_alert_and_pcap_data_planes(self) -> None:
        rendered = self.render_flow()

        self.assertIn("Resilient Alert, Evidence & AI Triage Pipeline", rendered)
        self.assertNotIn("Autonomous SIEM Alert Enrichment", rendered)
        self.assertLess(rendered.index("Durable alert intake"), rendered.index("alert-store Commit"))
        self.assertLess(rendered.index("alert-store Commit"), rendered.index("Public lookups"))
        self.assertLess(rendered.index("Security Onion PCAP"), rendered.index("Relay PCAP Broker"))
        self.assertLess(rendered.index("Relay PCAP Broker"), rendered.index("Mac Artifact Intake"))
        self.assertLess(rendered.index("Mac Artifact Intake"), rendered.index("Zeek + TShark"))

        for required_text in (
            "durable SQLite outbox",
            "n8n carries request metadata only",
            "read-only bounded stream",
            "checksum + resumable rsync",
            "raw PCAP removed",
            "parsed PCAP + prior analyses + agent memory",
            "SOC Analyst AI",
        ):
            self.assertIn(required_text, rendered)

    def test_flow_page_keeps_complete_enrichment_catalog_and_outputs(self) -> None:
        rendered = self.render_flow()

        for service in self.builder.ENRICHMENT_FLOW_SERVICES:
            self.assertIn(service["name"], rendered)
        for output in ("SQLite", "AI Reports + Memory", "Onion Sentinel", "Telegram"):
            self.assertIn(output, rendered)
        self.assertEqual(
            self.builder.PAGE_BY_KEY["flow"]["subtitle"],
            "Resilient alert intake, evidence enrichment, and AI triage",
        )

    def test_flow_css_keeps_both_routes_responsive(self) -> None:
        css = self.builder.FLOW_PAGE_CSS

        self.assertIn(".flow-lane-ingress,.flow-lane-pcap", css)
        self.assertIn(".flow-pcap-band", css)
        self.assertIn(".flow-stage-heading", css)

    def test_builder_reexports_bounded_flow_module_assets(self) -> None:
        self.assertIs(self.builder.render_flow_page, self.page.render_flow_page)
        self.assertIs(self.builder.inject_flow_assets, self.page.inject_flow_assets)
        self.assertIs(self.builder.FLOW_PAGE_CSS, self.page.FLOW_PAGE_CSS)
        self.assertIs(self.builder.FLOW_PAGE_JS, self.page.FLOW_PAGE_JS)
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 600)

    def test_flow_view_model_escapes_runtime_labels(self) -> None:
        rendered = self.page.render_flow_page(self.page.FlowPageViewModel(
            analysis_provider="Provider <unsafe>",
            analysis_model='model"unsafe',
            analysis_icon='assets/icon"unsafe.svg',
            total_groups=1,
            total_observations=2,
            ai_coverage=50,
            urgent_groups=1,
            ai_markdown_reports=3,
            ai_json_reports=4,
            telegram_critical=5,
            telegram_high=6,
            enrichment_tiles_html='<article id="owned-tile"></article>',
        ))
        self.assertIn("Provider &lt;unsafe&gt;", rendered)
        self.assertIn("model&quot;unsafe", rendered)
        self.assertIn('assets/icon&quot;unsafe.svg', rendered)
        self.assertIn('<article id="owned-tile"></article>', rendered)

    def test_installer_copies_flow_module_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_flow_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_flow_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
