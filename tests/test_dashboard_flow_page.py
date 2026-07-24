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


if __name__ == "__main__":
    unittest.main()
