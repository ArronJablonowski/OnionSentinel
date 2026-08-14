#!/usr/bin/env python3
"""Regression checks for System Health page controls."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
COMPONENT_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_system_health_components.py"


def load_component():
    spec = importlib.util.spec_from_file_location("dashboard_system_health_components", COMPONENT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DashboardSystemHealthComponentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.component = load_component()

    def test_system_health_page_section_contract_is_exact_and_stable(self) -> None:
        first = self.component.system_health_page_section()
        second = self.component.system_health_page_section()

        self.assertIs(type(first), str)
        self.assertIs(first, second)
        self.assertEqual(str(inspect.signature(self.component.system_health_page_section)), "() -> 'str'")
        self.assertEqual(len(first), 4148)
        self.assertEqual(
            hashlib.sha256(first.encode("utf-8")).hexdigest(),
            "5378cb02f436bcc2d715be7569304eaf2cb877ed14afc17ca76bfc0d2b63ec41",
        )
        self.assertTrue(
            first.startswith(
                '\n    <section class="view-section active system-health-view" aria-label="System Health">'
            )
        )
        self.assertTrue(first.endswith("\n    </section>"))

        ordered_contracts = (
            'id="system-health-refresh"',
            'aria-label="System Health summary"',
            'aria-label="Beacon gaps"',
            'aria-label="PCAP workflow health"',
            'aria-label="Pipeline throughput and backlog"',
            'aria-label="Beacon history"',
            'id="health-beacon-page-size"',
            '<col class="health-col-time">',
            '<col class="health-col-result">',
            '<col class="health-col-stage">',
            '<col class="health-col-relay">',
            '<col class="health-col-alerts">',
            '<col class="health-col-http">',
            '<col class="health-col-details">',
            'id="health-beacon-rows"',
        )
        offsets = tuple(first.index(contract) for contract in ordered_contracts)
        self.assertEqual(offsets, tuple(sorted(offsets)))

    def test_health_tables_expose_page_size_and_pagination_controls(self) -> None:
        html = self.component.system_health_page_section() + self.component.SYSTEM_HEALTH_JS

        for element_id in (
            "health-beacon-page-size",
            "health-beacon-prev",
            "health-beacon-page-label",
            "health-beacon-next",
            "health-pcap-page-size",
            "health-pcap-prev",
            "health-pcap-page-label",
            "health-pcap-next",
        ):
            self.assertIn(element_id, html)

        self.assertIn("beaconPageSize = 25", html)
        self.assertIn("pcapPageSize = 25", html)
        self.assertIn("health-pipeline-details", html)
        self.assertIn("renderPipelineHealth", html)

    def test_system_health_javascript_is_syntax_valid(self) -> None:
        javascript = self.component.SYSTEM_HEALTH_JS.replace("<script>", "").replace("</script>", "")
        with tempfile.NamedTemporaryFile("w", suffix=".js") as handle:
            handle.write(javascript)
            handle.flush()
            result = subprocess.run(["node", "--check", handle.name], capture_output=True, text=True, check=False)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_beacon_result_badges_never_wrap(self) -> None:
        css = self.component.SYSTEM_HEALTH_CSS

        self.assertIn(".health-beacon-table th:nth-child(2),.health-beacon-table td:nth-child(2)", css)
        self.assertIn(".health-beacon-table .health-col-result{width:132px}", css)
        self.assertIn(".health-result{box-sizing:border-box;min-width:104px", css)
        self.assertIn("white-space:nowrap", css)
        self.assertIn("word-break:keep-all", css)

    def test_all_health_tables_have_explicit_column_contracts(self) -> None:
        html = self.component.system_health_page_section() + self.component.SYSTEM_HEALTH_JS
        css = self.component.SYSTEM_HEALTH_CSS

        for table_class in (
            "health-beacon-table",
            "health-pcap-table",
            "health-pipeline-stage-table",
        ):
            self.assertIn(table_class, html)
            self.assertIn(f".{table_class}", css)

        for column_class in (
            "health-col-time",
            "health-col-result",
            "health-col-outcome",
            "health-col-request",
            "health-col-backlog",
            "health-col-drain",
        ):
            self.assertIn(column_class, html)

        self.assertIn(".health-data-table{width:100%;table-layout:fixed}", css)
        self.assertIn(".health-pcap-recent td::before{display:none;content:none}", css)

    def test_mobile_health_table_labels_match_semantic_columns(self) -> None:
        css = self.component.SYSTEM_HEALTH_CSS

        expected_labels = (
            '.system-health-table td:nth-child(3)::before{content:"Stage"}',
            '.system-health-table td:nth-child(4)::before{content:"Relay"}',
            '.system-health-table td:nth-child(5)::before{content:"Alerts"}',
            '.health-pcap-recent td:nth-child(3)::before{content:"Outcome"}',
            '.health-pcap-recent td:nth-child(7)::before{content:"Transfer Time"}',
        )
        for label in expected_labels:
            self.assertIn(label, css)


if __name__ == "__main__":
    unittest.main()
