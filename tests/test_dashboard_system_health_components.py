#!/usr/bin/env python3
"""Regression checks for System Health page controls."""
from __future__ import annotations

import importlib.util
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

    def test_system_health_javascript_is_syntax_valid(self) -> None:
        javascript = self.component.SYSTEM_HEALTH_JS.replace("<script>", "").replace("</script>", "")
        with tempfile.NamedTemporaryFile("w", suffix=".js") as handle:
            handle.write(javascript)
            handle.flush()
            result = subprocess.run(["node", "--check", handle.name], capture_output=True, text=True, check=False)

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
