#!/usr/bin/env python3
"""Contracts for visibility-aware live updates on every dashboard table page."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
REACTIVE_PATH = ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_reactive_tables.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_builder():
    spec = importlib.util.spec_from_file_location("reactive_table_test_builder", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ReactiveTablePageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = load_builder()
        cls.shell = cls.builder.build_html([])

    def render(self, page: str) -> str:
        return self.builder.render_static_page(self.shell, page, [])

    def test_shared_runtime_is_visibility_aware_and_prevents_overlap(self) -> None:
        source = REACTIVE_PATH.read_text(encoding="utf-8")

        self.assertIn("if (!job || job.running || document.hidden) return false", source)
        self.assertIn("document.addEventListener('visibilitychange'", source)
        self.assertIn("window.addEventListener('focus'", source)
        self.assertIn("window.addEventListener('online'", source)
        self.assertIn("job.nextAt = now() + job.intervalMs", source)
        self.assertIn("onion-sentinel:reactive-update", source)
        self.assertIn("onion-sentinel:reactive-error", source)
        self.assertIn("id = 'onion-sentinel-live-status'", source)

    def test_every_page_with_a_table_registers_a_live_data_job(self) -> None:
        expected_jobs = {
            "alerts": "soc-alerts-live-stream",
            "investigations": "incident-response-cases",
            "asset_inventory": "asset-inventory-tables",
            "system_health": "system-health-tables",
            "siem_engineering": "siem-engineering-tables",
            "threat_hunter": "threat-hunter-tables",
            "reports": "llm-analysis-tables",
        }
        for page_key, job_name in expected_jobs.items():
            with self.subTest(page=page_key):
                page = self.render(page_key)
                self.assertIn("<table", page)
                self.assertIn(job_name, page)
                self.assertIn("window.OnionSentinelReactiveTables", page)
                self.assertIn("onion-sentinel-live-status", page)

    def test_incident_refresh_preserves_sort_paging_and_expanded_case(self) -> None:
        page = self.render("investigations")

        self.assertIn("const expandedCase=openCase", page)
        self.assertIn("incidents.some(item=>item.case_id===expandedCase)", page)
        self.assertIn("void toggleCase(expandedCase)", page)
        self.assertIn("if(loadPromise)return loadPromise", page)
        self.assertIn("sort:sortKey,direction:sortDirection", page)
        self.assertIn("incidentCanRefresh", page)
        self.assertIn("analyst-adjudication-modal", page)

    def test_asset_and_report_refreshes_keep_existing_controls(self) -> None:
        asset_page = self.render("asset_inventory")
        report_page = self.render("reports")

        self.assertIn("if(assetLoadPromise)return assetLoadPromise", asset_page)
        self.assertIn("if(dhcpLoadPromise)return dhcpLoadPromise", asset_page)
        self.assertIn("search.addEventListener('input',render)", asset_page)
        self.assertIn("Promise.all([load(),loadDhcp()])", asset_page)
        self.assertIn("loadLogs(false)", report_page)
        self.assertIn("Promise.all([loadCurrent(), loadLogs(false)])", report_page)

    def test_report_derived_tables_soft_refresh_and_restore_expansion(self) -> None:
        siem_page = self.render("siem_engineering")
        hunt_page = self.render("threat_hunter")

        self.assertIn("refreshFragment('.siem-engineering-view'", siem_page)
        self.assertIn("aria-controls", siem_page)
        self.assertIn("detail.hidden = false", siem_page)
        self.assertIn("refreshFragment('.threat-hunter-view'", hunt_page)
        self.assertIn("data-hunt-key=", hunt_page)
        self.assertIn("row.setAttribute('aria-expanded', 'true')", hunt_page)

    def test_installer_copies_the_reactive_runtime(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_reactive_tables.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_reactive_tables.py"',
            installer,
        )


if __name__ == "__main__":
    unittest.main()
