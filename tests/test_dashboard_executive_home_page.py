#!/usr/bin/env python3
"""Executive Home view-model, renderer, and deployment contracts."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_executive_home_page.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load():
    spec = importlib.util.spec_from_file_location("dashboard_executive_home_page", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardExecutiveHomePageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = load()

    def view(self):
        donut = (self.page.ExecutiveDonutRowViewModel("High <risk>", 2, "high"),)
        hourly = self.page.ExecutiveHourlyIntakeViewModel(buckets=(
            self.page.ExecutiveHourlyBucketViewModel(
                "2026-08-07T16:00:00Z", "16:00 UTC", 4, True,
            ),
        ), exact=True)
        cache = self.page.ExecutiveCacheViewModel(
            available=True, runtime_available=True, fresh_entries=3,
            stale_entries=1, api_calls_avoided=9, hit_rate="90%",
            provider_loads=1, stale_fallbacks=0, payload_size="1.0 KB",
        )
        return self.page.ExecutiveHomePageViewModel(
            latest_seen="2026-08-07  10:00:00-06:00 <latest>", total_groups=2,
            total_observations=8, urgent_groups=2, suppressed_groups=1,
            analyzed_groups=2, urgent_percent=100, ai_percent=100,
            suppression_percent=50, cache_kpi_label="Cache <hit>",
            cache_kpi_value="90%", cache_kpi_note="9 calls <avoided>",
            severity_rows=donut, status_rows=donut, ai_rows=donut,
            top_rule_rows=(("Rule <one>", 7),), destination_rows=(("1.2.3.4", 7),),
            source_ip_rows=(("10.0.0.1", 7),), source_rows=(("suricata.alert", 2),),
            hourly=hourly, cache=cache,
        )

    def test_page_escapes_runtime_labels_and_renders_all_metric_cards(self) -> None:
        rendered = self.page.render_executive_home(self.view())
        for token in ("Severity mix", "Workflow status", "AI analysis coverage",
                      "Alert intake", "Threat-intel cache", "Top detection families"):
            self.assertIn(token, rendered)
        self.assertIn("High &lt;risk&gt;", rendered)
        self.assertIn("Rule &lt;one&gt;", rendered)
        self.assertIn("Cache &lt;hit&gt;", rendered)
        self.assertNotIn("<latest>", rendered)

    def test_hourly_card_preserves_exact_utc_data_for_local_client(self) -> None:
        rendered = self.page.render_executive_hourly_intake(self.view().hourly)
        self.assertIn('data-hour-start="2026-08-07T16:00:00Z"', rendered)
        self.assertIn('data-current-hour="true"', rendered)
        self.assertIn("Exact committed intake", rendered)
        self.assertIn("current hour is partial", rendered)

    def test_cache_card_distinguishes_durable_and_process_lifetimes(self) -> None:
        rendered = self.page.render_executive_cache(self.view().cache)
        self.assertIn("1.0 KB normalized cache payload", rendered)
        self.assertIn("Since alert-store restart", rendered)
        self.assertIn("Process counters reset when alert-store restarts", rendered)

    def test_module_is_bounded_and_has_no_runtime_io_imports(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 600)
        for forbidden in ("sqlite3", "subprocess", "urllib", "pathlib", "load_hourly_alert_intake"):
            self.assertNotIn(forbidden, source)

    def test_installer_copies_executive_page_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_executive_home_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_executive_home_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
