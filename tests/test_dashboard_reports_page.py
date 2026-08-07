#!/usr/bin/env python3
"""Reports view-model, provenance, rendering, and deployment contracts."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_reports_page.py"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load(path: Path, name: str):
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardReportsPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = load(MODULE_PATH, "dashboard_reports_page")
        cls.builder = load(BUILDER_PATH, "dashboard_reports_builder_page_test")

    def row(self, **overrides):
        values = dict(
            started="2026-08-07  10:00:00-06:00", alert_count="2",
            rule_name="Alert <name>", route="10.0.0.1 > 1.2.3.4 : 443",
            status_key="running", status_label="Running", agent="SOC Analyst",
            job="SOC alert triage", runtime="1m 2s", gpu_temperature="50.0",
            gpu_utilization="75.0%", cpu_temperature="45.0", soc_temperature="48.0",
            memory="60.0%", power="30.0 W", cpu="20.0%", pcap_size="1.0 MB",
            alert_size="2.0 KB", model="Codex CLI · gpt-5.5 (high)",
            detail="detail <unsafe>", run_kind="second_opinion",
        )
        values.update(overrides)
        return self.page.ReportsLogRowViewModel(**values)

    def current(self, **overrides):
        values = dict(
            title="Current <alert>", route="10.0.0.1 > 1.2.3.4 : 443",
            started="2026-08-07  10:00:00-06:00", running=True,
            status_label="Second-opinion review", agent="Incident Responder",
            job="Incident response investigation", model="Codex CLI · gpt-5.6-sol (xhigh)",
            alert_count="1", queue_size="3",
        )
        values.update(overrides)
        return self.page.ReportsCurrentRunViewModel(**values)

    def test_renderer_escapes_content_and_preserves_observed_provenance(self) -> None:
        rendered = self.page.render_reports_page(self.page.ReportsPageViewModel(
            current=self.current(), rows=(self.row(),), total_runs=4,
        ))
        self.assertIn("Current &lt;alert&gt;", rendered)
        self.assertIn("Alert &lt;name&gt;", rendered)
        self.assertIn("detail &lt;unsafe&gt;", rendered)
        self.assertIn("Codex CLI · gpt-5.6-sol (xhigh)", rendered)
        self.assertIn("Incident Responder", rendered)
        self.assertIn("Incident response investigation", rendered)
        self.assertIn('class="llm-log-second-opinion"', rendered)

    def test_builder_adapter_uses_executed_route_not_configured_model(self) -> None:
        view = self.builder._reports_log_row_view({
            "status": "running", "agent_role": "soc-analyst",
            "model_route": "codex-cli:gpt-5.5:high", "model": "old-local-model",
            "alert": {"rule_name": "Observed rule", "source_ip": "10.0.0.1",
                      "destination_ip": "1.2.3.4", "destination_port": "443"},
        })
        self.assertEqual(view.model, "Codex CLI · gpt-5.5 (high)")
        self.assertEqual(view.agent, "SOC Analyst")
        self.assertEqual(view.job, "SOC alert triage")

    def test_idle_current_panel_does_not_claim_a_running_agent_or_model(self) -> None:
        rendered = self.page.render_reports_current_panel(self.current(
            running=False, status_label="Idle", agent="No agent running",
            job="No active job", model="No model running",
        ))
        self.assertIn("No agent running", rendered)
        self.assertIn("No active job", rendered)
        self.assertIn("No model running", rendered)
        self.assertIn('class="llm-status-badge unknown"', rendered)

    def test_module_is_bounded_and_has_no_runtime_io_imports(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 600)
        for forbidden in ("sqlite3", "subprocess", "urllib", "pathlib", "JsonlLogIndex"):
            self.assertNotIn(forbidden, source)

    def test_installer_copies_reports_page_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_reports_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_reports_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
