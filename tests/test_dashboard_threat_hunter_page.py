#!/usr/bin/env python3
"""Threat Hunter page, query, compatibility, and deployment contracts."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_threat_hunter_page.py"
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


class DashboardThreatHunterPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = load(MODULE_PATH, "dashboard_threat_hunter_page")
        cls.builder = load(BUILDER_PATH, "dashboard_threat_hunter_builder_test")

    def candidate(self, **overrides):
        values = dict(
            digest="hunt<&>", rule_name='Rule "A" detection', title="Fallback title",
            source_ip="10.0.0.1", destination_ip="1.2.3.4",
            destination_port="443", alert_source="suricata.alert",
            criticality="High", criticality_rank=4, repeat_count=7,
            first_seen="2026-08-07T11:00:00Z",
            last_seen="2026-08-07T12:00:00Z",
            hypothesis="Review <endpoint> context",
        )
        values.update(overrides)
        return self.page.ThreatHuntCandidateViewModel(**values)

    def test_query_generation_preserves_bounded_security_pivots(self) -> None:
        kql, oql, osquery = self.page.threat_hunt_queries(self.candidate())
        self.assertEqual(
            kql,
            'rule.name : "Rule \\"A\\" detection" and event.dataset : "suricata.alert" and '
            'source.ip : "10.0.0.1" and destination.ip : "1.2.3.4" and destination.port : 443',
        )
        self.assertIn('rule.name == "Rule \\"A\\" detection" AND event.dataset == "suricata.alert"', oql)
        self.assertIn("remote_address = '1.2.3.4' AND remote_port = 443", osquery)
        self.assertIn("FROM process_open_sockets AS pos", osquery)

    def test_renderer_escapes_candidate_content_and_keeps_copy_controls(self) -> None:
        rendered = self.page.render_threat_hunter_page([self.candidate()])
        self.assertIn('data-hunt-key="hunt&lt;&amp;&gt;"', rendered)
        self.assertIn('Rule &quot;A&quot; detection', rendered)
        self.assertIn('Review &lt;endpoint&gt; context', rendered)
        self.assertEqual(rendered.count('data-copy-target='), 3)
        self.assertIn('Security Onion OQL', rendered)
        self.assertIn('OSQuery', rendered)

    def test_builder_reexports_assets_and_compatibility_helpers(self) -> None:
        self.assertIs(self.builder.THREAT_HUNTER_CSS, self.page.THREAT_HUNTER_CSS)
        self.assertIs(self.builder.THREAT_HUNTER_JS, self.page.THREAT_HUNTER_JS)
        self.assertIs(self.builder.threat_hunt_code_block, self.page.threat_hunt_code_block)
        self.assertIn("inject_threat_hunter_page_assets", self.builder.inject_threat_hunter_assets.__code__.co_names)
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 600)

    def test_client_preserves_accessible_expansion_copy_and_reactive_state(self) -> None:
        script = self.page.THREAT_HUNTER_JS
        self.assertIn("navigator.clipboard.writeText", script)
        self.assertIn("event.key !== 'Enter' && event.key !== ' '", script)
        self.assertIn("register('threat-hunter-tables'", script)
        self.assertIn("CSS.escape(key)", script)

    def test_installer_copies_threat_hunter_module_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_threat_hunter_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_threat_hunter_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
