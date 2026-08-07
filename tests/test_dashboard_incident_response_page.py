#!/usr/bin/env python3
"""Characterization and deployment tests for the Incident Responder page."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
MODULE_PATH = SCRIPT_DIR / "dashboard_incident_response_page.py"
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


class DashboardIncidentResponsePageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = load(MODULE_PATH, "dashboard_incident_response_page")
        cls.builder = load(BUILDER_PATH, "dashboard_incident_response_builder_test")
        cls.rendered = cls.page.incident_response_page_section()

    def test_builder_reexports_the_page_renderer(self) -> None:
        self.assertIs(
            self.builder.incident_response_page_section,
            self.page.incident_response_page_section,
        )

    def test_page_preserves_case_queue_and_reanalysis_contracts(self) -> None:
        for required in (
            'id="incident-response-view"',
            'id="ir-table-body"',
            'id="ir-mobile-list"',
            'id="ir-reanalyze-all"',
            '/api/soc-incidents?${params}',
            '/api/soc-incidents/reanalysis-runs${query}',
            '/api/soc-incidents/reanalyze-all',
            '/api/soc-incidents/${encodeURIComponent(caseId)}/reanalyze',
            '/api/soc-incidents/${encodeURIComponent(item.case_id)}/detail',
            "window.OnionSentinelReactiveTables.register('incident-response-cases'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.rendered)
        self.assertEqual(self.rendered.count("<script>"), 1)
        self.assertEqual(self.rendered.count("</script>"), 1)

    def test_page_preserves_evidence_and_accessibility_controls(self) -> None:
        for required in (
            'aria-label="Incident response cases"',
            'aria-live="polite"',
            "button.className='ir-query-copy'",
            "details.className='ir-query-details'",
            "navigator.clipboard.writeText",
            "document.addEventListener('onion-sentinel:adjudicated'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.rendered)

    def test_module_is_bounded_and_installed_once(self) -> None:
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 600)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_incident_response_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_incident_response_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
