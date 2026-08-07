#!/usr/bin/env python3
"""Reports asset, compatibility, and deployment contracts."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_reports_assets.py"
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


class DashboardReportsAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = load(MODULE_PATH, "dashboard_reports_assets")
        cls.builder = load(BUILDER_PATH, "dashboard_reports_builder_assets_test")

    def test_builder_reexports_canonical_reports_assets(self) -> None:
        self.assertIs(self.builder.REPORTS_PAGE_ASSETS, self.assets.REPORTS_PAGE_ASSETS)
        self.assertIs(self.builder.inject_reports_assets, self.assets.inject_reports_assets)

    def test_client_preserves_observed_provenance_and_reactive_refresh(self) -> None:
        script = self.assets.REPORTS_PAGE_ASSETS
        for token in (
            "executedModel(current, true)", "agentLabel(log)", "jobLabel(log)",
            "const rows = [...activeRuns, ...historical]",
            "register('llm-analysis-tables'", "intervalMs: 4000",
        ):
            self.assertIn(token, script)

    def test_asset_injection_is_idempotent_and_module_is_bounded(self) -> None:
        shell = "<html><head></head><body></body></html>"
        rendered = self.assets.inject_reports_assets(shell)
        rendered = self.assets.inject_reports_assets(rendered)
        self.assertEqual(rendered.count(self.assets.REPORTS_PAGE_ASSETS), 1)
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 600)

    def test_installer_copies_reports_assets_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_reports_assets.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_reports_assets.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
