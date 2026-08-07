#!/usr/bin/env python3
"""SIEM Engineering asset, compatibility, and deployment contracts."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_siem_engineering_assets.py"
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


class DashboardSiemEngineeringAssetsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.assets = load(MODULE_PATH, "dashboard_siem_engineering_assets")
        cls.builder = load(BUILDER_PATH, "dashboard_siem_engineering_builder_assets_test")

    def test_builder_reexports_canonical_assets(self) -> None:
        self.assertIs(self.builder.SIEM_ENGINEERING_CSS, self.assets.SIEM_ENGINEERING_CSS)
        self.assertIs(
            self.builder.SIEM_ENGINEERING_EXPANSION_CSS,
            self.assets.SIEM_ENGINEERING_EXPANSION_CSS,
        )
        self.assertIs(self.builder.SIEM_ENGINEERING_JS, self.assets.SIEM_ENGINEERING_JS)
        self.assertIs(
            self.builder.inject_siem_engineering_assets,
            self.assets.inject_siem_engineering_assets,
        )

    def test_assets_preserve_report_and_hidden_detail_styles(self) -> None:
        styles = self.assets.SIEM_ENGINEERING_CSS + self.assets.SIEM_ENGINEERING_EXPANSION_CSS
        self.assertIn(".siem-analysis-report", styles)
        self.assertIn(".siem-recommendation-detail[hidden]", styles)

    def test_client_preserves_keyboard_reactive_and_safe_selector_behavior(self) -> None:
        script = self.assets.SIEM_ENGINEERING_JS
        self.assertIn("event.key !== 'Enter' && event.key !== ' '", script)
        self.assertIn("register('siem-engineering-tables'", script)
        self.assertIn("CSS.escape(detailId)", script)

    def test_asset_injection_is_idempotent(self) -> None:
        shell = "<html><head></head><body></body></html>"
        rendered = self.assets.inject_siem_engineering_assets(shell)
        rendered = self.assets.inject_siem_engineering_assets(rendered)
        self.assertEqual(rendered.count(self.assets.SIEM_ENGINEERING_CSS), 1)
        self.assertEqual(rendered.count(self.assets.SIEM_ENGINEERING_EXPANSION_CSS), 1)
        self.assertEqual(rendered.count(self.assets.SIEM_ENGINEERING_JS), 1)
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 600)

    def test_installer_copies_siem_engineering_assets_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_siem_engineering_assets.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_siem_engineering_assets.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
