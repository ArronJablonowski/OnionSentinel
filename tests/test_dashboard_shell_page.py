#!/usr/bin/env python3
"""Contracts for the immutable generated-dashboard shell renderer."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
SHELL_PATH = SCRIPTS / "dashboard_shell_page.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardShellPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shell = load_module("dashboard_shell_page", SHELL_PATH)
        cls.builder = load_module("dashboard_shell_test_builder", BUILDER_PATH)

    def test_renderer_substitutes_each_explicit_view_model_field(self) -> None:
        view = self.shell.DashboardShellViewModel(
            navigation_html="<nav>unit navigation</nav>",
            overview_html="<section>unit overview</section>",
            metrics_html="<section>unit metrics</section>",
            alert_table_html="<table>unit table</table>",
            generated_at="unit generated",
            database_path="~/unit.sqlite3",
            source_directory="~/unit reports",
            adjudication_modal_html="<dialog>unit adjudication</dialog>",
        )
        page = self.shell.render_dashboard_shell(view)
        for expected in (
            "unit navigation",
            "unit overview",
            "unit metrics",
            "unit table",
            "unit generated",
            "~/unit.sqlite3",
            "~/unit reports",
            "unit adjudication",
        ):
            self.assertIn(expected, page)
        self.assertNotIn("__ONION_SENTINEL_", page)

    def test_builder_uses_canonical_shell_renderer(self) -> None:
        self.assertIs(self.builder.render_dashboard_shell, self.shell.render_dashboard_shell)
        self.assertIs(self.builder.DashboardShellViewModel, self.shell.DashboardShellViewModel)
        page = self.builder.build_html([])
        self.assertTrue(page.startswith('<!doctype html><html lang="en">'))
        self.assertTrue(page.endswith("</body></html>"))
        self.assertNotIn("__ONION_SENTINEL_", page)

    def test_shell_preserves_security_and_live_data_contracts(self) -> None:
        source = self.shell.DASHBOARD_SHELL_TEMPLATE
        self.assertIn(
            "fetch('/api/soc-alerts/status',{method:'POST',headers:{'Content-Type':'application/json'}",
            source,
        )
        self.assertIn("encodeURIComponent(id)", source)
        self.assertIn("new EventSource('/api/soc-alerts/events')", source)
        self.assertIn("return `/api/soc-alerts?${params.toString()}`", source)
        self.assertIn("/api/soc-alerts/status", source)
        self.assertIn('id="suppress-modal"', source)
        self.assertIn('role="dialog" aria-modal="true"', source)

    def test_shell_is_bounded_pure_and_deployed_once(self) -> None:
        source = SHELL_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 600)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home"):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_shell_page.py"), 2)


if __name__ == "__main__":
    unittest.main()
