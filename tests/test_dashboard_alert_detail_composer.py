#!/usr/bin/env python3
"""Contracts for the pure canonical detailed-alert report composer."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
COMPOSER_PATH = SCRIPTS / "dashboard_alert_detail_composer.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AlertDetailComposerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.composer = load_module("dashboard_alert_detail_composer", COMPOSER_PATH)
        cls.builder = load_module("alert_detail_composer_test_builder", BUILDER_PATH)
        cls.layout = sys.modules["dashboard_alert_detail_layout"]

    def test_builder_reexports_the_canonical_composer(self) -> None:
        self.assertIs(
            self.builder.canonical_detail_report_markdown,
            self.composer.canonical_detail_report_markdown,
        )

    def test_every_report_contains_the_exact_versioned_section_order(self) -> None:
        result = self.composer.canonical_detail_report_markdown(
            "",
            {"alert_id": "alert-1", "rule_name": "Example"},
            {},
            None,
            "",
        )
        self.assertEqual(
            self.composer.generated_section_order(result.markdown),
            self.layout.DETAIL_REPORT_SECTION_ORDER,
        )
        self.assertEqual(result.issues, ())
        self.assertIn("No parsed Zeek/TShark PCAP summary", result.markdown)

    def test_legacy_ai_sections_are_fallback_only_and_unknown_content_is_preserved(self) -> None:
        source = (
            "## AI Analysis Output\n\nlegacy analysis\n\n"
            "## AI Model Used\n\nlegacy model\n\n"
            "## Vendor Extension\n\nlegacy vendor evidence"
        )
        fallback = self.composer.canonical_detail_report_markdown(
            source,
            {"alert_id": "alert-1"},
            {},
            None,
            "",
        )
        self.assertIn("legacy analysis", fallback.markdown)
        self.assertIn("legacy model", fallback.markdown)
        self.assertIn("legacy vendor evidence", fallback.markdown)
        self.assertTrue(any("Vendor Extension" in issue for issue in fallback.issues))

        current = self.composer.canonical_detail_report_markdown(
            source,
            {"alert_id": "alert-1"},
            {},
            {"response": {"bluf": "current analysis"}},
            "",
        )
        self.assertIn("current analysis", current.markdown)
        self.assertNotIn("legacy analysis", current.markdown)

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = COMPOSER_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 130)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_composer.py"), 2)


if __name__ == "__main__":
    unittest.main()
