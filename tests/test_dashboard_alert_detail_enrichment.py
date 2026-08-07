#!/usr/bin/env python3
"""Contracts for public-enrichment alert detail rendering and status."""
from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
ENRICHMENT_PATH = SCRIPTS / "dashboard_alert_detail_enrichment.py"
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


class AlertDetailEnrichmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.enrichment = load_module("dashboard_alert_detail_enrichment", ENRICHMENT_PATH)
        cls.builder = load_module("alert_detail_enrichment_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_enrichment_contract(self) -> None:
        for name in (
            "public_enrichment_has_content",
            "public_enrichment_markdown",
            "public_enrichment_status",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.enrichment, name))

    def test_embedded_records_win_and_stored_records_are_the_fallback(self) -> None:
        embedded = {"records": [{"source": "embedded", "indicator": "1.1.1.1"}]}
        stored = {"external_intel": {"records": [{"source": "stored", "indicator": "2.2.2.2"}]}}
        raw = {"enrichment": {"external_intel": embedded}}
        rendered = self.enrichment.public_enrichment_markdown(raw, json.dumps(stored))
        self.assertIn("embedded", rendered)
        self.assertNotIn("stored", rendered)
        fallback = self.enrichment.public_enrichment_markdown({}, json.dumps(stored))
        self.assertIn("stored", fallback)

    def test_rendered_evidence_escapes_tables_and_includes_limits(self) -> None:
        external = {
            "records": [{
                "source": "vendor|feed",
                "indicator": "example.test",
                "verdict": "review",
                "tags": ["c2", "rare"],
                "cached_at": "2026-07-24T18:30:00Z",
            }],
            "skipped": [{"source": "quota", "reason": "rate limit", "limit_note": "retry later"}],
            "errors": [{"source": "offline", "reason": "timeout"}],
        }
        rendered = self.enrichment.public_enrichment_markdown(
            {"enrichment": {"external_intel": external}}
        )
        self.assertIn("vendor\\|feed", rendered)
        self.assertIn("c2, rare", rendered)
        self.assertNotIn("T18:", rendered)
        self.assertIn("### Skipped / Limits", rendered)
        self.assertIn("rate limit", rendered)
        self.assertIn("timeout", rendered)

    def test_status_contract_covers_each_lifecycle_state(self) -> None:
        cases = (
            ({}, "none"),
            ({"external_intel": {"records": [{}]}}, "enriched"),
            ({"external_intel": {"errors": [{}]}}, "error"),
            ({"external_intel": {"skipped": [{}]}}, "checked"),
            ({"external_intel": {"indicators": {"domains": ["example.test"]}}}, "pending"),
            ({"external_intel": {}}, "none"),
        )
        for record, expected in cases:
            with self.subTest(expected=expected, record=record):
                self.assertEqual(self.enrichment.public_enrichment_status(record)[0], expected)
        self.assertTrue(self.enrichment.public_enrichment_has_content(cases[1][0]))
        self.assertFalse(self.enrichment.public_enrichment_has_content(cases[-1][0]))

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = ENRICHMENT_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 180)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_enrichment.py"), 2)


if __name__ == "__main__":
    unittest.main()
