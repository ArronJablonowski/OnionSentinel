#!/usr/bin/env python3
"""Contracts for structured Security Onion alert evidence sections."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
EVIDENCE_PATH = SCRIPTS / "dashboard_alert_detail_evidence.py"
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


class AlertDetailEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.evidence = load_module("dashboard_alert_detail_evidence", EVIDENCE_PATH)
        cls.builder = load_module("alert_detail_evidence_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_structured_evidence_contract(self) -> None:
        for name in (
            "alert_detail_markdown",
            "detail_section_markdown",
            "standard_alert_detail_sections",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.evidence, name))

    def test_standard_sections_are_fixed_and_complete(self) -> None:
        sections = self.evidence.standard_alert_detail_sections({})
        self.assertEqual(
            tuple(sections),
            (
                "security onion detail fields",
                "network and flow details",
                "protocol details",
                "host and sensor details",
                "threat context",
            ),
        )
        for section in sections.values():
            self.assertIn("No additional", section)

    def test_preserved_raw_event_and_normalized_fields_are_both_used(self) -> None:
        raw = {
            "network": {"transport": "tcp"},
            "source": {"asn": 64512, "org": "Example Org"},
            "security_onion": {
                "enrichment_note": "known lab service",
                "raw_event": {
                    "event": {"action": "allowed"},
                    "network": {"direction": "outbound"},
                    "suricata": {"eve": {"app_proto": "tls"}},
                },
            },
        }
        sections = self.evidence.standard_alert_detail_sections(raw)
        self.assertIn("| Transport | tcp |", sections["network and flow details"])
        self.assertIn("| Direction | outbound |", sections["network and flow details"])
        self.assertIn("| Application protocol | tls |", sections["network and flow details"])
        self.assertIn("64512", sections["network and flow details"])
        self.assertIn("| Event action | allowed |", sections["security onion detail fields"])
        self.assertIn("known lab service", sections["threat context"])

    def test_compatibility_report_keeps_the_established_section_order(self) -> None:
        markdown = self.evidence.alert_detail_markdown({})
        headings = [line for line in markdown.splitlines() if line.startswith("## ")]
        self.assertEqual(
            headings,
            [
                "## Network And Flow Details",
                "## Protocol Details",
                "## Host And Sensor Details",
                "## Threat Context",
                "## Security Onion Detail Fields",
            ],
        )

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = EVIDENCE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 200)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_evidence.py"), 2)


if __name__ == "__main__":
    unittest.main()
