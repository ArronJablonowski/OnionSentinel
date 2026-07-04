#!/usr/bin/env python3
"""Regression checks for editable SOC settings prompt helpers."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PORTAL_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "report_portal.py"


def load_portal():
    spec = importlib.util.spec_from_file_location("report_portal_settings", PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SocSettingsPromptApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.portal = load_portal()
        self.prompt_path = Path(self.tmp.name) / "config" / "incident_responder_system_prompt.md"
        self.portal.INCIDENT_RESPONDER_PROMPT_FILE = self.prompt_path

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_incident_responder_prompt_save_and_read(self) -> None:
        ok, payload = self.portal.save_incident_responder_prompt("Senior IR responder prompt")

        self.assertTrue(ok)
        self.assertEqual(payload["path"], str(self.prompt_path))
        self.assertEqual(self.prompt_path.read_text(encoding="utf-8"), "Senior IR responder prompt\n")

        read_payload = self.portal.read_incident_responder_prompt()
        self.assertTrue(read_payload["ok"])
        self.assertEqual(read_payload["prompt"], "Senior IR responder prompt\n")

    def test_incident_responder_prompt_rejects_empty_value(self) -> None:
        ok, payload = self.portal.save_incident_responder_prompt("  ")

        self.assertFalse(ok)
        self.assertIn("cannot be empty", payload["error"])
        self.assertFalse(self.prompt_path.exists())


if __name__ == "__main__":
    unittest.main()
