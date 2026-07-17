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
        self.memory_dir = Path(self.tmp.name) / "agent-memory"
        self.memory_dir.mkdir()
        self.portal.AGENT_MEMORY_DIR = self.memory_dir
        self.portal.SOC_ANALYST_MEMORY_FILE = self.memory_dir / "soc-analyst-memory.md"
        self.portal.SHARED_AGENT_MEMORY_FILE = self.memory_dir / "shared-agent-memory.md"

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

    def test_agent_memory_read_is_allowlisted_and_read_only(self) -> None:
        self.portal.SOC_ANALYST_MEMORY_FILE.write_text("# SOC Analyst Memory\n\nKnown pattern.\n", encoding="utf-8")

        status, payload = self.portal.read_agent_memory("soc-analyst")

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["read_only"])
        self.assertEqual(payload["label"], "SOC Analyst Memory")
        self.assertIn("Known pattern.", payload["content"])
        self.assertIn("  ", payload["modified_at"])

    def test_agent_memory_rejects_unknown_and_path_like_keys(self) -> None:
        for key in ("unknown", "../config/secrets", "/etc/passwd"):
            status, payload = self.portal.read_agent_memory(key)
            self.assertEqual(status, 400)
            self.assertFalse(payload["ok"])

    def test_agent_memory_rejects_symlink_escape(self) -> None:
        outside = Path(self.tmp.name) / "outside.md"
        outside.write_text("outside", encoding="utf-8")
        self.portal.SOC_ANALYST_MEMORY_FILE.symlink_to(outside)

        status, payload = self.portal.read_agent_memory("soc-analyst")

        self.assertEqual(status, 403)
        self.assertFalse(payload["ok"])

    def test_agent_memory_enforces_view_size_limit(self) -> None:
        self.portal.AGENT_MEMORY_VIEW_MAX_BYTES = 8
        self.portal.SHARED_AGENT_MEMORY_FILE.write_text("too much memory", encoding="utf-8")

        status, payload = self.portal.read_agent_memory("shared")

        self.assertEqual(status, 413)
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
