#!/usr/bin/env python3
"""Contracts for the prompt builder's extracted compatibility adapters."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

import prompt_builder_compatibility as compatibility  # noqa: E402


def load_builder():
    path = BIN / "build-ai-investigation-prompt.py"
    spec = importlib.util.spec_from_file_location("prompt_compatibility_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load prompt builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PromptBuilderCompatibilityTests(unittest.TestCase):
    def test_legacy_builder_reexports_compatibility_entry_points(self):
        builder = load_builder()
        names = (
            "alert_group_id",
            "alert_group_key",
            "compact_package_to_budget",
            "incident_prompt_mandatory_grounding_digest",
            "load_json_bounded",
            "project_incident_evidence_hits",
            "project_incident_evidence_osquery_rows",
            "rows",
            "safe_filename",
        )

        for name in names:
            with self.subTest(name=name):
                self.assertIs(getattr(builder, name), getattr(compatibility, name))

    def test_filename_adapter_preserves_timezone_offset(self):
        self.assertEqual(
            compatibility.filename_timestamp("2026-08-08 12:34:56-06:00"),
            "20260808-123456-0600",
        )


if __name__ == "__main__":
    unittest.main()
