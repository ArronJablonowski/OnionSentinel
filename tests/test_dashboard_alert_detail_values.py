#!/usr/bin/env python3
"""Contracts for pure alert-detail values and Markdown-table primitives."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
VALUES_PATH = SCRIPTS / "dashboard_alert_detail_values.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class MappingRow:
    def __init__(self, values: dict[str, object]) -> None:
        self.values = values

    def __getitem__(self, key: str) -> object:
        if key not in self.values:
            raise IndexError(key)
        return self.values[key]


class AlertDetailValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.values = load_module("dashboard_alert_detail_values", VALUES_PATH)
        cls.builder = load_module("alert_detail_values_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_pure_value_contract(self) -> None:
        for name in (
            "detail_table",
            "json_object",
            "markdown_cell",
            "nested_object",
            "nested_value",
            "present_values",
            "raw_event_for_details",
            "row_value",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.values, name))

    def test_row_and_json_access_are_total_for_expected_inputs(self) -> None:
        self.assertEqual(self.values.json_object('{"answer": 42}'), {"answer": 42})
        self.assertEqual(self.values.json_object("[1, 2]"), {})
        self.assertEqual(self.values.json_object("not-json"), {})
        self.assertEqual(self.values.row_value({"answer": 42}, "answer"), 42)
        self.assertEqual(self.values.row_value(MappingRow({"answer": 42}), "answer"), 42)
        self.assertEqual(self.values.row_value(MappingRow({}), "missing", "fallback"), "fallback")

    def test_nested_access_and_raw_event_fallback_preserve_types(self) -> None:
        raw_event = {"event": {"dataset": "suricata.alert"}, "count": 3}
        raw = {"security_onion": {"raw_event": raw_event}}
        self.assertIs(self.values.raw_event_for_details(raw), raw_event)
        self.assertEqual(self.values.nested_value(raw, "security_onion", "raw_event", "count"), "3")
        self.assertEqual(
            self.values.nested_object(raw, "security_onion", "raw_event", "event"),
            {"dataset": "suricata.alert"},
        )
        fallback = {"security_onion": {}}
        self.assertIs(self.values.raw_event_for_details(fallback), fallback)

    def test_markdown_cells_escape_tables_and_bound_large_values(self) -> None:
        rendered = self.values.markdown_cell({"pipe": "a|b", "lines": "one\ntwo"}, max_len=80)
        self.assertIn("\\|", rendered)
        self.assertNotIn("\n", rendered)
        self.assertLessEqual(len(rendered), 80)
        self.assertTrue(self.values.markdown_cell("x" * 20, max_len=8).endswith("…"))
        self.assertEqual(self.values.markdown_cell(None), "")

    def test_detail_table_omits_empty_values_without_losing_zero(self) -> None:
        lines = self.values.detail_table("Evidence", [("Empty", None), ("Count", 0)])
        markdown = "\n".join(lines)
        self.assertIn("## Evidence", markdown)
        self.assertIn("| Count | 0 |", markdown)
        self.assertNotIn("Empty", markdown)
        self.assertEqual(self.values.present_values(None, "", 0, False, "value"), [0, False, "value"])

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = VALUES_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 150)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_values.py"), 2)


if __name__ == "__main__":
    unittest.main()
