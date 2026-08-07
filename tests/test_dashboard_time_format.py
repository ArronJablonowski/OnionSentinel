#!/usr/bin/env python3
"""Contracts for shared dashboard timestamp parsing and display formatting."""
from __future__ import annotations

import datetime as dt
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
TIME_PATH = SCRIPTS / "dashboard_time_format.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardTimeFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.time = load_module("dashboard_time_format", TIME_PATH)
        cls.builder = load_module("dashboard_time_format_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_shared_timestamp_contract(self) -> None:
        for name in (
            "format_project_timestamp",
            "normalize_iso_display_text",
            "parse_iso_datetime",
            "parse_iso_timestamp",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.time, name))

    def test_parser_accepts_z_offsets_spaces_and_naive_values(self) -> None:
        self.assertEqual(
            self.time.parse_iso_datetime("2026-07-24T18:30:00Z"),
            dt.datetime(2026, 7, 24, 18, 30, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(
            self.time.parse_iso_datetime("2026-07-24  12:30:00-06:00").utcoffset(),
            dt.timedelta(hours=-6),
        )
        self.assertEqual(
            self.time.parse_iso_datetime("2026-07-24T18:30:00").tzinfo,
            dt.timezone.utc,
        )
        self.assertIsNone(self.time.parse_iso_datetime("not-a-timestamp"))

    def test_display_normalization_handles_embedded_timestamps(self) -> None:
        source = "started 2026-07-24T18:30:00Z; ended 2026-07-24T18:31:02.125Z"
        rendered = self.time.normalize_iso_display_text(source)
        self.assertNotIn("T18:", rendered)
        self.assertIn("started 2026-07-24", rendered)
        self.assertIn("; ended 2026-07-24", rendered)
        self.assertIn(".125", rendered)

    def test_formatter_preserves_seconds_and_milliseconds_policy(self) -> None:
        seconds = self.time.format_project_timestamp(
            dt.datetime(2026, 7, 24, 18, 30, tzinfo=dt.timezone.utc)
        )
        millis = self.time.format_project_timestamp(
            dt.datetime(2026, 7, 24, 18, 30, 0, 123000, tzinfo=dt.timezone.utc)
        )
        self.assertIn("  ", seconds)
        self.assertNotRegex(seconds, r"\.\d{3}[+-]")
        self.assertRegex(millis, r"\.123[+-]")

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = TIME_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 100)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_time_format.py"), 2)


if __name__ == "__main__":
    unittest.main()
