#!/usr/bin/env python3
"""Contracts for read-only Markdown report discovery and fallback models."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPTS / "dashboard_report_repository.py"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class DashboardReportRepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repository = load_module("dashboard_report_repository", MODULE_PATH)
        cls.builder = load_module("dashboard_report_repository_test_builder", BUILDER_PATH)

    def config(self, *sources: Path):
        return self.repository.ReportRepositoryConfig(
            sources=tuple(sources),
            supported_suffixes=frozenset({".md", ".markdown"}),
            derived_directories=frozenset({"ai-analysis", "pcap-analysis"}),
        )

    def report_text(
        self,
        alert_id: str,
        *,
        severity: str = "HIGH",
        source_ip: str = "10.0.0.10",
        destination_ip: str = "198.51.100.20",
        generated_at: str = "2026-08-01T12:30:00Z",
    ) -> str:
        return f"""---
alert_id: {alert_id}
source_ip: {source_ip}
source_port: 54321
destination_ip: {destination_ip}
destination_port: 443
generated_at: {generated_at}
---

# [{severity}] Example Detection

{{"rule_id":"2100498","rule_name":"Example Rule"}}

Analyst-visible report summary.
"""

    def test_alert_id_extraction_supports_front_matter_bullet_and_json(self) -> None:
        cases = {
            "alert_id: front-matter-id": "front-matter-id",
            "- **Alert ID:** bullet-id": "bullet-id",
            '{"alert_id":"json-id"}': "json-id",
            "No identifier": None,
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(self.repository.extract_markdown_alert_id(text), expected)

    def test_index_preserves_later_source_precedence_and_deduplicates_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            (first / "report.md").write_text(self.report_text("same-id", severity="LOW"), encoding="utf-8")
            winner = second / "report.md"
            winner.write_text(self.report_text("same-id", severity="CRITICAL"), encoding="utf-8")
            indexed = self.repository.index_markdown_reports(
                self.config(first, first, second)
            )

        self.assertEqual(len(indexed), 1)
        self.assertEqual(indexed["same-id"][0], winner)
        self.assertIn("CRITICAL", indexed["same-id"][1])

    def test_hidden_unsupported_derived_and_escaping_paths_are_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reports"
            outside = root / "outside.md"
            source.mkdir()
            outside.write_text(self.report_text("outside"), encoding="utf-8")
            (source / ".hidden.md").write_text(self.report_text("hidden"), encoding="utf-8")
            (source / "ignored.txt").write_text(self.report_text("text"), encoding="utf-8")
            derived = source / "ai-analysis"
            derived.mkdir()
            (derived / "derived.md").write_text(self.report_text("derived"), encoding="utf-8")
            try:
                (source / "escape.md").symlink_to(outside)
            except OSError:
                pass
            primary = source / "primary.md"
            primary.write_text(self.report_text("primary"), encoding="utf-8")
            indexed = self.repository.index_markdown_reports(self.config(source))
            fallback = self.repository.load_markdown_fallback_reports(self.config(source))

        self.assertEqual(set(indexed), {"primary"})
        self.assertEqual([report.source.name for report in fallback], [primary.name])

    def test_fallback_report_parses_identity_endpoints_timestamp_and_severity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            report_path = source / "case.markdown"
            report_path.write_text(self.report_text("case-id", severity="CRITICAL"), encoding="utf-8")
            reports = self.repository.load_markdown_fallback_reports(self.config(source))

        self.assertEqual(len(reports), 1)
        report = reports[0]
        self.assertEqual(report.title, "[CRITICAL] Example Detection")
        self.assertEqual(report.criticality, "Critical")
        self.assertEqual(report.source_ip, "10.0.0.10")
        self.assertEqual(report.source_port, "54321")
        self.assertEqual(report.destination_ip, "198.51.100.20")
        self.assertEqual(report.destination_port, "443")
        self.assertEqual(report.rule_id, "2100498")
        self.assertEqual(report.rule_name, "Example Rule")
        self.assertEqual(report.alert_ts, 1785587400.0)
        self.assertIn("SQLite alert-store is unavailable", report.ai_status_detail)
        self.assertIn("Example Detection", report.rendered_html)

    def test_fallback_reports_sort_by_criticality_then_recency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            low = source / "low.md"
            high_old = source / "high-old.md"
            high_new = source / "high-new.md"
            low.write_text(self.report_text("low", severity="LOW"), encoding="utf-8")
            high_old.write_text(self.report_text("old", severity="HIGH"), encoding="utf-8")
            high_new.write_text(self.report_text("new", severity="HIGH"), encoding="utf-8")
            os.utime(high_old, (1, 1))
            os.utime(high_new, (2, 2))
            reports = self.repository.load_markdown_fallback_reports(self.config(source))

        self.assertEqual([report.source.name for report in reports], ["high-new.md", "high-old.md", "low.md"])

    def test_missing_sources_are_read_only_and_not_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            self.assertEqual(self.repository.index_markdown_reports(self.config(missing)), {})
            self.assertEqual(self.repository.load_markdown_fallback_reports(self.config(missing)), [])
            self.assertFalse(missing.exists())

    def test_builder_reexports_parsers_and_honors_runtime_source_overrides(self) -> None:
        for name in (
            "extract_markdown_alert_id", "clean_title_from_markdown", "detect_criticality",
            "extract_network_endpoints", "extract_rule_identity", "extract_alert_timestamp",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.repository, name))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            path = source / "runtime.md"
            path.write_text(self.report_text("runtime-id"), encoding="utf-8")
            with mock.patch.object(self.builder, "MARKDOWN_SOURCES", (source,)):
                indexed = self.builder.load_markdown_reports_by_alert_id()
                fallback = self.builder.load_markdown_only_reports()
        self.assertEqual(indexed["runtime-id"][0], path)
        self.assertEqual(fallback[0].source, path)

    def test_dead_sqlite_markdown_composer_is_removed(self) -> None:
        self.assertFalse(hasattr(self.builder, "sqlite_report_markdown"))
        self.assertNotIn("def sqlite_report_markdown", BUILDER_PATH.read_text(encoding="utf-8"))

    def test_module_is_bounded_read_only_and_deployed_before_builder(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 280)
        for forbidden in ("sqlite3", "subprocess", "urllib", "mkdir(", "write_text("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_report_repository.py"), 2)
        self.assertLess(
            installer.index("dashboard_alert_report_factory.py"),
            installer.index("dashboard_report_repository.py"),
        )


if __name__ == "__main__":
    unittest.main()
