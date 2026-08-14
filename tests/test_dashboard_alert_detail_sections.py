#!/usr/bin/env python3
"""Contracts for core identity, summary, notes, and raw-log sections."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
SECTIONS_PATH = SCRIPTS / "dashboard_alert_detail_sections.py"
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


class AlertDetailSectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sections = load_module("dashboard_alert_detail_sections", SECTIONS_PATH)
        cls.builder = load_module("alert_detail_sections_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_core_section_contract(self) -> None:
        for name in (
            "CRITICALITY_LABELS",
            "alert_identity_markdown",
            "alert_summary_markdown",
            "analyst_notes_markdown",
            "complete_alert_json_markdown",
            "raw_alert_markdown",
            "raw_logs_markdown",
            "severity_label_from_row",
            "triage_reasons_markdown",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.sections, name))

    def test_severity_and_identity_prefer_authoritative_triage_state(self) -> None:
        row = {
            "triage_level": "high",
            "severity": 3,
            "rule_name": "Example Rule",
            "alert_id": "alert-1",
            "filter_status": "escalated",
            "routing": "incident-response",
            "triage_score": 88,
            "traffic_direction": "outbound",
            "source_ip": "10.0.0.2",
            "source_port": 51515,
            "destination_ip": "203.0.113.8",
            "destination_port": 443,
        }
        identity = self.sections.alert_identity_markdown(
            row,
            "generated_at: 2026-07-24T18:30:00Z",
        )
        self.assertTrue(identity.startswith("# [HIGH] Example Rule"))
        self.assertIn("10.0.0.2:51515 -> 203.0.113.8:443", identity)
        self.assertIn("**Workflow status:** escalated", identity)
        self.assertNotIn("T18:", identity)
        self.assertEqual(self.sections.severity_label_from_row({"severity": 1}), "Critical")

    def test_summary_preserves_zero_counts_and_normalizes_timestamps(self) -> None:
        summary = self.sections.alert_summary_markdown({
            "rule_name": "Rule|Name",
            "seen_count": 0,
            "raw_alert_count": 0,
            "first_seen": "2026-07-24T18:30:00Z",
            "filter_status": "accepted",
        })
        self.assertIn("Rule\\|Name", summary)
        self.assertIn("| Seen count | 0 |", summary)
        self.assertIn("| Grouped alert rows | 0 |", summary)
        self.assertNotIn("T18:", summary)

    def test_summary_preserves_field_and_callback_order(self) -> None:
        row = object()
        values = {
            "rule_name": "rule",
            "event_dataset": "dataset",
            "severity": 0,
            "severity_label": "label",
            "triage_level": "triage",
            "first_seen": "first",
            "last_seen": "last",
            "seen_count": 0,
            "raw_alert_count": 0,
            "source_ip": "source",
            "destination_ip": "destination",
            "destination_port": 0,
            "routing": "route",
            "filter_status": "status",
        }
        trace: list[tuple[object, ...]] = []

        def traced_row_value(candidate: object, key: str, default: object = None) -> object:
            trace.append(("row", candidate, key, default))
            return values.get(key, default)

        def traced_normalize(value: object) -> str:
            trace.append(("normalize", value))
            return f"time:{value}"

        def traced_cell(value: object, max_len: int = 420) -> str:
            trace.append(("cell", value, max_len))
            return f"cell:{value}:{max_len}"

        with (
            mock.patch.object(self.sections, "row_value", side_effect=traced_row_value),
            mock.patch.object(self.sections, "normalize_iso_display_text", side_effect=traced_normalize),
            mock.patch.object(self.sections, "markdown_cell", side_effect=traced_cell),
        ):
            summary = self.sections.alert_summary_markdown(row)

        self.assertEqual(
            summary,
            "\n".join([
                "## Alert Summary", "", "| Field | Value |", "| --- | --- |",
                "| Rule name | cell:rule:240 |",
                "| Event dataset | cell:dataset:160 |",
                "| Severity | cell:0:420 |",
                "| Severity label | cell:label:420 |",
                "| Triage level | cell:triage:420 |",
                "| First seen | cell:time:first:420 |",
                "| Last seen | cell:time:last:420 |",
                "| Seen count | cell:0:420 |",
                "| Grouped alert rows | cell:0:420 |",
                "| Source IP | cell:source:420 |",
                "| Destination IP | cell:destination:420 |",
                "| Destination port | cell:n/a:420 |",
                "| Route | cell:route:420 |",
                "| Filter status | cell:status:420 |",
            ]),
        )
        self.assertEqual(
            trace,
            [
                ("row", row, "rule_name", None), ("cell", "rule", 240),
                ("row", row, "event_dataset", None), ("cell", "dataset", 160),
                ("row", row, "severity", None), ("row", row, "severity", None),
                ("cell", 0, 420),
                ("row", row, "severity_label", None), ("cell", "label", 420),
                ("row", row, "triage_level", None), ("cell", "triage", 420),
                ("row", row, "first_seen", None), ("normalize", "first"),
                ("cell", "time:first", 420),
                ("row", row, "last_seen", None), ("normalize", "last"),
                ("cell", "time:last", 420),
                ("row", row, "seen_count", None), ("row", row, "seen_count", None),
                ("cell", 0, 420),
                ("row", row, "raw_alert_count", "n/a"), ("cell", 0, 420),
                ("row", row, "source_ip", None), ("cell", "source", 420),
                ("row", row, "destination_ip", None), ("cell", "destination", 420),
                ("row", row, "destination_port", None), ("cell", "n/a", 420),
                ("row", row, "routing", None), ("cell", "route", 420),
                ("row", row, "filter_status", None), ("cell", "status", 420),
            ],
        )

    def test_summary_none_paths_read_nullable_fields_once(self) -> None:
        row = object()
        trace: list[tuple[str, object]] = []

        def traced_row_value(candidate: object, key: str, default: object = None) -> object:
            self.assertIs(candidate, row)
            trace.append((key, default))
            return default

        with mock.patch.object(self.sections, "row_value", side_effect=traced_row_value):
            summary = self.sections.alert_summary_markdown(row)

        self.assertIn("| Severity | n/a |", summary)
        self.assertIn("| Seen count | n/a |", summary)
        self.assertEqual(trace.count(("severity", None)), 1)
        self.assertEqual(trace.count(("seen_count", None)), 1)
        self.assertEqual(trace.count(("raw_alert_count", "n/a")), 1)

    def test_identity_preserves_callback_and_conversion_order(self) -> None:
        row = object()
        trace: list[tuple[object, ...]] = []

        class TextProbe:
            def __init__(self, name: str, text: str) -> None:
                self.name = name
                self.text = text

            def __str__(self) -> str:
                trace.append(("str", self.name))
                return self.text

        class SeverityProbe:
            def upper(self) -> str:
                trace.append(("upper",))
                return "HIGH"

        values = {
            "timestamp": "",
            "last_seen": "last",
            "source_ip": TextProbe("source-ip", "10.0.0.1"),
            "source_port": TextProbe("source-port", "1234"),
            "destination_ip": TextProbe("destination-ip", "203.0.113.8"),
            "destination_port": None,
            "filter_status": TextProbe("status", "accepted"),
            "rule_name": "Rule",
            "alert_id": "alert-1",
            "routing": "soc",
            "triage_score": 42,
            "traffic_direction": "outbound",
        }

        def traced_row_value(candidate: object, key: str, default: object = None) -> object:
            trace.append(("row", candidate, key, default))
            return values.get(key, default)

        def traced_search(pattern: str, text: object, *, flags: int = 0) -> None:
            trace.append(("search", pattern, text, flags))
            return None

        def traced_severity(candidate: object) -> SeverityProbe:
            trace.append(("severity", candidate))
            return SeverityProbe()

        def traced_normalize(value: object) -> str:
            trace.append(("normalize", value))
            return f"time:{value}"

        with (
            mock.patch.object(self.sections.re, "search", side_effect=traced_search),
            mock.patch.object(self.sections, "row_value", side_effect=traced_row_value),
            mock.patch.object(self.sections, "severity_label_from_row", side_effect=traced_severity),
            mock.patch.object(self.sections, "normalize_iso_display_text", side_effect=traced_normalize),
        ):
            identity = self.sections.alert_identity_markdown(row, "source")

        self.assertEqual(
            identity,
            "\n".join([
                "# [HIGH] Rule", "",
                "- **Generated:** time:last",
                "- **Alert ID:** alert-1",
                "- **Workflow status:** accepted",
                "- **Filter status:** accepted",
                "- **Route:** soc",
                "- **Score:** 42",
                "- **Direction:** outbound",
                "- **Traffic:** 10.0.0.1:1234 -> 203.0.113.8",
            ]),
        )
        self.assertEqual(
            trace,
            [
                (
                    "search",
                    r"^(?:generated_at:\s*|[-*]\s+\*\*Generated:\*\*\s*)([^\n]+)",
                    "source",
                    self.sections.re.IGNORECASE | self.sections.re.MULTILINE,
                ),
                ("row", row, "timestamp", None),
                ("row", row, "last_seen", None),
                ("row", row, "source_ip", None),
                ("row", row, "source_port", None),
                ("row", row, "destination_ip", None),
                ("row", row, "destination_port", None),
                ("str", "source-ip"),
                ("str", "source-port"),
                ("str", "destination-ip"),
                ("row", row, "filter_status", None),
                ("severity", row),
                ("upper",),
                ("row", row, "rule_name", None),
                ("normalize", "last"),
                ("row", row, "alert_id", None),
                ("str", "status"),
                ("str", "status"),
                ("row", row, "routing", None),
                ("row", row, "triage_score", "n/a"),
                ("row", row, "traffic_direction", None),
            ],
        )

    def test_identity_generated_match_skips_row_timestamp_fallbacks(self) -> None:
        trace: list[tuple[object, ...]] = []

        class GeneratedText(str):
            def strip(self, chars: str | None = None) -> "GeneratedText":
                trace.append(("strip", chars))
                return GeneratedText(super().strip(chars))

        class MatchProbe:
            def group(self, index: int) -> GeneratedText:
                trace.append(("group", index))
                return GeneratedText('  "generated"  ')

        def traced_row_value(row: object, key: str, default: object = None) -> object:
            trace.append(("row", key, default))
            return default

        with (
            mock.patch.object(self.sections.re, "search", return_value=MatchProbe()),
            mock.patch.object(self.sections, "row_value", side_effect=traced_row_value),
            mock.patch.object(self.sections, "normalize_iso_display_text", side_effect=lambda value: str(value)),
        ):
            identity = self.sections.alert_identity_markdown({}, "generated_at: ignored")

        self.assertIn("- **Generated:** generated", identity)
        self.assertEqual(trace[:3], [("group", 1), ("strip", None), ("strip", "\"'")])
        self.assertNotIn(("row", "timestamp", None), trace)
        self.assertNotIn(("row", "last_seen", None), trace)

    def test_triage_notes_and_raw_logs_preserve_legacy_and_ai_evidence(self) -> None:
        triage = self.sections.triage_reasons_markdown(
            {"triage": {"reasons": ["rare destination", "rare destination", "high score"]}},
            {},
        )
        self.assertEqual(triage.count("rare destination"), 1)
        existing = "## Analyst Notes\n\nconfirmed by analyst"
        self.assertEqual(self.sections.analyst_notes_markdown({"analyst notes": existing}), existing)
        raw_logs = self.sections.raw_logs_markdown(
            {"z": 1, "a": 2},
            analysis={"response": {"verdict": "review"}},
            legacy_sections=[("Old Section", "legacy evidence")],
        )
        self.assertLess(raw_logs.index("Legacy Source Content"), raw_logs.index("Complete Alert JSON"))
        self.assertIn("legacy evidence", raw_logs)
        self.assertIn("Complete AI Response JSON", raw_logs)
        self.assertLess(raw_logs.index('"a": 2'), raw_logs.index('"z": 1'))

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = SECTIONS_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 200)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_sections.py"), 2)


if __name__ == "__main__":
    unittest.main()
