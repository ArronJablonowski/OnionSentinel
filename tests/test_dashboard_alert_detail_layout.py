#!/usr/bin/env python3
"""Contracts for canonical alert-detail layout and legacy normalization."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
LAYOUT_PATH = SCRIPTS / "dashboard_alert_detail_layout.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AlertDetailLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.layout = load_module("dashboard_alert_detail_layout", LAYOUT_PATH)
        cls.builder = load_module("alert_detail_layout_test_builder", BUILDER_PATH)

    def test_builder_reexports_the_canonical_layout_contract(self) -> None:
        for name in (
            "DetailLayoutResult",
            "demote_markdown_headings",
            "normalized_heading_text",
            "split_detail_source_sections",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.layout, name))
        self.assertIs(
            self.builder.DETAIL_REPORT_SECTION_ORDER,
            self.layout.DETAIL_REPORT_SECTION_ORDER,
        )

    def test_section_contract_has_one_fixed_analyst_facing_order(self) -> None:
        self.assertEqual(self.layout.DETAIL_REPORT_SECTION_ORDER[0], "triage reasons")
        self.assertEqual(self.layout.DETAIL_REPORT_SECTION_ORDER[-1], "raw logs")
        self.assertLess(
            self.layout.DETAIL_REPORT_SECTION_ORDER.index("ai analysis output"),
            self.layout.DETAIL_REPORT_SECTION_ORDER.index("ai model used"),
        )
        self.assertEqual(
            len(self.layout.DETAIL_REPORT_SECTION_ORDER),
            len(set(self.layout.DETAIL_REPORT_SECTION_ORDER)),
        )

    def test_unknown_and_duplicate_sections_are_preserved_under_raw_logs(self) -> None:
        sections, legacy, issues = self.layout.split_detail_source_sections(
            "## Alert Summary\nfirst\n\n"
            "## Unknown Vendor Section\n### Child\nunknown body\n\n"
            "## Alert Summary\nsecond"
        )
        self.assertEqual(sections["alert summary"], "## Alert Summary\n\nfirst")
        self.assertEqual([title for title, _ in legacy], ["Unknown Vendor Section", "Duplicate Alert Summary"])
        self.assertIn("##### Child", legacy[0][1])
        self.assertIn("unknown body", legacy[0][1])
        self.assertEqual(len(issues), 2)

    def test_front_matter_preamble_aliases_and_replaced_sections_are_exact(self) -> None:
        sections, legacy, issues = self.layout.split_detail_source_sections(
            "---\n"
            "title: legacy\n"
            "## Metadata Heading\n"
            "---\n"
            "ignored preamble\n"
            "## *Public Enrichment*\n"
            " enrichment body \n"
            "## Raw Alert\n"
            '{"event": true}\n'
        )

        self.assertEqual(
            sections,
            {
                "enriched alert details": "## Enriched Alert Details\n\nenrichment body",
                "raw alert": '## Raw Alert\n\n{"event": true}',
            },
        )
        self.assertEqual(legacy, [])
        self.assertEqual(issues, [])

    def test_alias_duplicates_keep_the_first_and_relocate_the_second_exactly(self) -> None:
        sections, legacy, issues = self.layout.split_detail_source_sections(
            "## Enriched Alert Details\nfirst\n"
            "## Public Enrichment\n### Nested\nsecond"
        )

        self.assertEqual(
            sections,
            {"enriched alert details": "## Enriched Alert Details\n\nfirst"},
        )
        self.assertEqual(
            legacy,
            [("Duplicate Public Enrichment", "##### Nested\nsecond")],
        )
        self.assertEqual(
            issues,
            [
                'Legacy data contains duplicate "Enriched Alert Details" sections; '
                "the first section was retained and the duplicate was moved to Raw Logs."
            ],
        )

    def test_preamble_non_h2_and_empty_sections_preserve_current_boundaries(self) -> None:
        self.assertEqual(
            self.layout.split_detail_source_sections("preamble only\n### Child"),
            ({}, [], []),
        )
        sections, legacy, issues = self.layout.split_detail_source_sections(
            "preamble\n"
            "## Analyst Notes\n\n"
            "### Child stays nested\n"
            "## Raw Logs"
        )
        self.assertEqual(
            sections,
            {
                "analyst notes": "## Analyst Notes\n\n### Child stays nested",
                "raw logs": "## Raw Logs",
            },
        )
        self.assertEqual(legacy, [])
        self.assertEqual(issues, [])

    def test_fenced_headings_and_malformed_documents_are_bounded(self) -> None:
        sections, legacy, issues = self.layout.split_detail_source_sections(
            "---\nunclosed metadata\n## Alert Summary\nbody"
        )
        self.assertIn("alert summary", sections)
        self.assertIn("body", sections["alert summary"])
        self.assertEqual(legacy, [])
        self.assertIn("front matter is not closed", issues[0])

        sections, legacy, issues = self.layout.split_detail_source_sections(
            "## Raw Logs\n```\n## not a peer"
        )
        self.assertIn("raw logs", sections)
        self.assertEqual(legacy, [])
        self.assertTrue(any("unclosed fenced code block" in issue for issue in issues))

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = LAYOUT_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 250)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_layout.py"), 2)


if __name__ == "__main__":
    unittest.main()
