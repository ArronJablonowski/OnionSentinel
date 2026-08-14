#!/usr/bin/env python3
"""Contracts for the extracted alert-detail Markdown renderer."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPTS / "build_soc_alerts_dashboard.py"
MARKDOWN_PATH = SCRIPTS / "dashboard_alert_detail_markdown.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AlertDetailMarkdownTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.renderer = load_module("dashboard_alert_detail_markdown", MARKDOWN_PATH)
        cls.builder = load_module("alert_detail_markdown_test_builder", BUILDER_PATH)

    def test_builder_reexports_canonical_renderer_contract(self) -> None:
        for name in (
            "inline_markdown",
            "is_table_separator",
            "render_table",
            "strip_markdown_front_matter",
            "markdown_to_html",
        ):
            self.assertIs(getattr(self.builder, name), getattr(self.renderer, name))

    def test_nested_collapsible_sections_close_without_capturing_peers(self) -> None:
        rendered = self.renderer.markdown_to_html(
            "## Parsed PCAP Evidence\n\nParent evidence.\n\n"
            "### TShark Findings\n\n- packet one\n- packet two\n\n"
            "## AI Analysis Output\n\nIndependent conclusion.\n\n"
            "## AI Model Used\n\nunit-model"
        )
        self.assertIn('<summary>Parsed PCAP Evidence</summary>', rendered)
        self.assertIn('<summary>TShark Findings</summary>', rendered)
        self.assertIn('<section class="detail-report-section detail-section-ai-analysis-output">', rendered)
        self.assertIn('<summary>AI Model Used</summary>', rendered)
        self.assertLess(rendered.index("packet two"), rendered.index("Independent conclusion"))
        self.assertEqual(rendered.count("<details"), rendered.count("</details>"))

    def test_content_is_escaped_and_links_are_safely_bounded(self) -> None:
        rendered = self.renderer.markdown_to_html(
            "<script>alert(1)</script> **bold** "
            "[safe](https://example.test/path?a=1&b=2) "
            "[unsafe](javascript:alert(1))"
        )
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        self.assertIn('target="_blank" rel="noopener"', rendered)
        # Preserve the established renderer output during extraction; URL
        # canonicalization is a separate behavior change from this boundary.
        self.assertIn("https://example.test/path?a=1&amp;amp;b=2", rendered)
        self.assertNotIn('href="javascript:', rendered)

    def test_enrichment_table_keeps_semantic_column_contract(self) -> None:
        rendered = self.renderer.markdown_to_html(
            "| Source | Indicator | Type | Verdict | Confidence | Tags | Cached |\n"
            "| --- | --- | --- | --- | --- | --- | --- |\n"
            "| unit | 192.0.2.1 | ip | benign | high | test | now |"
        )
        self.assertIn("public-enrichment-records-table", rendered)
        self.assertIn('<col class="enrichment-col-tags">', rendered)
        self.assertIn("<td>192.0.2.1</td>", rendered)

    def test_table_renderer_preserves_short_and_separator_boundaries(self) -> None:
        self.assertEqual(self.renderer.render_table([]), "")
        self.assertEqual(self.renderer.render_table(["| only |"]), "")
        self.assertEqual(
            self.renderer.render_table(["| H1 | H2 |", "| --- | --- |"]),
            '<div class="table-wrap"><table><thead><tr><th>H1</th><th>H2</th>'
            "</tr></thead><tbody><tr><td>---</td><td>---</td></tr></tbody>"
            "</table></div>",
        )
        self.assertEqual(
            self.renderer.render_table(
                ["| H1 | H2 |", "| --- | --- |", "| a | b |"]
            ),
            '<div class="table-wrap"><table><thead><tr><th>H1</th><th>H2</th>'
            "</tr></thead><tbody><tr><td>a</td><td>b</td></tr></tbody>"
            "</table></div>",
        )

    def test_table_renderer_keeps_invalid_separator_and_ragged_rows_as_data(self) -> None:
        rendered = self.renderer.render_table(
            [
                "| **Name** | Link |",
                "| -- | not-a-separator |",
                "| <unsafe> | [site](https://example.test) | extra |",
            ]
        )
        self.assertEqual(
            rendered,
            '<div class="table-wrap"><table><thead><tr><th><strong>Name</strong></th>'
            "<th>Link</th></tr></thead><tbody>"
            "<tr><td>--</td><td>not-a-separator</td></tr>"
            '<tr><td>&lt;unsafe&gt;</td><td><a href="https://example.test" '
            'target="_blank" rel="noopener">site</a></td><td>extra</td></tr>'
            "</tbody></table></div>",
        )

    def test_skipped_enrichment_header_uses_only_the_skipped_table_classes(self) -> None:
        rendered = self.renderer.render_table(
            [
                "| SOURCE | Indicator | Reason | Limit Note |",
                "| --- | --- | --- | --- |",
                "| unit | example | bounded | none |",
            ]
        )
        self.assertTrue(
            rendered.startswith(
                '<div class="table-wrap public-enrichment-table '
                'public-enrichment-skipped-table"><table><thead>'
            )
        )
        self.assertNotIn("<colgroup>", rendered)
        self.assertNotIn("public-enrichment-records-table", rendered)

    def test_front_matter_code_lists_quotes_and_empty_input_are_deterministic(self) -> None:
        rendered = self.renderer.markdown_to_html(
            "---\ntype: report\n---\n\n# Unit\n\n1. first\n2. second\n\n"
            "> quote\n\n```json\n{\"value\":\"<unsafe>\"}\n```"
        )
        self.assertNotIn("type: report", rendered)
        self.assertIn("<ol><li>first</li><li>second</li></ol>", rendered)
        self.assertIn("<blockquote>quote</blockquote>", rendered)
        self.assertIn("&lt;unsafe&gt;", rendered)
        self.assertEqual(
            self.renderer.markdown_to_html(""),
            "<p>No markdown content available.</p>",
        )

    def test_module_is_bounded_pure_and_deployed_once(self) -> None:
        source = MARKDOWN_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 300)
        for forbidden in ("import sqlite3", "import subprocess", "from pathlib", "Path.home", "open("):
            self.assertNotIn(forbidden, source)
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertEqual(installer.count("dashboard_alert_detail_markdown.py"), 2)


if __name__ == "__main__":
    unittest.main()
