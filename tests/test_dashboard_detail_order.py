import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
SHELL_MODULE_PATH = SCRIPT_DIR / "dashboard_shell_page.py"


def dashboard_contract_source() -> str:
    """Return builder source plus the shell in its former f-string brace form."""
    shell = SHELL_MODULE_PATH.read_text(encoding="utf-8")
    return MODULE_PATH.read_text(encoding="utf-8") + shell.replace("{", "{{").replace("}", "}}")


def load_builder():
    if str(SCRIPT_DIR) not in sys.path:
        sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("build_soc_alerts_dashboard", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardDetailOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_ai_output_precedes_collapsed_model_metadata(self) -> None:
        markdown = self.builder.ai_analysis_report_markdown(None)

        self.assertLess(markdown.index("## AI Analysis Output"), markdown.index("## AI Model Used"))

        html = self.builder.markdown_to_html(markdown)
        self.assertLess(html.index("AI Analysis Output"), html.index("<summary>AI Model Used</summary>"))
        self.assertIn("detail-section-ai-model-used", html)
        self.assertNotIn("<details open", html)

    def test_correlation_assessment_stays_inside_ai_output_contract_section(self) -> None:
        analysis = {
            "generated_at": "2026-07-15  10:00:00-06:00",
            "response": {
                "correlation_assessment": {
                    "correlation_found": True,
                    "confidence": "medium",
                    "related_groups": [{"group_id": "b" * 20, "reason": "shared domain"}],
                    "shared_evidence": ["example.test"],
                    "contradicting_evidence": ["different destination"],
                    "attack_chain_hypothesis": "DNS activity preceded TLS traffic.",
                    "recommended_pivots": ["Review the shared host timeline."],
                }
            },
        }

        markdown = self.builder.ai_analysis_output_markdown(analysis)

        self.assertIn("### Correlation Assessment", markdown)
        self.assertIn("DNS activity preceded TLS traffic.", markdown)
        self.assertNotIn("## Correlated Detections", markdown)

    def test_front_matter_is_hidden_from_rendered_detail_view(self) -> None:
        markdown = "\n".join(
            [
                "---",
                "type: soc-alert-report",
                'alert_id: ".ds-logs-suricata.alerts-so-example"',
                "tags:",
                "  - security-onion",
                "  - soc-alert",
                "  - n8n-generated",
                "---",
                "",
                "# [LOW] Example Alert",
                "",
                "Rendered analyst content.",
            ]
        )

        html = self.builder.markdown_to_html(markdown)

        self.assertEqual(self.builder.extract_markdown_alert_id(markdown), ".ds-logs-suricata.alerts-so-example")
        self.assertIn("[LOW] Example Alert", html)
        self.assertIn("Rendered analyst content.", html)
        self.assertNotIn("soc-alert-report", html)
        self.assertNotIn("n8n-generated", html)

    def test_ai_analysis_output_shows_generated_timestamp(self) -> None:
        markdown = self.builder.ai_analysis_output_markdown(
            {
                "generated_at": "2026-07-08T12:13:30-06:00",
                "response": {
                    "detection_outcome": "true_positive_suspicious",
                    "bluf": "True Positive - Suspicious: The detection matched real concerning behavior, but supplied evidence does not prove compromise.",
                    "summary": "Example AI summary",
                    "public_enrichment_findings": ["OTX marked the destination suspicious."],
                },
            }
        )

        self.assertIn("## AI Analysis Output", markdown)
        self.assertIn("**Generated:** 2026-07-08  12:13:30-06:00", markdown)
        self.assertIn("### BLUF", markdown)
        self.assertIn("**Detection outcome:** true_positive_suspicious", markdown)
        self.assertIn("True Positive - Suspicious:", markdown)
        self.assertIn("### Assessment", markdown)
        self.assertIn("### Public Enrichment Findings", markdown)
        self.assertIn("OTX marked the destination suspicious.", markdown)
        self.assertLess(markdown.index("### BLUF"), markdown.index("### Assessment"))
        self.assertLess(markdown.index("**Generated:**"), markdown.index("### Assessment"))

        html = self.builder.markdown_to_html(markdown)
        self.assertIn("<strong>Generated:</strong> 2026-07-08  12:13:30-06:00", html)

    def test_empty_ai_analysis_output_shows_generated_na(self) -> None:
        markdown = self.builder.ai_analysis_output_markdown(None)

        self.assertIn("**Generated:** n/a", markdown)
        self.assertLess(markdown.index("**Generated:** n/a"), markdown.index("No AI analysis artifact"))

    def test_derived_artifact_directories_are_not_primary_alert_reports(self) -> None:
        self.assertIn("pcap-analysis", self.builder.DERIVED_REPORT_DIRECTORIES)
        self.assertIn("ai-analysis", self.builder.DERIVED_REPORT_DIRECTORIES)
        source = dashboard_contract_source()
        self.assertIn("relative_parts[0].lower() in DERIVED_REPORT_DIRECTORIES", source)

    def test_primary_alert_report_wins_over_newer_derived_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "soc-alerts"
            source.mkdir()
            alert_id = "synthetic-primary-report-id"
            primary = source / "alert-report.md"
            primary.write_text(
                f"---\ntype: soc-alert-report\nalert_id: {alert_id}\n---\n\n# Primary Alert Report\n",
                encoding="utf-8",
            )
            pcap_dir = source / "pcap-analysis"
            pcap_dir.mkdir()
            (pcap_dir / "newer-pcap-analysis.md").write_text(
                f"---\ntype: soc-pcap-analysis\nalert_id: {alert_id}\n---\n\n# Derived PCAP Artifact\n",
                encoding="utf-8",
            )
            self.builder.SOURCE_DIR = source
            self.builder.MARKDOWN_SOURCES = (source, source)

            indexed = self.builder.load_markdown_reports_by_alert_id()

        self.assertEqual(indexed[alert_id][0].name, primary.name)
        self.assertIn("Primary Alert Report", indexed[alert_id][1])

    def test_canonical_contract_requires_ai_output_and_model_independently(self) -> None:
        self.assertIn("ai analysis output", self.builder.DETAIL_REPORT_SECTION_ORDER)
        self.assertIn("ai model used", self.builder.DETAIL_REPORT_SECTION_ORDER)
        self.assertLess(
            self.builder.DETAIL_REPORT_SECTION_ORDER.index("ai analysis output"),
            self.builder.DETAIL_REPORT_SECTION_ORDER.index("ai model used"),
        )

    def test_pinned_row_uses_visible_header_bottom_or_viewport_top(self) -> None:
        source = dashboard_contract_source()
        self.assertIn("rect&&rect.bottom>0&&rect.top<=1", source)
        self.assertIn("Math.ceil(rect.bottom)", source)

    def test_legacy_ai_section_order_is_normalized(self) -> None:
        markdown = "\n\n".join(
            [
                "## Alert Summary\n\nbody",
                "## AI Model Used\n\n| Field | Value |\n| --- | --- |\n| Model | devstral:latest |",
                "## AI Analysis Output\n\n### Summary\n\nanalysis",
                "## Public Enrichment\n\nintel",
            ]
        )

        normalized = self.builder.move_ai_output_before_model(markdown)

        self.assertLess(normalized.index("## AI Analysis Output"), normalized.index("## AI Model Used"))
        self.assertLess(normalized.index("## AI Model Used"), normalized.index("## Public Enrichment"))

    def test_requested_detail_sections_are_collapsed_by_default(self) -> None:
        html = self.builder.markdown_to_html(
            "\n\n".join(
                [
                    "## Alert Summary\n\nsummary",
                    "## Analyst Notes\n\nnotes",
                    "## Parsed PCAP Evidence\n\npcap",
                    "## Public Enrichment\n\nintel",
                    "## Security Onion Detail Fields\n\nfields",
                ]
            )
        )

        self.assertIn("<summary>Alert Summary</summary>", html)
        self.assertIn("<summary>Analyst Notes</summary>", html)
        self.assertIn("<summary>Parsed PCAP Evidence</summary>", html)
        self.assertIn("<summary>Public Enrichment</summary>", html)
        self.assertIn("<summary>Security Onion Detail Fields</summary>", html)
        self.assertIn("detail-section-alert-summary", html)
        self.assertIn("detail-section-analyst-notes", html)
        self.assertIn("detail-section-parsed-pcap-evidence", html)
        self.assertIn("detail-section-public-enrichment", html)
        self.assertIn("detail-section-security-onion-detail-fields", html)
        self.assertNotIn("<details open", html)

    def test_detail_accordions_use_compact_consistent_spacing(self) -> None:
        source = dashboard_contract_source()

        self.assertIn(".detail-collapsible-section{{display:block;margin:6px 0}}", source)
        self.assertIn(".detail-collapsible-section>summary{{display:flex", source)

    def test_enrichment_results_table_preserves_readable_tags_column(self) -> None:
        html = self.builder.markdown_to_html(
            "\n".join(
                [
                    "| Source | Indicator | Type | Verdict | Confidence | Tags | Cached |",
                    "| --- | --- | --- | --- | --- | --- | --- |",
                    "| abuseipdb | 198.51.100.10 | ip | benign | 0 | Data Center/Web Hosting/Transit, Example Corp, US | 2026-07-21  18:27:38.891-06:00 |",
                ]
            )
        )

        self.assertIn('class="table-wrap public-enrichment-table public-enrichment-records-table"', html)
        self.assertIn('<col class="enrichment-col-tags">', html)
        self.assertIn('<col class="enrichment-col-cached">', html)

        source = dashboard_contract_source()
        self.assertIn(".enrichment-col-tags{{width:360px}}", source)
        self.assertIn(":is(.detail-template,.mobile-pill-details) .markdown-body .public-enrichment-records-table", source)
        self.assertIn("min-width:1154px!important", source)
        self.assertIn("width:180px!important;min-width:180px!important", source)
        self.assertIn("width:100px!important;min-width:100px!important", source)
        self.assertIn(
            "width:360px!important;min-width:360px!important;word-break:normal!important;overflow-wrap:anywhere!important",
            source,
        )

    def test_nested_pcap_accordion_does_not_capture_following_top_level_sections(self) -> None:
        html = self.builder.markdown_to_html(
            "\n\n".join(
                [
                    "## Parsed PCAP Evidence\n\npcap overview",
                    "### TShark Findings\n\npacket details",
                    "### Evidence Limits\n\nbounded evidence",
                    "## Alert Summary\n\nsummary details",
                    "## Raw Logs\n\nraw details",
                ]
            )
        )

        summary_open = '<details class="detail-report-section detail-collapsible-section detail-section-alert-summary">'
        raw_logs_open = '<details class="detail-report-section detail-collapsible-section detail-section-raw-logs">'
        self.assertIn(f'</div></details>\n{summary_open}', html)
        self.assertIn(f'</div></details>\n{raw_logs_open}', html)
        self.assertEqual(html.count('<summary>Parsed PCAP Evidence</summary>'), 1)
        self.assertEqual(html.count('<summary>Alert Summary</summary>'), 1)
        self.assertEqual(html.count('<summary>Raw Logs</summary>'), 1)

    def test_timeline_is_inserted_after_alert_identity_before_analysis(self) -> None:
        rendered = self.builder.markdown_to_html(
            "\n\n".join(
                [
                    "# [LOW] Example Alert",
                    "- **Generated:** 2026-07-08  12:13:30-06:00",
                    "- **Traffic:** 192.0.2.10:1234 -> 198.51.100.10:443",
                    "## Alert Summary",
                    "| Field | Value |",
                    "| --- | --- |",
                    "| Rule name | Example Alert |",
                    "## AI Analysis Output",
                    "analysis",
                ]
            )
        )

        with_timeline = self.builder.insert_timeline_after_alert_identity(
            rendered,
            '<details class="alert-timeline-section"><summary>Duplicate Alert Timeline</summary></details>',
        )

        self.assertLess(with_timeline.index("[LOW] Example Alert"), with_timeline.index("Duplicate Alert Timeline"))
        self.assertLess(with_timeline.index("Traffic:"), with_timeline.index("Duplicate Alert Timeline"))
        self.assertLess(with_timeline.index("Duplicate Alert Timeline"), with_timeline.index("AI Analysis Output"))

    def test_alert_detail_expansion_is_not_persisted_across_full_page_loads(self) -> None:
        stabilizer = self.builder.ALERTS_PAGE_SCROLL_STABILIZER

        self.assertNotIn("sessionStorage", stabilizer)
        self.assertIn("clear()", stabilizer)
        self.assertIn("overflow-x:hidden", stabilizer)
        self.assertIn("scrollRestoration", stabilizer)

        source = dashboard_contract_source()
        self.assertIn('aria-expanded="false"', source)
        self.assertIn("setAttribute('aria-expanded','true')", source)
        self.assertIn("setAttribute('aria-expanded','false')", source)
        self.assertIn("tbody.report-row-group.expanded'))return", source)

    def test_canonical_report_always_contains_every_section_in_exact_order(self) -> None:
        row = {
            "alert_id": "synthetic-alert",
            "timestamp": "2026-07-15T08:00:00-06:00",
            "first_seen": "2026-07-15T07:55:00-06:00",
            "last_seen": "2026-07-15T08:00:00-06:00",
            "seen_count": 2,
            "raw_alert_count": 2,
            "rule_name": "Synthetic Detection",
            "severity": 2,
            "severity_label": "medium",
            "triage_level": "medium",
            "triage_score": 45,
            "filter_status": "accepted",
            "routing": "store-only",
            "traffic_direction": "outbound",
            "source_ip": "192.0.2.10",
            "source_port": 51515,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "event_dataset": "suricata.alert",
            "alert_json": "{}",
            "enrichment_json": "{}",
        }

        result = self.builder.canonical_detail_report_markdown("", row, {}, None, "")

        h2_order = [
            self.builder.normalized_heading_text(line)[1]
            for line in result.markdown.splitlines()
            if self.builder.normalized_heading_text(line)
            and self.builder.normalized_heading_text(line)[0] == 2
        ]
        self.assertEqual(tuple(h2_order), self.builder.DETAIL_REPORT_SECTION_ORDER)
        self.assertEqual(result.issues, ())

    def test_legacy_sections_are_relocated_without_changing_the_contract(self) -> None:
        row = {
            "alert_id": "synthetic-alert",
            "timestamp": "2026-07-15T08:00:00-06:00",
            "rule_name": "Synthetic Detection",
            "severity_label": "low",
            "filter_status": "accepted",
            "alert_json": "{}",
            "enrichment_json": "{}",
        }
        source = "\n\n".join(
            [
                "## Alert Summary\n\nlegacy summary",
                "## Unexpected Historical Section\n\nlegacy body",
                "## AI Model Used\n\nlegacy model",
                "## AI Analysis Output\n\nlegacy output",
            ]
        )

        result = self.builder.canonical_detail_report_markdown(source, row, {}, None, "")

        self.assertTrue(result.issues)
        self.assertIn("Unexpected Historical Section", result.markdown)
        self.assertGreater(result.markdown.index("## Raw Logs"), result.markdown.index("## Alert Summary"))
        self.assertNotIn("## Unexpected Historical Section", result.markdown.splitlines())

    def test_finalized_report_marks_contract_valid_and_orders_timeline(self) -> None:
        row = {
            "alert_id": "synthetic-alert",
            "timestamp": "2026-07-15T08:00:00-06:00",
            "rule_name": "Synthetic Detection",
            "severity_label": "low",
            "filter_status": "accepted",
            "alert_json": "{}",
            "enrichment_json": "{}",
        }
        result = self.builder.canonical_detail_report_markdown("", row, {}, None, "")
        rendered = self.builder.markdown_to_html(result.markdown)
        final = self.builder.finalize_detail_report_html(
            rendered,
            '<details class="alert-timeline-section"><summary>Duplicate Alert Timeline</summary></details>',
            result.issues,
        )

        self.assertIn('data-layout-valid="true"', final)
        self.assertNotIn("detail-layout-error", final)
        self.assertLess(final.index("detail-section-triage-reasons"), final.index("alert-timeline-section"))
        self.assertLess(final.index("alert-timeline-section"), final.index("detail-section-ai-analysis-output"))

    def test_layout_error_is_rendered_for_legacy_schema_violations(self) -> None:
        error = self.builder.detail_layout_error_html(["Unknown source heading was relocated."])

        self.assertIn('role="alert"', error)
        self.assertIn("Detailed Alert Report layout error", error)
        self.assertIn("Unknown source heading was relocated.", error)
        self.assertIn(self.builder.DETAIL_REPORT_LAYOUT_VERSION, error)

    def test_dashboard_runtime_surfaces_layout_contract_errors(self) -> None:
        source = dashboard_contract_source()

        self.assertIn("showDetailLayoutContractError", source)
        self.assertIn("MutationObserver", source)
        self.assertIn(".detail-layout-error", source)
        self.assertIn("Legacy or malformed data could not be mapped cleanly", source)

    def test_pinned_alert_row_uses_measured_columns_and_synced_horizontal_scroll(self) -> None:
        source = dashboard_contract_source()

        self.assertIn("PINNED_ALERT_ROW_SCROLL_SYNC", source)
        self.assertIn("visibleSourceCells", source)
        self.assertIn("grid-template-columns", source)
        self.assertIn("viewport.addEventListener('wheel'", source)
        self.assertIn("synchronize(viewport, tableCard)", source)
        self.assertIn(".pinned-alert-cell.action-cell .ack-button", source)

    def test_alert_title_column_expands_and_clamps_to_two_lines(self) -> None:
        source = dashboard_contract_source()

        self.assertIn("--soc-alert-title-column-width:420px", source)
        self.assertIn(".alert-table td.alert-cell", source)
        self.assertIn("-webkit-line-clamp:2", source)
        self.assertIn("word-break:normal", source)
        self.assertIn("minimumTwoLineWidth", source)
        self.assertIn("Math.max(420, Math.min(960", source)
        self.assertIn("soc:alert-column-width-changed", source)
        self.assertIn("ALERT_COLUMN_SINGLE_WRAP_CONTRACT + '</body>'", source)

    def test_dashboard_uses_tightly_framed_favicon(self) -> None:
        source = dashboard_contract_source()
        favicon = MODULE_PATH.parent.parent / "assets" / "onion-sentinel-favicon.png"

        self.assertIn('rel="icon" type="image/png" sizes="64x64"', source)
        self.assertIn("assets/onion-sentinel-favicon.png", source)
        self.assertTrue(favicon.is_file())

    def test_detail_fragments_are_published_without_clearing_live_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            detail_dir = Path(tmp) / "details"
            detail_dir.mkdir()
            existing_digest = "a" * 12
            new_digest = "b" * 12
            existing_path = detail_dir / f"{existing_digest}.html"
            existing_path.write_text("old live fragment", encoding="utf-8")
            (detail_dir / f"{'c' * 12}.html").write_text("stale", encoding="utf-8")
            reports = [
                SimpleNamespace(digest=existing_digest, rendered_html="updated fragment"),
                SimpleNamespace(digest=new_digest, rendered_html="new fragment"),
            ]
            self.builder.DETAIL_DIR = detail_dir
            real_replace = self.builder.os.replace

            def observed_replace(source, destination):
                destination = Path(destination)
                if destination == existing_path:
                    self.assertEqual(destination.read_text(encoding="utf-8"), "old live fragment")
                return real_replace(source, destination)

            with mock.patch.object(self.builder.shutil, "rmtree", side_effect=AssertionError("live directory cleared")):
                with mock.patch.object(self.builder.os, "replace", side_effect=observed_replace):
                    written = self.builder.write_detail_fragments(reports)

            self.assertEqual({path.name for path in written}, {f"{existing_digest}.html", f"{new_digest}.html"})
            self.assertIn("updated fragment", existing_path.read_text(encoding="utf-8"))
            self.assertIn("new fragment", (detail_dir / f"{new_digest}.html").read_text(encoding="utf-8"))
            self.assertFalse((detail_dir / f"{'c' * 12}.html").exists())
            self.assertEqual(list(detail_dir.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
