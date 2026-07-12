import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"


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

        source = MODULE_PATH.read_text()
        self.assertIn('aria-expanded="false"', source)
        self.assertIn("setAttribute('aria-expanded','true')", source)
        self.assertIn("setAttribute('aria-expanded','false')", source)
        self.assertIn("tbody.report-row-group.expanded'))return", source)


if __name__ == "__main__":
    unittest.main()
