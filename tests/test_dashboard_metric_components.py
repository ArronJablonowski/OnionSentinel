#!/usr/bin/env python3
"""Regression checks for SOC Alerts metric-card render helpers."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
BUILDER_RUNTIME_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_builder_runtime.py"
SHELL_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_shell_page.py"
SOC_SHELL_CONTENT_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_soc_shell_content.py"
SCRIPT_DIR = REPO_ROOT / "onion-sentinel-dashboard" / "scripts"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import dashboard_metric_components


def dashboard_contract_source() -> str:
    shell = SHELL_PATH.read_text(encoding="utf-8")
    soc_content = SOC_SHELL_CONTENT_PATH.read_text(encoding="utf-8")
    return BUILDER_RUNTIME_PATH.read_text(encoding="utf-8") + soc_content + shell.replace("{", "{{").replace("}", "}}")


def load_builder():
    spec = importlib.util.spec_from_file_location("build_soc_alerts_dashboard", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardMetricComponentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_ai_activity_metric_exposes_queue_counts(self) -> None:
        html = self.builder.render_ai_activity_metric(
            {
                "active": False,
                "label": "AI:Idle",
                "detail": "Model: devstral:latest",
                "model": "devstral:latest",
                "counts": {
                    "analyzing": 0,
                    "queued": 2,
                    "analyzed": 3,
                    "not_queued": 4,
                    "total": 9,
                },
            }
        )

        self.assertIn('id="ai-analyzed-count">3</b> Analyzed', html)
        self.assertIn('id="ai-queued-count">2</b> Queued', html)
        self.assertIn('id="ai-skipped-count">4</b> Skipped', html)
        self.assertIn("Model: devstral:latest", html)

    def test_metric_section_helpers_keep_stable_ids(self) -> None:
        combined = "".join(
            [
                self.builder.render_active_alerts_metric("<span>severity</span>"),
                self.builder.render_alert_status_metric(),
                self.builder.render_latest_network_metric("<span>latest</span>"),
            ]
        )

        for element_id in (
            "visible-metric-extra",
            "top-api-grouped-total",
            "top-api-visible-total",
            "top-api-acknowledged-total",
            "top-api-suppressed-total",
            "top-api-source-ip",
            "top-api-destination-ip",
            "top-api-destination-port",
        ):
            self.assertIn(f'id="{element_id}"', combined)

    def test_system_health_metric_escapes_runtime_text(self) -> None:
        html = dashboard_metric_components.render_size_metric(
            "1.0 MB",
            '2026-07-06  13:00:00-06:00 <latest>',
            "512 KB",
        )

        self.assertIn("SOC Reports:</b> 1.0 MB", html)
        self.assertIn('id="pcap-ingest-size">512 KB</span>', html)
        self.assertIn("Last Alert:</b> 2026-07-06&nbsp;&nbsp;13:00:00-06:00 &lt;latest&gt;", html)

    def test_active_alert_metrics_use_all_matching_active_groups(self) -> None:
        source = dashboard_contract_source()

        self.assertIn(
            "apiActiveTotal=Number(data.active_total??data.status_counts?.open",
            source,
        )
        self.assertIn(
            "apiSeverityCounts=data.active_severity_counts||data.severity_counts||null",
            source,
        )
        self.assertIn("setActiveAlertCount(apiActiveTotal)", source)
        self.assertNotIn("setActiveAlertCount(apiTotalMatching)", source)

    def test_alert_table_exposes_group_evidence_columns(self) -> None:
        source = dashboard_contract_source()

        for contract_token in (
            "Detection Outcome",
            "PCAP Size",
            "pcap_size_bytes",
            "detection_outcome_label",
            "apiDetectionOutcomePill",
            'colspan="18"',
        ):
            self.assertIn(contract_token, source)

    def test_siem_engineering_rows_expand_into_evidence_reports(self) -> None:
        report = self.builder.AlertReport(
            title="Repeated outbound scan",
            source=Path("synthetic.md"),
            rel_source="synthetic.md",
            mtime=0.0,
            size=256,
            digest="synthetic-digest",
            rendered_html="",
            summary="Repeated behavior warrants a scoped rule review.",
            criticality="High",
            criticality_rank=4,
            alert_source="suricata.alert",
            filter_status="accepted",
            source_ip="192.0.2.10",
            source_port="41000",
            destination_ip="198.51.100.20",
            destination_port="443",
            source_endpoint="192.0.2.10:41000",
            destination_endpoint="198.51.100.20:443",
            rule_id="synthetic-rule",
            rule_name="Synthetic repeated outbound scan",
            raw_alert_count=8,
            total_seen_count=8,
            repeat_count=8,
            first_seen="2026-07-20  08:00:00-06:00",
            last_seen="2026-07-20  09:00:00-06:00",
            alert_group_key="synthetic-group",
            alert_ts=1.0,
            ai_status_key="analyzed",
            ai_status_label="Analyzed",
            ai_status_detail="AI artifact available",
            enrichment_status_key="enriched",
            enrichment_status_label="Enriched",
            enrichment_status_detail="Two sources",
            enrichment_record_count=2,
            enrichment_skip_count=0,
            enrichment_error_count=0,
            pcap_status_key="analyzed",
            pcap_status_label="Analyzed",
            pcap_status_detail="Parsed PCAP evidence available",
            tuning_recommendation="threshold",
            tuning_reason="Repeated expected traffic creates avoidable review volume.",
            recommended_tuning_actions=["Threshold only this verified route."],
            ai_analysis={
                "generated_at": "2026-07-20T09:05:00-06:00",
                "response": {
                    "detection_outcome": "true_positive_benign",
                    "bluf": "The traffic is real but expected.",
                    "summary": "A narrowly scoped threshold is appropriate.",
                    "public_enrichment_findings": ["Synthetic enrichment finding"],
                    "pcap_analysis_findings": ["Synthetic PCAP finding"],
                    "recommended_next_steps": ["Backtest before deployment"],
                },
            },
        )

        current = self.builder.siem_engineering_tuning_row(report, 1)
        candidate = self.builder.siem_engineering_detection_row(report, 1)

        for rendered in (current, candidate):
            self.assertIn('data-siem-toggle', rendered)
            self.assertIn('tabindex="0"', rendered)
            self.assertIn('aria-expanded="false"', rendered)
            self.assertIn('class="siem-recommendation-detail" hidden', rendered)
            self.assertIn("What should change", rendered)
            self.assertIn("Detection context", rendered)
            self.assertIn("Public enrichment findings", rendered)
            self.assertIn("PCAP findings", rendered)
            self.assertIn("Complete AI response JSON", rendered)
            self.assertIn("Synthetic enrichment finding", rendered)

        self.assertIn("Current rule tuning analysis", current)
        self.assertIn("New detection candidate analysis", candidate)
        self.assertIn("[data-siem-toggle]", self.builder.SIEM_ENGINEERING_JS)
        self.assertIn("event.key !== 'Enter'", self.builder.SIEM_ENGINEERING_JS)


if __name__ == "__main__":
    unittest.main()
