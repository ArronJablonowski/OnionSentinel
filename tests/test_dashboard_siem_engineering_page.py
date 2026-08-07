#!/usr/bin/env python3
"""SIEM Engineering view-model, rendering, and deployment contracts."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
MODULE_PATH = SCRIPT_DIR / "dashboard_siem_engineering_page.py"
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load():
    spec = importlib.util.spec_from_file_location("dashboard_siem_engineering_page", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardSiemEngineeringPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = load()

    def recommendation(self, **overrides):
        values = dict(
            title="Rule <title>", digest="digest<&>", rel_source="report.md",
            summary="Summary", ai_summary="AI <summary>", criticality="High",
            criticality_rank=4, alert_source="suricata.alert", source_ip="10.0.0.1",
            destination_ip="1.2.3.4", destination_port="443",
            source_endpoint="10.0.0.1:50000", destination_endpoint="1.2.3.4:443",
            rule_id="rule-1", rule_name="Rule <name>", raw_alert_count=7,
            total_seen_count=7, repeat_count=7, first_seen="2026-08-07  08:00:00-06:00",
            last_seen="2026-08-07  09:00:00-06:00", alert_group_key="group-1",
            alert_ts=1.0, ai_status_key="analyzed", ai_status_label="Analyzed",
            ai_status_detail="Artifact available", enrichment_status_label="Enriched",
            enrichment_status_detail="Two sources", enrichment_record_count=2,
            enrichment_skip_count=0, enrichment_error_count=0,
            pcap_status_label="Analyzed", pcap_status_detail="Packets parsed",
            tuning_recommendation="threshold", tuning_reason="Expected repeated traffic.",
            recommended_tuning_actions=("Backtest <scope>.",), generated_at="2026-08-07  09:05:00-06:00",
            response={"detection_outcome": "true_positive_benign", "bluf": "Expected <traffic>.",
                      "public_enrichment_findings": ["Known <vendor>"],
                      "pcap_analysis_findings": ["TLS observed"]},
        )
        values.update(overrides)
        return self.page.SiemRecommendationViewModel(**values)

    def test_renderer_escapes_model_and_detection_content(self) -> None:
        rendered = self.page.render_siem_engineering_tuning_row(self.recommendation(), 1)
        self.assertIn("Rule &lt;name&gt;", rendered)
        self.assertIn("Backtest &lt;scope&gt;.", rendered)
        self.assertIn("Expected &lt;traffic&gt;.", rendered)
        self.assertNotIn("Rule <name>", rendered)

    def test_page_renders_readiness_counts_and_best_roi(self) -> None:
        candidate = self.recommendation()
        view = self.page.SiemEngineeringPageViewModel(
            mode="codex", local_model="gpt-5.5", cloud_model="gpt-5.6-sol",
            analyzed=1, total=1, all_candidates=(candidate,),
            actionable=(candidate,), repeated=(),
        )
        rendered = self.page.render_siem_engineering_page(view)
        self.assertIn("<strong>Ready</strong>", rendered)
        self.assertIn("1/1 analyzed", rendered)
        self.assertIn("#1 ROI tune", rendered)
        self.assertIn("gpt-5.6-sol", rendered)

    def test_detail_keeps_evidence_and_complete_response_sections(self) -> None:
        rendered = self.page.render_siem_engineering_detail_report(self.recommendation(), "current-rule")
        for label in ("Detection context", "Public enrichment findings", "PCAP findings", "Complete AI response JSON"):
            self.assertIn(label, rendered)

    def test_module_is_bounded_and_has_no_runtime_io_imports(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertLessEqual(len(source.splitlines()), 600)
        for forbidden in ("sqlite3", "subprocess", "urllib", "pathlib", "load_soc_ai_settings"):
            self.assertNotIn(forbidden, source)

    def test_installer_copies_siem_page_module_once(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        command = (
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/dashboard_siem_engineering_page.py" '
            '"$DASHBOARD_RUNTIME_DIR/scripts/dashboard_siem_engineering_page.py"'
        )
        self.assertEqual(installer.count(command), 1)


if __name__ == "__main__":
    unittest.main()
