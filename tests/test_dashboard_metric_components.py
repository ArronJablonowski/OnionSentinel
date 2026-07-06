#!/usr/bin/env python3
"""Regression checks for SOC Alerts metric-card render helpers."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"


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


if __name__ == "__main__":
    unittest.main()
