#!/usr/bin/env python3
"""Regression checks for duplicate-alert timeline rendering."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_timeline_components.py"


def load_module():
    spec = importlib.util.spec_from_file_location("dashboard_timeline_components", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DashboardTimelineComponentsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.timeline = load_module()

    def test_timeline_expands_seen_count_into_observation_rows(self) -> None:
        html = self.timeline.alert_seen_timeline_html({
            "member_timeline": [
                {
                    "alert_id": "alert:first",
                    "timestamp": "2026-07-07  10:00:00-06:00",
                    "first_seen": "2026-07-07  10:00:00-06:00",
                    "last_seen": "2026-07-07  10:00:00-06:00",
                    "seen_count": 16,
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.10",
                    "destination_port": 443,
                },
                {
                    "alert_id": "alert:last",
                    "timestamp": "2026-07-07  10:05:00-06:00",
                    "first_seen": "2026-07-07  10:05:00-06:00",
                    "last_seen": "2026-07-07  10:05:00-06:00",
                    "seen_count": 10,
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.10",
                    "destination_port": 443,
                },
            ]
        })

        self.assertIn("2 alert row(s), 26 observation(s)", html)
        self.assertIn('data-timeline-total="26"', html)
        self.assertIn("Page 1 of 2", html)
        self.assertEqual(html.count("data-timeline-row"), 26)
        self.assertIn("<dt>Duration:</dt><dd>5 minutes, 0 seconds</dd>", html)

    def test_timeline_table_declares_compact_endpoint_columns(self) -> None:
        html = self.timeline.alert_seen_timeline_html({
            "member_timeline": [
                {
                    "alert_id": "alert:first",
                    "timestamp": "2026-07-07  10:00:00-06:00",
                    "seen_count": 1,
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.10",
                    "destination_port": 443,
                },
                {
                    "alert_id": "alert:last",
                    "timestamp": "2026-07-07  10:05:00-06:00",
                    "seen_count": 1,
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.10",
                    "destination_port": 443,
                },
            ]
        })

        self.assertIn('<col class="timeline-col-destination">', html)
        self.assertIn('<col class="timeline-col-port">', html)
        self.assertLess(html.index('timeline-col-destination'), html.index('timeline-col-port'))
        self.assertLess(html.index('<th>Destination IP</th>'), html.index('<th>Destination Port</th>'))

    def test_timeline_renders_burst_bands_for_dense_clusters(self) -> None:
        events = []
        for minute in range(12):
            events.append({
                "alert_id": f"alert:first:{minute}",
                "timestamp": f"2026-07-08  10:{minute:02d}:00-06:00",
                "seen_count": 1,
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.10",
                "destination_port": 3478,
            })
        for minute in range(8):
            events.append({
                "alert_id": f"alert:last:{minute}",
                "timestamp": f"2026-07-10  12:{minute:02d}:00-06:00",
                "seen_count": 1,
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.10",
                "destination_port": 3478,
            })

        html = self.timeline.alert_seen_timeline_html({"member_timeline": events})

        self.assertIn("alert-timeline-burst", html)
        self.assertGreaterEqual(html.count("alert-timeline-burst"), 2)
        self.assertIn("Activity burst", html)

    def test_single_event_does_not_render_duplicate_timeline(self) -> None:
        html = self.timeline.alert_seen_timeline_html({
            "member_timeline": [{"timestamp": "2026-07-07  10:00:00-06:00", "seen_count": 1}]
        })

        self.assertEqual(html, "")


if __name__ == "__main__":
    unittest.main()
