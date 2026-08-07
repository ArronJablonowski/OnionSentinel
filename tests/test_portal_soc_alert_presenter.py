"""Direct contracts for the modular SOC alert API row presenter."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_alert_presenter import (  # noqa: E402
    SocAlertPresentationDependencies,
    compose_soc_alert_row,
)


class SocAlertPresenterTests(unittest.TestCase):
    def row(self) -> dict:
        return {
            "group_key": "group-key", "alert_id": "alert-1",
            "group_first_seen": "first-group", "first_seen": "first",
            "group_last_seen": "last-group", "last_seen": "last",
            "raw_alert_count": 2, "total_seen_count": 7, "seen_count": 4,
            "timestamp": "timestamp", "rule_name": "Rule", "event_dataset": "suricata.alert",
            "severity": 3, "severity_label": "high", "triage_score": 90,
            "triage_level": "high", "routing": "review", "traffic_direction": "outbound",
            "source_ip": "192.0.2.10", "source_port": 1234,
            "destination_ip": "198.51.100.10", "destination_port": 443,
            "transport_protocol": "tcp", "filter_status": "", "filter_reason": "",
            "suppression_key": "suppression",
        }

    def dependencies(self) -> SocAlertPresentationDependencies:
        return SocAlertPresentationDependencies(
            dashboard_group_id=lambda key: "dash" if key == "group-key" else "",
            ai_status=lambda row, group, reports, artifacts, threshold: {
                "ai_status_key": f"{group}:{threshold}"
            },
            enrichment_status=lambda value: {"enrichment_value": value or "none"},
            pcap_status=lambda group, alert, analysis, requests: {
                "pcap_status_key": f"{group}:{alert}:{bool(analysis)}:{bool(requests)}"
            },
            incident_defaults=lambda: {"incident_status": "not_escalated"},
            review_defaults=lambda: {"reviewer_status": "not_requested"},
        )

    def test_projection_preserves_counts_status_and_callback_outputs(self) -> None:
        row = self.row()
        row["payload_size_bytes"] = 512
        row["enrichment_json"] = "enriched"

        result = compose_soc_alert_row(
            row,
            {"dash": {"status": "acknowledged", "reason": "reviewed", "updated_by": "analyst"}},
            {}, {"pcap": True}, {"request": True}, {},
            {"dash": {"pcap_size_bytes": 2048, "detection_outcome": "inconclusive"}},
            "medium", self.dependencies(),
        )

        self.assertEqual(result["seen_count"], 7)
        self.assertEqual(result["payload_size_bytes"], 512)
        self.assertEqual(result["filter_status"], "accepted")
        self.assertEqual(result["analyst_status"], "acknowledged")
        self.assertEqual(result["analyst_status_updated_by"], "analyst")
        self.assertEqual(result["ai_status_key"], "dash:medium")
        self.assertEqual(result["enrichment_value"], "enriched")
        self.assertEqual(result["pcap_status_key"], "dash:alert-1:True:True")
        self.assertEqual(result["pcap_size_bytes"], 2048)

    def test_missing_optional_fields_and_metadata_use_explicit_defaults(self) -> None:
        result = compose_soc_alert_row(
            self.row(), None, None, None, None, None, None,
            "informational", self.dependencies(),
        )

        self.assertEqual(result["payload_size_bytes"], 0)
        self.assertEqual(result["analyst_status"], "open")
        self.assertEqual(result["enrichment_value"], "none")
        self.assertEqual(result["pcap_size_bytes"], 0)
        self.assertEqual(result["detection_outcome_label"], "n/a")
        self.assertEqual(result["incident_status"], "not_escalated")
        self.assertEqual(result["reviewer_status"], "not_requested")


if __name__ == "__main__":
    unittest.main()
