"""Historical events must not acquire their recent receipt date in the UI."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "onion-sentinel-dashboard/scripts"))
from dashboard_alert_report_factory import report_timestamp
from dashboard_alert_repository import original_event_timestamp
from dashboard_alert_detail_sections import alert_summary_markdown
from dashboard_time_format import parse_iso_timestamp


class EventReceiptTimesTests(unittest.TestCase):
    def row(self, original):
        return {
            "timestamp": "2026-10-08T13:00:00Z",
            "last_seen": "2026-10-08T14:00:00Z",
            "alert_json": json.dumps({"security_onion": {"raw_event": {"@timestamp": original}}}),
        }

    def test_original_event_wins_over_recent_normalized_and_receipt_times(self):
        row = self.row("2026-08-27T12:00:00Z")
        self.assertEqual(report_timestamp(row), parse_iso_timestamp("2026-08-27T12:00:00Z"))

    def test_invalid_original_does_not_fall_back_to_recent_receipt(self):
        self.assertEqual(report_timestamp(self.row("invalid")), 0.0)

    def test_missing_event_does_not_fabricate_current_time(self):
        row = self.row(None)
        row["timestamp"] = None
        self.assertEqual(original_event_timestamp(row), "")
        self.assertEqual(report_timestamp(row), 0.0)

    def test_summary_distinguishes_event_and_receipt_fields(self):
        row = self.row("2026-08-27T12:00:00Z")
        row.update(event_timestamp=original_event_timestamp(row), first_seen="2026-10-08T13:55:00Z")
        text = alert_summary_markdown(row)
        self.assertIn("| Original event time |", text)
        self.assertIn("| First received |", text)
        self.assertIn("| Last received |", text)
        self.assertIn("2026-08-27", text)
