"""Direct contracts for SOC PCAP request aggregation and status policy."""
from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_pcap_status import (  # noqa: E402
    SocPcapStatusDependencies,
    compose_pcap_status,
    load_pcap_request_statuses,
)


class SocPcapStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE pcap_requests (request_id TEXT, alert_id TEXT, group_id TEXT, "
            "status TEXT, outcome TEXT, error TEXT, request_json TEXT, created_at TEXT, updated_at TEXT, "
            "completed_at TEXT)"
        )

    def tearDown(self) -> None:
        self.conn.close()

    def dependencies(self) -> SocPcapStatusDependencies:
        return SocPcapStatusDependencies(
            table_exists=lambda conn, table: bool(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()),
            dashboard_group_id=lambda key: "dash" if key == "group-key" else "",
        )

    def test_newest_request_is_indexed_by_group_alert_and_request(self) -> None:
        self.conn.executemany(
            "INSERT INTO pcap_requests VALUES (?, 'alert', 'dash', ?, '', ?, ?, ?, ?, ?)",
            [
                ("old", "failed", "old", "{}", "2026-08-07T16:00:00Z", "", ""),
                ("new", "fulfilled", "", json.dumps({"capture_file": "/capture"}),
                 "2026-08-07T17:00:00Z", "", "2026-08-07T17:01:00Z"),
            ],
        )

        result = load_pcap_request_statuses(
            self.conn, [{"group_key": "group-key", "alert_id": "alert"}], self.dependencies(),
        )

        self.assertEqual(result["dash"]["request_id"], "new")
        self.assertEqual(result["alert"]["status"], "fulfilled")
        self.assertTrue(result["new"]["used_capture_file"])

    def test_parsed_analysis_precedes_request_state(self) -> None:
        result = compose_pcap_status(
            "dash", "alert", {"group_ids": {"dash"}}, {"dash": {"status": "failed"}},
        )
        self.assertEqual(result["pcap_status_key"], "analyzed")

    def test_active_request_states_use_queued_or_parsing_labels(self) -> None:
        expected = {"pending": "Queued", "claimed": "Queued", "fulfilled": "Parsing"}
        for status, label in expected.items():
            with self.subTest(status=status):
                result = compose_pcap_status("dash", "alert", {}, {"dash": {"status": status}})
                self.assertEqual(result["pcap_status_key"], "queued")
                self.assertEqual(result["pcap_status_label"], label)

    def test_failed_request_distinguishes_retry_no_packets_and_other_failure(self) -> None:
        retry = compose_pcap_status(
            "dash", "alert", {},
            {"dash": {"status": "failed", "error": "no matching packets", "used_capture_file": False}},
        )
        no_packets = compose_pcap_status(
            "dash", "alert", {},
            {"dash": {"status": "failed", "error": "no matching packets", "used_capture_file": True}},
        )
        failed = compose_pcap_status(
            "dash", "alert", {}, {"dash": {"status": "failed", "error": "broker unavailable"}},
        )
        none = compose_pcap_status("dash", "alert", {}, {})

        self.assertEqual((retry["pcap_status_key"], retry["pcap_status_label"]), ("error", "Retry"))
        self.assertEqual(no_packets["pcap_status_key"], "no-packets")
        self.assertEqual(failed["pcap_status_label"], "Failed")
        self.assertEqual(none["pcap_status_key"], "none")

    def test_policy_retirement_is_presented_as_skipped_with_exact_reason(self) -> None:
        result = compose_pcap_status(
            "dash", "alert", {},
            {"dash": {
                "status": "rejected",
                "outcome": "policy_skipped",
                "error": "Automatic PCAP analysis skipped below configured high threshold",
            }},
        )
        self.assertEqual(
            (result["pcap_status_key"], result["pcap_status_label"]),
            ("not-queued", "Skipped"),
        )
        self.assertIn("high threshold", result["pcap_status_detail"])


if __name__ == "__main__":
    unittest.main()
