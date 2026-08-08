from __future__ import annotations

import json
import sqlite3
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_pcap_request_store import (  # noqa: E402
    PcapRequestStoreSources,
    insert_pcap_request,
    pcap_capture_file_from_json,
    read_pcap_request_candidate,
)


class PcapRequestStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.sources = PcapRequestStoreSources(
            table_exists=lambda conn, table: conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone() is not None,
            table_columns=lambda conn, table: {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            },
            now_iso=lambda: "2026-08-07T12:00:00Z",
        )

    def tearDown(self) -> None:
        self.conn.close()

    def create_summary(self, *, network_protocol=True):
        protocol = ", network_protocol TEXT" if network_protocol else ""
        self.conn.execute(
            "CREATE TABLE alert_group_summary ("
            "group_id TEXT, group_key TEXT, representative_alert_id TEXT, "
            "first_seen TEXT, last_seen TEXT, timestamp TEXT, source_ip TEXT, "
            "source_port INTEGER, destination_ip TEXT, destination_port INTEGER"
            f"{protocol}, transport_protocol TEXT)"
        )
        columns = (
            "group_id, group_key, representative_alert_id, first_seen, "
            "last_seen, timestamp, source_ip, source_port, destination_ip, "
            "destination_port, "
            + ("network_protocol, " if network_protocol else "")
            + "transport_protocol"
        )
        values = [
            "abcdef123456", "group-key", "alert-1", None,
            "2026-08-07T12:01:00Z", "2026-08-07T12:00:00Z",
            "192.0.2.10", 1111, "198.51.100.20", 443,
        ]
        if network_protocol:
            values.append("ipv4")
        values.append("tcp")
        self.conn.execute(
            f"INSERT INTO alert_group_summary ({columns}) VALUES "
            f"({','.join('?' for _ in values)})",
            values,
        )

    def request(self):
        return {
            "request_id": "request-1", "alert_id": "alert-1",
            "group_id": "abcdef123456", "group_key": "group-key",
            "first_seen": "2026-08-07T12:00:00Z",
            "last_seen": "2026-08-07T12:01:00Z",
            "source_ip": "192.0.2.10", "source_port": 1111,
            "destination_ip": "198.51.100.20", "destination_port": 443,
            "network_protocol": "ipv4", "transport_protocol": "tcp",
            "community_id": None, "requested_by": "analyst",
            "reason": "review", "max_window_seconds": 120,
            "capture_file": "/nsm/test.pcap", "require_source_port": True,
        }

    def test_capture_file_prefers_suricata_then_direct(self) -> None:
        self.assertEqual(
            pcap_capture_file_from_json(
                '{"capture_file":"direct"}',
                '{"suricata":{"capture_file":"nested"}}',
            ),
            "direct",
        )
        self.assertEqual(
            pcap_capture_file_from_json(
                "invalid", '{"suricata":{"capture_file":"nested"}}'
            ),
            "nested",
        )
        self.assertIsNone(pcap_capture_file_from_json("[]", "{}"))

    def test_missing_summary_or_group_returns_no_candidate(self) -> None:
        self.assertEqual(
            read_pcap_request_candidate(
                self.sources, self.conn, "abcdef123456"
            ),
            {},
        )
        self.create_summary()
        self.assertEqual(
            read_pcap_request_candidate(self.sources, self.conn, "missing"),
            {},
        )

    def test_summary_candidate_supports_legacy_protocol_schema(self) -> None:
        self.create_summary(network_protocol=False)
        candidate = read_pcap_request_candidate(
            self.sources, self.conn, "abcdef123456"
        )
        self.assertEqual(candidate["first_seen"], "2026-08-07T12:00:00Z")
        self.assertIsNone(candidate["network_protocol"])
        self.assertEqual(candidate["transport_protocol"], "tcp")

    def test_representative_alert_enriches_candidate_and_capture_file(self) -> None:
        self.create_summary()
        self.conn.execute(
            "CREATE TABLE alerts (alert_id TEXT, first_seen TEXT, source_port INTEGER, "
            "raw_event_json TEXT, alert_json TEXT)"
        )
        self.conn.execute(
            "INSERT INTO alerts VALUES "
            "('alert-1', '2026-08-07T11:59:00Z', 2222, "
            "'{\"suricata\":{\"capture_file\":\"/nsm/capture.pcap\"}}', '{}')"
        )
        candidate = read_pcap_request_candidate(
            self.sources, self.conn, "abcdef123456"
        )
        self.assertEqual(candidate["first_seen"], "2026-08-07T11:59:00Z")
        self.assertEqual(candidate["source_port"], 2222)
        self.assertEqual(candidate["destination_port"], 443)
        self.assertEqual(candidate["capture_file"], "/nsm/capture.pcap")

    def test_insert_requires_queue_table(self) -> None:
        with self.assertRaises(sqlite3.Error):
            insert_pcap_request(self.sources, self.conn, self.request())

    def test_insert_and_retry_are_idempotent_and_schema_adaptive(self) -> None:
        self.conn.execute(
            "CREATE TABLE pcap_requests ("
            "request_id TEXT PRIMARY KEY, status TEXT, group_id TEXT, reason TEXT, "
            "requested_by TEXT, max_window_seconds INTEGER, request_json TEXT, "
            "created_at TEXT, updated_at TEXT, error TEXT, completed_at TEXT)"
        )
        row = insert_pcap_request(self.sources, self.conn, self.request())
        self.assertEqual(row["status"], "pending")
        self.assertTrue(json.loads(row["request_json"])["require_source_port"])
        self.conn.execute(
            "UPDATE pcap_requests SET status='failed', error='no packets', "
            "completed_at='done' WHERE request_id='request-1'"
        )
        retry = self.request()
        retry["reason"] = "retry"
        row = insert_pcap_request(self.sources, self.conn, retry)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["reason"], "retry")
        self.assertIsNone(row["error"])
        self.assertIsNone(row["completed_at"])
        count = self.conn.execute("SELECT COUNT(*) FROM pcap_requests").fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
