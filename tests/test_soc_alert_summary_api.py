#!/usr/bin/env python3
"""Regression checks for the SOC Alerts grouped-summary API path."""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PORTAL_PATH = REPO_ROOT / "onion-sentinel-dashboard" / "report_portal.py"


def load_portal():
    spec = importlib.util.spec_from_file_location("report_portal", PORTAL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SocAlertSummaryApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "alerts.sqlite3"
        self.portal = load_portal()
        self.portal.SOC_ALERT_STORE_DB = self.db_path
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY,
              first_seen TEXT,
              last_seen TEXT,
              seen_count INTEGER,
              timestamp TEXT,
              rule_name TEXT,
              event_dataset TEXT,
              severity INTEGER,
              severity_label TEXT,
              source_ip TEXT,
              destination_ip TEXT,
              triage_level TEXT,
              filter_status TEXT
            );
            CREATE TABLE alert_group_summary (
              group_id TEXT PRIMARY KEY,
              group_key TEXT NOT NULL UNIQUE,
              representative_alert_id TEXT,
              first_seen TEXT,
              last_seen TEXT,
              raw_alert_count INTEGER NOT NULL DEFAULT 0,
              total_seen_count INTEGER NOT NULL DEFAULT 0,
              timestamp TEXT,
              rule_name TEXT,
              event_dataset TEXT,
              severity INTEGER,
              severity_label TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              traffic_direction TEXT,
              triage_score INTEGER,
              triage_level TEXT,
              routing TEXT,
              filter_status TEXT,
              alert_json TEXT,
              filter_reason TEXT,
              suppression_key TEXT,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE suppression_log (
              suppression_key TEXT PRIMARY KEY,
              rule_name TEXT NOT NULL,
              reason TEXT,
              window_start TEXT NOT NULL,
              last_seen TEXT NOT NULL,
              seen_count INTEGER NOT NULL DEFAULT 1,
              suppressed_count INTEGER NOT NULL DEFAULT 0,
              escalated_count INTEGER NOT NULL DEFAULT 0,
              ttl_seconds INTEGER NOT NULL,
              escalation_threshold INTEGER NOT NULL
            );
            """
        )
        self.insert_summary(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted",
            "newest-alert",
            "Newest detection",
            "critical",
            "2026-07-03  12:00:00Z",
            2,
            5,
        )
        self.insert_summary(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted",
            "older-alert",
            "Older detection",
            "high",
            "2026-07-03  11:00:00Z",
            1,
            1,
        )
        self.conn.commit()

    def tearDown(self) -> None:
        self.conn.close()
        self.tmp.cleanup()

    def insert_summary(
        self,
        group_key: str,
        alert_id: str,
        rule_name: str,
        level: str,
        last_seen: str,
        raw_count: int,
        total_count: int,
    ) -> str:
        group_id = self.portal.soc_alert_group_id(group_key)
        self.conn.execute(
            """
            INSERT INTO alert_group_summary (
              group_id, group_key, representative_alert_id, first_seen, last_seen,
              raw_alert_count, total_seen_count, timestamp, rule_name, event_dataset,
              severity, severity_label, source_ip, source_port, destination_ip,
              destination_port, transport_protocol, traffic_direction, triage_score,
              triage_level, routing, filter_status, alert_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'suricata.alert', 4, ?, '192.0.2.10',
                    4444, '198.51.100.10', 443, 'tcp', 'outbound', 90, ?,
                    'analyst-review-immediate', 'accepted', '{}', ?)
            """,
            (
                group_id,
                group_key,
                alert_id,
                last_seen,
                last_seen,
                raw_count,
                total_count,
                last_seen,
                rule_name,
                level,
                level,
                last_seen,
            ),
        )
        return group_id

    def test_alert_list_uses_summary_table_and_orders_newest_first(self) -> None:
        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 2)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["seen_count"], 5)

    def test_acknowledged_group_is_hidden_from_open_slice(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
            "repeat_count": 5,
        })

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 1)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "older-alert")


if __name__ == "__main__":
    unittest.main()
