#!/usr/bin/env python3
"""Regression checks for the SOC Alerts grouped-summary API path."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import time
import unittest
import datetime as dt
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


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
        self.portal.SOC_ALERT_STORE_API_URL = ""
        self.portal.SOC_ALERT_STATUS_FILE = Path(self.tmp.name) / ".soc_alert_status.json"
        self.portal.SOC_ALERT_STATIC_STATUS_FILE = Path(self.tmp.name) / "soc-alerts-status.json"
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR = Path(self.tmp.name) / "pcap-analysis"
        self.portal.SOC_ALERT_PCAP_ARTIFACT_DIR = Path(self.tmp.name) / "pcap-artifacts"
        self.portal.SOC_ALERT_AI_ANALYSIS_DIR = Path(self.tmp.name) / "ai-analysis"
        self.portal.SOC_ALERT_AI_ANALYSIS_DIR.mkdir()
        self.portal.SOC_ALERT_DETAIL_DIR = Path(self.tmp.name) / "details"
        self.portal.SOC_ALERT_DETAIL_DIR.mkdir()
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
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              triage_level TEXT,
              filter_status TEXT,
              alert_json TEXT,
              raw_event_json TEXT
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
            CREATE TABLE pcap_requests (
              request_id TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              alert_id TEXT,
              group_id TEXT,
              group_key TEXT,
              first_seen TEXT,
              last_seen TEXT,
              source_ip TEXT,
              source_port INTEGER,
              destination_ip TEXT,
              destination_port INTEGER,
              network_protocol TEXT,
              transport_protocol TEXT,
              community_id TEXT,
              requested_by TEXT,
              reason TEXT NOT NULL,
              max_window_seconds INTEGER NOT NULL,
              relay_host TEXT,
              artifact_path TEXT,
              artifact_sha256 TEXT,
              artifact_size_bytes INTEGER,
              error TEXT,
              request_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              claimed_at TEXT,
              completed_at TEXT,
              transfer_stage TEXT,
              transfer_bytes INTEGER NOT NULL DEFAULT 0,
              transfer_total_bytes INTEGER NOT NULL DEFAULT 0,
              transfer_progress_at TEXT,
              transfer_duration_seconds INTEGER,
              updated_at TEXT NOT NULL
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
        self.insert_summary(
            "critical|Suppressed backend detection|192.0.2.30|198.51.100.30|suppressed",
            "backend-suppressed-alert",
            "Suppressed backend detection",
            "critical",
            "2026-07-03  12:30:00Z",
            7,
            7,
            filter_status="suppressed",
        )
        self.conn.commit()

    def test_detail_sections_collapse_by_default(self) -> None:
        detail_html = (
            "<h3>Alert Summary</h3><p>summary context</p>"
            "<h3>Network And Flow Details</h3><p>flow context</p>"
            "<h4>Nested Evidence</h4><p>stays inside</p>"
            "<h3>TShark Corroboration</h3><p>packet parser context</p>"
            "<h3>Threat Context</h3><p>ioc context</p>"
            "<h3>Analyst Notes</h3><p>operator notes</p>"
            "<h3>Other Section</h3><p>remains expanded</p>"
        )

        collapsed = self.portal.soc_alert_collapse_detail_sections(detail_html)

        self.assertEqual(collapsed.count('class="detail-report-section detail-collapsible-section'), 5)
        self.assertNotIn("<details open", collapsed)
        self.assertIn("<summary>Alert Summary</summary>", collapsed)
        self.assertIn("<summary>Network And Flow Details</summary>", collapsed)
        self.assertIn("<summary>TShark Findings</summary>", collapsed)
        self.assertIn("<summary>Threat Context</summary>", collapsed)
        self.assertIn("<summary>Analyst Notes</summary>", collapsed)
        self.assertIn("<h4>Nested Evidence</h4><p>stays inside</p></div></details>", collapsed)
        self.assertIn("<h3>Other Section</h3><p>remains expanded</p>", collapsed)

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
        filter_status: str = "accepted",
        source_ip: str = "192.0.2.10",
        destination_ip: str = "198.51.100.10",
        destination_port: int = 443,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'suricata.alert', 4, ?, ?,
                    4444, ?, ?, 'tcp', 'outbound', 90, ?,
              'analyst-review-immediate', ?, '{}', ?)
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
                source_ip,
                destination_ip,
                destination_port,
                level,
                filter_status,
                last_seen,
            ),
        )
        return group_id

    def test_alert_list_uses_summary_table_and_orders_newest_first(self) -> None:
        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 2)
        self.assertEqual(payload["status_counts"]["open"], 2)
        self.assertEqual(payload["status_counts"]["suppressed"], 1)
        self.assertEqual(payload["status_counts"]["acknowledged"], 0)
        self.assertEqual(payload["status_counts"]["total"], 3)
        self.assertEqual(payload["severity_counts"]["critical"], 1)
        self.assertEqual(payload["severity_counts"]["high"], 1)
        self.assertEqual(payload["severity_counts"]["medium"], 0)
        self.assertEqual(payload["severity_counts"]["low"], 0)
        self.assertEqual(payload["severity_counts"]["informational"], 0)
        self.assertEqual(payload["top_endpoints"]["source_ip"], "192.0.2.10")
        self.assertEqual(payload["top_endpoints"]["destination_ip"], "198.51.100.10")
        self.assertEqual(payload["top_endpoints"]["destination_port"], "443")
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["seen_count"], 5)
        self.assertEqual(payload["alerts"][0]["ai_status_key"], "queued")
        self.assertEqual(payload["alerts"][0]["ai_status_label"], "Queued")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "none")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "None")
        self.assertNotIn("backend-suppressed-alert", [alert["representative_alert_id"] for alert in payload["alerts"]])

    def test_alert_list_marks_groups_with_parsed_pcap_analysis(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "unit-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"group_id": newest_group_id, "alert_id": "newest-alert"},
                    "pcap_files": [{"name": "unit.pcap", "size_bytes": 128}],
                    "zeek": {"available": True},
                    "tshark": {"available": False},
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "analyzed")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "Analyzed")

    def test_detail_fragment_rejects_legacy_layout_instead_of_appending_pcap(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_DETAIL_DIR / f"{newest_group_id}.html").write_text(
            "<h2>AI Model Used</h2><h4>PCAP Analysis Findings</h4><ul><li>n/a</li></ul>",
            encoding="utf-8",
        )
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "unit-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"request_id": "unit", "group_id": newest_group_id, "alert_id": "newest-alert"},
                    "generated_at": "2026-07-03  12:01:00-06:00",
                    "pcap_files": [{"name": "unit.pcap", "size_bytes": 128}],
                    "zeek": {
                        "available": True,
                        "record_counts": {"conn": 1},
                        "top_connections": [{"id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10"}],
                    },
                    "tshark": {
                        "available": True,
                        "samples": [{"protocol_hierarchy": "frame\\nip\\ntcp", "conversations": "192.0.2.10 <-> 198.51.100.10"}],
                    },
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alert_detail_fragment_response(newest_group_id)

        self.assertEqual(status, 200)
        self.assertFalse(payload["layout_valid"])
        self.assertTrue(payload["layout_issues"])
        self.assertIn("Detailed Alert Report layout error", payload["detail_html"])
        self.assertIn("PCAP Analysis Findings", payload["detail_html"])
        self.assertNotIn("Parsed PCAP Evidence", payload["detail_html"])
        self.assertNotIn("Top Connections", payload["detail_html"])
        self.assertNotIn("192.0.2.10", payload["detail_html"])

    def test_pcap_request_endpoint_queues_group_for_broker(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.conn.execute(
            """
            INSERT INTO alerts (
              alert_id, first_seen, last_seen, timestamp, source_ip, source_port,
              destination_ip, destination_port, transport_protocol, alert_json,
              raw_event_json, triage_level, filter_status
            )
            VALUES (
              'newest-alert', '2026-07-03  12:00:01Z', '2026-07-03  12:00:01Z',
              '2026-07-03  12:00:01Z', '192.0.2.10', 5555, '198.51.100.10',
              443, 'tcp', '{}', '{"suricata":{"capture_file":"/nsm/suripcap/1/so-pcap.unit"}}',
              'critical', 'accepted'
            )
            """
        )
        self.conn.commit()

        status, payload = self.portal.soc_alert_pcap_request_response(
            newest_group_id,
            {"reason": "unit test analyst request", "requested_by": "unit-test", "require_source_port": True},
        )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        row = self.conn.execute("SELECT * FROM pcap_requests WHERE group_id = ?", (newest_group_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["reason"], "unit test analyst request")
        self.assertEqual(row["requested_by"], "unit-test")
        self.assertEqual(row["source_ip"], "192.0.2.10")
        self.assertEqual(row["destination_ip"], "198.51.100.10")
        request_json = json.loads(row["request_json"])
        self.assertTrue(request_json["require_source_port"])
        self.assertEqual(request_json["capture_file"], "/nsm/suripcap/1/so-pcap.unit")

    def test_production_pcap_request_uses_alert_store_api(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        response = mock.MagicMock()
        response.read.return_value = json.dumps({
            "ok": True,
            "status": "pending",
            "request": {"request_id": "synthetic-request", "group_id": group_id},
        }).encode("utf-8")
        context = mock.MagicMock()
        context.__enter__.return_value = response
        self.portal.SOC_ALERT_STORE_API_URL = "http://127.0.0.1:8787"

        with mock.patch.object(self.portal.urllib_request, "urlopen", return_value=context) as urlopen:
            status, payload = self.portal.soc_alert_pcap_request_response(
                group_id,
                {"reason": "unit test request"},
            )

        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "pending")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8787/pcap/request")
        sent = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent["group_id"], group_id)

    def test_pcap_request_endpoint_requeues_failed_request(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        status, first = self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "first request"})
        self.assertEqual(status, 202)
        request_id = first["request"]["request_id"]
        self.conn.execute(
            "UPDATE pcap_requests SET status = 'failed', error = 'no matching packets found', completed_at = updated_at WHERE request_id = ?",
            (request_id,),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "first request"})

        self.assertEqual(status, 202)
        row = self.conn.execute("SELECT * FROM pcap_requests WHERE request_id = ?", (request_id,)).fetchone()
        self.assertEqual(payload["request"]["request_id"], request_id)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["reason"], "first request")
        self.assertIsNone(row["error"])

    def test_alert_list_marks_no_matching_packets_pcap_status(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "unit test no packets"})
        self.conn.execute(
            "UPDATE pcap_requests SET status = 'failed', error = 'no matching packets found for requested window', request_json = ?, completed_at = updated_at WHERE group_id = ?",
            (
                json.dumps({"capture_file": "/nsm/suripcap/5/so-pcap.example"}),
                newest_group_id,
            ),
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "empty-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"group_id": newest_group_id, "alert_id": "newest-alert"},
                    "pcap_files": [],
                    "artifact_state": "artifact-not-copied-to-mac",
                    "zeek": {"available": False},
                    "tshark": {"available": False},
                }
            ),
            encoding="utf-8",
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "no-packets")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "No Packets")

    def test_alert_list_marks_stale_no_matching_packets_pcap_request_for_retry(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "unit test stale no packets"})
        self.conn.execute(
            "UPDATE pcap_requests SET status = 'failed', error = 'no matching packets found for requested window', request_json = ?, completed_at = updated_at WHERE group_id = ?",
            (json.dumps({"destination_ip": "198.51.100.10", "destination_port": 443}), newest_group_id),
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "empty-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"group_id": newest_group_id, "alert_id": "newest-alert"},
                    "pcap_files": [],
                    "artifact_state": "artifact-not-copied-to-mac",
                    "zeek": {"available": False},
                    "tshark": {"available": False},
                }
            ),
            encoding="utf-8",
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "error")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "Retry")

    def test_alert_list_uses_static_ai_status_when_available(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        (self.portal.SOC_ALERT_AI_ANALYSIS_DIR / "unit-local-ai-analysis.json").write_text(
            json.dumps({"alert_id": "newest-alert", "generated_at": "2026-07-03  12:01:00Z"}),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "ok": True,
                    "reports": {
                        newest_group_id: {
                            "ai_status_key": "analyzed",
                            "ai_status_label": "Analyzed",
                            "ai_status_detail": "unit test analysis artifact",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["ai_status_key"], "analyzed")
        self.assertEqual(payload["alerts"][0]["ai_status_label"], "Analyzed")
        self.assertEqual(payload["alerts"][0]["ai_status_detail"], "unit test analysis artifact")

    def test_alert_list_corrects_stale_skipped_ai_status_without_artifact(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "ok": True,
                    "reports": {
                        newest_group_id: {
                            "ai_status_key": "not-queued",
                            "ai_status_label": "Skipped",
                            "ai_status_detail": "stale status from previous build",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["ai_status_key"], "queued")
        self.assertEqual(payload["alerts"][0]["ai_status_label"], "Queued")
        self.assertIn("No AI analysis artifact exists", payload["alerts"][0]["ai_status_detail"])

    def test_manual_analyze_queues_fresh_full_group_prompt(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        prompt_path = Path(self.tmp.name) / "prompt.json"
        prompt_path.write_text("{}", encoding="utf-8")
        builder_path = Path(self.tmp.name) / "build-ai-investigation-prompt.py"
        builder_path.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        self.portal.SOC_ALERT_AI_PROMPT_BUILDER = builder_path
        self.portal.SOC_ALERT_AI_PROMPT_DIR = Path(self.tmp.name) / "ai-prompts"

        completed = mock.Mock(returncode=0, stdout=f"{prompt_path}\n", stderr="")
        with (
            mock.patch.object(self.portal, "soc_alert_group_representative_alert_id", return_value="newest-alert"),
            mock.patch.object(self.portal.subprocess, "run", return_value=completed) as run_mock,
        ):
            status, payload = self.portal.soc_alert_queue_analysis_response(group_id, {})

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["ai_status_key"], "queued")
        command = run_mock.call_args.args[0]
        self.assertIn("--alert-id", command)
        self.assertEqual(command[command.index("--alert-id") + 1], "newest-alert")
        self.assertIn("--related-limit", command)
        self.assertEqual(command[command.index("--related-limit") + 1], "250")
        self.assertIn("--pcap-analysis-limit", command)

    def test_top_endpoint_metrics_use_visible_alert_volume(self) -> None:
        self.insert_summary(
            "medium|Noisy visible detection|192.0.2.99|198.51.100.99|accepted",
            "noisy-visible-alert",
            "Noisy visible detection",
            "medium",
            "2026-07-03  10:00:00Z",
            1,
            20,
            source_ip="192.0.2.99",
            destination_ip="198.51.100.99",
            destination_port=8443,
        )
        self.conn.commit()
        status, payload = self.portal.soc_alerts_query_response({"limit": ["2"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["total_matching"], 3)
        self.assertEqual(len(payload["alerts"]), 2)
        self.assertEqual(payload["top_endpoints"]["source_ip"], "192.0.2.99")
        self.assertEqual(payload["top_endpoints"]["destination_ip"], "198.51.100.99")
        self.assertEqual(payload["top_endpoints"]["destination_port"], "8443")

    def test_suppressed_slice_includes_backend_filter_suppressed_groups(self) -> None:
        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["suppressed"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 1)
        self.assertEqual(payload["status_counts"]["total"], 3)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "backend-suppressed-alert")

    def test_metrics_count_backend_suppressed_groups_like_alert_table(self) -> None:
        self.portal.SOC_ALERT_PCAP_ARTIFACT_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ARTIFACT_DIR / "sample.pcap").write_bytes(b"pcap-data")
        status, payload = self.portal.soc_alert_metrics_response({"since": [""]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["grouped_total"], 3)
        self.assertEqual(payload["by_analyst_status"]["open"], 2)
        self.assertEqual(payload["by_analyst_status"]["active"], 2)
        self.assertEqual(payload["by_analyst_status"]["suppressed"], 1)
        self.assertEqual(payload["by_analyst_status"]["acknowledged"], 0)
        self.assertEqual(payload["by_analyst_status"]["total"], 3)
        self.assertEqual(payload["pcap_ingest_size_bytes"], len(b"pcap-data"))

    def test_system_health_includes_pcap_workflow_counts(self) -> None:
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "unit-pcap-analysis.json").write_text(
            json.dumps({"request": {"request_id": "unit"}, "pcap_files": []}),
            encoding="utf-8",
        )
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, group_id, reason, max_window_seconds,
              request_json, created_at, updated_at, completed_at, error
            )
            VALUES (
              'pcap-health-test', 'failed', ?, 'unit test', 120,
              '{}', '2026-07-03  12:00:00Z', '2026-07-03  12:01:00Z',
              '2026-07-03  12:01:00Z', 'no matching packets found'
            )
            """,
            (
                self.portal.soc_alert_group_id(
                    "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
                ),
            ),
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["pcap"]["request_counts"]["failed"], 1)
        self.assertEqual(payload["pcap"]["no_packet_failures"], 1)
        self.assertEqual(payload["pcap"]["analysis_count"], 1)
        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertEqual(payload["pcap"]["recent_requests"][0]["request_id"], "pcap-health-test")
        self.assertEqual(payload["pcap"]["recent_requests"][0]["status"], "failed")

    def test_system_health_derives_legacy_pcap_transfer_duration(self) -> None:
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, claimed_at, completed_at, updated_at
            ) VALUES (
              'pcap-duration-test', 'fulfilled', 'unit test', 120, '{}',
              '2026-07-03  12:00:00Z', '2026-07-03  12:01:00Z',
              '2026-07-03  12:03:05Z', '2026-07-03  12:03:05Z'
            )
            """
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        request = payload["pcap"]["recent_requests"][0]
        self.assertEqual(request["request_id"], "pcap-duration-test")
        self.assertEqual(request["transfer_duration_seconds"], 125)

    def test_system_health_warns_on_stale_or_unexpected_pcap_work(self) -> None:
        fresh_failure_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=30),
            timespec="seconds",
        )
        old_failure_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3),
            timespec="seconds",
        )
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, group_id, reason, max_window_seconds,
              request_json, created_at, updated_at, completed_at, error
            )
            VALUES
              ('pcap-stale-pending', 'pending', ?, 'unit test', 120, '{}',
               '2026-07-03  12:00:00Z', '2026-07-03  12:00:00Z', NULL, NULL),
              ('pcap-unexpected-failure', 'failed', ?, 'unit test', 120, '{}',
               ?, ?, ?, 'artifact upload failed'),
              ('pcap-old-unexpected-failure', 'failed', ?, 'unit test', 120, '{}',
               ?, ?, ?, 'old artifact upload failed'),
              ('pcap-legacy-invalid-json', 'failed', ?, 'unit test', 120, '{}',
               ?, ?, ?, 'PCAP export returned invalid JSON: no JSON object found: line 1 column 1 (char 0); preview=''''')
            """,
            (
                self.portal.soc_alert_group_id(
                    "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
                ),
                self.portal.soc_alert_group_id(
                    "medium|Older detection|192.0.2.20|198.51.100.20|accepted"
                ),
                fresh_failure_at,
                fresh_failure_at,
                fresh_failure_at,
                self.portal.soc_alert_group_id(
                    "low|Old failure|192.0.2.30|198.51.100.30|accepted"
                ),
                old_failure_at,
                old_failure_at,
                old_failure_at,
                self.portal.soc_alert_group_id(
                    "medium|Legacy invalid JSON|192.0.2.40|198.51.100.40|accepted"
                ),
                fresh_failure_at,
                fresh_failure_at,
                fresh_failure_at,
            ),
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 2)
        self.assertTrue(any("pending PCAP request" in item for item in payload["pcap"]["warnings"]))
        self.assertTrue(any("1 PCAP request failure(s) need review" in item for item in payload["pcap"]["warnings"]))

    def test_system_health_does_not_flag_queue_behind_fresh_large_transfer(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
            timespec="seconds",
        )
        fresh_at = self.portal.format_iso_timestamp(dt.datetime.now(dt.timezone.utc), timespec="seconds")
        self.conn.executemany(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, claimed_at, transfer_stage, transfer_bytes,
              transfer_total_bytes, transfer_progress_at, updated_at
            ) VALUES (?, ?, 'unit test', 120, '{}', ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "pcap-active-large", "claimed", old_at, old_at,
                    "security_onion_to_relay", 8 * 1024**3, 24 * 1024**3, fresh_at, fresh_at,
                ),
                (
                    "pcap-queued-behind-large", "pending", old_at, None,
                    None, 0, 0, None, old_at,
                ),
            ],
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertEqual(payload["pcap"]["active_transfers"][0]["request_id"], "pcap-active-large")

    def test_system_health_preserves_bounded_progress_between_serial_pcap_jobs(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
            timespec="seconds",
        )
        fresh_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
            timespec="seconds",
        )
        self.conn.executemany(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, updated_at, completed_at
            ) VALUES (?, ?, 'unit test', 120, '{}', ?, ?, ?)
            """,
            [
                ("pcap-old-pending", "pending", old_at, old_at, None),
                ("pcap-recent-terminal", "fulfilled", old_at, fresh_at, fresh_at),
            ],
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertTrue(payload["pcap"]["queue_progressing"])
        self.assertLessEqual(payload["pcap"]["last_progress_age_seconds"], 65)
        self.assertEqual(payload["pcap"]["warning_count"], 0)

    def test_event_snapshot_uses_consistent_status_and_metrics_counts(self) -> None:
        payload = self.portal.soc_alert_events_snapshot()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["counts"]["open"], 2)
        self.assertEqual(payload["counts"]["suppressed"], 0)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["open"], 2)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["suppressed"], 1)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["total"], payload["counts"]["total"])

    def test_event_snapshot_cache_coalesces_concurrent_browser_clients(self) -> None:
        self.portal.SOC_ALERT_EVENTS_CACHE.clear()
        payload = {"ok": True, "event": "soc-alerts"}

        def slow_snapshot() -> dict:
            time.sleep(0.05)
            return payload

        with mock.patch.object(self.portal, "soc_alert_events_snapshot", side_effect=slow_snapshot) as snapshot:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: self.portal.cached_soc_alert_events_snapshot(), range(16)))

        self.assertEqual(results, [payload] * 16)
        self.assertEqual(snapshot.call_count, 1)

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
        self.assertEqual(payload["severity_counts"]["critical"], 0)
        self.assertEqual(payload["severity_counts"]["high"], 1)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "older-alert")

    def test_legacy_bulk_acknowledged_payload_is_read_only(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        older_group_id = self.portal.soc_alert_group_id(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted"
        )
        self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
            "repeat_count": 5,
        })

        ok, payload = self.portal.update_soc_alert_status({"acknowledged": [older_group_id]})

        self.assertTrue(ok)
        self.assertEqual(payload["statuses"][newest_group_id]["status"], "acknowledged")
        self.assertNotIn(older_group_id, payload["statuses"])

    def test_acknowledge_without_repeat_count_uses_current_group_count(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )

        ok, payload = self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
        })

        self.assertTrue(ok)
        self.assertEqual(payload["statuses"][newest_group_id]["status"], "acknowledged")
        self.assertEqual(payload["statuses"][newest_group_id]["repeat_count"], 5)
        status, open_payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})
        self.assertEqual(status, 200)
        self.assertNotIn("newest-alert", [alert["representative_alert_id"] for alert in open_payload["alerts"]])

    def test_many_individual_status_updates_do_not_replace_each_other(self) -> None:
        group_ids = []
        for index in range(12):
            group_id = self.insert_summary(
                f"medium|Load test {index}|192.0.2.{40 + index}|198.51.100.{40 + index}|accepted",
                f"load-alert-{index}",
                f"Load test {index}",
                "medium",
                f"2026-07-03  10:{index:02d}:00Z",
                1,
                index + 1,
            )
            group_ids.append(group_id)
        self.conn.commit()

        def write_status(item: tuple[int, str]) -> None:
            index, group_id = item
            status = "suppressed" if index % 3 == 0 else "acknowledged"
            self.portal.update_soc_alert_status({
                "id": group_id,
                "status": status,
                "repeat_count": index + 1,
                "reason": f"load test {index}" if status == "suppressed" else "",
            })

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(write_status, enumerate(group_ids)))

        statuses = self.portal.load_soc_alert_statuses()
        self.assertEqual({group_id for group_id in group_ids}, {group_id for group_id in group_ids if group_id in statuses})
        for index, group_id in enumerate(group_ids):
            expected_status = "suppressed" if index % 3 == 0 else "acknowledged"
            self.assertEqual(statuses[group_id]["status"], expected_status)
            self.assertEqual(statuses[group_id]["repeat_count"], index + 1)

    def test_bulk_status_persistence_merges_without_deleting_other_groups(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        older_group_id = self.portal.soc_alert_group_id(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted"
        )
        self.portal.write_soc_alert_status(newest_group_id, {
            "status": "acknowledged",
            "repeat_count": 5,
            "updated_at": "2026-07-03  12:00:00Z",
        })

        self.portal.save_soc_alert_statuses_to_db({
            older_group_id: {
                "status": "suppressed",
                "repeat_count": 1,
                "reason": "unit test suppression",
                "updated_at": "2026-07-03  12:01:00Z",
            }
        })

        statuses = self.portal.load_soc_alert_statuses()
        self.assertEqual(statuses[newest_group_id]["status"], "acknowledged")
        self.assertEqual(statuses[older_group_id]["status"], "suppressed")

    def test_acknowledged_group_reopens_when_repeat_count_increases(self) -> None:
        newest_group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        newest_group_id = self.portal.soc_alert_group_id(newest_group_key)
        self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
            "repeat_count": 5,
        })
        self.conn.execute(
            """
            UPDATE alert_group_summary
            SET raw_alert_count = 3, total_seen_count = 6
            WHERE group_id = ?
            """,
            (newest_group_id,),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})
        status_payload = self.portal.soc_alert_status_response()

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 2)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertNotIn(newest_group_id, status_payload["statuses"])

    def test_production_status_update_uses_alert_store_api(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        response = mock.MagicMock()
        response.read.return_value = json.dumps({
            "ok": True,
            "statuses": {group_id: {"status": "acknowledged", "repeat_count": 5}},
        }).encode("utf-8")
        context = mock.MagicMock()
        context.__enter__.return_value = response
        self.portal.SOC_ALERT_STORE_API_URL = "http://127.0.0.1:8787"

        with mock.patch.object(self.portal.urllib_request, "urlopen", return_value=context) as urlopen:
            with mock.patch.object(self.portal, "write_soc_alert_status", side_effect=AssertionError("direct DB write")):
                ok, payload = self.portal.update_soc_alert_status({
                    "id": group_id,
                    "status": "acknowledged",
                    "repeat_count": 5,
                })

        self.assertTrue(ok)
        self.assertTrue(payload["ok"])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8787/analyst-status")
        sent = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent["id"], group_id)
        self.assertEqual(sent["status"], "acknowledged")


if __name__ == "__main__":
    unittest.main()
