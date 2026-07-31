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
    def test_missing_reviewer_confidence_cannot_authorize_automation(self) -> None:
        authorization = self.portal._soc_reviewer_automation_authorization({
            "reviewer_confidence": "",
            "automation_authorization": {},
        })
        self.assertFalse(authorization["authorized"])
        self.assertTrue(authorization["legacy_confidence_fallback"])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "alerts.sqlite3"
        self.portal = load_portal()
        self.portal.HOME = Path(self.tmp.name)
        self.portal.SOC_ALERT_STORE_DB = self.db_path
        self.portal.SOC_ALERT_STORE_API_URL = ""
        self.portal.SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED = True
        self.portal.SOC_ALERT_STATUS_FILE = Path(self.tmp.name) / ".soc_alert_status.json"
        self.portal.SOC_ALERT_STATIC_STATUS_FILE = Path(self.tmp.name) / "soc-alerts-status.json"
        self.portal.ASSET_INVENTORY_FILE = Path(self.tmp.name) / "asset-inventory.json"
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE = (
            Path(self.tmp.name) / "dhcp-observations.json"
        )
        self.portal.ASSET_INVENTORY_CACHE = {"signature": None, "inventory": None}
        self.portal.SOC_AI_SETTINGS_FILE = Path(self.tmp.name) / "ai-model-settings.json"
        self.portal.SOC_AI_SETTINGS_FILE.write_text(
            json.dumps(self.portal.default_soc_ai_settings()),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE = (
            Path(self.tmp.name) / "current-analysis.json"
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR = (
            Path(self.tmp.name) / "active-analyses"
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR.mkdir()
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE = Path(self.tmp.name) / "pcap-workflow-state.json"
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
              suppression_key TEXT,
              enrichment_json TEXT,
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
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              alert_id TEXT NOT NULL,
              generated_at TEXT NOT NULL,
              model TEXT,
              model_path TEXT,
              detection_outcome TEXT,
              bluf TEXT,
              summary TEXT,
              confidence TEXT,
              artifact_path TEXT,
              evidence_hash TEXT,
              response_json TEXT NOT NULL,
              created_at TEXT NOT NULL
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
        self.assertEqual(payload["active_total"], 2)
        self.assertEqual(payload["active_highest_severity"], "critical")
        self.assertEqual(payload["active_severity_counts"], payload["severity_counts"])
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
        self.assertEqual(payload["alerts"][0]["pcap_size_bytes"], 0)
        self.assertEqual(payload["alerts"][0]["detection_outcome"], "")
        self.assertEqual(payload["alerts"][0]["detection_outcome_label"], "n/a")
        self.assertNotIn("backend-suppressed-alert", [alert["representative_alert_id"] for alert in payload["alerts"]])

    def test_manual_incident_escalation_removes_every_group_alias_from_soc_alerts(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        older_group_id = self.portal.soc_alert_group_id(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted"
        )
        stable_group_id = "stable-incident-unit"
        self.conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL
            );
            CREATE TABLE incident_response_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              detail_json TEXT NOT NULL
            );
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO incident_response_cases VALUES (?, ?, ?)",
            ("ir-manual-unit", stable_group_id, newest_group_id),
        )
        self.conn.execute(
            """
            INSERT INTO incident_response_events (case_id, event_type, detail_json)
            VALUES (?, 'escalated', ?)
            """,
            (
                "ir-manual-unit",
                json.dumps({"dashboard_group_id": newest_group_id}),
            ),
        )
        self.conn.execute(
            "INSERT INTO alert_group_alias VALUES (?, ?)",
            (older_group_id, stable_group_id),
        )
        self.conn.commit()

        status, open_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        _, all_payload = self.portal.soc_alerts_query_response({"limit": ["10"]})
        metrics_status, metrics = self.portal.soc_alert_metrics_response({"since": [""]})
        status_payload = self.portal.soc_alert_status_response()

        self.assertEqual(status, 200)
        self.assertEqual(metrics_status, 200)
        self.assertEqual(open_payload["total_matching"], 0)
        self.assertEqual(open_payload["active_total"], 0)
        self.assertEqual(open_payload["status_counts"]["total"], 1)
        self.assertEqual(all_payload["total_matching"], 1)
        self.assertEqual(
            [alert["representative_alert_id"] for alert in all_payload["alerts"]],
            ["backend-suppressed-alert"],
        )
        self.assertEqual(metrics["grouped_total"], 1)
        self.assertEqual(metrics["by_analyst_status"]["total"], 1)
        self.assertEqual(status_payload["counts"]["open"], 0)
        self.assertEqual(status_payload["counts"]["escalated"], 2)
        self.assertEqual(status_payload["counts"]["total"], 1)

    def test_automatic_incident_event_does_not_remove_soc_alert_group(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL
            );
            CREATE TABLE incident_response_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              detail_json TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO incident_response_cases VALUES (?, ?, ?)",
            ("ir-auto-unit", "stable-auto-unit", newest_group_id),
        )
        self.conn.execute(
            """
            INSERT INTO incident_response_events (case_id, event_type, detail_json)
            VALUES (?, 'auto_escalated', ?)
            """,
            ("ir-auto-unit", json.dumps({"dashboard_group_id": newest_group_id})),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["total_matching"], 2)
        self.assertIn("newest-alert", [alert["representative_alert_id"] for alert in payload["alerts"]])

    def test_active_metrics_are_independent_of_page_size_and_selected_status_bucket(self) -> None:
        _, one_row = self.portal.soc_alerts_query_response({"limit": ["1"], "analyst_status": ["open"]})
        _, all_rows = self.portal.soc_alerts_query_response({"limit": ["100"], "analyst_status": ["open"]})
        _, suppressed_view = self.portal.soc_alerts_query_response({"limit": ["1"], "analyst_status": ["suppressed"]})

        self.assertEqual(one_row["count"], 1)
        self.assertEqual(one_row["total_matching"], 2)
        self.assertEqual(all_rows["count"], 2)
        self.assertEqual(one_row["active_total"], 2)
        self.assertEqual(one_row["active_total"], all_rows["active_total"])
        self.assertEqual(one_row["active_severity_counts"], all_rows["active_severity_counts"])
        self.assertEqual(one_row["active_severity_counts"], {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "informational": 0,
        })
        self.assertEqual(suppressed_view["total_matching"], 1)
        self.assertEqual(suppressed_view["active_total"], one_row["active_total"])
        self.assertEqual(suppressed_view["active_severity_counts"], one_row["active_severity_counts"])
        self.assertEqual(suppressed_view["active_highest_severity"], "critical")

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
        self.assertEqual(payload["alerts"][0]["pcap_size_bytes"], 128)

    def test_alert_list_aggregates_group_pcap_size_and_latest_detection_outcome(self) -> None:
        group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        group_id = self.portal.soc_alert_group_id(group_key)
        pcap_values = (
            ("request-one", "sha-one", 1024),
            ("request-one-retry", "sha-one", 1024),
            ("request-two", "sha-two", 2048),
        )
        for request_id, sha256, size_bytes in pcap_values:
            self.conn.execute(
                """
                INSERT INTO pcap_requests (
                  request_id, status, alert_id, group_id, group_key, reason,
                  max_window_seconds, artifact_path, artifact_sha256,
                  artifact_size_bytes, request_json, created_at, updated_at
                ) VALUES (?, 'fulfilled', 'newest-alert', ?, ?, 'unit test',
                          300, ?, ?, ?, '{}', ?, ?)
                """,
                (
                    request_id,
                    group_id,
                    group_key,
                    f"/tmp/{request_id}.pcap",
                    sha256,
                    size_bytes,
                    "2026-07-03  12:01:00Z",
                    "2026-07-03  12:01:00Z",
                ),
            )
        for analysis_id, generated_at, outcome in (
            ("analysis-old", "2026-07-03  12:01:00Z", "true_positive_suspicious"),
            ("analysis-new", "2026-07-03  12:02:00Z", "false_positive_logic_rule"),
        ):
            self.conn.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, generated_at,
                  detection_outcome, response_json, created_at
                ) VALUES (?, ?, 'newest-alert', ?, ?, '{}', ?)
                """,
                (analysis_id, group_id, generated_at, outcome, generated_at),
            )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        newest = payload["alerts"][0]
        self.assertEqual(newest["pcap_size_bytes"], 3072)
        self.assertEqual(newest["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(newest["detection_outcome_label"], "FP - Rule")

    def test_disagreement_freshness_and_adjudication_guard_follow_current_analysis(self) -> None:
        group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        group_id = self.portal.soc_alert_group_id(group_key)
        stable_group_id = "stable-detection-unit"
        self.conn.executescript(
            """
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL
            );
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT PRIMARY KEY,
              status TEXT,
              primary_outcome TEXT,
              primary_confidence TEXT,
              reviewer_outcome TEXT,
              reviewer_confidence TEXT,
              agreement TEXT,
              material_disagreement INTEGER,
              disputed_fields_json TEXT,
              generated_at TEXT
            );
            CREATE TABLE analyst_adjudications (
              adjudication_id TEXT PRIMARY KEY,
              dashboard_group_id TEXT NOT NULL,
              stable_group_id TEXT NOT NULL,
              case_id TEXT,
              analysis_id TEXT NOT NULL,
              outcome_override TEXT NOT NULL,
              confidence TEXT NOT NULL,
              rationale TEXT NOT NULL,
              evidence_gap TEXT,
              next_action TEXT,
              reviewer TEXT NOT NULL,
              event_status TEXT,
              detection_validity TEXT,
              activity_disposition TEXT,
              handling TEXT,
              duplicate_of TEXT,
              case_resolution_reason TEXT,
              created_at TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO alert_group_alias VALUES (?, ?)",
            (group_id, stable_group_id),
        )
        self.conn.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, generated_at, model,
              detection_outcome, confidence, evidence_hash, response_json, created_at
            ) VALUES (?, ?, 'newest-alert', ?, 'primary-model', ?, 'high',
                      'evidence-unit', ?, ?)
            """,
            (
                "analysis-disputed",
                stable_group_id,
                "2026-07-03  11:59:00Z",
                "true_positive_suspicious",
                json.dumps({
                    "evidence_used": ["alert", "flow"],
                    "evidence_gaps": ["endpoint process tree unavailable"],
                }),
                "2026-07-03  11:59:00Z",
            ),
        )
        self.conn.execute(
            """
            INSERT INTO ai_second_opinion_runs VALUES (
              'analysis-disputed', 'completed', 'true_positive_suspicious',
              'high', 'false_positive_logic_rule', 'medium', 'disagree',
              1, '["detection_outcome"]', '2026-07-03  11:59:30Z'
            )
            """
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        newest = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )

        self.assertEqual(status, 200)
        self.assertEqual(newest["analysis_id"], "analysis-disputed")
        self.assertEqual(newest["freshness_status"], "stale")
        self.assertEqual(newest["coverage_status"], "gaps")
        self.assertEqual(newest["primary_outcome"], "true_positive_suspicious")
        self.assertEqual(newest["reviewer_outcome"], "false_positive_logic_rule")
        self.assertEqual(newest["final_review_status"], "disputed_pending_human")

        ok, conflict = self.portal.update_soc_alert_status({
            "id": group_id,
            "status": "suppressed",
            "reason": "should require analyst review",
        })
        self.assertFalse(ok)
        self.assertEqual(conflict["status"], 409)

        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET agreement = 'partial_disagreement', material_disagreement = 0
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()
        _status, advisory_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        advisory = next(
            alert for alert in advisory_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            advisory["final_review_status"],
            "review_completed_not_authorized",
        )
        ok, conflict = self.portal.update_soc_alert_status({
            "id": group_id,
            "status": "suppressed",
            "reason": "medium review cannot authorize suppression",
        })
        self.assertFalse(ok)
        self.assertEqual(conflict["status"], 409)

        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET reviewer_confidence = 'high'
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()
        _status, high_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        high_advisory = next(
            alert for alert in high_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            high_advisory["final_review_status"],
            "reviewer_advisory",
        )

        self.conn.execute(
            """
            UPDATE ai_analysis_runs
            SET response_json = ?
            WHERE analysis_id = 'analysis-disputed'
            """,
            (
                json.dumps({
                    "_second_opinion": {
                        "automation_authorization": {
                            "authorized": False,
                            "reason_code": (
                                "reviewer_confidence_below_"
                                "automation_threshold"
                            ),
                        },
                    },
                }),
            ),
        )
        self.conn.commit()
        _status, denied_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        explicitly_denied = next(
            alert for alert in denied_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            explicitly_denied["final_review_status"],
            "review_completed_not_authorized",
        )
        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET status = 'failed', agreement = '', material_disagreement = 0
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()
        _status, failed_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        failed_review = next(
            alert for alert in failed_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            failed_review["final_review_status"],
            "review_required_failed",
        )
        self.assertEqual(failed_review["reviewer_error"], "")
        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET status = 'completed', agreement = 'material_disagreement',
                material_disagreement = 1
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()

        self.conn.execute(
            """
            INSERT INTO analyst_adjudications (
              adjudication_id, dashboard_group_id, stable_group_id, case_id,
              analysis_id, outcome_override, confidence, rationale,
              evidence_gap, next_action, reviewer, event_status,
              detection_validity, activity_disposition, handling, duplicate_of,
              case_resolution_reason, created_at
            ) VALUES (
              'adj-unit', ?, ?, NULL, 'analysis-disputed',
              'false_positive_logic_rule', 'high',
              'Corroborated by flow evidence.',
              'Endpoint process tree unavailable', 'Acquire endpoint telemetry',
              'unit-analyst', 'observed', 'logic_error', 'benign', 'no_action',
              NULL, NULL, '2026-07-03  12:02:00Z'
            )
            """,
            ("f" * 12, stable_group_id),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        newest = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(status, 200)
        self.assertEqual(newest["final_review_status"], "adjudicated")
        self.assertEqual(newest["detection_outcome"], "true_positive_suspicious")
        self.assertEqual(newest["effective_outcome"], "false_positive_logic_rule")
        self.assertEqual(newest["effective_outcome_label"], "FP - Rule")
        self.assertEqual(newest["adjudication"]["reviewer"], "unit-analyst")
        self.assertEqual(newest["adjudication"]["detection_validity"], "logic_error")
        history_status, history = self.portal.soc_adjudication_history_response(group_id)
        self.assertEqual(history_status, 200)
        self.assertEqual(history["history"][0]["adjudication_id"], "adj-unit")

        ok, _payload = self.portal.update_soc_alert_status({
            "id": group_id,
            "status": "suppressed",
            "reason": "adjudicated handling",
        })
        self.assertTrue(ok)

    def test_alert_list_batches_page_enrichment_without_per_group_lookup(self) -> None:
        group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        for alert_id, last_seen, external_intel in (
            (
                "enrichment-errors",
                "2026-07-03  12:02:00Z",
                {"errors": [{"source": "synthetic"}]},
            ),
            (
                "enrichment-records",
                "2026-07-03  12:01:00Z",
                {"records": [{"source": "synthetic"}]},
            ),
        ):
            self.conn.execute(
                """
                INSERT INTO alerts (
                  alert_id, first_seen, last_seen, timestamp, rule_name,
                  source_ip, destination_ip, triage_level, filter_status,
                  enrichment_json, alert_json, raw_event_json
                ) VALUES (?, ?, ?, ?, 'Newest detection', '192.0.2.10',
                          '198.51.100.10', 'critical', 'accepted', ?, '{}', '{}')
                """,
                (
                    alert_id,
                    last_seen,
                    last_seen,
                    last_seen,
                    json.dumps({"external_intel": external_intel}),
                ),
            )
        self.conn.commit()

        with mock.patch.object(
            self.portal,
            "soc_alert_group_enrichment_json",
            side_effect=AssertionError("per-group enrichment lookup must not run"),
        ):
            status, payload = self.portal.soc_alerts_query_response(
                {"limit": ["10"], "analyst_status": ["open"]}
            )

        self.assertEqual(status, 200)
        newest = next(alert for alert in payload["alerts"] if alert["group_key"] == group_key)
        self.assertEqual(newest["enrichment_status_key"], "enriched")
        self.assertEqual(newest["enrichment_record_count"], 1)

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
        response_body = json.dumps({
            "ok": True,
            "status": "pending",
            "request": {"request_id": "synthetic-request", "group_id": group_id},
        }).encode("utf-8")
        response.read.return_value = response_body
        response.headers = {"Content-Length": str(len(response_body))}
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

    def test_ai_analysis_threshold_skips_new_low_alerts_but_retains_history(self) -> None:
        low_group_id = self.insert_summary(
            "low|Below configured floor|192.0.2.40|198.51.100.40|accepted",
            "low-alert",
            "Below configured floor",
            "low",
            "2026-07-03  13:00:00Z",
            1,
            1,
        )
        settings = self.portal.default_soc_ai_settings()
        settings["soc_analyst_analysis_min_severity"] = "medium"
        self.portal.SOC_AI_SETTINGS_FILE.write_text(json.dumps(settings), encoding="utf-8")
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        low_alert = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "low-alert"
        )

        self.assertEqual(status, 200)
        self.assertEqual(low_alert["ai_status_key"], "not-queued")
        self.assertEqual(low_alert["ai_status_label"], "Skipped")
        self.assertIn("Medium automatic AI-analysis minimum", low_alert["ai_status_detail"])

        (self.portal.SOC_ALERT_AI_ANALYSIS_DIR / "low-alert-local-ai-analysis.json").write_text(
            json.dumps(
                {
                    "alert_id": "low-alert",
                    "generated_at": "2026-07-03  13:01:00Z",
                }
            ),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "reports": {
                        low_group_id: {
                            "ai_status_key": "analyzed",
                            "ai_status_label": "Analyzed",
                            "ai_status_detail": "historical analysis artifact",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        low_alert = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "low-alert"
        )

        self.assertEqual(status, 200)
        self.assertEqual(low_alert["ai_status_key"], "analyzed")
        self.assertEqual(low_alert["ai_status_label"], "Analyzed")

    def test_manual_analyze_queues_fresh_full_group_prompt(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        with (
            mock.patch.object(
                self.portal,
                "alert_store_post_json",
                return_value={"ok": True, "job": {"status": "pending"}},
            ) as post_mock,
        ):
            status, payload = self.portal.soc_alert_queue_analysis_response(group_id, {})

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["ai_status_key"], "queued")
        path, request_payload = post_mock.call_args.args
        self.assertEqual(path, "/ai/request")
        self.assertEqual(request_payload["group_id"], group_id)
        self.assertEqual(request_payload["related_limit"], 250)
        self.assertEqual(request_payload["pcap_analysis_limit"], 8)
        self.assertEqual(post_mock.call_args.kwargs["timeout"], 10.0)

    def test_manual_analyze_forwards_exact_frozen_dispatch_identity(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        identity = {
            "representative_alert_id": "frozen-alert:with:opaque-id",
            "stable_group_id": "abcdef1234567890abcd",
            "stable_group_key": "v2|critical|newest detection|192.0.2.10|198.51.100.10",
            "cohort_id": "newest-20-soc.2026_07_26",
            "dispatch_id": "a" * 64,
            "release_id": "d" * 40,
        }
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            return_value={"ok": True, "status": "queued", **identity},
        ) as post_mock:
            status, payload = self.portal.soc_alert_queue_analysis_response(
                group_id,
                identity,
            )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        path, request_payload = post_mock.call_args.args
        self.assertEqual(path, "/ai/request")
        for field, expected in identity.items():
            self.assertEqual(request_payload[field], expected)

    def test_manual_analyze_preserves_alert_store_identity_conflict(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            side_effect=self.portal.AlertStoreRequestError(
                "frozen representative no longer belongs to the group",
                409,
            ),
        ):
            status, payload = self.portal.soc_alert_queue_analysis_response(
                group_id,
                {"representative_alert_id": "stale-alert"},
            )

        self.assertEqual(status, 409)
        self.assertFalse(payload["ok"])
        self.assertIn("no longer belongs", payload["error"])

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
        # Broker summaries are emitted between serial transfers and may be
        # older than their three-minute freshness window during a large copy.
        # The request's fresh byte-progress heartbeat must take precedence.
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE.write_text(json.dumps({
            "generated_at": old_at,
            "component": "pcap_broker",
            "pcap_workflow": {"state": "healthy", "processed": 0},
        }), encoding="utf-8")

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertEqual(payload["pcap"]["active_transfers"][0]["request_id"], "pcap-active-large")
        self.assertFalse(any("telemetry is stale" in item for item in payload["pcap"]["warnings"]))

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

    def test_system_health_treats_fresh_capture_hold_as_advisory(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2),
            timespec="seconds",
        )
        fresh_at = self.portal.format_iso_timestamp(dt.datetime.now(dt.timezone.utc), timespec="seconds")
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, updated_at
            ) VALUES ('pcap-held', 'pending', 'unit test', 120, '{}', ?, ?)
            """,
            (old_at, old_at),
        )
        self.conn.commit()
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE.write_text(json.dumps({
            "generated_at": fresh_at,
            "component": "pcap_broker",
            "relay_host": "relay-test",
            "pcap_workflow": {
                "state": "capture_protection_hold",
                "deferred": True,
                "reason": "Zeek capture loss exceeds threshold",
                "processed": 0,
                "operational_failures": 0,
            },
        }), encoding="utf-8")

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertTrue(payload["pcap"]["capture_protection"]["active"])
        self.assertTrue(payload["pcap"]["advisories"])

    def test_system_health_rejects_stale_capture_hold_exemption(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2),
            timespec="seconds",
        )
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, updated_at
            ) VALUES ('pcap-stale-hold', 'pending', 'unit test', 120, '{}', ?, ?)
            """,
            (old_at, old_at),
        )
        self.conn.commit()
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE.write_text(json.dumps({
            "generated_at": old_at,
            "component": "pcap_broker",
            "pcap_workflow": {
                "state": "capture_protection_hold",
                "deferred": True,
                "reason": "stale hold",
            },
        }), encoding="utf-8")

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertFalse(payload["pcap"]["capture_protection"]["active"])
        self.assertTrue(any("pending PCAP request" in item for item in payload["pcap"]["warnings"]))
        self.assertTrue(any("telemetry is stale" in item for item in payload["pcap"]["warnings"]))

    def test_event_snapshot_uses_consistent_status_and_metrics_counts(self) -> None:
        payload = self.portal.soc_alert_events_snapshot()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["counts"]["open"], 2)
        self.assertEqual(payload["counts"]["suppressed"], 0)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["open"], 2)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["suppressed"], 1)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["total"], payload["counts"]["total"])
        self.assertEqual(
            set(payload["revisions"]),
            {
                "incidents",
                "asset_inventory",
                "dhcp_asset_discovery",
                "software_inventory",
            },
        )
        self.assertTrue(all(len(value) == 64 for value in payload["revisions"].values()))

    def test_live_revisions_do_not_expose_incident_or_asset_records(self) -> None:
        revisions = self.portal.dashboard_live_revisions()
        encoded = json.dumps(revisions)

        self.assertEqual(
            set(revisions),
            {
                "incidents",
                "asset_inventory",
                "dhcp_asset_discovery",
                "software_inventory",
            },
        )
        self.assertNotIn("Newest detection", encoded)
        self.assertNotIn("192.0.2.10", encoded)
        for value in revisions.values():
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_incident_revision_changes_when_a_case_is_added(self) -> None:
        initial = self.portal.incident_response_live_revision()
        self.conn.execute(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL,
              representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL,
              agent_status TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            INSERT INTO incident_response_cases (
              case_id, group_id, dashboard_group_id,
              representative_alert_id, status, agent_status, updated_at
            ) VALUES (?, ?, ?, ?, 'open', 'queued', ?)
            """,
            (
                "ir-revision-unit",
                "stable-revision-unit",
                self.portal.soc_alert_group_id(
                    "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
                ),
                "newest-alert",
                "2026-07-29 12:00:00Z",
            ),
        )
        self.conn.commit()

        changed = self.portal.incident_response_live_revision()

        self.assertNotEqual(changed, initial)

    def test_file_revision_changes_without_exposing_file_contents(self) -> None:
        path = Path(self.tmp.name) / "revision-state.json"
        initial = self.portal._bounded_file_revision(path, 1024)
        path.write_text('{"hostname":"sensitive-host.local"}', encoding="utf-8")

        changed = self.portal._bounded_file_revision(path, 1024)

        self.assertNotEqual(changed, initial)
        self.assertNotIn("sensitive-host", changed)

    def test_live_ai_activity_shows_primary_codex_model_with_effort(self) -> None:
        merged = self.portal.merge_live_llm_activity(
            {
                "active": False,
                "label": "AI Alert Triage",
                "detail": "Idle · Assigned: Ollama · previous-local:latest",
                "model": "Ollama · previous-local:latest",
                "provider": "Ollama",
                "route": "ollama:previous-local:latest",
                "counts": {"analyzing": 0, "queued": 2},
            },
            {
                "status": "running",
                "active_phase": "primary_analysis",
                "active_model": "gpt-5.6-sol",
                "active_model_path": "frontier-codex-cli",
                "active_model_route": "codex-cli:gpt-5.6-sol:xhigh",
                "active_provider": "codex-cli",
            },
        )

        self.assertTrue(merged["active"])
        self.assertEqual(merged["phase"], "primary_analysis")
        self.assertEqual(merged["provider"], "Codex CLI")
        self.assertEqual(merged["route"], "codex-cli:gpt-5.6-sol:xhigh")
        self.assertEqual(merged["model"], "Codex CLI · gpt-5.6-sol (xhigh)")
        self.assertEqual(
            merged["detail"],
            "Analyzing · Running: Codex CLI · gpt-5.6-sol (xhigh)",
        )
        self.assertEqual(merged["counts"]["analyzing"], 1)
        self.assertEqual(merged["counts"]["queued"], 2)

    def test_report_provenance_uses_observed_run_fields_not_current_settings(self) -> None:
        historical = self.portal.decorate_llm_analysis_record(
            {
                "status": "success",
                "agent_role": "incident-responder",
                "mode": "codex-cli",
                "model": "gpt-5.6-sol",
                "model_path": "frontier-codex-cli",
                "model_route": "codex-cli:gpt-5.6-sol:high",
            },
            live=False,
        )
        idle = self.portal.decorate_llm_analysis_record(
            {
                "status": "success",
                "agent_role": "incident-responder",
                "model": "gpt-5.6-sol",
                "model_route": "codex-cli:gpt-5.6-sol:high",
            },
            live=True,
        )

        self.assertEqual(historical["agent_label"], "Incident Responder")
        self.assertEqual(historical["job_type"], "incident_response_analysis")
        self.assertEqual(historical["job_label"], "Incident response investigation")
        self.assertEqual(
            historical["runtime_model_label"],
            "Codex CLI · gpt-5.6-sol (high)",
        )
        self.assertEqual(idle["runtime_model_label"], "No model running")
        self.assertEqual(idle["phase_label"], "Idle")

    def test_llm_analysis_log_includes_distinct_second_opinion_runs(self) -> None:
        log_path = Path(self.tmp.name) / "llm-analysis-log.jsonl"
        log_path.write_text(json.dumps({
            "log_id": "analysis-review-unit",
            "status": "success",
            "agent_role": "soc-analyst",
            "started_at": "2026-07-29  10:00:00-06:00",
            "finished_at": "2026-07-29  10:02:00-06:00",
            "runtime_seconds": 120,
            "model": "primary-model",
            "model_path": "ollama",
            "gpu_temperature_celsius_max": 41.25,
            "gpu_utilization_percent_max": 88.5,
            "cpu_temperature_celsius_max": 49.75,
            "soc_temperature_celsius_max": 51.0,
            "memory_used_percent_max": 57.5,
            "power_watts_max": 33.25,
            "cpu_used_percent_max": 62.5,
            "alert": {
                "primary_alert_id": "newest-alert",
                "rule_name": "Reviewer visibility test",
                "alert_count": 3,
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.10",
            },
        }) + "\n", encoding="utf-8")
        self.portal.SOC_ALERT_LLM_ANALYSIS_LOG_INDEX = (
            self.portal.JsonlLogIndex(log_path)
        )
        self.conn.executescript(
            """
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              alert_id TEXT NOT NULL,
              agent_role TEXT NOT NULL,
              trigger TEXT,
              status TEXT NOT NULL,
              reviewer_error TEXT,
              reviewer_model TEXT,
              reviewer_model_path TEXT,
              reviewer_outcome TEXT,
              reviewer_confidence TEXT,
              agreement TEXT,
              material_disagreement INTEGER NOT NULL DEFAULT 0,
              reviewer_runtime_seconds REAL,
              generated_at TEXT NOT NULL
            );
            INSERT INTO ai_second_opinion_runs VALUES (
              'analysis-review-unit', 'group-unit', 'newest-alert',
              'soc-analyst', 'Consequential conclusion', 'completed', NULL,
              'reviewer-model', 'frontier-codex-cli',
              'true_positive_suspicious', 'high', 'material_disagreement', 1,
              45.5, '2026-07-29  10:01:45-06:00'
            );
            """
        )
        self.conn.commit()

        payload = self.portal.llm_analysis_logs_response({
            "page": ["1"],
            "limit": ["25"],
        })

        self.assertEqual(payload["primary_total"], 1)
        self.assertEqual(payload["second_opinion_total"], 1)
        self.assertEqual(payload["total"], 2)
        reviewer = next(
            item for item in payload["logs"]
            if item.get("run_kind") == "second_opinion"
        )
        self.assertEqual(reviewer["parent_log_id"], "analysis-review-unit")
        self.assertEqual(reviewer["job_label"], "Second-opinion review")
        self.assertEqual(reviewer["status"], "success")
        self.assertEqual(reviewer["runtime_seconds"], 45.5)
        self.assertEqual(
            reviewer["runtime_model_label"],
            "Codex CLI · reviewer-model",
        )
        self.assertEqual(
            reviewer["alert"]["rule_name"],
            "Reviewer visibility test",
        )
        self.assertEqual(reviewer["gpu_temperature_celsius_max"], 41.25)
        self.assertEqual(reviewer["gpu_utilization_percent_max"], 88.5)
        self.assertEqual(reviewer["cpu_temperature_celsius_max"], 49.75)
        self.assertEqual(reviewer["soc_temperature_celsius_max"], 51.0)
        self.assertEqual(reviewer["memory_used_percent_max"], 57.5)
        self.assertEqual(reviewer["power_watts_max"], 33.25)
        self.assertEqual(reviewer["cpu_used_percent_max"], 62.5)
        self.assertIn("material disagreement", reviewer["error"])

    def test_llm_activity_reconciles_every_agent_role_from_database(self) -> None:
        log_path = Path(self.tmp.name) / "llm-analysis-log.jsonl"
        log_path.write_text(json.dumps({
            "log_id": "legacy-jsonl-id",
            "status": "success",
            "agent_role": "soc-analyst",
            "started_at": "2026-07-29  09:58:00-06:00",
            "finished_at": "2026-07-29  10:00:00-06:00",
            "model": "primary-model",
            "model_path": "ollama",
            "alert": {
                "primary_alert_id": "newest-alert",
                "rule_name": "Newest detection",
                "alert_count": 5,
            },
        }) + "\n", encoding="utf-8")
        self.portal.SOC_ALERT_LLM_ANALYSIS_LOG_INDEX = (
            self.portal.JsonlLogIndex(log_path)
        )
        self.conn.execute(
            "ALTER TABLE ai_analysis_runs ADD COLUMN "
            "agent_role TEXT NOT NULL DEFAULT 'soc-analyst'"
        )
        self.conn.executemany(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, generated_at, model,
              model_path, detection_outcome, bluf, summary, confidence,
              artifact_path, evidence_hash, response_json, created_at,
              agent_role
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL,
                      NULL, NULL, '{}', ?, ?)
            """,
            [
                (
                    "database-id-for-legacy-run",
                    "legacy-group",
                    "newest-alert",
                    "2026-07-29  10:00:02-06:00",
                    "primary-model",
                    "ollama",
                    "2026-07-29  10:00:02-06:00",
                    "soc-analyst",
                ),
                (
                    "siem-engineer-run",
                    "engineering-group",
                    "older-alert",
                    "2026-07-29  11:00:00-06:00",
                    "engineering-model",
                    "frontier-codex-cli",
                    "2026-07-29  11:00:00-06:00",
                    "siem-engineer",
                ),
            ],
        )
        self.conn.commit()

        payload = self.portal.llm_analysis_logs_response({
            "page": ["1"],
            "limit": ["25"],
        })

        self.assertEqual(payload["telemetry_total"], 1)
        self.assertEqual(payload["database_recovered_total"], 1)
        self.assertEqual(payload["primary_total"], 2)
        self.assertEqual(payload["total"], 2)
        self.assertEqual(payload["agent_totals"]["soc-analyst"], 1)
        self.assertEqual(payload["agent_totals"]["siem-engineer"], 1)
        siem = next(
            item for item in payload["logs"]
            if item.get("agent_role") == "siem-engineer"
        )
        self.assertEqual(siem["agent_label"], "SIEM Engineer")
        self.assertEqual(siem["job_label"], "Detection engineering analysis")
        self.assertEqual(
            siem["runtime_model_label"],
            "Codex CLI · engineering-model",
        )
        self.assertEqual(siem["telemetry_source"], "analysis_run_database")

    def test_failed_report_without_observation_does_not_claim_assigned_model(self) -> None:
        historical = self.portal.decorate_llm_analysis_record(
            {
                "status": "failure",
                "agent_role": "incident-responder",
                "model": "",
                "model_path": "",
                "model_route": "",
                "model_started": False,
                "assigned_model": "gpt-5.6-sol",
                "assigned_model_path": "frontier-codex-cli",
                "assigned_model_route": "codex-cli:gpt-5.6-sol:xhigh",
            },
            live=False,
        )

        self.assertEqual(historical["runtime_model_label"], "No model started")
        self.assertNotIn(
            "gpt-5.6-sol",
            historical["runtime_model_label"],
        )

    def test_saved_response_report_shows_no_model_started(self) -> None:
        historical = self.portal.decorate_llm_analysis_record(
            {
                "status": "success",
                "agent_role": "soc-analyst",
                "input_mode": "saved_response",
                "model": "",
                "model_path": "",
                "model_route": "",
                "model_started": False,
                "assigned_model": "devstral:latest",
                "assigned_model_path": "ollama",
                "assigned_model_route": "ollama:devstral:latest",
            },
            live=False,
        )

        self.assertEqual(historical["runtime_model_label"], "No model started")
        self.assertNotIn(
            "devstral",
            historical["runtime_model_label"],
        )

    def test_live_preparing_phase_claims_no_running_model(self) -> None:
        runtime = self.portal.llm_runtime_model_state(
            {
                "status": "running",
                "active_phase": "preparing",
                "active_model": "",
                "active_model_path": "",
                "active_model_route": "",
                "active_provider": "",
            }
        )

        self.assertEqual(runtime["phase_label"], "Preparing analysis")
        self.assertEqual(runtime["label"], "No model running")
        self.assertEqual(
            runtime["detail"],
            "Preparing analysis · No model running",
        )

    def test_active_run_files_report_both_concurrent_models(self) -> None:
        active_records = [
            {
                "log_id": "codex-run",
                "status": "running",
                "runner_pid": 101,
                "started_at": "2026-07-24  12:00:00-06:00",
                "prompt_package": "/tmp/codex-prompt.json",
                "agent_role": "soc-analyst",
                "active_phase": "primary_analysis",
                "active_model": "gpt-5.6-sol",
                "active_model_path": "frontier-codex-cli",
                "active_model_route": "codex-cli:gpt-5.6-sol:high",
                "active_provider": "codex-cli",
            },
            {
                "log_id": "ollama-run",
                "status": "running",
                "runner_pid": 202,
                "started_at": "2026-07-24  12:00:01-06:00",
                "prompt_package": "/tmp/ollama-prompt.json",
                "agent_role": "incident-responder",
                "active_phase": "second_opinion",
                "active_model": "gemma4:31b",
                "active_model_path": "ollama",
                "active_model_route": "ollama:gemma4:31b",
                "active_provider": "ollama",
            },
        ]
        for record in active_records:
            (
                self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR
                / f"{record['log_id']}.json"
            ).write_text(json.dumps(record), encoding="utf-8")
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps({"ai": {"counts": {"analyzing": 0, "queued": 3}}}),
            encoding="utf-8",
        )

        with mock.patch.object(
            self.portal,
            "llm_analysis_process_commands",
            return_value=[
                "101 python /runtime/run-local-ai-analysis.py",
                "202 python /runtime/run-local-ai-analysis.py",
            ],
        ):
            current = self.portal.read_llm_current_analysis()

        self.assertEqual(current["status"], "running")
        self.assertEqual(current["active_count"], 2)
        self.assertEqual(current["phase_label"], "Concurrent analyses")
        self.assertIn("SOC Analyst", current["agent_label"])
        self.assertIn("Incident Responder", current["agent_label"])
        self.assertIn("SOC alert triage", current["job_label"])
        self.assertIn("Incident response investigation", current["job_label"])
        self.assertEqual(
            [record["log_id"] for record in current["active_runs"]],
            ["codex-run", "ollama-run"],
        )
        merged = self.portal.merge_live_llm_activity(
            {"label": "AI Alert Triage", "counts": {"analyzing": 0, "queued": 3}},
            current,
        )
        self.assertTrue(merged["active"])
        self.assertEqual(merged["phase"], "concurrent")
        self.assertEqual(merged["counts"]["analyzing"], 2)
        self.assertEqual(merged["counts"]["queued"], 3)
        self.assertIn("Codex CLI · gpt-5.6-sol (high)", merged["model"])
        self.assertIn("Ollama · gemma4:31b", merged["model"])
        self.assertIn("2 analyses running", merged["detail"])

    def test_stale_active_run_does_not_hide_last_completed_record(self) -> None:
        self.portal.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE.write_text(
            json.dumps(
                {
                    "log_id": "completed-run",
                    "status": "success",
                    "model": "gpt-5.5",
                }
            ),
            encoding="utf-8",
        )
        (
            self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR
            / "stale-run.json"
        ).write_text(
            json.dumps(
                {
                    "log_id": "stale-run",
                    "status": "running",
                    "runner_pid": 909,
                    "prompt_package": "/tmp/reused-prompt.json",
                }
            ),
            encoding="utf-8",
        )

        with mock.patch.object(
            self.portal,
            "llm_analysis_process_commands",
            return_value=[
                "808 python /runtime/run-local-ai-analysis.py /tmp/reused-prompt.json",
            ],
        ):
            current = self.portal.read_llm_current_analysis()

        self.assertEqual(current["status"], "success")
        self.assertEqual(current["log_id"], "completed-run")
        self.assertNotIn("active_runs", current)

    def test_pid_status_supports_runs_without_prompt_path_in_command(self) -> None:
        commands = ["303 python /runtime/run-local-ai-analysis.py --generate-prompt"]

        self.assertTrue(
            self.portal.llm_analysis_process_active(
                "/tmp/generated-prompt.json",
                commands,
                303,
            )
        )
        self.assertFalse(
            self.portal.llm_analysis_process_active(
                "/tmp/generated-prompt.json",
                commands,
                404,
            )
        )
        self.assertTrue(
            self.portal.llm_analysis_process_active(
                "/tmp/generated-prompt.json",
                [
                    "505 python /runtime/run-local-ai-analysis.py "
                    "/tmp/generated-prompt.json",
                ],
            )
        )

    def test_event_snapshot_overrides_assigned_codex_with_active_ollama_reviewer(self) -> None:
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "ai": {
                        "active": True,
                        "label": "AI Alert Triage",
                        "detail": "Analyzing · Assigned: Codex CLI · gpt-5.5 (medium)",
                        "model": "Codex CLI · gpt-5.5 (medium)",
                        "provider": "Codex CLI",
                        "route": "codex-cli:gpt-5.5:medium",
                        "counts": {"analyzing": 1, "queued": 0},
                    },
                    "reports": {},
                }
            ),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE.write_text(
            json.dumps(
                {
                    "status": "running",
                    "prompt_package": "/tmp/runtime-review-prompt.json",
                    "active_phase": "second_opinion",
                    "active_model": "gemma4:31b",
                    "active_model_path": "ollama",
                    "active_model_route": "ollama:gemma4:31b",
                    "active_provider": "ollama",
                    "model": "gpt-5.5",
                    "model_route": "codex-cli:gpt-5.5:medium",
                    "mode": "codex-cli",
                }
            ),
            encoding="utf-8",
        )

        with mock.patch.object(self.portal, "llm_analysis_process_active", return_value=True):
            payload = self.portal.soc_alert_events_snapshot()

        self.assertTrue(payload["ai"]["active"])
        self.assertEqual(payload["ai"]["phase"], "second_opinion")
        self.assertEqual(payload["ai"]["provider"], "Ollama")
        self.assertEqual(payload["ai"]["route"], "ollama:gemma4:31b")
        self.assertEqual(payload["ai"]["model"], "Ollama · gemma4:31b")
        self.assertEqual(
            payload["ai"]["detail"],
            "Second-opinion review · Running: Ollama · gemma4:31b",
        )

    def test_live_ai_activity_post_processing_claims_no_running_model(self) -> None:
        merged = self.portal.merge_live_llm_activity(
            {
                "active": True,
                "label": "AI Alert Triage",
                "model": "Codex CLI · gpt-5.5 (medium)",
                "counts": {"analyzing": 1},
            },
            {
                "status": "running",
                "active_phase": "post_processing",
                "active_model": "",
                "active_model_path": "",
                "active_model_route": "",
                "active_provider": "",
                "model": "gpt-5.5",
                "model_route": "codex-cli:gpt-5.5:medium",
                "mode": "codex-cli",
            },
        )

        self.assertTrue(merged["active"])
        self.assertEqual(merged["phase"], "post_processing")
        self.assertEqual(merged["provider"], "")
        self.assertEqual(merged["route"], "")
        self.assertEqual(merged["model"], "No model running")
        self.assertEqual(merged["detail"], "Finalizing analysis · No model running")

    def test_live_ai_activity_supports_legacy_running_record(self) -> None:
        runtime = self.portal.llm_runtime_model_state(
            {
                "status": "running",
                "mode": "codex-cli",
                "model": "gpt-5.5",
                "model_path": "frontier-codex-cli",
                "model_route": "codex-cli:gpt-5.5:medium",
            }
        )

        self.assertTrue(runtime["running"])
        self.assertEqual(runtime["phase"], "primary_analysis")
        self.assertEqual(runtime["provider"], "Codex CLI")
        self.assertEqual(runtime["route"], "codex-cli:gpt-5.5:medium")
        self.assertEqual(runtime["model"], "gpt-5.5")
        self.assertEqual(runtime["label"], "Codex CLI · gpt-5.5 (medium)")
        self.assertEqual(
            runtime["detail"],
            "Analyzing · Running: Codex CLI · gpt-5.5 (medium)",
        )

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
        self.assertEqual(payload["active_total"], 1)
        self.assertEqual(payload["active_highest_severity"], "high")
        self.assertEqual(payload["active_severity_counts"]["critical"], 0)
        self.assertEqual(payload["active_severity_counts"]["high"], 1)
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
        response_body = json.dumps({
            "ok": True,
            "statuses": {group_id: {"status": "acknowledged", "repeat_count": 5}},
        }).encode("utf-8")
        response.read.return_value = response_body
        response.headers = {"Content-Length": str(len(response_body))}
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

    def test_direct_status_write_requires_explicit_offline_dr_mode(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_STORE_API_URL = ""
        self.portal.SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED = False

        with mock.patch.object(
            self.portal,
            "write_soc_alert_status",
            side_effect=AssertionError("direct DB write"),
        ):
            ok, payload = self.portal.update_soc_alert_status({
                "id": group_id,
                "status": "acknowledged",
                "repeat_count": 5,
            })

        self.assertFalse(ok)
        self.assertEqual(payload["status"], 503)
        self.assertIn("Direct SQLite writes are disabled", payload["error"])


if __name__ == "__main__":
    unittest.main()
