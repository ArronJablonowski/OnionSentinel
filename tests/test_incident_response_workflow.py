#!/usr/bin/env python3
"""Contracts for durable SOC-to-Incident-Response escalation."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = REPO_ROOT / "onion-sentinel-dashboard"
BUILDER_PATH = DASHBOARD_DIR / "scripts" / "build_soc_alerts_dashboard.py"
PORTAL_PATH = DASHBOARD_DIR / "report_portal.py"
ALERT_STORE_PATH = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class IncidentResponseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "alerts.sqlite3"
        self.portal = load_module("incident_response_test_portal", PORTAL_PATH)
        self.portal.SOC_ALERT_STORE_DB = self.db_path

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_sidebar_places_incident_responder_immediately_after_soc_alerts(self) -> None:
        builder = load_module("incident_response_test_builder", BUILDER_PATH)
        keys = [definition[0] for definition in builder.PAGE_DEFS]

        self.assertEqual(keys[keys.index("alerts") + 1], "investigations")
        self.assertEqual(keys[keys.index("investigations") + 1], "system_health")

    def test_generated_incident_page_keeps_table_and_lazy_detail_contract(self) -> None:
        builder = load_module("incident_response_render_test_builder", BUILDER_PATH)
        temp_root = Path(self.tmp.name)
        builder.DB_PATH = temp_root / "missing.sqlite3"
        builder.PCAP_ARTIFACT_DIR = temp_root / "pcap-artifacts"

        page = builder.render_static_page(builder.build_html([]), "investigations", [])

        self.assertIn('<h1 id="page-title">Incident Responder</h1>', page)
        self.assertIn('id="incident-response-view"', page)
        self.assertIn('id="ir-table-body"', page)
        self.assertIn('/api/soc-incidents', page)
        self.assertIn('/detail', page)
        self.assertIn('Incident Response Investigation', page)
        self.assertIn('<col class="ir-col-severity">', page)
        self.assertIn('<col class="ir-col-destination-port">', page)
        self.assertIn('<th>Destination Port</th>', page)
        self.assertIn('.ir-table col.ir-col-escalated{width:264px}', page)
        self.assertIn('class="ir-escalated"', page)
        self.assertIn('.ir-escalated{white-space:nowrap', page)
        self.assertIn('.ir-table th:first-child,.ir-case-row td:first-child', page)
        self.assertNotIn('.ir-table th:first-child,.ir-table td:first-child', page)
        self.assertIn('.ir-detail-shell,.ir-detail-content{text-align:left}', page)
        self.assertIn('<details class="ir-prior-ai"><summary>AI Analysis Output</summary>', page)
        self.assertIn('.ir-mobile-detail{padding:0 14px 16px;border-top:1px solid #1e303d;text-align:left}', page)
        self.assertIn(
            ".ai-status-analyzing,.ir-agent-analyzing{color:var(--cyan)!important;"
            "animation:ai-status-analyzing-pulse 1.25s ease-in-out infinite",
            page,
        )
        self.assertIn("@keyframes ai-status-analyzing-pulse", page)
        self.assertGreaterEqual(page.count("ir-agent-${esc(item.agent_status)}"), 2)
        self.assertIn('colspan="10"', page)
        self.assertLess(page.index("Incident Responder</h1>"), page.index('id="incident-response-view"'))

    def test_alert_rows_and_case_page_keep_the_full_escalation_contract(self) -> None:
        source = BUILDER_PATH.read_text(encoding="utf-8")

        self.assertGreaterEqual(source.count('data-escalate="'), 2)
        self.assertIn("requestIncidentEscalationForGroup", source)
        self.assertIn("button.textContent='Escalated'", source)
        self.assertIn("window.setTimeout(()=>removeEscalatedGroup(id),5000)", source)
        self.assertIn("escalationRemovalDeadlines", source)
        self.assertIn("loadApiAlerts(true)", source)
        self.assertNotIn("button.textContent==='Escalated')button.textContent='Escalate'", source)
        self.assertIn("/escalate", source)
        self.assertIn("/api/soc-incidents", source)
        self.assertIn("Incident Response Investigation", source)
        self.assertIn("/detail", source)

    def test_incident_detail_shows_kql_and_exact_query_dsl(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL, representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL, agent_status TEXT NOT NULL,
              escalated_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              escalated_by TEXT, reason TEXT, latest_analysis_id TEXT,
              latest_model TEXT, latest_generated_at TEXT, latest_error TEXT
            );
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT PRIMARY KEY, group_id TEXT, agent_role TEXT NOT NULL,
              generated_at TEXT, model TEXT, detection_outcome TEXT,
              bluf TEXT, summary TEXT, confidence TEXT, response_json TEXT
            );
            INSERT INTO incident_response_cases VALUES (
              'ir-query-audit', 'stable-query-group', 'cccccccccccc', 'alert-query',
              'open', 'analyzed', '2026-07-22  12:00:00-06:00',
              '2026-07-22  12:05:00-06:00', 'qa', 'Synthetic query audit',
              'ir-query-analysis', 'synthetic-model', '2026-07-22  12:05:00-06:00', NULL
            );
            """
        )
        incident_response = {
            "incident_response_report": {
                "executive_bluf": "Synthetic evidence warrants investigation.",
                "scope": "Reserved TEST-NET endpoints only.",
                "affected_systems": ["192.0.2.10"],
                "methodology": ["Reviewed the restricted query result."],
                "factual_timeline": [{
                    "timestamp": "2026-07-22  12:01:00-06:00",
                    "event": "Synthetic connection observed.",
                    "source_pack": "network_flow",
                    "query_digest": "digest-unit",
                    "confidence": "high",
                }],
                "security_onion_findings": ["Bounded TEST-NET flow returned one hit."],
                "detection_outcome_reasoning": "The event occurred but the synthetic fixture is inconclusive.",
                "osquery_findings": ["The reviewed system inventory pack returned one synthetic row."],
                "conclusion": "Synthetic test conclusion.",
                "confidence": "high",
            },
            "_incident_query_audit": {
                "trusted_source": "restricted-security-onion-wrapper",
                "read_only": True,
                "complete": True,
                "partial": False,
                "queries": [{
                    "pack": "network_flow",
                    "status": "ok",
                    "query_digest": "digest-unit",
                    "window": {
                        "start": "2026-07-22  12:00:00-06:00",
                        "end": "2026-07-22  12:10:00-06:00",
                    },
                    "total_hits": "not-a-number",
                    "returned_hits": 1,
                    "kql_equivalent": 'source.ip: "192.0.2.10"',
                    "query_dsl": {
                        "query": {"term": {"source.ip": "192.0.2.10"}},
                        "size": 25,
                    },
                }],
            },
            "_incident_osquery_audit": {
                "trusted_source": "restricted-security-onion-osquery-wrapper",
                "read_only": True,
                "query_contract": "onion-sentinel-incident-evidence-v2",
                "queries": [{
                    "pack": "system_inventory",
                    "target": "security-onion",
                    "status": "ok",
                    "query_digest": "digest-osquery-unit",
                    "query": "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
                    "total_rows": 1,
                    "returned_rows": 1,
                    "truncated": False,
                    "duration_ms": 42,
                    "rows_preview": [{
                        "hostname": "synthetic-security-onion",
                        "cpu_brand": "Synthetic CPU",
                        "physical_memory": "1024",
                    }],
                }],
            },
        }
        prior_response = {
            "bluf": "Synthetic SOC assessment.",
            "summary": "Synthetic prior analysis.",
            "public_enrichment_findings": ["No public service was queried."],
        }
        conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ir-query-analysis", "stable-query-group", "incident-responder",
                "2026-07-22  12:05:00-06:00", "synthetic-model", "inconclusive",
                "Synthetic IR BLUF", "Synthetic IR summary", "high",
                json.dumps(incident_response),
            ),
        )
        conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "soc-query-analysis", "stable-query-group", "soc-analyst",
                "2026-07-22  12:02:00-06:00", "synthetic-model", "inconclusive",
                "Synthetic SOC BLUF", "Synthetic SOC summary", "medium",
                json.dumps(prior_response),
            ),
        )
        conn.commit()
        conn.close()

        status, payload = self.portal.soc_incident_detail_response("ir-query-audit")

        self.assertEqual(status, 200)
        self.assertEqual(payload["query_count"], 2)
        self.assertIn("KQL (analyst-readable equivalent)", payload["incident_html"])
        self.assertIn('source.ip: &quot;192.0.2.10&quot;', payload["incident_html"])
        self.assertIn("Elasticsearch Query DSL (exact executed request)", payload["incident_html"])
        self.assertIn('&quot;source.ip&quot;: &quot;192.0.2.10&quot;', payload["incident_html"])
        self.assertIn("0 total / 1 returned", payload["incident_html"])
        self.assertIn("Detection Outcome Reasoning", payload["incident_html"])
        self.assertIn("OSquery Findings", payload["incident_html"])
        self.assertIn("OSquery Command Audit", payload["incident_html"])
        self.assertIn(
            "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
            payload["incident_html"],
        )
        self.assertIn("synthetic-security-onion", payload["incident_html"])
        self.assertIn("Synthetic SOC assessment.", payload["prior_ai_html"])

    def test_escalation_api_records_intent_through_alert_store(self) -> None:
        group_id = "a" * 12
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            return_value={"ok": True, "case_id": "ir-unit", "status": "queued"},
        ) as post:
            status, payload = self.portal.soc_alert_escalate_response(
                group_id,
                {"reason": "Unit-test escalation", "requested_by": "qa"},
            )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["agent_status"], "queued")
        path, request = post.call_args.args
        self.assertEqual(path, "/incidents/escalate")
        self.assertEqual(request["group_id"], group_id)
        self.assertEqual(request["reason"], "Unit-test escalation")
        self.assertEqual(request["related_limit"], 250)
        self.assertEqual(request["pcap_analysis_limit"], 25)

    def test_incident_list_returns_case_and_only_incident_responder_analysis(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL,
              representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL,
              agent_status TEXT NOT NULL,
              escalated_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              escalated_by TEXT,
              reason TEXT,
              latest_analysis_id TEXT,
              latest_model TEXT,
              latest_generated_at TEXT,
              latest_error TEXT
            );
            CREATE TABLE alert_group_summary (
              group_id TEXT PRIMARY KEY,
              rule_name TEXT,
              severity INTEGER,
              severity_label TEXT,
              triage_level TEXT,
              source_ip TEXT,
              destination_ip TEXT,
              destination_port INTEGER,
              raw_alert_count INTEGER,
              total_seen_count INTEGER,
              first_seen TEXT,
              last_seen TEXT
            );
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY,
              rule_name TEXT,
              severity INTEGER,
              severity_label TEXT,
              triage_level TEXT,
              source_ip TEXT,
              destination_ip TEXT,
              destination_port INTEGER,
              seen_count INTEGER,
              first_seen TEXT,
              last_seen TEXT
            );
            CREATE TABLE ai_analysis_runs (
              analysis_id TEXT PRIMARY KEY,
              agent_role TEXT NOT NULL,
              generated_at TEXT,
              model TEXT,
              detection_outcome TEXT,
              bluf TEXT,
              summary TEXT,
              confidence TEXT
            );
            INSERT INTO alert_group_summary VALUES (
              'aaaaaaaaaaaa', 'Synthetic alert', 3, 'high', 'high',
              '192.0.2.10', '198.51.100.10', 443, 4, 9,
              '2026-07-22  10:00:00-06:00', '2026-07-22  10:05:00-06:00'
            );
            INSERT INTO alerts VALUES (
              'alert-unit', 'Fallback alert', 2, 'medium', 'medium',
              '192.0.2.20', '198.51.100.20', 8443, 2,
              '2026-07-22  09:59:00-06:00', '2026-07-22  10:04:00-06:00'
            );
            INSERT INTO incident_response_cases VALUES (
              'ir-unit', 'stable-group', 'aaaaaaaaaaaa', 'alert-unit',
              'open', 'analyzed', '2026-07-22  10:06:00-06:00',
              '2026-07-22  10:08:00-06:00', 'qa', 'Escalated for validation',
              'ir-analysis', 'reviewer-model', '2026-07-22  10:08:00-06:00', NULL
            );
            INSERT INTO ai_analysis_runs VALUES (
              'ir-analysis', 'incident-responder', '2026-07-22  10:08:00-06:00',
              'reviewer-model', 'true_positive_suspicious', 'Contain the host.',
              'The evidence warrants incident handling.', 'high'
            );
            """
        )
        conn.commit()
        conn.close()

        status, payload = self.portal.soc_incidents_query_response(
            {"page": ["1"], "per_page": ["25"], "status": ["all"]}
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["status_counts"]["open"], 1)
        self.assertEqual(payload["agent_status_counts"]["analyzed"], 1)
        case = payload["incidents"][0]
        self.assertEqual(case["case_id"], "ir-unit")
        self.assertEqual(case["seen_count"], 9)
        self.assertEqual(case["source_ip"], "192.0.2.10")
        self.assertEqual(case["destination_ip"], "198.51.100.10")
        self.assertEqual(case["destination_port"], 443)
        self.assertEqual(case["analysis_bluf"], "Contain the host.")
        self.assertEqual(case["analysis_model"], "reviewer-model")

    def test_incident_list_falls_back_to_representative_alert_endpoints(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY, group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL, representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL, agent_status TEXT NOT NULL,
              escalated_at TEXT NOT NULL, updated_at TEXT NOT NULL,
              escalated_by TEXT, reason TEXT, latest_analysis_id TEXT,
              latest_model TEXT, latest_generated_at TEXT, latest_error TEXT
            );
            CREATE TABLE alert_group_summary (
              group_id TEXT PRIMARY KEY, rule_name TEXT, severity INTEGER,
              severity_label TEXT, triage_level TEXT, source_ip TEXT,
              destination_ip TEXT, destination_port INTEGER,
              raw_alert_count INTEGER, total_seen_count INTEGER,
              first_seen TEXT, last_seen TEXT
            );
            CREATE TABLE alerts (
              alert_id TEXT PRIMARY KEY, rule_name TEXT, severity INTEGER,
              severity_label TEXT, triage_level TEXT, source_ip TEXT,
              destination_ip TEXT, destination_port INTEGER, seen_count INTEGER,
              first_seen TEXT, last_seen TEXT
            );
            INSERT INTO alerts VALUES (
              'alert-fallback', 'Recovered endpoint alert', 3, 'high', 'high',
              '192.0.2.30', '198.51.100.30', 22, 6,
              '2026-07-22  11:00:00-06:00', '2026-07-22  11:05:00-06:00'
            );
            INSERT INTO incident_response_cases VALUES (
              'ir-fallback', 'stable-fallback', 'bbbbbbbbbbbb', 'alert-fallback',
              'open', 'queued', '2026-07-22  11:06:00-06:00',
              '2026-07-22  11:06:00-06:00', 'qa', 'Fallback validation',
              NULL, NULL, NULL, NULL
            );
            """
        )
        conn.commit()
        conn.close()

        status, payload = self.portal.soc_incidents_query_response(
            {"page": ["1"], "per_page": ["25"], "status": ["all"]}
        )

        self.assertEqual(status, 200)
        case = payload["incidents"][0]
        self.assertEqual(case["rule_name"], "Recovered endpoint alert")
        self.assertEqual(case["source_ip"], "192.0.2.30")
        self.assertEqual(case["destination_ip"], "198.51.100.30")
        self.assertEqual(case["destination_port"], 22)
        self.assertEqual(case["seen_count"], 6)

    def test_incident_list_is_empty_until_dr_schema_is_initialized(self) -> None:
        sqlite3.connect(self.db_path).close()

        status, payload = self.portal.soc_incidents_query_response(
            {"page": ["1"], "per_page": ["25"], "status": ["all"]}
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["schema_ready"])
        self.assertEqual(payload["total"], 0)
        self.assertEqual(payload["incidents"], [])

    def test_alert_store_uses_a_distinct_agent_job_and_analysis_role(self) -> None:
        source = ALERT_STORE_PATH.read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS incident_response_cases", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_response_events", source)
        self.assertIn("async function requestIncidentEscalation", source)
        self.assertIn("durableJobs.enqueue('incident_response_analysis'", source)
        self.assertIn("agent_role: 'incident-responder'", source)
        self.assertIn("parsedUrl.pathname === '/incidents/escalate'", source)


if __name__ == "__main__":
    unittest.main()
