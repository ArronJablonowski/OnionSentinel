#!/usr/bin/env python3
"""Contracts for durable SOC-to-Incident-Response escalation."""
from __future__ import annotations

import importlib.util
import io
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
INCIDENT_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_incident_response_page.py"
SHELL_PAGE_PATH = DASHBOARD_DIR / "scripts" / "dashboard_shell_page.py"
PORTAL_PATH = DASHBOARD_DIR / "report_portal.py"
ALERT_STORE_PATH = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
CONTROLLED_INCIDENT_COMPOSITION_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "composition"
    / "controlled_incident_composition.js"
)
MANUAL_ANALYSIS_DISPATCH_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "services" / "manual_analysis_dispatch.js"
)
INCIDENT_ANALYSIS_SCHEMA_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "services" / "incident_analysis_schema.js"
)
INCIDENT_REANALYSIS_REQUEST_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "services" / "incident_reanalysis_request.js"
)
INCIDENT_REANALYSIS_RUN_PERSISTENCE_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_run_persistence.js"
)
INCIDENT_REANALYSIS_JOB_OWNERSHIP_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_job_ownership.js"
)
INCIDENT_REANALYSIS_ATTEMPT_LIFECYCLE_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_attempt_lifecycle.js"
)
ANALYSIS_REQUEST_ROUTES_PATH = (
    REPO_ROOT / "n8n" / "alert_store" / "routes" / "analysis_request_routes.js"
)
INCIDENT_REANALYSIS_BINDING_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_reanalysis_binding.js"
)
INCIDENT_ANALYSIS_COMPLETION_PATH = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "incident_analysis_completion.js"
)
AI_RUNNER_PATH = REPO_ROOT / "n8n" / "bin" / "run-local-ai-analysis.py"
ANALYSIS_INDEX_PATH = (
    REPO_ROOT
    / "n8n"
    / "onion_sentinel"
    / "analysis"
    / "persistence"
    / "analysis_index.py"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class IncidentResponseWorkflowTests(unittest.TestCase):
    def test_incident_agent_display_state_preserves_partial_success(self) -> None:
        self.assertEqual(
            self.portal.soc_incident_agent_display_state(
                "failed", "analysis-1", "failed"
            ),
            ("review_failed", "Primary ready · review failed"),
        )
        self.assertEqual(
            self.portal.soc_incident_agent_display_state(
                "failed", "analysis-1", "not_requested"
            ),
            ("refresh_failed", "Analysis ready · refresh failed"),
        )
        self.assertEqual(
            self.portal.soc_incident_agent_display_state(
                "failed", "", "not_requested"
            ),
            ("analysis_failed", "Analysis failed"),
        )
        self.assertEqual(
            self.portal.soc_incident_agent_display_state(
                "analyzed", "analysis-1", "completed"
            ),
            ("analyzed", "analyzed"),
        )

    def test_incident_list_rejects_unallowlisted_sort_parameters(self) -> None:
        status, payload = self.portal.soc_incidents_query_response(
            {"sort": ["updated_at; DROP TABLE alerts"], "direction": ["desc"]}
        )
        self.assertEqual(status, 400)
        self.assertIn("sort field", payload["error"])

        status, payload = self.portal.soc_incidents_query_response(
            {"sort": ["severity"], "direction": ["sideways"]}
        )
        self.assertEqual(status, 400)
        self.assertIn("sort direction", payload["error"])

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
        self.assertEqual(
            keys[keys.index("investigations") + 1],
            "cyber_threat_intel",
        )
        self.assertEqual(
            keys[keys.index("cyber_threat_intel") + 1],
            "siem_engineering",
        )
        self.assertEqual(
            keys[keys.index("siem_engineering") + 1],
            "threat_hunter",
        )
        self.assertEqual(
            keys[keys.index("threat_hunter") + 1],
            "asset_inventory",
        )
        self.assertEqual(
            keys[keys.index("asset_inventory") + 1],
            "software_inventory",
        )
        self.assertEqual(
            keys[keys.index("software_inventory") + 1],
            "system_health",
        )

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
        self.assertIn('<col class="ir-col-case">', page)
        self.assertIn('<col class="ir-col-network">', page)
        self.assertIn('.ir-table col.ir-col-network{width:300px}', page)
        self.assertIn('.ir-table td.ir-network-cell{padding-left:6px;padding-right:6px}', page)
        self.assertIn(
            '.ir-network-path{display:grid;grid-template-columns:minmax(0,1fr) 14px '
            'minmax(0,1fr);gap:3px;align-items:start}',
            page,
        )
        self.assertIn(
            '.ir-network-arrow{margin-top:15px;color:#35d9ec;text-align:center;line-height:1.35}',
            page,
        )
        self.assertNotIn(
            'grid-template-columns:minmax(0,1fr) 14px minmax(0,1fr);gap:3px;align-items:center',
            page,
        )
        self.assertIn('class="ir-network-cell"', page)
        self.assertIn('overflow-wrap:anywhere;white-space:normal', page)
        self.assertNotIn(
            '.ir-network-value{display:block;overflow:hidden',
            page,
        )
        self.assertNotIn('data-ir-sort="destination_port"', page)
        self.assertIn("sort:sortKey,direction:sortDirection", page)
        self.assertIn('.ir-table col.ir-col-escalated{width:150px}', page)
        self.assertIn('class="ir-escalated"', page)
        self.assertIn('.ir-escalated{white-space:nowrap}', page)
        self.assertIn(
            '.ir-escalated-date,.ir-escalated-time{display:block;font-variant-numeric:tabular-nums}',
            page,
        )
        self.assertNotIn('.ir-escalated{display:grid', page)
        self.assertIn('.ir-table th:first-child,.ir-case-row td:first-child', page)
        self.assertNotIn('.ir-table th:first-child,.ir-table td:first-child', page)
        self.assertIn('.ir-detail-shell,.ir-detail-content{text-align:left}', page)
        self.assertIn('<details class="ir-prior-ai"><summary>AI Analysis Output</summary>', page)
        self.assertIn('.ir-mobile-detail{padding:0 14px 16px;border-top:1px solid #1e303d;text-align:left}', page)
        self.assertIn("const queryPurposes={", page)
        self.assertIn("details.className='ir-query-details'", page)
        self.assertIn(
            "summaryPurpose.textContent=String(record.dataset.queryPurpose||'').trim()||queryPurpose(pack)",
            page,
        )
        self.assertIn("summaryFinding.textContent=queryFinding(record,meta)", page)
        self.assertIn("content.querySelectorAll('pre.ir-query-code').forEach", page)
        self.assertIn("button.setAttribute('aria-label',`Copy ${headingText} for ${title}`)", page)
        self.assertIn("feedback.setAttribute('role','status')", page)
        self.assertIn("feedback.setAttribute('aria-live','polite')", page)
        self.assertIn("await navigator.clipboard.writeText(value)", page)
        self.assertIn("document.execCommand?.('copy')", page)
        self.assertIn("await copyExactQuery(code.textContent||'')", page)
        self.assertIn("feedback.textContent='Copied exact query.'", page)
        self.assertIn("feedback.textContent='Copy failed — select and copy the query manually.'", page)
        self.assertIn(".ir-query-details>summary", page)
        self.assertIn(".ir-query-copy", page)
        self.assertNotIn("details.open=true", page)
        self.assertIn(
            ".ai-status-analyzing,.ir-agent-analyzing{color:var(--cyan)!important;"
            "animation:ai-status-analyzing-pulse 1.25s ease-in-out infinite",
            page,
        )
        self.assertIn("@keyframes ai-status-analyzing-pulse", page)
        self.assertGreaterEqual(page.count("ir-agent-${esc(agentState)}"), 2)
        self.assertIn("item.agent_display_label||label(item.agent_status)", page)
        self.assertIn('colspan="9"', page)
        self.assertIn("const networkHtml=item=>", page)
        self.assertIn("const assetIdentityHtml=asset=>", page)
        self.assertIn("item.source_asset", page)
        self.assertIn("item.destination_asset", page)
        self.assertIn(".ir-network-hostname", page)
        self.assertIn("const escalatedHtml=value=>", page)
        self.assertIn('<col class="ir-col-assessment">', page)
        self.assertIn('<col class="ir-col-actions">', page)
        self.assertIn('class="ir-assessment-cell">${reviewBadges(item)}</td>', page)
        self.assertIn('class="ir-actions-cell">${reviewButton(item)}${reanalysisButton(item)}', page)
        self.assertIn('id="analyst-adjudication-modal"', page)
        self.assertIn("data-review-case=", page)
        self.assertIn("reviewBadges(item)", page)
        self.assertIn("disputed_pending_human", page)
        self.assertIn("review_required_failed", page)
        self.assertIn(
            "review_completed_not_authorized'?'Review complete · human decision",
            page,
        )
        self.assertIn("reviewerError", page)
        self.assertIn("Freshness:", page)
        self.assertIn("Coverage:", page)
        self.assertIn("'X-Onion-Sentinel-Request':'dashboard'", page)
        self.assertIn("/adjudicate", page)
        self.assertIn("onion-sentinel:adjudicated", page)
        self.assertIn('id="analyst-event-status"', page)
        self.assertIn('id="analyst-detection-validity"', page)
        self.assertIn('id="analyst-activity-disposition"', page)
        self.assertIn('id="analyst-handling"', page)
        self.assertIn('id="analyst-duplicate-of"', page)
        self.assertIn("effective_outcome", page)
        self.assertIn("if(saving)return", page)
        self.assertIn("resolutionReason.required=false", page)
        self.assertIn('id="ir-reanalyze-all"', page)
        self.assertIn('id="ir-reanalysis-progress"', page)
        self.assertIn('data-reanalyze-case=', page)
        self.assertIn("/api/soc-incidents/reanalyze-all", page)
        self.assertIn("/api/soc-incidents/reanalysis-runs", page)
        self.assertIn("<span>Run <code>", page)
        self.assertIn("<span>Release <code>", page)
        self.assertIn("counts.skipped", page)
        self.assertLess(page.index("Incident Responder</h1>"), page.index('id="incident-response-view"'))

    def test_alert_rows_and_case_page_keep_the_full_escalation_contract(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (BUILDER_PATH, SHELL_PAGE_PATH, INCIDENT_PAGE_PATH)
        )

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
                "security_onion_findings": [
                    "Bounded TEST-NET flow returned one hit.",
                    "pivot-oql-digest correlated one additional synthetic flow.",
                ],
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
            "_incident_live_osquery_audit": {
                "trusted_source": "restricted-elastic-osquery-manager-wrapper",
                "read_only": True,
                "complete": True,
                "query_contract": "onion-sentinel-live-osquery-v1",
                "queries": [{
                    "target_alias": "synthetic-endpoint",
                    "purpose": "Confirm the endpoint process inventory.",
                    "status": "ok",
                    "query_digest": "digest-live-osquery-unit",
                    "query": "SELECT pid, name, path FROM processes LIMIT 25;",
                    "total_rows": 2,
                    "returned_rows": 2,
                    "truncated": False,
                    "duration_ms": 17,
                    "rows_preview": [{"pid": "1", "name": "synthetic-init"}],
                }],
            },
            "_investigation_query_audit": {
                "query_contract": "onion-sentinel-investigation-pivots-v2",
                "provider_neutral": True,
                "model_route": "codex-cli:gpt-5.6-sol:high",
                "rounds_completed": 1,
                "queries_admitted": 2,
                "requests_ignored_or_over_budget": 0,
                "rounds": [{
                    "round": 1,
                    "trusted_queries": [
                        {
                            "query_id": "oql-pivot-1",
                            "dialect": "oql",
                            "pack": "network_flow",
                            "purpose": "correlate_observable",
                            "status": "ok",
                            "query_digest": "pivot-oql-digest",
                            "window": {
                                "start": "2026-07-22T17:55:00.000Z",
                                "end": "2026-07-22T18:15:00.000Z",
                            },
                            "total_hits": 1,
                            "returned_hits": 1,
                            "execution_backend": "so-elasticsearch-query",
                            "semantics": "compiled_oql_equivalent",
                            "oql_equivalent": 'source.ip:"192.0.2.10" | sortby @timestamp^',
                            "kql_equivalent": 'source.ip : "192.0.2.10"',
                            "query_dsl": {
                                "query": {"term": {"source.ip": "192.0.2.10"}},
                                "size": 25,
                            },
                        },
                        {
                            "query_id": "zeek-pivot-1",
                            "backend": "zeek",
                            "purpose": "Confirm the DNS answer tied to the flow.",
                            "operation": "dns",
                            "filters": {"query": "example.test"},
                            "limit": 10,
                            "status": "ok",
                            "query_digest": "pivot-zeek-digest",
                            "candidate_records_scanned": 4,
                            "records_returned": 1,
                            "result_truncated": False,
                        },
                    ],
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
        self.assertEqual(payload["query_count"], 5)
        self.assertIn("KQL (analyst-readable equivalent)", payload["incident_html"])
        self.assertIn('source.ip: &quot;192.0.2.10&quot;', payload["incident_html"])
        self.assertIn("Elasticsearch Query DSL (exact executed request)", payload["incident_html"])
        self.assertIn('&quot;source.ip&quot;: &quot;192.0.2.10&quot;', payload["incident_html"])
        self.assertIn("0 total / 1 returned", payload["incident_html"])
        self.assertIn(
            'data-query-finding="Synthetic connection observed."',
            payload["incident_html"],
        )
        self.assertIn("Detection Outcome Reasoning", payload["incident_html"])
        self.assertIn("OSquery Findings", payload["incident_html"])
        self.assertIn("Security Onion Appliance OSQuery Snapshot Audit", payload["incident_html"])
        self.assertIn(
            "SELECT hostname, cpu_brand, physical_memory FROM system_info;",
            payload["incident_html"],
        )
        self.assertIn("synthetic-security-onion", payload["incident_html"])
        self.assertIn("Endpoint Live OSQuery Audit", payload["incident_html"])
        self.assertIn("Confirm the endpoint process inventory.", payload["incident_html"])
        self.assertIn("SELECT pid, name, path FROM processes LIMIT 25;", payload["incident_html"])
        self.assertIn("synthetic-init", payload["incident_html"])
        self.assertIn("Interactive Investigation Pivot Audit", payload["incident_html"])
        self.assertIn("OQL (analyst-readable equivalent)", payload["incident_html"])
        self.assertIn("compiled_oql_equivalent", payload["incident_html"])
        self.assertIn("Structured PCAP/Zeek request (exact broker input)", payload["incident_html"])
        self.assertIn("Confirm the DNS answer tied to the flow.", payload["incident_html"])
        self.assertIn(
            'data-query-finding="pivot-oql-digest correlated one additional synthetic flow."',
            payload["incident_html"],
        )
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

    def test_escalation_api_forwards_exact_frozen_dispatch_identity(self) -> None:
        group_id = "a" * 12
        identity = {
            "representative_alert_id": "frozen-escalation-alert",
            "stable_group_id": "abcdef1234567890abcd",
            "stable_group_key": "v2|critical|escalation-test",
            "cohort_id": "newest-20-ir.2026_07_26",
            "dispatch_id": "b" * 64,
            "release_id": "d" * 40,
            "expected_assigned_route": "codex-cli:gpt-5.5:high",
            "expected_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
            "reviewer_required": True,
        }
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            return_value={"ok": True, "case_id": "ir-unit", **identity},
        ) as post:
            status, payload = self.portal.soc_alert_escalate_response(
                group_id,
                identity,
            )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        path, request = post.call_args.args
        self.assertEqual(path, "/incidents/escalate")
        for field, expected in identity.items():
            self.assertEqual(request[field], expected)

    def test_escalation_api_preserves_alert_store_identity_conflict(self) -> None:
        group_id = "a" * 12
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            side_effect=self.portal.AlertStoreRequestError(
                "frozen stable group no longer matches",
                409,
            ),
        ):
            status, payload = self.portal.soc_alert_escalate_response(
                group_id,
                {"stable_group_id": "abcdef1234567890abcd"},
            )

        self.assertEqual(status, 409)
        self.assertFalse(payload["ok"])
        self.assertIn("no longer matches", payload["error"])

    def test_adjudication_proxy_validates_and_forwards_bounded_human_fields(self) -> None:
        group_id = "a" * 12
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            return_value={"ok": True, "adjudication_id": "adj-unit"},
        ) as post:
            status, payload = self.portal.soc_alert_adjudication_response(
                group_id,
                {
                    "analysis_id": "analysis-unit",
                    "outcome_override": "true_positive_suspicious",
                    "confidence": "high",
                    "rationale": "Corroborated by independent evidence.",
                    "evidence_gap": "Endpoint telemetry unavailable.",
                    "next_action": "Acquire endpoint telemetry.",
                    "reviewer": "qa-analyst",
                    "event_status": "observed",
                    "detection_validity": "matched_intent",
                    "activity_disposition": "suspicious",
                    "handling": "investigate",
                    "duplicate_of": None,
                },
            )

        self.assertEqual(status, 201)
        self.assertTrue(payload["ok"])
        path, request = post.call_args.args
        self.assertEqual(path, "/adjudications")
        self.assertEqual(request["group_id"], group_id)
        self.assertEqual(request["analysis_id"], "analysis-unit")
        self.assertEqual(request["reviewer"], "qa-analyst")
        self.assertEqual(request["event_status"], "observed")
        self.assertEqual(request["detection_validity"], "matched_intent")
        self.assertEqual(request["activity_disposition"], "suspicious")
        self.assertEqual(request["handling"], "investigate")
        self.assertIsNone(request["duplicate_of"])
        self.assertFalse(request["resolve_case"])
        self.assertEqual(post.call_args.kwargs["timeout"], 10.0)

        status, payload = self.portal.soc_alert_adjudication_response(
            group_id,
            {
                "outcome_override": "not-a-valid-outcome",
                "confidence": "high",
                "rationale": "invalid",
                "reviewer": "qa",
            },
        )
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])

        status, payload = self.portal.soc_alert_adjudication_response(
            group_id,
            {
                "outcome_override": "inconclusive",
                "confidence": "low",
                "rationale": "Still requires review.",
                "reviewer": "qa",
                "resolve_case": "false",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("JSON boolean", payload["error"])

        status, payload = self.portal.soc_alert_adjudication_response(
            group_id,
            {
                "outcome_override": "inconclusive",
                "confidence": "low",
                "rationale": "Still requires review.",
                "reviewer": "qa",
                "event_status": "guessed",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("event status", payload["error"])

        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
        ) as contradictory_post:
            status, payload = self.portal.soc_alert_adjudication_response(
                group_id,
                {
                    "outcome_override": "false_positive_logic_rule",
                    "confidence": "high",
                    "rationale": "These labels must not be stored together.",
                    "reviewer": "qa",
                    "event_status": "observed",
                    "detection_validity": "logic_error",
                    "activity_disposition": "malicious",
                    "handling": "contain",
                },
            )
        self.assertEqual(status, 400)
        self.assertIn("conflicts with the explicit verdict factors", payload["error"])
        contradictory_post.assert_not_called()

    def test_portal_review_routes_require_same_origin_json_marker(self) -> None:
        source = PORTAL_PATH.read_text(encoding="utf-8") + (
            PORTAL_PATH.parent / "portal_request_routes.py"
        ).read_text(encoding="utf-8")

        self.assertIn("def _soc_review_write_authorized", source)
        self.assertIn('X-Onion-Sentinel-Request', source)
        self.assertIn('fetch_site != "same-origin"', source)
        self.assertIn('parsed_origin.netloc.lower() != request_host', source)
        alert_review = self.portal.classify_post_route(
            "/api/soc-alerts/group/adjudicate",
            cti_program_path=self.portal.CTI_PROGRAM_API_PATH,
            prompt_paths=self.portal.SOC_SETTINGS_PROMPT_API_PATHS,
        )
        incident_review = self.portal.classify_post_route(
            "/api/soc-incidents/ir-case/status",
            cti_program_path=self.portal.CTI_PROGRAM_API_PATH,
            prompt_paths=self.portal.SOC_SETTINGS_PROMPT_API_PATHS,
        )
        self.assertTrue(alert_review.review_write)
        self.assertTrue(incident_review.review_write)

    def test_portal_alert_action_posts_through_bounded_dispatch(self) -> None:
        raw = json.dumps({"reason": "manual triage"}).encode()
        handler = self.portal.PortalHandler.__new__(self.portal.PortalHandler)
        handler.path = "/api/soc-alerts/group%20one/analyze"
        handler.headers = {"Content-Length": str(len(raw))}
        handler.rfile = io.BytesIO(raw)
        handler._send = mock.Mock(return_value="sent")
        with (
            mock.patch.object(
                self.portal,
                "dispatch_authorized_soc_write",
                return_value=(202, {"ok": True}),
            ) as dispatch_write,
            mock.patch.object(
                self.portal.SOC_ALERT_RESPONSE_CACHE,
                "clear",
            ) as clear_cache,
        ):
            result = handler.do_POST()

        self.assertEqual(result, "sent")
        route, payload, callbacks = dispatch_write.call_args.args
        self.assertEqual(route.operation, "soc_alert_analyze")
        self.assertEqual(route.resource_id, "group one")
        self.assertEqual(payload, {"reason": "manual triage"})
        self.assertIs(callbacks, self.portal.PORTAL_SOC_WRITE_CALLBACKS)
        clear_cache.assert_called_once_with()
        self.assertEqual(handler._send.call_args.args[0], 202)

    def test_portal_rejects_unauthorized_review_before_dispatch(self) -> None:
        raw = json.dumps({"status": "closed"}).encode()
        handler = self.portal.PortalHandler.__new__(self.portal.PortalHandler)
        handler.path = "/api/soc-incidents/ir-case/status"
        handler.headers = {"Content-Length": str(len(raw))}
        handler.rfile = io.BytesIO(raw)
        handler._send = mock.Mock(return_value="forbidden")
        handler._soc_review_write_authorized = mock.Mock(return_value=False)
        with mock.patch.object(
            self.portal,
            "dispatch_authorized_soc_write",
        ) as dispatch_write:
            result = handler.do_POST()

        self.assertEqual(result, "forbidden")
        dispatch_write.assert_not_called()
        self.assertEqual(
            handler._send.call_args.args[0],
            self.portal.HTTPStatus.FORBIDDEN,
        )

    def test_portal_preserves_strict_review_json_errors(self) -> None:
        cases = (
            (
                "/api/soc-alerts/group/adjudicate",
                "Request body must be valid JSON.",
            ),
            (
                "/api/soc-incidents/ir-case/reanalyze",
                "Request body must be a JSON object.",
            ),
        )
        for path, expected_error in cases:
            with self.subTest(path=path):
                raw = b"{not-json"
                handler = self.portal.PortalHandler.__new__(
                    self.portal.PortalHandler
                )
                handler.path = path
                handler.headers = {"Content-Length": str(len(raw))}
                handler.rfile = io.BytesIO(raw)
                handler._send = mock.Mock(return_value="bad-request")
                handler._soc_review_write_authorized = mock.Mock(
                    return_value=True
                )
                with mock.patch.object(
                    self.portal,
                    "dispatch_authorized_soc_write",
                ) as dispatch_write:
                    result = handler.do_POST()

                self.assertEqual(result, "bad-request")
                dispatch_write.assert_not_called()
                status, body = handler._send.call_args.args[:2]
                self.assertEqual(status, self.portal.HTTPStatus.BAD_REQUEST)
                self.assertEqual(json.loads(body)["error"], expected_error)

    def test_portal_preserves_lenient_alert_action_json_fallback(self) -> None:
        raw = b"{not-json"
        handler = self.portal.PortalHandler.__new__(self.portal.PortalHandler)
        handler.path = "/api/soc-alerts/group/ack"
        handler.headers = {"Content-Length": str(len(raw))}
        handler.rfile = io.BytesIO(raw)
        handler._send = mock.Mock(return_value="sent")
        with mock.patch.object(
            self.portal,
            "dispatch_authorized_soc_write",
            return_value=(400, {"ok": False}),
        ) as dispatch_write:
            result = handler.do_POST()

        self.assertEqual(result, "sent")
        self.assertEqual(dispatch_write.call_args.args[1], {})

    def test_portal_get_uses_classified_incident_target(self) -> None:
        handler = self.portal.PortalHandler.__new__(self.portal.PortalHandler)
        handler.path = "/api/soc-incidents/ir%20case/detail"
        handler._send = mock.Mock(return_value="sent")
        with mock.patch.object(
            self.portal,
            "soc_incident_detail_response",
            return_value=(200, {"ok": True}),
        ) as detail_response:
            result = handler.do_GET()

        self.assertEqual(result, "sent")
        detail_response.assert_called_once_with("ir case")
        self.assertEqual(handler._send.call_args.args[0], 200)

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

    def test_incident_paths_ignore_unrelated_latest_analysis_pointer(self) -> None:
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
              analysis_id TEXT PRIMARY KEY, group_id TEXT, agent_role TEXT,
              generated_at TEXT, created_at TEXT, model TEXT,
              detection_outcome TEXT, bluf TEXT, summary TEXT, confidence TEXT,
              response_json TEXT
            );
            INSERT INTO incident_response_cases VALUES (
              'ir-pointer', 'stable-correct', 'dddddddddddd', 'alert-pointer',
              'open', 'analyzed', '2026-07-22  13:00:00-06:00',
              '2026-07-22  13:05:00-06:00', 'qa', 'Pointer validation',
              'analysis-wrong', 'wrong-model',
              '2026-07-22  13:05:00-06:00', NULL
            );
            """
        )
        correct_response = json.dumps({
            "incident_response_report": {
                "executive_bluf": "Correct group analysis.",
                "conclusion": "Use the group-bound incident run.",
                "confidence": "high",
            },
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "investigate",
            "duplicate_of": None,
        })
        wrong_response = json.dumps({
            "incident_response_report": {
                "executive_bluf": "Unrelated analysis must not render.",
                "conclusion": "Wrong group.",
                "confidence": "high",
            },
        })
        conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "analysis-wrong", "stable-other", "incident-responder",
                "2026-07-22  13:05:00-06:00", "2026-07-22  13:05:00-06:00",
                "wrong-model", "true_positive_malicious", "wrong", "wrong",
                "high", wrong_response,
            ),
        )
        conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "analysis-correct", "stable-correct", "incident-responder",
                "2026-07-22  13:04:00-06:00", "2026-07-22  13:04:00-06:00",
                "correct-model", "true_positive_suspicious", "correct", "correct",
                "high", correct_response,
            ),
        )
        conn.commit()
        conn.close()

        status, detail = self.portal.soc_incident_detail_response("ir-pointer")
        self.assertEqual(status, 200)
        self.assertEqual(detail["review"]["analysis_id"], "analysis-correct")
        self.assertIn("Correct group analysis.", detail["incident_html"])
        self.assertNotIn("Unrelated analysis must not render.", detail["incident_html"])

        status, listing = self.portal.soc_incidents_query_response(
            {"page": ["1"], "per_page": ["25"], "status": ["all"]}
        )
        self.assertEqual(status, 200)
        self.assertEqual(listing["incidents"][0]["analysis_id"], "analysis-correct")
        self.assertEqual(listing["incidents"][0]["analysis_model"], "correct-model")

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
        composition = CONTROLLED_INCIDENT_COMPOSITION_PATH.read_text(encoding="utf-8")
        dispatch = MANUAL_ANALYSIS_DISPATCH_PATH.read_text(encoding="utf-8")
        schema = INCIDENT_ANALYSIS_SCHEMA_PATH.read_text(encoding="utf-8")
        routes = ANALYSIS_REQUEST_ROUTES_PATH.read_text(encoding="utf-8")

        self.assertIn("createIncidentAnalysisSchema", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_response_cases", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_response_events", schema)
        self.assertIn("async function requestIncidentEscalation", source)
        self.assertIn("createControlledIncidentComposition", source)
        self.assertIn("createManualAnalysisDispatch", composition)
        self.assertIn("enqueueJob('incident_response_analysis'", dispatch)
        self.assertIn("agent_role: 'incident-responder'", dispatch)
        self.assertIn("manualReanalysis: false", dispatch)
        self.assertIn("'/incidents/escalate'", routes)

    def test_case_bound_reanalysis_has_durable_run_progress_contract(self) -> None:
        source = ALERT_STORE_PATH.read_text(encoding="utf-8")
        composition = CONTROLLED_INCIDENT_COMPOSITION_PATH.read_text(encoding="utf-8")
        schema = INCIDENT_ANALYSIS_SCHEMA_PATH.read_text(encoding="utf-8")
        request_source = INCIDENT_REANALYSIS_REQUEST_PATH.read_text(encoding="utf-8")
        run_persistence_source = INCIDENT_REANALYSIS_RUN_PERSISTENCE_PATH.read_text(
            encoding="utf-8"
        )
        job_ownership_source = INCIDENT_REANALYSIS_JOB_OWNERSHIP_PATH.read_text(
            encoding="utf-8"
        )
        attempt_lifecycle_source = (
            INCIDENT_REANALYSIS_ATTEMPT_LIFECYCLE_PATH.read_text(encoding="utf-8")
        )
        routes = ANALYSIS_REQUEST_ROUTES_PATH.read_text(encoding="utf-8")
        binding_source = INCIDENT_REANALYSIS_BINDING_PATH.read_text(encoding="utf-8")
        completion_source = INCIDENT_ANALYSIS_COMPLETION_PATH.read_text(encoding="utf-8")
        index_source = ANALYSIS_INDEX_PATH.read_text(encoding="utf-8")

        self.assertIn("createIncidentAnalysisSchema", source)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_reanalysis_runs", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_reanalysis_run_cases", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_reanalysis_attempts", schema)
        self.assertNotIn("async function requestIncidentReanalysis", source)
        self.assertIn("createControlledIncidentComposition", source)
        self.assertIn("createIncidentReanalysisRequest", composition)
        self.assertIn("async function request(payload", request_source)
        self.assertIn("reanalysis_run_id: context.runId", request_source)
        self.assertIn("case_id: normalized.storedCaseId", request_source)
        self.assertIn("alert_id: normalized.representativeAlertId", request_source)
        self.assertIn("group_id: normalized.groupId", request_source)
        self.assertIn("dashboard_group_id: normalized.dashboardGroupId", request_source)
        self.assertNotIn("async function updateIncidentReanalysisProgress", source)
        self.assertNotIn("async function bindIncidentReanalysisResult", source)
        self.assertNotIn("function incidentReanalysisAttemptId", source)
        self.assertIn("async function update({job, requestedStatus", attempt_lifecycle_source)
        self.assertIn("async function bindResult({", binding_source)
        self.assertIn("function attemptId(leaseToken)", job_ownership_source)
        self.assertIn(
            "WHERE case_id = ? AND status = 'queued' AND run_id != ?",
            run_persistence_source,
        )
        self.assertNotIn(
            "WHERE case_id = ? AND status IN ('queued', 'running') AND run_id != ?",
            run_persistence_source,
        )
        self.assertIn("releaseId: incidentReanalysisReleaseId", composition)
        self.assertIn("releaseId: releaseId()", request_source)
        self.assertIn("process.env.ONION_SENTINEL_RELEASE_ID || 'unversioned'", source)
        self.assertNotIn("incidentReanalysisReleaseId(payload?.release_id)", source)
        self.assertIn(
            '"reanalysis_attempt_id": reanalysis_attempt_id or None',
            index_source,
        )
        self.assertIn('"analysis_started_at": analysis_started_at', index_source)
        self.assertIn('"provider": response.get("_analysis_provider")', index_source)
        self.assertIn('"harness": response.get("_analysis_harness")', index_source)
        self.assertIn(
            "payload?.provider || response._analysis_provider",
            completion_source,
        )
        self.assertIn(
            "incidentAnalysisProvider(executedModelPath, provider)",
            binding_source,
        )
        self.assertIn("'/incidents/reanalyze'", routes)
        self.assertIn("'/incidents/reanalyze-all'", routes)

    def test_portal_does_not_forward_client_supplied_release_id(self) -> None:
        captured: list[tuple[str, dict]] = []

        def mutation(path, payload, **_kwargs):
            captured.append((path, payload))
            return 202, {"ok": True}

        with (
            mock.patch.object(
                self.portal,
                "_soc_incident_case_group_id",
                return_value=(200, "stable-group"),
            ),
            mock.patch.object(
                self.portal,
                "_soc_alert_store_mutation",
                side_effect=mutation,
            ),
        ):
            status, _payload = self.portal.soc_incident_reanalysis_response(
                "ir-case",
                {
                    "release_id": "forged-browser-release",
                    "expected_assigned_route": "codex-cli:gpt-5.5:high",
                    "expected_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                    "reviewer_required": True,
                    "requested_by": "dashboard",
                },
            )
            bulk_status, _bulk_payload = (
                self.portal.soc_incident_bulk_reanalysis_response(
                    {"release_id": "forged-browser-release"}
                )
            )

        self.assertEqual(status, 202)
        self.assertEqual(bulk_status, 202)
        self.assertEqual(len(captured), 2)
        for _path, forwarded in captured:
            self.assertNotIn("release_id", forwarded)
            self.assertNotIn("expected_assigned_route", forwarded)
            self.assertNotIn("expected_reviewer_route", forwarded)
            self.assertNotIn("reviewer_required", forwarded)

    def test_case_reanalysis_forwards_exact_frozen_dispatch_identity(self) -> None:
        identity = {
            "representative_alert_id": "frozen-reanalysis-alert",
            "stable_group_id": "abcdef1234567890abcd",
            "stable_group_key": "v2|critical|reanalysis-test",
            "cohort_id": "newest-20-ir.2026_07_26",
            "dispatch_id": "c" * 64,
            "release_id": "d" * 40,
            "expected_assigned_route": "codex-cli:gpt-5.5:high",
            "expected_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
            "reviewer_required": True,
        }
        with (
            mock.patch.object(
                self.portal,
                "_soc_incident_case_group_id",
                return_value=(200, "a" * 12),
            ),
            mock.patch.object(
                self.portal,
                "_soc_alert_store_mutation",
                return_value=(202, {"ok": True, **identity}),
            ) as mutation,
        ):
            status, payload = self.portal.soc_incident_reanalysis_response(
                "ir-frozen-case",
                identity,
            )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        path, request = mutation.call_args.args
        self.assertEqual(path, "/incidents/reanalyze")
        for field, expected in identity.items():
            self.assertEqual(request[field], expected)

    def test_reanalysis_progress_api_reports_exact_case_counts(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.executescript(
            """
            CREATE TABLE incident_reanalysis_runs (
              run_id TEXT PRIMARY KEY, release_id TEXT NOT NULL, scope TEXT NOT NULL,
              status TEXT NOT NULL, requested_by TEXT, reason TEXT,
              total_count INTEGER NOT NULL, created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL, completed_at TEXT
            );
            CREATE TABLE incident_reanalysis_run_cases (
              run_id TEXT NOT NULL, case_id TEXT NOT NULL, group_id TEXT NOT NULL,
              dashboard_group_id TEXT NOT NULL, representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL, skip_reason TEXT, latest_error TEXT,
              queued_at TEXT, started_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL
            );
            INSERT INTO incident_reanalysis_runs VALUES (
              'irr-11111111-1111-1111-1111-111111111111', 'release-unit',
              'all_cases', 'running', 'qa', 'Rerun every case', 4,
              '2026-07-25T12:00:00Z', '2026-07-25T12:01:00Z', NULL
            );
            INSERT INTO incident_reanalysis_run_cases VALUES
              ('irr-11111111-1111-1111-1111-111111111111', 'ir-a', 'stable-a', 'aaaaaaaaaaaa', 'alert-a', 'completed', NULL, NULL, '2026-07-25T12:00:00Z', '2026-07-25T12:00:10Z', '2026-07-25T12:00:30Z', '2026-07-25T12:00:30Z'),
              ('irr-11111111-1111-1111-1111-111111111111', 'ir-b', 'stable-b', 'aaaaaaaaaaaa', 'alert-b', 'running', NULL, NULL, '2026-07-25T12:00:00Z', '2026-07-25T12:00:40Z', NULL, '2026-07-25T12:00:40Z'),
              ('irr-11111111-1111-1111-1111-111111111111', 'ir-c', 'stable-c', 'aaaaaaaaaaaa', 'alert-c', 'queued', NULL, NULL, '2026-07-25T12:00:00Z', NULL, NULL, '2026-07-25T12:00:00Z'),
              ('irr-11111111-1111-1111-1111-111111111111', 'ir-d', 'stable-d', 'aaaaaaaaaaaa', 'alert-d', 'skipped', 'missing representative', NULL, NULL, NULL, '2026-07-25T12:00:00Z', '2026-07-25T12:00:00Z');
            """
        )
        conn.commit()
        conn.close()

        status, payload = self.portal.soc_incident_reanalysis_runs_response({})

        self.assertEqual(status, 200)
        run = payload["latest_run"]
        self.assertEqual(run["run_id"], "irr-11111111-1111-1111-1111-111111111111")
        self.assertEqual(run["release_id"], "release-unit")
        self.assertEqual(run["total_count"], 4)
        self.assertEqual(
            run["counts"],
            {"queued": 1, "running": 1, "completed": 1, "failed": 0, "skipped": 1},
        )
        self.assertEqual(len(payload["cases"]), 4)


if __name__ == "__main__":
    unittest.main()
