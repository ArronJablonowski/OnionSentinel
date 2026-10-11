from __future__ import annotations

from incident_response_workflow_fixtures import (
    AI_RUNNER_PATH,
    ALERT_STORE_PATH,
    ANALYSIS_INDEX_PATH,
    ANALYSIS_REQUEST_ROUTES_PATH,
    APPLICATION_COMPOSITION_PATH,
    APPLICATION_GRAPH_RUNTIME_PATH,
    BUILDER_PATH,
    CONTROLLED_INCIDENT_COMPOSITION_PATH,
    DASHBOARD_DIR,
    INCIDENT_ANALYSIS_COMPLETION_PATH,
    INCIDENT_ANALYSIS_SCHEMA_PATH,
    INCIDENT_PAGE_PATH,
    INCIDENT_REANALYSIS_ATTEMPT_LIFECYCLE_PATH,
    INCIDENT_REANALYSIS_BINDING_PATH,
    INCIDENT_REANALYSIS_JOB_OWNERSHIP_PATH,
    INCIDENT_REANALYSIS_REQUEST_PATH,
    INCIDENT_REANALYSIS_RUN_PERSISTENCE_PATH,
    MANUAL_ANALYSIS_DISPATCH_PATH,
    PORTAL_HTTP_HANDLER_PATH,
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    SHELL_PAGE_PATH,
    importlib,
    io,
    json,
    load_module,
    mock,
    sqlite3,
    sys,
    tempfile,
    unittest,
)

class IncidentResponseWorkflowTestsIncidentListReturnsCaseAndOnlyIncidentResponderAnalysisCases:
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
        graph = APPLICATION_GRAPH_RUNTIME_PATH.read_text(encoding="utf-8")
        composition = CONTROLLED_INCIDENT_COMPOSITION_PATH.read_text(encoding="utf-8")
        application = APPLICATION_COMPOSITION_PATH.read_text(encoding="utf-8")
        dispatch = MANUAL_ANALYSIS_DISPATCH_PATH.read_text(encoding="utf-8")
        schema = INCIDENT_ANALYSIS_SCHEMA_PATH.read_text(encoding="utf-8")
        routes = ANALYSIS_REQUEST_ROUTES_PATH.read_text(encoding="utf-8")

        self.assertIn("createApplicationComposition", graph)
        self.assertIn("createIncidentAnalysisSchema", application)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_response_cases", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_response_events", schema)
        self.assertIn("async function requestIncidentEscalation", dispatch)
        self.assertIn("createControlledIncidentComposition", graph)
        self.assertIn("createManualAnalysisDispatch", composition)
        self.assertIn("enqueueJob('incident_response_analysis'", dispatch)
        self.assertIn("agent_role: 'incident-responder'", dispatch)
        self.assertIn("manualReanalysis: false", dispatch)
        self.assertIn("'/incidents/escalate'", routes)


    def test_case_bound_reanalysis_has_durable_run_progress_contract(self) -> None:
        source = ALERT_STORE_PATH.read_text(encoding="utf-8")
        graph = APPLICATION_GRAPH_RUNTIME_PATH.read_text(encoding="utf-8")
        composition = CONTROLLED_INCIDENT_COMPOSITION_PATH.read_text(encoding="utf-8")
        application = APPLICATION_COMPOSITION_PATH.read_text(encoding="utf-8")
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

        self.assertIn("createApplicationComposition", graph)
        self.assertIn("createIncidentAnalysisSchema", application)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_reanalysis_runs", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_reanalysis_run_cases", schema)
        self.assertIn("CREATE TABLE IF NOT EXISTS incident_reanalysis_attempts", schema)
        self.assertNotIn("async function requestIncidentReanalysis", source)
        self.assertIn("createControlledIncidentComposition", graph)
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
        self.assertIn("platform.env.ONION_SENTINEL_RELEASE_ID || 'unversioned'", graph)
        self.assertNotIn("incidentReanalysisReleaseId(payload?.release_id)", graph)
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
