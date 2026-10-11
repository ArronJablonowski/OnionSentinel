from __future__ import annotations

from incident_harness_cohort_fixtures import (
    EVALUATOR_PATH,
    EVALUATOR_SPEC,
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    cohort,
    cohort_analysis_metadata,
    cohort_artifact_adapters,
    cohort_artifact_io,
    cohort_dispatch_adapters,
    cohort_dispatch_identity,
    cohort_evaluation_query_audit,
    cohort_evaluator,
    cohort_execution_proof_service,
    cohort_freeze_state_composition,
    cohort_manifest_adapters,
    cohort_manifest_contract,
    cohort_monitor_adapters,
    cohort_preflight,
    cohort_private_input,
    cohort_query_audit_projection,
    cohort_representative_state,
    cohort_runner_contracts,
    cohort_runtime_composition,
    cohort_second_opinion_state,
    cohort_source_rows,
    cohort_storage_core,
    cohort_storage_state,
    hashlib,
    importlib,
    json,
    mock,
    os,
    sqlite3,
    stat,
    tempfile,
    unittest,
)

class IncidentHarnessCohortTestsSocRoleUsesAnalyzeAndMonitorsExactNewAnalysisIdCases:
    def test_soc_role_uses_analyze_and_monitors_exact_new_analysis_id(self) -> None:
        source_path = self.root / "shared-frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        manifest = cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="preselected-soc-cohort",
            reason="Exercise the SOC Analyst harness on the frozen cohort.",
            expected_count=1,
            expected_release_id=self.release_id,
            agent_role="soc-analyst",
        )
        self.assertEqual(manifest["agent_role"], "soc-analyst")
        self.assertEqual(manifest["members"][0]["dispatch"]["kind"], "analyze")
        self.assertEqual(
            manifest["members"][0]["pre_state"]["soc_analysis_ids"],
            [],
        )
        calls = []

        def analyze(url: str, payload):
            calls.append((url, dict(payload)))
            connection = self._connect()
            connection.execute(
                """
                INSERT INTO durable_jobs (
                  job_type, dedupe_key, payload_json, status, attempt_count,
                  requested_at, updated_at
                ) VALUES (
                  'ai_analysis', ?, ?, 'pending', 0,
                  '2026-07-25T12:10:00Z', '2026-07-25T12:10:00Z'
                )
                """,
                (
                    self.stable_one,
                    json.dumps(
                        {
                            "alert_id": payload[
                                "representative_alert_id"
                            ],
                            "representative_alert_id": payload[
                                "representative_alert_id"
                            ],
                            "group_id": payload["stable_group_id"],
                            "stable_group_id": payload[
                                "stable_group_id"
                            ],
                            "stable_group_key": payload[
                                "stable_group_key"
                            ],
                            "dashboard_group_id": self.dashboard_a,
                            "cohort_id": payload["cohort_id"],
                            "dispatch_id": payload["dispatch_id"],
                            "release_id": payload["release_id"],
                            "expected_assigned_route": payload[
                                "expected_assigned_route"
                            ],
                            "expected_reviewer_route": payload[
                                "expected_reviewer_route"
                            ],
                            "reviewer_required": payload[
                                "reviewer_required"
                            ],
                            "agent_role": "soc-analyst",
                            "manual_reanalysis": True,
                        }
                    ),
                ),
            )
            connection.commit()
            connection.close()
            response = {
                "ok": True,
                "status": "queued",
                "group_id": self.dashboard_a,
                "queue_group_id": self.stable_one,
                "stable_group_id": self.stable_one,
                "stable_group_key": payload["stable_group_key"],
                "representative_alert_id": "alert-a-newest",
                "cohort_id": payload["cohort_id"],
                "dispatch_id": payload["dispatch_id"],
                "release_id": payload["release_id"],
                "expected_assigned_route": payload[
                    "expected_assigned_route"
                ],
                "expected_reviewer_route": payload[
                    "expected_reviewer_route"
                ],
                "reviewer_required": payload["reviewer_required"],
                "requested_at": "2026-07-25T12:10:00Z",
            }
            return cohort.HttpResult(
                202,
                response,
                hashlib.sha256(json.dumps(response).encode()).hexdigest(),
            )

        queued = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            poster=analyze,
        )
        self.assertEqual(len(calls), 1)
        self.assertTrue(
            calls[0][0].endswith(f"/{self.dashboard_a}/analyze")
        )
        self.assertEqual(queued["members"][0]["dispatch"]["state"], "accepted")
        queued["members"][0]["dispatch"]["started_at"] = (
            "2026-07-25T12:10:00Z"
        )
        cohort.write_private_json(
            self.manifest_path,
            queued,
            digest_field="manifest_sha256",
        )

        soc_tool_call_bindings = [
            {
                "call_id": "round-1-soc-pivot",
                "round_number": 1,
                "query_id": "soc-pivot",
                "backend": "elastic",
                "status": "ok",
                "request_digest": "d" * 64,
                "result_digest": "e" * 64,
                "read_only": True,
            }
        ]
        response = {
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "investigate",
            "summary": "Observed café traffic — reviewed.",
            "confidence_score": 0.0000001,
            "serialization_probe": {
                "observed_at": "2026-07-25T18:00:00Z",
                "\ue000": "private-use",
                "😀": "astral",
            },
            "_analysis_model": "gpt-5.5",
            "_analysis_model_path": "codex_cli",
            "_analysis_model_route": "codex-cli:gpt-5.5:high",
            "_analysis_provider": "codex-cli",
            "_analysis_harness": "onion-sentinel",
            "_analysis_evaluation_memory_frozen": True,
            "_second_opinion": {
                "status": "completed",
                "model_route": "codex-cli:gpt-5.6-sol:xhigh",
                "response": {
                    "_analysis_model_route": (
                        "codex-cli:gpt-5.6-sol:xhigh"
                    )
                },
            },
            "_investigation_query_audit": {
                "read_only": True,
                "complete": True,
                "all_tool_call_bindings_read_only": True,
                "evaluation_requirement_satisfied": True,
                "query_contract": (
                    "onion-sentinel-investigation-pivots-v2"
                ),
                "provider_neutral": True,
                "rounds_completed": 1,
                "queries_admitted": 1,
                "successful_read_only_queries": 1,
                "tool_call_bindings": soc_tool_call_bindings,
                "rounds": [
                    {
                        "round": 1,
                        "trusted_queries": [
                            {
                                "query_id": "soc-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                                "result_digest": "e" * 64,
                                "returned_hits": 1,
                            }
                        ],
                        "results": [
                            {
                                "query_id": "soc-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                            }
                        ],
                    }
                ],
            },
        }
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, agent_role, generated_at,
              model, model_path, detection_outcome, confidence,
              evidence_hash, response_json, created_at
            ) VALUES (
              'analysis-soc-new', ?, 'alert-a-newest', 'soc-analyst',
              '2026-07-25T12:11:00Z', 'gpt-5.5', 'codex_cli',
              'true_positive_suspicious', 'high', 'evidence-soc',
              ?, '2026-07-25T12:11:00Z'
            )
            """,
            (self.stable_one, json.dumps(response)),
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed', completed_at = '2026-07-25T12:11:00Z',
                last_completed_at = '2026-07-25T12:11:00Z',
                updated_at = '2026-07-25T12:11:00Z'
            WHERE job_type = 'ai_analysis' AND dedupe_key = ?
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        monitored, terminal = cohort.monitor_cohort_once(
            self.db_path,
            self.manifest_path,
        )
        self.assertTrue(terminal)
        result = monitored["members"][0]["monitor"]
        self.assertEqual(result["analysis_id"], "analysis-soc-new")
        self.assertEqual(result["analysis"]["agent_role"], "soc-analyst")
        self.assertEqual(
            result["analysis"]["result"]["_analysis_harness"],
            "onion-sentinel",
        )
        self.assertEqual(
            result["analysis"]["response_canonical_sha256"],
            cohort.alert_store_response_sha256(json.dumps(response)),
        )
        manifest = cohort.load_private_manifest(self.manifest_path)
        analysis = manifest["members"][0]["monitor"]["analysis"]
        exported_tool_bindings = analysis["query_audit"][
            "_investigation_query_audit"
        ]["tool_call_bindings"]
        exported_model_call_facts = [
            {
                "call_id": "primary-initial",
                "purpose": "initial primary analysis",
                "requested_route": "codex-cli:gpt-5.5:high",
                "independent_review": False,
                "status": "completed",
            },
            {
                "call_id": "independent-review-1",
                "purpose": "independent second-opinion review",
                "requested_route": "codex-cli:gpt-5.6-sol:xhigh",
                "independent_review": True,
                "status": "completed",
            },
        ]
        proof = {
            "status": "passed",
            "fresh_analysis": True,
            "dispatch_accepted_once": True,
            "analysis_id": "analysis-soc-new",
            "analysis_generated_at": "2026-07-25T12:11:00Z",
            "release_id": self.release_id,
            "harness": {
                "run_id": "analysis-soc-new",
                "trace_id": "trace-soc-export",
                "stable_group_id": self.stable_one,
                "representative_alert_id": "alert-a-newest",
                "status": "succeeded",
                "stage": "complete",
                "role": "soc-analyst",
                "task_kind": "reanalysis",
                "policy_mode": "shadow",
                "assigned_route": "codex-cli:gpt-5.5:high",
                "assigned_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
                "started_at": "2026-07-25T12:10:30Z",
                "completed_at": "2026-07-25T12:12:00Z",
                "chain_valid": True,
                "chain_head_sha256": "a" * 64,
                "ledger_manifest_bound": True,
                "ledger_manifest_schema": (
                    "onion-sentinel-harness-ledger-manifest-v2"
                ),
                "skill_selection_attestation_validated": True,
                "skill_selection_attestation": {
                    "registry_version": 1,
                    "registry_sha256": "9" * 64,
                    "selected": [],
                    "selected_count": 0,
                    "truncated": False,
                    "advisory_mode": "advisory_only",
                },
                "model_call_count": 2,
                "successful_model_call_count": 2,
                "successful_primary_model_call_count": 1,
                "model_purpose_count": 2,
                "terminally_successful_model_purpose_count": 2,
                "incomplete_model_purpose_count": 0,
                "exact_reviewer_repair_count": 0,
                "superseded_validation_failure_count": 0,
                "unexpected_unsuccessful_model_call_count": 0,
                "malformed_model_purpose_sequence_count": 0,
                "model_call_contract": {
                    "schema": "onion-sentinel-model-call-contract-v1",
                    "valid": True,
                    "model_call_count": 2,
                    "canonical_model_call_count": 2,
                    "noncanonical_model_call_count": 0,
                    "primary_initial_call_count": 1,
                    "query_planning_call_count": 0,
                    "primary_followup_call_count": 0,
                    "reviewer_model_call_count": 1,
                    "facts": exported_model_call_facts,
                    "facts_sha256": cohort.sha256_value(
                        exported_model_call_facts
                    ),
                    "violation_count": 0,
                    "violations": [],
                    "global_reasons": [],
                },
                "reviewer_completion": {
                    "model_call_count": 1,
                    "completed_model_call_count": 1,
                    "primary_decision_count": 1,
                    "reviewer_decision_count": 1,
                    "has_primary_decision": True,
                    "has_reviewer_decision": True,
                    "decision_comparable": True,
                    "missing_reviewer_decision": False,
                    "completion_contract_required": True,
                    "completion_contract_satisfied": True,
                    "completion_contract_failure_reasons": [],
                },
                "route_authorization_failure_count": 0,
                "route_identity_mismatch_count": 0,
                "tool_call_count": 1,
                "successful_tool_call_count": 1,
                "read_only_tool_call_count": 1,
                "read_only_violation_count": 0,
                "successful_read_only_tool_call_bindings": (
                    exported_tool_bindings
                ),
                "successful_read_only_tool_call_bindings_sha256": (
                    cohort.sha256_value(exported_tool_bindings)
                ),
                "query_audit": cohort._query_audit_execution_binding(
                    analysis
                ),
                "memory_frozen": True,
                "submitted_response_sha256": "b" * 64,
                "response_canonical_sha256": analysis[
                    "response_canonical_sha256"
                ],
            },
        }
        proof["proof_sha256"] = cohort.sha256_value(proof)
        with mock.patch.object(
            cohort,
            "_harness_execution_proof",
            return_value=proof,
        ):
            exported = cohort.export_cohort(
                self.db_path,
                self.manifest_path,
                self.output_path,
                harness_database_path=self.root / "harness.sqlite3",
            )
        self.assertEqual(exported["agent_role"], "soc-analyst")
        self.assertEqual(
            exported["members"][0]["result"]["analysis"]["model"],
            "gpt-5.5",
        )
        loaded, _source_file_sha256 = (
            cohort_evaluator.load_result_export(
                self.output_path,
                role="soc-analyst",
                expected_count=1,
            )
        )
        self.assertEqual(
            loaded["ordered_identities"][0]["stable_group_id"],
            self.stable_one,
        )


    def test_ambiguous_dispatch_is_recorded_and_never_retried(self) -> None:
        self._freeze(count=1)
        calls = 0

        def ambiguous(_url, _payload):
            nonlocal calls
            calls += 1
            raise cohort.AmbiguousDispatchError("synthetic timeout")

        with self.assertRaises(cohort.AmbiguousDispatchError):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=ambiguous,
            )
        recorded = cohort.load_private_manifest(self.manifest_path)
        self.assertEqual(recorded["state"], "dispatch_ambiguous")
        self.assertEqual(recorded["members"][0]["dispatch"]["attempt_count"], 1)

        with self.assertRaisesRegex(cohort.CohortError, "refusing"):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=ambiguous,
            )
        self.assertEqual(calls, 1)


    def test_monitor_and_export_bind_exact_results_without_raw_content(self) -> None:
        self._freeze()
        self._queue()
        queued_manifest = cohort.load_private_manifest(self.manifest_path)
        for member in queued_manifest["members"]:
            member["dispatch"]["started_at"] = "2026-07-25T12:00:00Z"
        cohort.write_private_json(
            self.manifest_path,
            queued_manifest,
            digest_field="manifest_sha256",
        )
        secret_marker = "never-export-this-api-key"
        response = {
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "investigate",
            "_analysis_model": "gpt-5.6-sol",
            "_analysis_model_path": "codex_cli",
            "_analysis_provider": "codex-cli",
            "api_key": secret_marker,
            "_incident_query_audit": {
                "trusted_source": "restricted-security-onion-wrapper",
                "read_only": True,
                "complete": True,
                "queries": [
                    {
                        "pack": "network_flow",
                        "status": "ok",
                        "query_digest": "query-digest-unit",
                        "returned_hits": 2,
                        "query_dsl": {
                            "query": {"term": {"source.ip": "192.0.2.1"}}
                        },
                        "rows": [{"secret": secret_marker}],
                    }
                ],
            },
        }
        connection = self._connect()
        for analysis_id, stable, alert_id in (
            ("analysis-new", self.stable_one, "alert-a-newest"),
            ("analysis-reanalysis", self.stable_two, "alert-c-existing"),
        ):
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role, generated_at,
                  model, model_path, detection_outcome, confidence,
                  evidence_hash, response_json, created_at
                ) VALUES (
                  ?, ?, ?, 'incident-responder', '2026-07-25T12:05:00Z',
                  'gpt-5.6-sol', 'codex_cli',
                  'true_positive_suspicious', 'high', ?, ?,
                  '2026-07-25T12:05:00Z'
                )
                """,
                (
                    analysis_id,
                    stable,
                    alert_id,
                    f"evidence-{analysis_id}",
                    json.dumps(response),
                ),
            )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed', latest_analysis_id = 'analysis-new',
                latest_model = 'gpt-5.6-sol',
                latest_generated_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-new'
            """
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-reanalysis',
                latest_model = 'gpt-5.6-sol',
                latest_generated_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.execute(
            """
            UPDATE incident_reanalysis_run_cases
            SET status = 'completed', analysis_id = 'analysis-reanalysis',
                executed_model = 'gpt-5.6-sol',
                executed_provider = 'codex-cli',
                executed_model_path = 'codex_cli',
                result_generated_at = '2026-07-25T12:05:00Z',
                completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            """
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed',
                completed_at = '2026-07-25T12:05:00Z',
                last_completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            """
        )
        connection.commit()
        connection.close()

        monitored, terminal = cohort.monitor_cohort_once(
            self.db_path,
            self.manifest_path,
        )
        self.assertTrue(terminal)
        self.assertEqual(monitored["state"], "terminal")
        self.assertEqual(
            [item["monitor"]["analysis_id"] for item in monitored["members"]],
            ["analysis-new", "analysis-reanalysis"],
        )

        exported = cohort.export_cohort(
            self.db_path,
            self.manifest_path,
            self.output_path,
        )
        text = self.output_path.read_text(encoding="utf-8")
        self.assertNotIn(secret_marker, text)
        self.assertNotIn("source.ip", text)
        self.assertNotIn("query_dsl", text)
        self.assertIn("query-digest-unit", text)
        self.assertTrue(exported["content_policy"]["contains_credentials"] is False)
        self.assertEqual(
            stat.S_IMODE(self.output_path.stat().st_mode),
            0o600,
        )


    def test_tampered_manifest_is_rejected(self) -> None:
        self._freeze(count=1)
        document = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        document["reason"] = "Tampered reason that is deliberately long enough."
        self.manifest_path.write_text(json.dumps(document), encoding="utf-8")
        os.chmod(self.manifest_path, 0o600)

        with self.assertRaisesRegex(cohort.CohortError, "does not match"):
            cohort.load_private_manifest(self.manifest_path)


    def test_dashboard_transport_is_loopback_only_and_has_no_bulk_route(self) -> None:
        with self.assertRaisesRegex(cohort.CohortError, "loopback"):
            cohort.validate_loopback_base_url("http://192.0.2.10:8766")
        self.assertEqual(
            cohort.validate_loopback_base_url("http://127.0.0.1:8766"),
            "http://127.0.0.1:8766",
        )
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"/api/soc-incidents/reanalyze-all"', source)
