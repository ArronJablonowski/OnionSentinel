from __future__ import annotations

from evaluate_harness_traces_fixtures import (
    EVALUATOR_PATH,
    HARNESS_PATH,
    HARNESS_SPEC,
    INSTALLER_PATH,
    Path,
    ROOT,
    SPEC,
    canonical_json,
    collections,
    contextlib,
    create_terminal_harness_database,
    create_trace_database,
    digest_json,
    evaluator,
    harness,
    hashlib,
    importlib,
    io,
    json,
    os,
    replace_terminal_manifest,
    sqlite3,
    sys,
    tempfile,
    trace_evaluation_api,
    trace_evaluation_contract,
    trace_evaluation_events,
    trace_evaluation_integrity,
    trace_evaluation_model_completion,
    trace_evaluation_model_contract,
    trace_evaluation_model_routes,
    trace_evaluation_output,
    trace_evaluation_reviewer,
    trace_evaluation_run,
    trace_evaluation_skills,
    trace_evaluation_storage,
    trace_evaluation_summary,
    unittest,
    v2_skill_selection,
)

class HarnessTraceEvaluatorTestsEvaluatorUsesExtractedSkillAttestationServiceCases:
    def test_evaluator_uses_extracted_skill_attestation_service(self):
        self.assertIs(
            evaluator.evaluate_skill_attestation,
            trace_evaluation_skills.skill_selection_attestation_result,
        )


    def test_evaluator_uses_extracted_read_only_storage_services(self):
        self.assertIs(
            evaluator.open_trace_database,
            trace_evaluation_storage.connect_read_only,
        )
        self.assertIs(
            evaluator.read_database_schema_version,
            trace_evaluation_storage.database_schema_version,
        )
        self.assertIs(
            evaluator.read_rows_for_run,
            trace_evaluation_storage.rows_for_run,
        )


    def test_evaluator_uses_extracted_trace_integrity_services(self):
        self.assertIs(
            evaluator.build_ledger_manifest,
            trace_evaluation_integrity.ledger_manifest,
        )
        self.assertIs(
            evaluator.verify_trace_chain,
            trace_evaluation_integrity.verify_chain,
        )


    def test_evaluator_uses_extracted_reviewer_services(self):
        self.assertIs(
            evaluator.evaluate_reviewer_result,
            trace_evaluation_reviewer.reviewer_result,
        )
        self.assertIs(
            evaluator.evaluate_reviewer_completion,
            trace_evaluation_reviewer.reviewer_completion_contract,
        )


    def test_evaluator_uses_extracted_model_call_contract(self):
        self.assertIs(
            evaluator.build_model_call_contract,
            trace_evaluation_model_contract.canonical_model_call_contract,
        )


    def test_evaluator_uses_extracted_model_purpose_completion(self):
        self.assertIs(
            evaluator.evaluate_model_purpose_completion,
            trace_evaluation_model_completion.model_purpose_completion,
        )


    def test_evaluator_uses_extracted_model_route_services(self):
        self.assertIs(
            evaluator.expected_route_identity,
            trace_evaluation_model_routes.expected_route_identity,
        )
        self.assertIs(
            evaluator.evaluate_model_route_consistency,
            trace_evaluation_model_routes.model_route_consistency,
        )


    def test_evaluator_uses_extracted_run_evaluation(self):
        self.assertIs(
            evaluator.evaluate_trace_run,
            trace_evaluation_run.evaluate_run,
        )


    def test_evaluator_uses_extracted_output_services(self):
        self.assertIs(
            evaluator.atomic_private_json,
            trace_evaluation_output.atomic_private_json,
        )
        self.assertIs(
            evaluator.human_report,
            trace_evaluation_output.human_report,
        )


    def test_evaluator_uses_extracted_summary_service(self):
        self.assertIs(
            evaluator.summarize_trace_runs,
            trace_evaluation_summary.summarize,
        )


    def test_evaluator_uses_extracted_event_and_contract_services(self):
        self.assertIs(
            evaluator.trace_budget_operation_id,
            trace_evaluation_events.budget_operation_id,
        )
        self.assertIs(
            evaluator.evaluate_tool_coverage_gaps,
            trace_evaluation_events.unresolved_tool_coverage_gaps,
        )
        self.assertIs(evaluator.safe_json, trace_evaluation_contract.safe_json)
        self.assertIs(
            evaluator.EvaluationError,
            trace_evaluation_contract.EvaluationError,
        )
        self.assertEqual(
            evaluator.RUN_IDENTITY_COLUMNS,
            trace_evaluation_contract.RUN_IDENTITY_COLUMNS,
        )


    def test_cli_reexports_trace_evaluation_api(self):
        self.assertIs(
            evaluator.evaluate_database,
            trace_evaluation_api.evaluate_database,
        )
        self.assertIs(evaluator.evaluate_run, trace_evaluation_api.evaluate_run)
        self.assertIs(evaluator.summarize, trace_evaluation_api.summarize)


    def test_resolved_repair_is_not_reported_as_tool_coverage_gap(self) -> None:
        calls = [
            {
                "call_id": "round-1-exact-ssh",
                "round_number": 1,
                "status": "rejected",
                "coverage": "evidence-gap",
            },
            {
                "call_id": "round-2-exact-ssh",
                "round_number": 2,
                "status": "ok",
                "coverage": "exact-zero",
            },
        ]

        self.assertEqual(
            evaluator.unresolved_tool_coverage_gaps(calls),
            [],
        )


    def test_unrepaired_tool_failure_remains_a_coverage_gap(self) -> None:
        calls = [
            {
                "call_id": "round-1-exact-ssh",
                "round_number": 1,
                "status": "rejected",
                "coverage": "evidence-gap",
            },
        ]

        self.assertEqual(
            evaluator.unresolved_tool_coverage_gaps(calls),
            ["round-1-exact-ssh"],
        )


    def test_terminal_repair_failure_remains_a_coverage_gap(self) -> None:
        calls = [
            {
                "call_id": "round-1-exact-ssh",
                "round_number": 1,
                "status": "rejected",
                "coverage": "evidence-gap",
            },
            {
                "call_id": "round-2-exact-ssh",
                "round_number": 2,
                "status": "error",
                "coverage": "evidence-gap",
            },
        ]

        self.assertEqual(
            evaluator.unresolved_tool_coverage_gaps(calls),
            ["round-2-exact-ssh"],
        )


    def test_reports_requested_metrics_and_leaves_database_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            create_trace_database(database)
            before_digest = hashlib.sha256(database.read_bytes()).hexdigest()
            before_mtime = database.stat().st_mtime_ns

            report = evaluator.evaluate_database(database)

            self.assertEqual(report["run_count"], 1)
            self.assertEqual(report["completion"]["success_rate"], 1.0)
            self.assertTrue(report["integrity"]["all_chains_valid"])
            legacy_skill = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertTrue(legacy_skill["legacy"])
            self.assertTrue(legacy_skill["valid"])
            self.assertFalse(legacy_skill["mandatory_ready"])
            self.assertEqual(
                report["skill_selection_attestation"]["legacy_run_count"],
                1,
            )
            self.assertEqual(report["models"]["call_count"], 2)
            self.assertEqual(report["models"]["independent_review_call_count"], 1)
            self.assertEqual(report["models"]["purpose_count"], 2)
            self.assertEqual(
                report["models"]["terminally_successful_purpose_count"],
                2,
            )
            self.assertEqual(report["models"]["incomplete_purpose_count"], 0)
            self.assertEqual(
                report["models"]["malformed_purpose_sequence_count"],
                0,
            )
            model_contract = report["runs"][0]["models"][
                "model_call_contract"
            ]
            self.assertTrue(model_contract["valid"])
            self.assertEqual(
                model_contract["canonical_model_call_count"],
                2,
            )
            self.assertEqual(
                model_contract["facts_sha256"],
                evaluator.digest_json(model_contract["facts"]),
            )
            self.assertEqual(report["tools"]["call_count"], 3)
            self.assertEqual(report["tools"]["successful_call_count"], 2)
            self.assertEqual(report["tools"]["read_only_call_count"], 2)
            self.assertEqual(report["tools"]["rejected_count"], 1)
            self.assertEqual(report["tools"]["coverage_gap_count"], 1)
            self.assertEqual(report["tools"]["truncated_count"], 1)
            self.assertEqual(report["tools"]["read_only_violation_count"], 1)
            self.assertEqual(
                report["runs"][0]["tools"]["successful_call_count"],
                2,
            )
            self.assertEqual(
                report["runs"][0]["tools"]["read_only_call_count"],
                2,
            )
            bindings = report["runs"][0]["tools"][
                "successful_read_only_call_bindings"
            ]
            self.assertEqual(len(bindings), 1)
            self.assertEqual(bindings[0]["call_id"], "elastic-ok")
            self.assertIs(bindings[0]["read_only"], True)
            self.assertEqual(
                report["runs"][0]["tools"][
                    "successful_read_only_call_bindings_sha256"
                ],
                evaluator.digest_json(bindings),
            )
            self.assertEqual(
                report["evidence"]["average_distinct_source_classes_per_run"],
                2.0,
            )
            self.assertEqual(
                report["reviewer"]["material_disagreement_runs"],
                1,
            )
            self.assertEqual(
                report["runs"][0]["reviewer"]["disputed_fields"],
                ["detection_outcome", "handling"],
            )
            self.assertEqual(
                report["runs"][0]["reviewer"]["comparison_basis"],
                "primary_vs_independent-review",
            )
            self.assertEqual(report["budgets"]["violation_runs"], 1)
            self.assertEqual(
                report["budgets"]["violation_counts"],
                {
                    "max_prompt_evidence_bytes": 1,
                    "max_queries_per_round": 1,
                    "max_queries_total": 1,
                },
            )
            self.assertEqual(report["budgets"]["violation_operation_count"], 3)
            query_operations = [
                item
                for item in report["runs"][0]["budget_violation_operations"]
                if item["operation_id"] == "query-round:1"
            ]
            self.assertEqual(len(query_operations), 2)
            self.assertTrue(
                all(
                    item["sources"]
                    == ["policy.budget", "queries.completed"]
                    for item in query_operations
                )
            )
            self.assertEqual(report["memory_promotion"]["blocked_count"], 1)
            self.assertEqual(
                report["memory_promotion"]["requires_approval_count"],
                1,
            )
            self.assertEqual(report["memory_promotion"]["candidate_count"], 2)
            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                before_digest,
            )
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)


    def test_validates_digest_bound_sanitized_skill_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(database)

            report = evaluator.evaluate_database(database, run_id)

            attestation = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertEqual(
                attestation,
                {
                    "present": True,
                    "legacy": False,
                    "valid": True,
                    "available": True,
                    "job_digest_bound": True,
                    "mandatory_ready": True,
                    "registry_version": 1,
                    "registry_sha256": "a" * 64,
                    "selected": [
                        {
                            "id": "suricata-detection-validation",
                            "version": 3,
                            "skill_sha256": "b" * 64,
                        }
                    ],
                    "selected_count": 1,
                    "truncated": False,
                    "advisory_mode": "advisory_only",
                    "error_count": 0,
                    "errors": [],
                },
            )
            self.assertEqual(
                report["skill_selection_attestation"],
                {
                    "present_run_count": 1,
                    "valid_run_count": 1,
                    "mandatory_ready_run_count": 1,
                    "legacy_run_count": 0,
                    "unavailable_run_count": 0,
                    "invalid_run_count": 0,
                    "invalid_run_ids": [],
                },
            )
            serialized = json.dumps(report, sort_keys=True)
            self.assertNotIn(
                "This skill content must not enter the trace",
                serialized,
            )


    def test_validates_digest_bound_v2_skill_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(
                database,
                skill_selection=v2_skill_selection(),
            )

            report = evaluator.evaluate_database(database, run_id)

            attestation = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertEqual(
                attestation,
                {
                    "present": True,
                    "legacy": False,
                    "valid": True,
                    "available": True,
                    "job_digest_bound": True,
                    "mandatory_ready": True,
                    "framework_version": 2,
                    "registry_version": 8,
                    "registry_sha256": "c" * 64,
                    "provider": "codex-cli",
                    "provider_compatible": True,
                    "selected": [
                        {
                            "id": "dns-triage",
                            "version": "2.3.1",
                            "skill_sha256": "d" * 64,
                            "selection_reason": (
                                "exact_match_capability_and_promotion_gates_satisfied"
                            ),
                        }
                    ],
                    "selected_count": 1,
                    "truncated": False,
                    "rejected": [
                        {"id": "legacy-dns", "reason": "artifact_revoked"},
                    ],
                    "aggregate_budget": {
                        "max_queries": 4,
                        "max_rows": 400,
                        "max_bytes": 4000,
                        "timeout_seconds": 40,
                    },
                    "advisory_mode": "identity_only_no_execution",
                    "error_count": 0,
                    "errors": [],
                },
            )


    def test_rejects_tampered_v2_skill_selection_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(
                database,
                skill_selection=v2_skill_selection(),
            )
            with harness._connect(database) as connection:
                row = connection.execute(
                    """
                    SELECT payload_json
                    FROM harness_events
                    WHERE run_id = ? AND event_type = 'run.started'
                    """,
                    (run_id,),
                ).fetchone()
                payload = json.loads(row["payload_json"])
                payload["skill_selection_attestation"]["selected"][0][
                    "selection_reason"
                ] = "untrusted-free-form-reason"
                connection.execute(
                    """
                    UPDATE harness_events
                    SET payload_json = ?
                    WHERE run_id = ? AND event_type = 'run.started'
                    """,
                    (harness.canonical_json(payload), run_id),
                )
                connection.commit()

            report = evaluator.evaluate_database(database, run_id)

            attestation = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertFalse(attestation["valid"])
            self.assertFalse(attestation["mandatory_ready"])
            self.assertIn(
                "selected skill selection reason is invalid",
                attestation["errors"],
            )


    def test_version_zero_skill_registry_is_never_evaluation_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(
                database,
                skill_registry_version=0,
            )

            report = evaluator.evaluate_database(database, run_id)

            attestation = report["runs"][0][
                "skill_selection_attestation"
            ]
            self.assertTrue(attestation["present"])
            self.assertTrue(attestation["valid"])
            self.assertFalse(attestation["available"])
            self.assertFalse(attestation["mandatory_ready"])
            self.assertEqual(attestation["registry_version"], 0)
            self.assertEqual(attestation["advisory_mode"], "unavailable")
            self.assertEqual(
                report["skill_selection_attestation"][
                    "mandatory_ready_run_count"
                ],
                0,
            )
            self.assertEqual(
                report["skill_selection_attestation"][
                    "unavailable_run_count"
                ],
                1,
            )


    def test_exact_reviewer_validation_repair_completes_one_purpose(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            policy = harness.HarnessPolicy.from_dict(
                {
                    "schema": harness.POLICY_SCHEMA,
                    "version": "reviewer-repair-test",
                    "enabled": True,
                    "mode": "shadow",
                    "budgets": dict(harness.DEFAULT_BUDGETS),
                    "role_capabilities": {
                        role: sorted(capabilities)
                        for role, capabilities
                        in harness.DEFAULT_ROLE_CAPABILITIES.items()
                    },
                    "approval_required": [],
                    "memory": {
                        "require_independent_agreement": True,
                        "shared_requires_human_approval": True,
                    },
                }
            )
            primary_route = "codex-cli:gpt-5.5:high"
            reviewer_route = "codex-cli:gpt-5.6-sol:xhigh"
            prompt = {
                "alert": {"alert_id": "reviewer-repair-alert"},
                "evidence_reference_contract": {"references": []},
            }
            envelope = harness.JobEnvelope.from_prompt(
                run_id="reviewer-repair-run",
                prompt_package=prompt,
                role=harness.AgentRole.SOC_ANALYST.value,
                assigned_route=primary_route,
                configuration={"reviewer_route": reviewer_route},
                source_revision="1" * 40,
                policy_version="reviewer-repair-test",
            )
            run = harness.HarnessRun(
                harness.HarnessStore(database),
                envelope,
                policy,
            )
            primary_response = {
                "_analysis_model": "gpt-5.5",
                "_analysis_model_path": "frontier-codex-cli",
                "_analysis_provider": "codex-cli",
                "_analysis_model_route": primary_route,
            }
            run.preflight_model_call(
                call_id="primary-initial",
                input_value=prompt,
                requested_route=primary_route,
                purpose="initial primary analysis",
            )
            run.model_call(
                call_id="primary-initial",
                purpose="initial primary analysis",
                requested_route=primary_route,
                response=primary_response,
                input_value=prompt,
                duration_seconds=0.1,
            )
            run.record_response(
                {
                    "detection_outcome": "inconclusive",
                    "confidence": "medium",
                    "confidence_score": 0.5,
                },
                decision_id="primary",
                decision_type="primary-analysis",
                hypothesis_revision=1,
            )
            reviewer_response = {
                "_analysis_model": "gpt-5.6-sol",
                "_analysis_model_path": "frontier-codex-cli",
                "_analysis_provider": "codex-cli",
                "_analysis_model_route": reviewer_route,
            }
            for attempt, status in (
                (1, "validation-failed"),
                (2, "completed"),
            ):
                call_id = f"independent-review-{attempt}"
                run.preflight_model_call(
                    call_id=call_id,
                    input_value=prompt,
                    requested_route=reviewer_route,
                    purpose=evaluator.REVIEWER_REPAIR_PURPOSE,
                    independent_review=True,
                )
                run.model_call(
                    call_id=call_id,
                    purpose=evaluator.REVIEWER_REPAIR_PURPOSE,
                    requested_route=reviewer_route,
                    response=reviewer_response,
                    input_value=prompt,
                    duration_seconds=0.1,
                    independent_review=True,
                    status=status,
                )
            run.record_response(
                {
                    "detection_outcome": "inconclusive",
                    "confidence": "medium",
                    "confidence_score": 0.5,
                },
                decision_id="independent-review",
                decision_type="independent-review",
                hypothesis_revision=1,
            )
            run.complete(check_budget=False)

            report = evaluator.evaluate_database(database, run.run_id)
            models = report["runs"][0]["models"]

            self.assertEqual(models["successful_call_count"], 2)
            self.assertEqual(models["purpose_count"], 2)
            self.assertEqual(
                models["terminally_successful_purpose_count"],
                2,
            )
            self.assertEqual(models["incomplete_purpose_count"], 0)
            self.assertEqual(models["exact_reviewer_repair_count"], 1)
            self.assertEqual(
                models["superseded_validation_failure_count"],
                1,
            )
            self.assertEqual(
                models["unexpected_unsuccessful_call_count"],
                0,
            )
            self.assertEqual(
                models["malformed_purpose_sequence_count"],
                0,
            )
            classifications = {
                item["call_id"]: item["classification"]
                for item in models["call_status_classifications"]
            }
            self.assertEqual(
                classifications["independent-review-1"],
                "superseded-validation-failure",
            )
            self.assertEqual(
                classifications["independent-review-2"],
                "successful",
            )
            self.assertNotIn(
                "model-purpose-incomplete",
                report["runs"][0]["coverage_gap_reasons"],
            )
            self.assertTrue(
                report["runs"][0]["reviewer"][
                    "completion_contract_satisfied"
                ]
            )
            self.assertEqual(
                report["models"]["exact_reviewer_repair_count"],
                1,
            )
            self.assertTrue(report["runs"][0]["integrity"]["valid"])


