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

class HarnessTraceEvaluatorTestsModelPurposeCompletionRejectsMalformedRetryPatternsCases:
    def test_model_purpose_completion_rejects_malformed_retry_patterns(self):
        reviewer = {"has_reviewer_decision": True}

        def call(
            call_id,
            status,
            *,
            purpose=evaluator.REVIEWER_REPAIR_PURPOSE,
            independent_review=1,
            created_at="2026-07-25T00:00:20Z",
        ):
            return {
                "call_id": call_id,
                "purpose": purpose,
                "requested_route": "codex-cli:gpt-5.6-sol:xhigh",
                "independent_review": independent_review,
                "status": status,
                "created_at": created_at,
            }

        accepted_single = evaluator.model_purpose_completion(
            [call("independent-review-1", "completed")],
            reviewer,
        )
        self.assertEqual(
            accepted_single["terminally_successful_purpose_count"],
            1,
        )
        self.assertEqual(
            accepted_single["malformed_purpose_sequence_count"],
            0,
        )

        malformed_cases = {
            "lone-validation-failure": [
                call("independent-review-1", "validation-failed"),
            ],
            "runtime-failure-then-success": [
                call("independent-review-1", "failed:RuntimeError"),
                call(
                    "independent-review-2",
                    "completed",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            "three-attempts": [
                call("independent-review-1", "validation-failed"),
                call(
                    "independent-review-2",
                    "validation-failed",
                    created_at="2026-07-25T00:00:30Z",
                ),
                call(
                    "independent-review-3",
                    "completed",
                    created_at="2026-07-25T00:00:40Z",
                ),
            ],
            "wrong-purpose": [
                call(
                    "independent-review-1",
                    "validation-failed",
                    purpose="renamed reviewer purpose",
                ),
                call(
                    "independent-review-2",
                    "completed",
                    purpose="renamed reviewer purpose",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            "success-then-validation-failure": [
                call("independent-review-1", "completed"),
                call(
                    "independent-review-2",
                    "validation-failed",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            "renamed-single-reviewer": [
                call(
                    "renamed-review-call",
                    "completed",
                    purpose="renamed reviewer purpose",
                ),
            ],
            "empty-primary-purpose": [
                call(
                    "primary-empty-purpose",
                    "completed",
                    purpose="",
                    independent_review=0,
                ),
            ],
        }
        for label, calls in malformed_cases.items():
            with self.subTest(label=label):
                result = evaluator.model_purpose_completion(
                    calls,
                    reviewer,
                )
                self.assertEqual(result["exact_reviewer_repair_count"], 0)
                self.assertGreater(
                    result["malformed_purpose_sequence_count"],
                    0,
                )
                if label not in {
                    "renamed-single-reviewer",
                    "empty-primary-purpose",
                }:
                    self.assertGreater(
                        result["unexpected_unsuccessful_call_count"],
                        0,
                    )

        missing_decision = evaluator.model_purpose_completion(
            [
                call("independent-review-1", "validation-failed"),
                call(
                    "independent-review-2",
                    "completed",
                    created_at="2026-07-25T00:00:30Z",
                ),
            ],
            {"has_reviewer_decision": False},
        )
        self.assertEqual(missing_decision["exact_reviewer_repair_count"], 0)
        self.assertEqual(
            missing_decision["malformed_purpose_sequence_count"],
            1,
        )
        self.assertEqual(
            missing_decision["unexpected_unsuccessful_call_count"],
            1,
        )


    def test_model_call_contract_is_closed_and_reviewer_is_conditional(self):
        primary = {
            "call_id": "primary-initial",
            "purpose": evaluator.PRIMARY_INITIAL_PURPOSE,
            "requested_route": "codex-cli:gpt-5.5:high",
            "independent_review": 0,
            "status": "completed",
            "created_at": "2026-07-25T00:00:10Z",
        }
        contract = evaluator.canonical_model_call_contract([primary])
        self.assertTrue(contract["valid"])
        self.assertEqual(contract["canonical_model_call_count"], 1)
        no_reviewer = {
            "model_call_count": 0,
            "completed_model_call_count": 0,
            "primary_decision_count": 1,
            "reviewer_decision_count": 0,
            "has_primary_decision": True,
            "has_reviewer_decision": False,
            "decision_comparable": False,
            "missing_reviewer_decision": False,
        }
        completion = evaluator.reviewer_completion_contract(
            no_reviewer,
            {"exact_reviewer_repair_count": 0},
        )
        self.assertFalse(completion["completion_contract_required"])
        self.assertTrue(completion["completion_contract_satisfied"])

        for field, value in (
            ("call_id", "invented-call"),
            ("purpose", "renamed purpose"),
            ("status", "success"),
        ):
            with self.subTest(field=field):
                changed = dict(primary)
                changed[field] = value
                rejected = evaluator.canonical_model_call_contract([changed])
                self.assertFalse(rejected["valid"])
                self.assertEqual(
                    rejected["noncanonical_model_call_count"],
                    1,
                )

        incomplete_reviewer = {
            **no_reviewer,
            "model_call_count": 1,
            "completed_model_call_count": 1,
            "reviewer_decision_count": 1,
            "has_reviewer_decision": True,
            "decision_comparable": False,
        }
        completion = evaluator.reviewer_completion_contract(
            incomplete_reviewer,
            {"exact_reviewer_repair_count": 0},
        )
        self.assertTrue(completion["completion_contract_required"])
        self.assertFalse(completion["completion_contract_satisfied"])


    def test_adjudication_is_canonical_but_not_a_second_reviewer(self):
        route = "codex-cli:gpt-5.6-sol:xhigh"
        reviewer_call = {
            "call_id": "independent-review-1",
            "purpose": evaluator.REVIEWER_REPAIR_PURPOSE,
            "requested_route": route,
            "independent_review": 1,
            "status": "completed",
            "created_at": "2026-07-25T00:00:20Z",
        }
        adjudication_call = {
            "call_id": "disagreement-adjudication-1",
            "purpose": evaluator.ADJUDICATION_PURPOSE,
            "requested_route": route,
            "independent_review": 1,
            "status": "completed",
            "created_at": "2026-07-25T00:00:30Z",
        }
        contract = evaluator.canonical_model_call_contract(
            [reviewer_call, adjudication_call]
        )
        self.assertFalse(contract["valid"])
        self.assertEqual(contract["noncanonical_model_call_count"], 0)
        self.assertIn(
            "primary-initial-count-not-one", contract["global_reasons"]
        )
        primary_call = {
            "call_id": evaluator.PRIMARY_INITIAL_CALL_ID,
            "purpose": evaluator.PRIMARY_INITIAL_PURPOSE,
            "requested_route": "codex-cli:gpt-5.5:high",
            "independent_review": 0,
            "status": "completed",
            "created_at": "2026-07-25T00:00:10Z",
        }
        complete_contract = evaluator.canonical_model_call_contract(
            [primary_call, reviewer_call, adjudication_call]
        )
        self.assertTrue(complete_contract["valid"])
        self.assertEqual(
            complete_contract["noncanonical_model_call_count"], 0
        )

        purpose = evaluator.model_purpose_completion(
            [reviewer_call, adjudication_call],
            {"has_reviewer_decision": True},
        )
        self.assertEqual(purpose["malformed_purpose_sequence_count"], 0)
        self.assertEqual(purpose["exact_reviewer_repair_count"], 0)
        self.assertEqual(purpose["exact_adjudication_repair_count"], 0)

        decisions = [
            {
                "decision_id": "primary",
                "decision_type": "primary-analysis",
                "payload_json": json.dumps(
                    {"detection_outcome": "inconclusive"}
                ),
            },
            {
                "decision_id": "independent-review",
                "decision_type": "independent-review",
                "payload_json": json.dumps(
                    {"detection_outcome": "informational_no_action"}
                ),
            },
        ]
        reviewer = evaluator.reviewer_result(
            [reviewer_call, adjudication_call], decisions, collections.Counter()
        )
        self.assertEqual(reviewer["model_call_count"], 1)
        completion = evaluator.reviewer_completion_contract(
            reviewer, purpose
        )
        self.assertTrue(completion["completion_contract_satisfied"])


    def test_supplemental_reviewer_call_is_bounded_and_canonical(self):
        primary_route = "codex-cli:gpt-5.5:high"
        reviewer_route = "codex-cli:gpt-5.6-sol:xhigh"
        calls = [
            {
                "call_id": evaluator.PRIMARY_INITIAL_CALL_ID,
                "purpose": evaluator.PRIMARY_INITIAL_PURPOSE,
                "requested_route": primary_route,
                "independent_review": 0,
                "status": "completed",
                "created_at": "2026-07-25T00:00:10Z",
            },
            {
                "call_id": "independent-review-1",
                "purpose": evaluator.REVIEWER_REPAIR_PURPOSE,
                "requested_route": reviewer_route,
                "independent_review": 1,
                "status": "completed",
                "created_at": "2026-07-25T00:00:20Z",
            },
            {
                "call_id": evaluator.SUPPLEMENTAL_REVIEW_CALL_ID,
                "purpose": evaluator.SUPPLEMENTAL_REVIEW_PURPOSE,
                "requested_route": reviewer_route,
                "independent_review": 1,
                "status": "completed",
                "created_at": "2026-07-25T00:00:30Z",
            },
        ]
        contract = evaluator.canonical_model_call_contract(calls)

        self.assertTrue(contract["valid"])
        self.assertEqual(contract["reviewer_model_call_count"], 2)
        self.assertEqual(contract["adjudicator_model_call_count"], 0)

        decisions = [
            {
                "decision_id": "primary",
                "decision_type": "primary-analysis",
                "payload_json": json.dumps(
                    {"detection_outcome": "inconclusive"}
                ),
            },
            {
                "decision_id": "independent-review",
                "decision_type": "independent-review",
                "payload_json": json.dumps(
                    {"detection_outcome": "informational_no_action"}
                ),
            },
        ]
        reviewer = evaluator.reviewer_result(
            calls, decisions, collections.Counter()
        )
        self.assertEqual(reviewer["model_call_count"], 2)
        self.assertEqual(reviewer["supplemental_model_call_count"], 1)
        purpose = evaluator.model_purpose_completion(calls, reviewer)
        completion = evaluator.reviewer_completion_contract(
            reviewer, purpose
        )
        self.assertTrue(completion["completion_contract_satisfied"])


    def test_model_call_contract_treats_planning_repair_as_followup_round(
        self,
    ):
        route = "codex-cli:gpt-5.5:high"

        def model_call(
            call_id: str,
            purpose: str,
            *,
            second: int,
            independent_review: int = 0,
            status: str = "completed",
        ) -> dict:
            return {
                "call_id": call_id,
                "purpose": purpose,
                "requested_route": route,
                "independent_review": independent_review,
                "status": status,
                "created_at": f"2026-07-25T00:00:{second:02d}Z",
            }

        initial = model_call(
            evaluator.PRIMARY_INITIAL_CALL_ID,
            evaluator.PRIMARY_INITIAL_PURPOSE,
            second=1,
        )
        repair = model_call(
            evaluator.QUERY_PLANNING_REPAIR_CALL_ID,
            evaluator.QUERY_PLANNING_REPAIR_PURPOSE,
            second=2,
        )
        followup_two = model_call(
            "primary-followup-2",
            "primary investigation follow-up round 2",
            second=3,
        )
        contract = evaluator.canonical_model_call_contract(
            [initial, repair, followup_two]
        )
        self.assertTrue(contract["valid"])
        self.assertEqual(contract["query_planning_repair_call_count"], 1)
        self.assertEqual(contract["primary_followup_call_count"], 1)
        self.assertEqual(contract["canonical_model_call_count"], 3)

        invalid_sequences = {
            "missing-repair-slot": [
                initial,
                followup_two,
            ],
            "reuses-repair-slot": [
                initial,
                repair,
                model_call(
                    "primary-followup-1",
                    "primary investigation follow-up round 1",
                    second=3,
                ),
            ],
            "skips-after-repair": [
                initial,
                repair,
                model_call(
                    "primary-followup-3",
                    "primary investigation follow-up round 3",
                    second=3,
                ),
            ],
            "duplicate-repair": [
                initial,
                repair,
                model_call(
                    evaluator.QUERY_PLANNING_REPAIR_CALL_ID,
                    evaluator.QUERY_PLANNING_REPAIR_PURPOSE,
                    second=3,
                ),
            ],
            "wrong-repair-purpose": [
                initial,
                {
                    **repair,
                    "purpose": "unbounded query repair",
                },
                followup_two,
            ],
        }
        for label, calls in invalid_sequences.items():
            with self.subTest(label=label):
                rejected = evaluator.canonical_model_call_contract(calls)
                self.assertFalse(rejected["valid"])
                self.assertGreater(rejected["violation_count"], 0)


    def test_run_filter_unknown_run_and_private_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "harness.sqlite3"
            output = root / "reports" / "evaluation.json"
            create_trace_database(database)

            report = evaluator.evaluate_database(database, "run-1")
            evaluator.atomic_private_json(output, report)

            self.assertEqual(report["selected_run_id"], "run-1")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8"))["schema"],
                evaluator.REPORT_SCHEMA,
            )
            with self.assertRaisesRegex(evaluator.EvaluationError, "unknown"):
                evaluator.evaluate_database(database, "run-missing")


    def test_detects_tampered_chain_and_optional_failure_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            create_trace_database(database)
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE harness_events SET payload_json = '{"tampered":true}'
                    WHERE run_id = 'run-1' AND sequence = 2
                    """
                )
                connection.commit()

            report = evaluator.evaluate_database(database)

            self.assertFalse(report["integrity"]["all_chains_valid"])
            self.assertEqual(report["integrity"]["invalid_run_ids"], ["run-1"])
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = evaluator.main(
                    [
                        "--db",
                        str(database),
                        "--fail-on-invalid-chain",
                    ]
                )
            self.assertEqual(exit_code, 1)


    def test_read_only_evaluator_detects_terminal_ledger_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(database)

            report = evaluator.evaluate_database(database, run_id)
            self.assertTrue(report["integrity"]["all_chains_valid"])
            self.assertTrue(
                report["runs"][0]["integrity"]["ledger_manifest_bound"]
            )

            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE harness_evidence
                    SET status = 'tampered-after-completion'
                    WHERE run_id = ? AND evidence_ref = 'alert:ledger-1'
                    """,
                    (run_id,),
                )
                connection.commit()
            before_digest = hashlib.sha256(database.read_bytes()).hexdigest()
            before_mtime = database.stat().st_mtime_ns

            report = evaluator.evaluate_database(database, run_id)

            self.assertFalse(report["integrity"]["all_chains_valid"])
            self.assertEqual(report["integrity"]["invalid_run_ids"], [run_id])
            self.assertIn(
                "terminal ledger manifest mismatch",
                report["runs"][0]["integrity"]["errors"],
            )
            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                before_digest,
            )
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)


    def test_current_terminal_manifest_is_mandatory_and_legacy_is_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            run_id = create_terminal_harness_database(database)

            with harness._connect(database) as connection:
                legacy_manifest = harness.ledger_manifest(
                    connection,
                    run_id,
                    schema=harness.LEDGER_MANIFEST_SCHEMA_V1,
                )
                legacy_v2_manifest = harness.ledger_manifest(
                    connection,
                    run_id,
                    schema=harness.LEDGER_MANIFEST_SCHEMA_V2,
                )

            replace_terminal_manifest(
                database,
                run_id,
                legacy_manifest,
                legacy_identity="reviewer-only",
            )
            report = evaluator.evaluate_database(database, run_id)
            self.assertIn(
                "terminal ledger manifest schema downgrade",
                report["runs"][0]["integrity"]["errors"],
            )

            replace_terminal_manifest(
                database,
                run_id,
                legacy_manifest,
                legacy_identity=True,
            )
            report = evaluator.evaluate_database(database, run_id)
            integrity = report["runs"][0]["integrity"]
            self.assertTrue(integrity["valid"])
            self.assertTrue(integrity["ledger_manifest_required"])
            self.assertEqual(
                integrity["ledger_manifest_schema"],
                evaluator.LEDGER_MANIFEST_SCHEMA_V1,
            )

            replace_terminal_manifest(
                database,
                run_id,
                legacy_v2_manifest,
                legacy_identity="v2",
            )
            report = evaluator.evaluate_database(database, run_id)
            integrity = report["runs"][0]["integrity"]
            self.assertTrue(integrity["valid"])
            self.assertEqual(
                integrity["ledger_manifest_schema"],
                evaluator.LEDGER_MANIFEST_SCHEMA_V2,
            )

            replace_terminal_manifest(database, run_id, None)
            report = evaluator.evaluate_database(database, run_id)
            integrity = report["runs"][0]["integrity"]
            self.assertFalse(integrity["valid"])
            self.assertFalse(integrity["ledger_manifest_bound"])
            self.assertIn(
                "terminal ledger manifest is missing or malformed",
                integrity["errors"],
            )


    def test_rejects_future_database_schema_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            create_terminal_harness_database(database)
            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute(
                    """
                    UPDATE harness_metadata
                    SET value = ?
                    WHERE key = 'schema_version'
                    """,
                    (str(evaluator.CURRENT_SQL_SCHEMA_VERSION + 1),),
                )
                connection.commit()
            before_digest = hashlib.sha256(database.read_bytes()).hexdigest()
            before_mtime = database.stat().st_mtime_ns

            with self.assertRaisesRegex(
                evaluator.EvaluationError,
                "newer runtime",
            ):
                evaluator.evaluate_database(database)

            self.assertEqual(
                hashlib.sha256(database.read_bytes()).hexdigest(),
                before_digest,
            )
            self.assertEqual(database.stat().st_mtime_ns, before_mtime)


    def test_reports_route_authorization_and_observed_identity_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "harness.sqlite3"
            policy = harness.HarnessPolicy.from_dict(
                {
                    "schema": harness.POLICY_SCHEMA,
                    "version": "route-audit-test",
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
            prompt = {
                "alert": {"alert_id": "route-audit-alert"},
                "evidence_reference_contract": {"references": []},
            }
            route = "codex-cli:gpt-5.6-sol:high"
            envelope = harness.JobEnvelope.from_prompt(
                run_id="route-audit-run",
                prompt_package=prompt,
                role=harness.AgentRole.SOC_ANALYST.value,
                assigned_route=route,
                configuration={
                    "reviewer_route": "codex-cli:gpt-5.6-terra:high"
                },
                source_revision="1" * 40,
                policy_version="route-audit-test",
            )
            run = harness.HarnessRun(
                harness.HarnessStore(database),
                envelope,
                policy,
            )
            run.preflight_model_call(
                call_id="authorized-wrong-runtime",
                input_value={"case": "route-audit"},
                requested_route=route,
                purpose="authorized model call",
            )
            run.model_call(
                call_id="authorized-wrong-runtime",
                purpose="authorized model call",
                requested_route=route,
                response={
                    "_analysis_model": "gemma4:31b",
                    "_analysis_model_path": "ollama",
                    "_analysis_provider": "ollama",
                    "_analysis_model_route": "ollama:gemma4:31b",
                },
                input_value={"case": "route-audit"},
                duration_seconds=0.1,
                status="validation-failed",
            )
            run.model_call(
                call_id="missing-authorization",
                purpose="direct model call",
                requested_route=route,
                response={
                    "_analysis_model": "gpt-5.6-sol",
                    "_analysis_model_path": "frontier-codex-cli",
                    "_analysis_provider": "codex-cli",
                    "_analysis_model_route": route,
                },
                input_value={"case": "route-audit"},
                duration_seconds=0.1,
            )
            run.complete(check_budget=False)

            report = evaluator.evaluate_database(database, run.run_id)
            route_metrics = report["runs"][0]["models"][
                "route_consistency"
            ]
            self.assertEqual(route_metrics["authorized_call_count"], 1)
            self.assertEqual(
                route_metrics["authorization_failure_count"],
                1,
            )
            self.assertEqual(
                route_metrics["authorization_failures"][0]["call_id"],
                "missing-authorization",
            )
            self.assertIn(
                "authorization-event-missing",
                route_metrics["authorization_failures"][0]["reasons"],
            )
            self.assertEqual(route_metrics["identity_mismatch_count"], 1)
            self.assertEqual(
                route_metrics["identity_failures"][0]["call_id"],
                "authorized-wrong-runtime",
            )
            self.assertEqual(
                report["models"]["route_authorization"]["failure_count"],
                1,
            )
            self.assertEqual(
                report["models"]["runtime_identity"]["mismatch_count"],
                1,
            )
            self.assertIn(
                "model-route-authorization-failure",
                report["runs"][0]["coverage_gap_reasons"],
            )
            self.assertIn(
                "model-runtime-identity-mismatch",
                report["runs"][0]["coverage_gap_reasons"],
            )
            self.assertTrue(report["runs"][0]["integrity"]["valid"])
