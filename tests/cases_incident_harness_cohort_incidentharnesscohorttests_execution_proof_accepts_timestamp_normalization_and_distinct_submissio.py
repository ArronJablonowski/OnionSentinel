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

class IncidentHarnessCohortTestsExecutionProofAcceptsTimestampNormalizationAndDistinctSubmissioCases:
    def test_execution_proof_accepts_timestamp_normalization_and_distinct_submission_digest(
        self,
    ) -> None:
        analysis_id = "analysis-normalized-timestamp"
        response_digest = "a" * 64
        submitted_digest = "b" * 64
        member = {
            "rank": 1,
            "dashboard_group_id": self.dashboard_a,
            "stable_group_id": self.stable_one,
            "representative_alert_id": "alert-a-newest",
            "pre_state": {"soc_analysis_ids": []},
            "dispatch": {
                "kind": "analyze",
                "state": "accepted",
                "attempt_count": 1,
                "started_at": "2026-07-25  23:00:00.000-06:00",
            },
        }
        manifest = {
            "agent_role": "soc-analyst",
            "execution_contract": cohort.execution_contract(
                expected_release_id=self.release_id,
                expected_assigned_route=(
                    "codex-cli:gpt-5.5:high"
                ),
                expected_reviewer_route=(
                    "codex-cli:gpt-5.6-sol:xhigh"
                ),
            ),
        }
        tool_call_bindings = [
            {
                "call_id": "round-1-soc-proof-pivot",
                "round_number": 1,
                "query_id": "soc-proof-pivot",
                "backend": "elastic",
                "status": "ok",
                "request_digest": "d" * 64,
                "result_digest": "e" * 64,
                "read_only": True,
            }
        ]
        monitor = {
            "state": "completed",
            "analysis_id": analysis_id,
            "analysis": {
                "analysis_id": analysis_id,
                "agent_role": "soc-analyst",
                "generated_at": "2026-07-25  23:02:35.980-06:00",
                "response_canonical_sha256": response_digest,
                "result": {
                    "_analysis_model_route": (
                        "codex-cli:gpt-5.5:high"
                    ),
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
                },
                "query_audit": {
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
                        "queries": [
                            {
                                "query_id": "soc-proof-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                                "result_digest": "e" * 64,
                                "returned_hits": 1,
                            }
                        ],
                        "round_results": [
                            {
                                "query_id": "soc-proof-pivot",
                                "backend": "elastic",
                                "status": "ok",
                                "query_digest": "f" * 64,
                            }
                        ],
                        "tool_call_bindings": tool_call_bindings,
                    }
                },
            },
        }
        zero_routes = {
            "contract_available": True,
            "authorization_failure_count": 0,
            "authorization_denied_event_count": 0,
            "authorization_malformed_event_count": 0,
            "authorization_orphan_event_count": 0,
            "authorization_unverified_call_count": 0,
            "observation_denied_event_count": 0,
            "observation_malformed_event_count": 0,
            "observation_orphan_event_count": 0,
            "identity_mismatch_count": 0,
            "identity_unverified_call_count": 0,
        }
        model_call_facts = [
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
        trace_report = {
            "runs": [
                {
                    "run_id": analysis_id,
                    "trace_id": "trace-normalized",
                    "correlation_id": self.stable_one,
                    "alert_id": "alert-a-newest",
                    "role": "soc-analyst",
                    "task_kind": "reanalysis",
                    "status": "succeeded",
                    "stage": "complete",
                    "assigned_route": "codex-cli:gpt-5.5:high",
                    "assigned_reviewer_route": (
                        "codex-cli:gpt-5.6-sol:xhigh"
                    ),
                    "policy_mode": "shadow",
                    "started_at": "2026-07-25  23:00:01.000-06:00",
                    "completed_at": "2026-07-25  23:03:00.000-06:00",
                    "terminal_execution_summary": {
                        "analysis_id": analysis_id,
                        "submitted_response_sha256": submitted_digest,
                        "stored_response_sha256": response_digest,
                        "evaluation_memory_frozen": True,
                    },
                    "skill_selection_attestation": {
                        "present": True,
                        "legacy": False,
                        "valid": True,
                        "available": True,
                        "job_digest_bound": True,
                        "mandatory_ready": True,
                        "registry_version": 1,
                        "registry_sha256": "9" * 64,
                        "selected": [
                            {
                                "id": "suricata-detection-validation",
                                "version": 3,
                                "skill_sha256": "8" * 64,
                            }
                        ],
                        "selected_count": 1,
                        "truncated": False,
                        "advisory_mode": "advisory_only",
                        "error_count": 0,
                        "errors": [],
                    },
                    "integrity": {
                        "valid": True,
                        "head_sha256": "c" * 64,
                        "ledger_manifest_bound": True,
                        "ledger_manifest_schema": (
                            "onion-sentinel-harness-ledger-manifest-v2"
                        ),
                    },
                    "counts": {"model_calls": 2, "tool_calls": 1},
                    "models": {
                        "successful_call_count": 2,
                        "successful_primary_call_count": 1,
                        "purpose_count": 2,
                        "terminally_successful_purpose_count": 2,
                        "incomplete_purpose_count": 0,
                        "exact_reviewer_repair_count": 0,
                        "superseded_validation_failure_count": 0,
                        "unexpected_unsuccessful_call_count": 0,
                        "malformed_purpose_sequence_count": 0,
                        "model_call_contract": {
                            "schema": (
                                "onion-sentinel-model-call-contract-v1"
                            ),
                            "valid": True,
                            "model_call_count": 2,
                            "canonical_model_call_count": 2,
                            "noncanonical_model_call_count": 0,
                            "primary_initial_call_count": 1,
                            "query_planning_call_count": 0,
                            "primary_followup_call_count": 0,
                            "reviewer_model_call_count": 1,
                            "facts": model_call_facts,
                            "facts_sha256": cohort.sha256_value(
                                model_call_facts
                            ),
                            "violation_count": 0,
                            "violations": [],
                            "global_reasons": [],
                        },
                        "route_consistency": zero_routes,
                    },
                    "reviewer": {
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
                    "tools": {
                        "successful_call_count": 1,
                        "read_only_call_count": 1,
                        "read_only_violation_count": 0,
                        "successful_read_only_call_bindings": (
                            tool_call_bindings
                        ),
                        "successful_read_only_call_bindings_sha256": (
                            cohort.sha256_value(tool_call_bindings)
                        ),
                    },
                }
            ],
            "data_quality": {"malformed_json_counts": {}},
        }
        fake_evaluator = type(
            "FakeTraceEvaluator",
            (),
            {"evaluate_database": staticmethod(lambda _path, _run: trace_report)},
        )

        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            proof = cohort._harness_execution_proof(
                harness_database_path=self.root / "synthetic-harness.sqlite3",
                manifest=manifest,
                member=member,
                monitor=monitor,
            )

        self.assertEqual(proof["status"], "passed")
        self.assertEqual(
            proof["harness"]["submitted_response_sha256"],
            submitted_digest,
        )
        self.assertNotEqual(submitted_digest, response_digest)
        self.assertEqual(proof["harness"]["tool_call_count"], 1)
        self.assertEqual(
            proof["harness"]["successful_tool_call_count"],
            1,
        )
        self.assertTrue(
            proof["harness"][
                "skill_selection_attestation_validated"
            ]
        )
        self.assertEqual(
            proof["harness"]["skill_selection_attestation"],
            {
                "registry_version": 1,
                "registry_sha256": "9" * 64,
                "selected": [
                    {
                        "id": "suricata-detection-validation",
                        "version": 3,
                        "skill_sha256": "8" * 64,
                    }
                ],
                "selected_count": 1,
                "truncated": False,
                "advisory_mode": "advisory_only",
            },
        )

        trace = trace_report["runs"][0]
        trace["skill_selection_attestation"]["mandatory_ready"] = False
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-skill-selection-attestation-invalid",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["skill_selection_attestation"]["mandatory_ready"] = True
        trace["skill_selection_attestation"]["registry_version"] = 0
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-skill-selection-attestation-invalid",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["skill_selection_attestation"]["registry_version"] = 1
        trace["counts"]["model_calls"] = 1
        trace["models"].update(
            {
                "successful_call_count": 1,
                "purpose_count": 1,
                "terminally_successful_purpose_count": 1,
            }
        )
        trace["models"]["model_call_contract"].update(
            {
                "model_call_count": 1,
                "canonical_model_call_count": 1,
                "reviewer_model_call_count": 0,
                "facts": model_call_facts[:1],
                "facts_sha256": cohort.sha256_value(
                    model_call_facts[:1]
                ),
            }
        )
        trace["reviewer"].update(
            {
                "model_call_count": 0,
                "completed_model_call_count": 0,
                "reviewer_decision_count": 0,
                "has_reviewer_decision": False,
                "decision_comparable": False,
                "missing_reviewer_decision": False,
                "completion_contract_required": False,
                "completion_contract_satisfied": True,
            }
        )
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-required-reviewer-call-missing",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )

        trace["counts"]["model_calls"] = 3
        trace["models"].update(
            {
                "successful_call_count": 2,
                "purpose_count": 2,
                "terminally_successful_purpose_count": 2,
                "exact_reviewer_repair_count": 1,
                "superseded_validation_failure_count": 1,
            }
        )
        trace["reviewer"]["model_call_count"] = 2
        trace["reviewer"].update(
            {
                "completed_model_call_count": 1,
                "reviewer_decision_count": 1,
                "has_reviewer_decision": True,
                "decision_comparable": True,
                "completion_contract_required": True,
                "completion_contract_satisfied": True,
            }
        )
        trace["models"]["model_call_contract"].update(
            {
                "model_call_count": 3,
                "canonical_model_call_count": 3,
                "reviewer_model_call_count": 2,
            }
        )
        repaired_facts = [
            model_call_facts[0],
            {
                **model_call_facts[1],
                "status": "validation-failed",
            },
            {
                **model_call_facts[1],
                "call_id": "independent-review-2",
            },
        ]
        trace["models"]["model_call_contract"]["facts"] = repaired_facts
        trace["models"]["model_call_contract"]["facts_sha256"] = (
            cohort.sha256_value(repaired_facts)
        )
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            repaired_proof = cohort._harness_execution_proof(
                harness_database_path=self.root / "synthetic-harness.sqlite3",
                manifest=manifest,
                member=member,
                monitor=monitor,
            )
        self.assertEqual(
            repaired_proof["harness"][
                "superseded_validation_failure_count"
            ],
            1,
        )

        trace["reviewer"]["decision_comparable"] = False
        trace["reviewer"]["completion_contract_satisfied"] = False
        trace["reviewer"]["completion_contract_failure_reasons"] = [
            "reviewer-decision-not-comparable"
        ]
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-reviewer-completion-incomplete",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["reviewer"]["decision_comparable"] = True
        trace["reviewer"]["completion_contract_satisfied"] = True
        trace["reviewer"]["completion_contract_failure_reasons"] = []

        trace["models"]["model_call_contract"]["valid"] = False
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-model-call-contract-noncanonical",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["models"]["model_call_contract"]["valid"] = True

        trace["models"]["unexpected_unsuccessful_call_count"] = 1
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-model-purpose-incomplete",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )
        trace["models"]["unexpected_unsuccessful_call_count"] = 0

        trace_report["runs"][0]["counts"]["tool_calls"] = 0
        trace_report["runs"][0]["tools"]["successful_call_count"] = 0
        trace_report["runs"][0]["tools"]["read_only_call_count"] = 0
        with mock.patch.object(
            cohort,
            "_load_trace_evaluator",
            return_value=fake_evaluator,
        ):
            with self.assertRaisesRegex(
                cohort.CohortError,
                "harness-tool-call-ledger-missing",
            ):
                cohort._harness_execution_proof(
                    harness_database_path=(
                        self.root / "synthetic-harness.sqlite3"
                    ),
                    manifest=manifest,
                    member=member,
                    monitor=monitor,
                )


