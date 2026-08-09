#!/usr/bin/env python3
"""Tests for the offline SOC/IR cohort accuracy evaluator."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "operations" / "evaluate-investigation-cohort.py"
SPEC = importlib.util.spec_from_file_location(
    "evaluate_investigation_cohort",
    MODULE_PATH,
)
assert SPEC and SPEC.loader
evaluator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evaluator)
import cohort_evaluation_query_audit  # noqa: E402
import cohort_evaluation_execution_contract  # noqa: E402
import cohort_evaluation_execution_proof  # noqa: E402
import cohort_evaluation_contracts  # noqa: E402
import cohort_evaluation_result_policy  # noqa: E402
import cohort_execution_result  # noqa: E402


class InvestigationCohortEvaluationTests(unittest.TestCase):
    def test_evaluator_uses_extracted_query_audit_services(self) -> None:
        self.assertIs(
            evaluator.evaluate_query_audit_binding,
            cohort_evaluation_query_audit.query_audit_execution_binding,
        )
        self.assertIs(
            evaluator.summarize_query_audit,
            cohort_evaluation_query_audit.query_audit_summary,
        )

    def test_evaluator_uses_extracted_execution_contract_services(self) -> None:
        self.assertIs(
            evaluator.validate_execution_contract,
            cohort_evaluation_execution_contract.validate_execution_contract,
        )
        self.assertIs(
            evaluator.collect_prior_analysis_ids,
            cohort_execution_result.prior_analysis_ids,
        )
        self.assertIs(
            evaluator.derive_expected_task_kind,
            cohort_execution_result.expected_task_kind,
        )

    def test_evaluator_uses_extracted_result_policy_services(self) -> None:
        self.assertIs(
            evaluator.validate_safe_export_content,
            cohort_evaluation_result_policy.validate_safe_export_content,
        )
        self.assertIs(
            evaluator.normalize_observed_labels,
            cohort_evaluation_result_policy.observed_labels,
        )

    def test_evaluator_uses_execution_proof_orchestrator(self) -> None:
        self.assertIs(
            evaluator.admit_execution_proof,
            cohort_evaluation_execution_proof.validate_execution_proof,
        )

    def test_evaluator_uses_canonical_evaluation_contracts(self) -> None:
        self.assertIs(
            evaluator.RUBRIC_WEIGHTS,
            cohort_evaluation_contracts.RUBRIC_WEIGHTS,
        )
        self.assertIs(
            evaluator.VERDICT_VALUE_SETS,
            cohort_evaluation_contracts.VERDICT_VALUE_SETS,
        )
        self.assertIs(
            evaluator.QUERY_CLASSES,
            cohort_evaluation_contracts.QUERY_CLASSES,
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-investigation-evaluation-"
        )
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.stable_ids = tuple(
            f"{rank:020x}"
            for rank in range(1, evaluator.EXPECTED_ROLE_COUNT + 1)
        )
        self.release_id = "a" * 40
        self.ir_path = self.root / "ir-export.json"
        self.soc_path = self.root / "soc-export.json"
        self.adjudication_path = self.root / "adjudication.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_private(self, path: Path, document: dict) -> None:
        path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.chmod(path, 0o600)

    def _labels(
        self,
        *,
        outcome: str = "true_positive_suspicious",
        handling: str = "investigate",
    ) -> dict:
        return {
            "detection_outcome": outcome,
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": handling,
            "duplicate_of": None,
        }

    def _score(self, total: float) -> dict[str, float]:
        score: dict[str, float] = {}
        remaining = float(total)
        for criterion, maximum in evaluator.RUBRIC_WEIGHTS.items():
            awarded = min(float(maximum), remaining)
            score[criterion] = awarded
            remaining -= awarded
        self.assertAlmostEqual(remaining, 0.0)
        return score

    def _result_export(
        self,
        role: str,
        cohort_id: str,
        *,
        expected_count: int = evaluator.EXPECTED_ROLE_COUNT,
        second_outcome: str = "true_positive_suspicious",
        second_read_only: bool = True,
        source_rows_sha256: str = "e" * 64,
        first_detection_rule: str | None = None,
        expected_route: str = "codex-cli:gpt-5.5:high",
        reviewer_route: str = "codex-cli:gpt-5.6-sol:xhigh",
        evaluation_profile: str = "",
    ) -> dict:
        members = []
        stable_ids = self.stable_ids[:expected_count]
        contract = {
            "harness_required": True,
            "harness_mode": "shadow",
            "memory_frozen": True,
            "expected_release_id": self.release_id,
            "expected_assigned_route": expected_route,
            "expected_reviewer_route": reviewer_route,
            "reviewer_required": True,
            "evaluation_profile": evaluation_profile,
        }
        for rank, stable_id in enumerate(stable_ids, start=1):
            stable_group_key = f"v2|fixture|{rank}"
            labels = self._labels(
                outcome=(
                    second_outcome
                    if rank == 2
                    else "true_positive_suspicious"
                )
            )
            analysis_id = f"analysis-{role}-{rank}"
            dispatch_kind = (
                "analyze" if role == "soc-analyst" else "escalate"
            )
            response_canonical_sha256 = f"{rank + 2:064x}"
            tool_call_bindings = [
                {
                    "call_id": f"round-1-pivot-{rank}",
                    "round_number": 1,
                    "query_id": f"pivot-{rank}",
                    "backend": "elastic",
                    "status": "ok",
                    "request_digest": f"{rank + 8:064x}",
                    "result_digest": "c" * 64,
                    "read_only": True,
                }
            ]
            query_audit = {
                "_investigation_query_audit": {
                    "read_only": True,
                    "complete": True,
                    "all_tool_call_bindings_read_only": True,
                    "evaluation_requirement_satisfied": True,
                    "partial": False,
                    "query_contract": (
                        "onion-sentinel-investigation-pivots-v2"
                    ),
                    "provider_neutral": True,
                    "rounds_completed": 1,
                    "queries_admitted": 1,
                    "successful_read_only_queries": 1,
                    "tool_call_bindings": tool_call_bindings,
                    "queries": [
                        {
                            "query_id": f"pivot-{rank}",
                            "backend": "elastic",
                            "status": "ok",
                            "query_digest": "b" * 64,
                            "result_digest": "c" * 64,
                            "returned_hits": 1,
                        }
                    ],
                    "round_results": [
                        {
                            "query_id": f"pivot-{rank}",
                            "backend": "elastic",
                            "status": "ok",
                            "query_digest": "b" * 64,
                        }
                    ],
                }
            }
            if role == "incident-responder":
                query_audit["_incident_query_audit"] = {
                    "trusted_source": True,
                    "read_only": (
                        second_read_only if rank == 2 else True
                    ),
                    "complete": True,
                    "partial": False,
                    "queries": [
                        {
                            "pack": "alert_context",
                            "status": "completed",
                            "query_digest": "a" * 64,
                            "returned_hits": 3,
                            "partial": False,
                        }
                    ],
                }
            model_call_facts = [
                {
                    "call_id": "primary-initial",
                    "purpose": "initial primary analysis",
                    "requested_route": expected_route,
                    "independent_review": False,
                    "status": "completed",
                },
                {
                    "call_id": "independent-review-1",
                    "purpose": "independent second-opinion review",
                    "requested_route": reviewer_route,
                    "independent_review": True,
                    "status": "completed",
                },
            ]
            execution_proof = {
                "status": "passed",
                "fresh_analysis": True,
                "dispatch_accepted_once": True,
                "analysis_id": analysis_id,
                "analysis_generated_at": "2026-07-25T00:02:00Z",
                "release_id": self.release_id,
                "harness": {
                    "run_id": analysis_id,
                    "trace_id": f"trace-{role}-{rank}",
                    "stable_group_id": stable_id,
                    "representative_alert_id": f"alert-{rank}",
                    "status": "succeeded",
                    "stage": "complete",
                    "role": role,
                    "task_kind": (
                        "reanalysis"
                        if role == "soc-analyst"
                        else "incident-response"
                    ),
                    "policy_mode": "shadow",
                    "assigned_route": expected_route,
                    "assigned_reviewer_route": reviewer_route,
                    "started_at": "2026-07-25T00:01:30Z",
                    "completed_at": "2026-07-25T00:03:00Z",
                    "chain_valid": True,
                    "chain_head_sha256": f"{rank + 4:064x}",
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
                        "facts_sha256": evaluator.sha256_value(
                            model_call_facts
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
                        tool_call_bindings
                    ),
                    "successful_read_only_tool_call_bindings_sha256": (
                        evaluator.sha256_value(tool_call_bindings)
                    ),
                    "query_audit": (
                        evaluator._query_audit_execution_binding(
                            {"query_audit": query_audit}
                        )
                    ),
                    "memory_frozen": True,
                    "submitted_response_sha256": f"{rank + 6:064x}",
                    "response_canonical_sha256": (
                        response_canonical_sha256
                    ),
                },
            }
            execution_proof["proof_sha256"] = evaluator.sha256_value(
                execution_proof
            )
            members.append(
                {
                    "rank": rank,
                    "dashboard_group_id": f"{rank:012x}",
                    "stable_group_id": stable_id,
                    "stable_group_key": stable_group_key,
                    "representative_alert_id": f"alert-{rank}",
                    "detection": {
                        "stable_group_key": stable_group_key,
                        "rule_name": (
                            first_detection_rule
                            if rank == 1 and first_detection_rule
                            else f"PRIVATE RULE {rank}"
                        ),
                        "source_ip": f"10.0.0.{rank}",
                    },
                    "pre_state": {},
                    "dispatch": {
                        "kind": dispatch_kind,
                        "state": "accepted",
                        "attempt_count": 1,
                        "started_at": "2026-07-25T00:01:00Z",
                    },
                    "result": {
                        "state": "completed",
                        "analysis_id": analysis_id,
                        "analysis": {
                            "analysis_id": analysis_id,
                            "agent_role": role,
                            "generated_at": "2026-07-25T00:02:00Z",
                            "model": "gpt-test",
                            "confidence": "medium",
                            "detection_outcome": labels["detection_outcome"],
                            "response_sha256": f"{rank:064x}",
                            "response_canonical_sha256": (
                                response_canonical_sha256
                            ),
                            "result": {
                                **{
                                    key: labels[key]
                                    for key in (
                                        "event_status",
                                        "detection_validity",
                                        "activity_disposition",
                                        "handling",
                                        "duplicate_of",
                                    )
                                },
                                "_analysis_provider": "codex-cli",
                                "_analysis_model_route": expected_route,
                                "_analysis_evaluation_memory_frozen": True,
                                "_second_opinion": {
                                    "status": "completed",
                                    "model_route": reviewer_route,
                                    "response": {
                                        "_analysis_model_route": reviewer_route,
                                    },
                                },
                            },
                            "query_audit": query_audit,
                        },
                        "second_opinion": {
                            "status": "completed",
                            "material_disagreement": 0,
                        },
                    },
                    "execution_proof": execution_proof,
                }
            )
        ordered_identities = [
            {
                "rank": member["rank"],
                "dashboard_group_id": member["dashboard_group_id"],
                "stable_group_id": member["stable_group_id"],
                "stable_group_key": member["stable_group_key"],
                "representative_alert_id": member[
                    "representative_alert_id"
                ],
            }
            for member in members
        ]
        selection = {
            "mode": "imported_rows",
            "source_sha256": source_rows_sha256,
            "source_count": expected_count,
            "order_preserved": True,
            "ordered_identity_sha256": evaluator.sha256_value(
                ordered_identities
            ),
        }
        frozen_plan = {
            "schema": evaluator.MANIFEST_SCHEMA,
            "cohort_id": cohort_id,
            "agent_role": role,
            "count": expected_count,
            "created_at": "2026-07-25T00:00:00Z",
            "selection": selection,
            "execution_contract": contract,
            "members": [
                {
                    **identity,
                    "pre_state_sha256": evaluator.sha256_value({}),
                    "detection_sha256": evaluator.sha256_value(
                        members[index]["detection"]
                    ),
                    "dispatch_kind": members[index]["dispatch"]["kind"],
                }
                for index, identity in enumerate(ordered_identities)
            ],
        }
        frozen_plan_sha256 = evaluator.sha256_value(frozen_plan)
        for member in members:
            dispatch = member["dispatch"]
            dispatch_id = evaluator._expected_dispatch_id(
                cohort_id=cohort_id,
                frozen_plan_sha256=frozen_plan_sha256,
                member=member,
                dispatch_kind=dispatch["kind"],
            )
            job_id = int(member["rank"])
            payload_sha256 = f"{job_id + 100:064x}"
            shared = {
                "stable_group_id": member["stable_group_id"],
                "stable_group_key": member["stable_group_key"],
                "representative_alert_id": member[
                    "representative_alert_id"
                ],
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": self.release_id,
                "expected_assigned_route": expected_route,
                "expected_reviewer_route": reviewer_route,
                "reviewer_required": True,
            }
            dispatch.update(
                {
                    "dispatch_id": dispatch_id,
                    "accepted": dict(shared),
                    "readback": {
                        **shared,
                        "job_id": job_id,
                        "job_payload_sha256": payload_sha256,
                    },
                }
            )
            member["result"]["job"] = {
                **shared,
                "id": job_id,
                "job_type": (
                    "ai_analysis"
                    if dispatch["kind"] == "analyze"
                    else "incident_response_analysis"
                ),
                "dedupe_key": member["stable_group_id"],
                "status": "completed",
                "attempt_count": 1,
                "requested_at": "2026-07-25T00:01:10Z",
                "completed_at": "2026-07-25T00:02:30Z",
                "last_completed_at": "2026-07-25T00:02:30Z",
                "updated_at": "2026-07-25T00:02:31Z",
                "payload_sha256": payload_sha256,
            }
        document = {
            "schema": evaluator.RESULT_SCHEMA,
            "agent_role": role,
            "cohort_id": cohort_id,
            "reason": "Unit-test cohort",
            "count": expected_count,
            "frozen_at": "2026-07-25T00:00:00Z",
            "exported_at": "2026-07-25T01:00:00Z",
            "source_manifest_sha256": "f" * 64,
            "frozen_plan_sha256": frozen_plan_sha256,
            "selection": selection,
            "execution_contract": contract,
            "execution_gate": {
                "status": "passed",
                "expected_count": expected_count,
                "passed_count": expected_count,
                "ordered_identity_sha256": selection[
                    "ordered_identity_sha256"
                ],
                "contract_sha256": evaluator.sha256_value(contract),
            },
            "security_onion_access": "none",
            "content_policy": {
                "contains_raw_alerts": False,
                "contains_prompts": False,
                "contains_raw_model_responses": False,
                "contains_query_text": False,
                "contains_query_results": False,
                "contains_credentials": False,
            },
            "members": members,
        }
        document["export_sha256"] = evaluator.sha256_value(document)
        return document

    def _assessment(
        self,
        role: str,
        rank: int,
        *,
        score: float,
        hard_failures: list[str] | None = None,
        improvement_codes: list[str] | None = None,
    ) -> dict:
        return {
            "analysis_id": f"analysis-{role}-{rank}",
            "scores": self._score(score),
            "hard_failures": hard_failures or [],
            "failure_modes": (
                ["missing_scope_pivot"] if improvement_codes else []
            ),
            "improvement_codes": improvement_codes or [],
        }

    def _adjudication(
        self,
        *,
        expected_count: int = evaluator.EXPECTED_ROLE_COUNT,
    ) -> dict:
        cases = []
        for rank, stable_id in enumerate(
            self.stable_ids[:expected_count], start=1
        ):
            cases.append(
                {
                    "stable_group_id": stable_id,
                    "ground_truth": {
                        "labels": self._labels(),
                        "confidence": "high",
                        "detection_sha256": evaluator.sha256_value(
                            {
                                "stable_group_key": f"v2|fixture|{rank}",
                                "rule_name": f"PRIVATE RULE {rank}",
                                "source_ip": f"10.0.0.{rank}",
                            }
                        ),
                        "evidence_basis_sha256": "a" * 64,
                        "scope_timeline_sha256": "b" * 64,
                        "attribution_sha256": "c" * 64,
                        "required_query_classes": [
                            "oql",
                            "zeek",
                            "suricata",
                        ],
                        "telemetry_gap_codes": [],
                    },
                    "role_assessments": {
                        "incident-responder": self._assessment(
                            "incident-responder",
                            rank,
                            score=90 if rank == 1 else 95,
                            hard_failures=(
                                ["nonexistent_evidence"] if rank == 2 else []
                            ),
                            improvement_codes=(
                                ["bind_every_claim_to_evidence"]
                                if rank == 2
                                else []
                            ),
                        ),
                        "soc-analyst": self._assessment(
                            "soc-analyst",
                            rank,
                            score=80 if rank == 1 else 88,
                            improvement_codes=(
                                ["expand_scope_pivots"] if rank == 1 else []
                            ),
                        ),
                    },
                }
            )
        return {
            "schema": evaluator.ADJUDICATION_SCHEMA,
            "experiment_id": "bounded-cohort-unit",
            "expected_count": expected_count,
            "independent_review": True,
            "reviewer_count": 1,
            "adjudicated_at": "2026-07-25T02:00:00Z",
            "methodology_sha256": "d" * 64,
            "source_cohorts": {
                "incident-responder": "ir-newest-unit",
                "soc-analyst": "soc-newest-unit",
            },
            "cases": cases,
        }

    def _write_fixture_documents(
        self,
        *,
        expected_count: int = evaluator.EXPECTED_ROLE_COUNT,
        soc_second_outcome: str = "true_positive_malicious",
        ir_second_read_only: bool = True,
    ) -> None:
        self._write_private(
            self.ir_path,
            self._result_export(
                "incident-responder",
                "ir-newest-unit",
                expected_count=expected_count,
                second_read_only=ir_second_read_only,
            ),
        )
        self._write_private(
            self.soc_path,
            self._result_export(
                "soc-analyst",
                "soc-newest-unit",
                expected_count=expected_count,
                second_outcome=soc_second_outcome,
            ),
        )
        self._write_private(
            self.adjudication_path,
            self._adjudication(expected_count=expected_count),
        )

    def test_scores_roles_separately_and_enforces_hard_failures(self) -> None:
        self._write_fixture_documents()

        report = evaluator.evaluate_cohorts(
            result_paths={
                "incident-responder": self.ir_path,
                "soc-analyst": self.soc_path,
            },
            adjudication_path=self.adjudication_path,
        )

        self.assertEqual(report["schema"], evaluator.REPORT_SCHEMA)
        self.assertEqual(
            report["execution_contract"]["expected_assigned_route"],
            "codex-cli:gpt-5.5:high",
        )
        for source in report["result_sources"].values():
            self.assertEqual(
                source["expected_reviewer_route"],
                "codex-cli:gpt-5.6-sol:xhigh",
            )
            self.assertIs(source["reviewer_required"], True)
            self.assertEqual(source["evaluation_profile"], "")
        incident = report["roles"]["incident-responder"]
        soc = report["roles"]["soc-analyst"]
        self.assertEqual(
            incident["aggregate"]["classification_counts"],
            {"pass": 19, "needs_review": 0, "fail": 1},
        )
        self.assertEqual(incident["cases"][1]["raw_score"], 95.0)
        self.assertEqual(incident["cases"][1]["effective_score"], 0.0)
        self.assertEqual(
            incident["cases"][1]["hard_failures"],
            ["nonexistent_evidence"],
        )
        self.assertEqual(
            soc["aggregate"]["classification_counts"],
            {"pass": 18, "needs_review": 2, "fail": 0},
        )
        self.assertFalse(soc["cases"][1]["exact_verdict_match"])
        self.assertEqual(
            soc["cases"][1]["mismatched_labels"],
            ["detection_outcome"],
        )
        self.assertEqual(
            report["cross_role"]["agent_verdict_disagreement_case_count"],
            1,
        )
        self.assertFalse(
            incident["aggregate"]["shadow_acceptance_gate"]["passed"]
        )

    def test_cross_role_routes_and_required_profile_must_match(self) -> None:
        self._write_private(
            self.ir_path,
            self._result_export(
                "incident-responder",
                "ir-newest-unit",
            ),
        )
        self._write_private(
            self.soc_path,
            self._result_export(
                "soc-analyst",
                "soc-newest-unit",
                expected_route="codex-cli:gpt-5.6-terra:high",
                reviewer_route="codex-cli:gpt-5.6-luna:xhigh",
            ),
        )
        self._write_private(
            self.adjudication_path,
            self._adjudication(),
        )
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "same execution contract",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

        profile = "onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1"
        self._write_private(
            self.ir_path,
            self._result_export(
                "incident-responder",
                "ir-newest-unit",
                evaluation_profile=profile,
            ),
        )
        self._write_private(
            self.soc_path,
            self._result_export(
                "soc-analyst",
                "soc-newest-unit",
                evaluation_profile=profile,
            ),
        )
        report = evaluator.evaluate_cohorts(
            result_paths={
                "incident-responder": self.ir_path,
                "soc-analyst": self.soc_path,
            },
            adjudication_path=self.adjudication_path,
            required_evaluation_profile=profile,
        )
        self.assertEqual(
            report["execution_contract"]["evaluation_profile"], profile
        )

        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "required evaluation profile",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
                required_evaluation_profile="wrong-profile",
            )

    def test_explicit_non_read_only_audit_blocks_grading(self) -> None:
        self._write_fixture_documents(ir_second_read_only=False)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "read-only/freeze gate failed",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_zero_tool_call_ledger_blocks_grading(self) -> None:
        self._write_fixture_documents()
        document = json.loads(self.soc_path.read_text(encoding="utf-8"))
        proof = document["members"][0]["execution_proof"]
        harness = proof["harness"]
        harness["tool_call_count"] = 0
        harness["successful_tool_call_count"] = 0
        harness["read_only_tool_call_count"] = 0
        proof.pop("proof_sha256")
        proof["proof_sha256"] = evaluator.sha256_value(proof)
        document.pop("export_sha256")
        document["export_sha256"] = evaluator.sha256_value(document)
        self._write_private(self.soc_path, document)

        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "read-only/freeze gate failed",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_exact_reviewer_repair_is_gradeable_but_tampering_is_not(
        self,
    ) -> None:
        self._write_fixture_documents()
        document = json.loads(self.soc_path.read_text(encoding="utf-8"))
        proof = document["members"][0]["execution_proof"]
        harness = proof["harness"]
        harness.update(
            {
                "model_call_count": 3,
                "successful_model_call_count": 2,
                "model_purpose_count": 2,
                "terminally_successful_model_purpose_count": 2,
                "exact_reviewer_repair_count": 1,
                "superseded_validation_failure_count": 1,
            }
        )
        contract = harness["model_call_contract"]
        repaired_facts = [
            contract["facts"][0],
            {
                **contract["facts"][1],
                "status": "validation-failed",
            },
            {
                **contract["facts"][1],
                "call_id": "independent-review-2",
            },
        ]
        contract.update(
            {
                "model_call_count": 3,
                "canonical_model_call_count": 3,
                "reviewer_model_call_count": 2,
                "facts": repaired_facts,
                "facts_sha256": evaluator.sha256_value(repaired_facts),
            }
        )
        harness["reviewer_completion"]["model_call_count"] = 2
        proof.pop("proof_sha256")
        proof["proof_sha256"] = evaluator.sha256_value(proof)
        document.pop("export_sha256")
        document["export_sha256"] = evaluator.sha256_value(document)
        self._write_private(self.soc_path, document)

        report = evaluator.evaluate_cohorts(
            result_paths={
                "incident-responder": self.ir_path,
                "soc-analyst": self.soc_path,
            },
            adjudication_path=self.adjudication_path,
        )
        self.assertEqual(report["schema"], evaluator.REPORT_SCHEMA)

        harness["unexpected_unsuccessful_model_call_count"] = 1
        proof.pop("proof_sha256")
        proof["proof_sha256"] = evaluator.sha256_value(proof)
        document.pop("export_sha256")
        document["export_sha256"] = evaluator.sha256_value(document)
        self._write_private(self.soc_path, document)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "read-only/freeze gate failed",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_planning_repair_then_followup_two_is_gradeable(self) -> None:
        document = self._result_export(
            "soc-analyst",
            "soc-planning-repair",
        )
        harness = document["members"][0]["execution_proof"]["harness"]
        primary_route = harness["assigned_route"]
        reviewer_fact = harness["model_call_contract"]["facts"][1]
        facts = [
            harness["model_call_contract"]["facts"][0],
            {
                "call_id": "primary-query-planning-repair-1",
                "purpose": "primary query-planning repair 1 of 1",
                "requested_route": primary_route,
                "independent_review": False,
                "status": "completed",
            },
            {
                "call_id": "primary-followup-2",
                "purpose": "primary investigation follow-up round 2",
                "requested_route": primary_route,
                "independent_review": False,
                "status": "completed",
            },
            reviewer_fact,
        ]
        harness.update(
            {
                "model_call_count": 4,
                "successful_model_call_count": 4,
                "successful_primary_model_call_count": 3,
                "model_purpose_count": 4,
                "terminally_successful_model_purpose_count": 4,
            }
        )
        contract = harness["model_call_contract"]
        contract.update(
            {
                "model_call_count": 4,
                "canonical_model_call_count": 4,
                "query_planning_repair_call_count": 1,
                "primary_followup_call_count": 1,
                "facts": facts,
                "facts_sha256": evaluator.sha256_value(facts),
            }
        )
        self.assertTrue(evaluator._bounded_model_call_proof_valid(harness))

        contract["facts"][2] = {
            **contract["facts"][2],
            "call_id": "primary-followup-1",
            "purpose": "primary investigation follow-up round 1",
        }
        contract["facts_sha256"] = evaluator.sha256_value(
            contract["facts"]
        )
        self.assertFalse(evaluator._bounded_model_call_proof_valid(harness))

    def test_offline_gate_accepts_canonical_adjudication_and_repair(
        self,
    ) -> None:
        harness = self._result_export(
            "soc-analyst",
            "cohort-adjudicator-proof",
            expected_count=1,
        )["members"][0]["execution_proof"]["harness"]
        contract = harness["model_call_contract"]
        adjudicator = {
            "call_id": "disagreement-adjudication-1",
            "purpose": "bounded disagreement adjudication",
            "requested_route": harness["assigned_reviewer_route"],
            "independent_review": True,
            "status": "completed",
        }
        facts = [*contract["facts"], adjudicator]
        harness.update(
            {
                "model_call_count": 3,
                "successful_model_call_count": 3,
                "model_purpose_count": 3,
                "terminally_successful_model_purpose_count": 3,
                "exact_adjudication_repair_count": 0,
            }
        )
        contract.update(
            {
                "model_call_count": 3,
                "canonical_model_call_count": 3,
                "adjudicator_model_call_count": 1,
                "facts": facts,
                "facts_sha256": evaluator.sha256_value(facts),
            }
        )
        self.assertTrue(evaluator._bounded_model_call_proof_valid(harness))

        repaired_facts = [
            *facts[:-1],
            {**adjudicator, "status": "validation-failed"},
            {
                **adjudicator,
                "call_id": "disagreement-adjudication-2",
            },
        ]
        harness.update(
            {
                "model_call_count": 4,
                "successful_model_call_count": 3,
                "exact_adjudication_repair_count": 1,
                "superseded_validation_failure_count": 1,
            }
        )
        contract.update(
            {
                "model_call_count": 4,
                "canonical_model_call_count": 4,
                "adjudicator_model_call_count": 2,
                "facts": repaired_facts,
                "facts_sha256": evaluator.sha256_value(repaired_facts),
            }
        )
        self.assertTrue(evaluator._bounded_model_call_proof_valid(harness))

    def test_offline_gate_recomputes_call_grammar_and_reviewer_facts(
        self,
    ) -> None:
        for tamper in ("call-purpose", "reviewer-comparison"):
            with self.subTest(tamper=tamper):
                self._write_fixture_documents()
                document = json.loads(
                    self.soc_path.read_text(encoding="utf-8")
                )
                proof = document["members"][0]["execution_proof"]
                harness = proof["harness"]
                if tamper == "call-purpose":
                    contract = harness["model_call_contract"]
                    contract["facts"][0]["purpose"] = "renamed purpose"
                    contract["facts_sha256"] = evaluator.sha256_value(
                        contract["facts"]
                    )
                else:
                    harness["reviewer_completion"][
                        "decision_comparable"
                    ] = False
                proof.pop("proof_sha256")
                proof["proof_sha256"] = evaluator.sha256_value(proof)
                document.pop("export_sha256")
                document["export_sha256"] = evaluator.sha256_value(document)
                self._write_private(self.soc_path, document)

                with self.assertRaisesRegex(
                    evaluator.CohortEvaluationError,
                    "read-only/freeze gate failed",
                ):
                    evaluator.evaluate_cohorts(
                        result_paths={
                            "incident-responder": self.ir_path,
                            "soc-analyst": self.soc_path,
                        },
                        adjudication_path=self.adjudication_path,
                    )

    def test_query_audit_digest_mismatch_blocks_grading(self) -> None:
        self._write_fixture_documents()
        document = json.loads(self.ir_path.read_text(encoding="utf-8"))
        query = document["members"][0]["result"]["analysis"][
            "query_audit"
        ]["_incident_query_audit"]["queries"][0]
        query["returned_hits"] = 99
        document.pop("export_sha256")
        document["export_sha256"] = evaluator.sha256_value(document)
        self._write_private(self.ir_path, document)

        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "query-audit binding does not match",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def _single_role_adjudication(self, role: str) -> Path:
        document = json.loads(
            self.adjudication_path.read_text(encoding="utf-8")
        )
        document["source_cohorts"] = {
            role: document["source_cohorts"][role]
        }
        for item in document["cases"]:
            item["role_assessments"] = {
                role: item["role_assessments"][role]
            }
        target = self.root / f"{role}-adjudication.json"
        self._write_private(target, document)
        return target

    def test_writes_owner_only_bounded_reports_without_private_detection_data(
        self,
    ) -> None:
        self._write_fixture_documents()
        report = evaluator.evaluate_cohorts(
            result_paths={
                "incident-responder": self.ir_path,
                "soc-analyst": self.soc_path,
            },
            adjudication_path=self.adjudication_path,
        )
        json_out = self.root / "reports" / "evaluation.json"
        markdown_out = self.root / "reports" / "evaluation.md"

        evaluator.write_private_json(json_out, report)
        evaluator.write_private_bytes(
            markdown_out, evaluator.render_markdown(report).encode("utf-8")
        )

        self.assertEqual(stat.S_IMODE(json_out.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(markdown_out.stat().st_mode), 0o600)
        combined = (
            json_out.read_text(encoding="utf-8")
            + markdown_out.read_text(encoding="utf-8")
        )
        self.assertNotIn("PRIVATE RULE", combined)
        self.assertNotIn("10.0.0.", combined)
        self.assertNotIn("query text", combined.lower())
        self.assertIn("expand_scope_pivots", combined)
        self.assertEqual(
            json.loads(json_out.read_text(encoding="utf-8"))[
                "content_policy"
            ]["contains_raw_alerts"],
            False,
        )

    def test_rejects_cohort_drift_score_overflow_and_analysis_mismatch(
        self,
    ) -> None:
        self._write_fixture_documents()
        document = json.loads(
            self.adjudication_path.read_text(encoding="utf-8")
        )
        document["cases"][0]["stable_group_id"] = "3" * 20
        self._write_private(self.adjudication_path, document)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError, "stable cohort differs"
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

        self._write_private(self.adjudication_path, self._adjudication())
        document = json.loads(
            self.adjudication_path.read_text(encoding="utf-8")
        )
        document["cases"][0]["role_assessments"]["soc-analyst"]["scores"][
            "action_safety"
        ] = 9
        self._write_private(self.adjudication_path, document)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError, "between 0 and 8"
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

        self._write_private(self.adjudication_path, self._adjudication())
        document = json.loads(
            self.adjudication_path.read_text(encoding="utf-8")
        )
        document["cases"][0]["role_assessments"]["soc-analyst"][
            "analysis_id"
        ] = "wrong-analysis"
        self._write_private(self.adjudication_path, document)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError, "analysis_id does not match"
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_rejects_stable_group_key_binding_drift(self) -> None:
        self._write_fixture_documents()
        document = json.loads(self.soc_path.read_text(encoding="utf-8"))
        document["members"][0]["stable_group_key"] = "v2|changed"
        document.pop("export_sha256")
        document["export_sha256"] = evaluator.sha256_value(document)
        self._write_private(self.soc_path, document)

        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "stable_group_key binding changed",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_rejects_permissive_or_raw_result_exports(self) -> None:
        self._write_fixture_documents()
        os.chmod(self.soc_path, 0o644)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError, "owner-only"
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

        document = self._result_export(
            "soc-analyst", "soc-newest-unit"
        )
        document["content_policy"]["contains_query_text"] = True
        document.pop("export_sha256")
        document["export_sha256"] = evaluator.sha256_value(document)
        self._write_private(self.soc_path, document)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError, "secret-free"
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_cli_emits_safe_summary_and_optional_gate_failure(self) -> None:
        self._write_fixture_documents()
        json_out = self.root / "cli" / "evaluation.json"
        markdown_out = self.root / "cli" / "evaluation.md"

        exit_code = evaluator.main(
            [
                "--result",
                f"incident-responder={self.ir_path}",
                "--result",
                f"soc-analyst={self.soc_path}",
                "--adjudication",
                str(self.adjudication_path),
                "--json-out",
                str(json_out),
                "--markdown-out",
                str(markdown_out),
                "--fail-on-gate",
            ]
        )

        self.assertEqual(exit_code, 1)
        self.assertTrue(json_out.is_file())
        self.assertTrue(markdown_out.is_file())

    def test_refuses_grading_until_both_roles_share_the_exact_source(self) -> None:
        self._write_fixture_documents()
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "requires both",
        ):
            evaluator.evaluate_cohorts(
                result_paths={"soc-analyst": self.soc_path},
                adjudication_path=self.adjudication_path,
            )

        self._write_private(
            self.soc_path,
            self._result_export(
                "soc-analyst",
                "soc-newest-unit",
                source_rows_sha256="9" * 64,
            ),
        )
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "same frozen source cohort",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_refuses_same_source_identity_with_different_detection_snapshot(
        self,
    ) -> None:
        self._write_fixture_documents()
        self._write_private(
            self.soc_path,
            self._result_export(
                "soc-analyst",
                "soc-newest-unit",
                first_detection_rule="DIFFERENT HYDRATED DETECTION",
            ),
        )

        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "same frozen source cohort",
        ):
            evaluator.evaluate_cohorts(
                result_paths={
                    "incident-responder": self.ir_path,
                    "soc-analyst": self.soc_path,
                },
                adjudication_path=self.adjudication_path,
            )

    def test_project_timestamp_double_space_remains_gradeable(self) -> None:
        self._write_fixture_documents()
        for path in (self.ir_path, self.soc_path):
            document = json.loads(path.read_text(encoding="utf-8"))
            for member in document["members"]:
                member["dispatch"]["started_at"] = (
                    "2026-07-25  18:01:00.000-06:00"
                )
                analysis = member["result"]["analysis"]
                analysis["generated_at"] = (
                    "2026-07-25  18:02:00.000-06:00"
                )
                job = member["result"]["job"]
                job["requested_at"] = (
                    "2026-07-25  18:01:10.000-06:00"
                )
                job["completed_at"] = (
                    "2026-07-25  18:02:30.000-06:00"
                )
                job["last_completed_at"] = (
                    "2026-07-25  18:02:30.000-06:00"
                )
                job["updated_at"] = (
                    "2026-07-25  18:02:31.000-06:00"
                )
                proof = member["execution_proof"]
                proof["analysis_generated_at"] = (
                    "2026-07-25  18:02:00.000-06:00"
                )
                proof["harness"]["started_at"] = (
                    "2026-07-25  18:01:30.000-06:00"
                )
                proof["harness"]["completed_at"] = (
                    "2026-07-25  18:03:00.000-06:00"
                )
                proof.pop("proof_sha256")
                proof["proof_sha256"] = evaluator.sha256_value(proof)
            document.pop("export_sha256")
            document["export_sha256"] = evaluator.sha256_value(document)
            self._write_private(path, document)

        report = evaluator.evaluate_cohorts(
            result_paths={
                "incident-responder": self.ir_path,
                "soc-analyst": self.soc_path,
            },
            adjudication_path=self.adjudication_path,
        )
        self.assertTrue(report["dual_role_execution_gate"]["passed"])

    def test_rejects_legacy_or_missing_exact_durable_job_proof(self) -> None:
        legacy = self._result_export(
            "soc-analyst",
            "soc-newest-unit",
        )
        legacy["schema"] = (
            "onion-sentinel-incident-harness-cohort-export-v2"
        )
        legacy.pop("export_sha256")
        legacy["export_sha256"] = evaluator.sha256_value(legacy)
        self._write_private(self.soc_path, legacy)
        with self.assertRaisesRegex(
            evaluator.CohortEvaluationError,
            "unsupported schema",
        ):
                evaluator.load_result_export(
                    self.soc_path,
                    role="soc-analyst",
                    expected_count=evaluator.EXPECTED_ROLE_COUNT,
                )

    def test_rejects_legacy_or_unsafe_skill_selection_proof(self) -> None:
        def missing_validation(harness: dict) -> None:
            harness.pop("skill_selection_attestation_validated")

        def version_zero(harness: dict) -> None:
            harness["skill_selection_attestation"][
                "registry_version"
            ] = 0

        def invalid_registry_digest(harness: dict) -> None:
            harness["skill_selection_attestation"][
                "registry_sha256"
            ] = "not-a-digest"

        def leaked_skill_content(harness: dict) -> None:
            harness["skill_selection_attestation"]["selected"] = [
                {
                    "id": "suricata-detection-validation",
                    "version": 1,
                    "skill_sha256": "8" * 64,
                    "guidance": "raw skill content is forbidden",
                }
            ]
            harness["skill_selection_attestation"]["selected_count"] = 1

        mutations = {
            "legacy-missing-validation": missing_validation,
            "version-zero": version_zero,
            "invalid-registry-digest": invalid_registry_digest,
            "skill-content-leak": leaked_skill_content,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                document = self._result_export(
                    "soc-analyst",
                    "soc-skill-proof-unit",
                )
                proof = document["members"][0]["execution_proof"]
                mutate(proof["harness"])
                proof.pop("proof_sha256")
                proof["proof_sha256"] = evaluator.sha256_value(proof)
                document.pop("export_sha256")
                document["export_sha256"] = evaluator.sha256_value(
                    document
                )
                self._write_private(self.soc_path, document)
                with self.assertRaisesRegex(
                    evaluator.CohortEvaluationError,
                    "skill (selection|identity)",
                ):
                    evaluator.load_result_export(
                        self.soc_path,
                        role="soc-analyst",
                        expected_count=evaluator.EXPECTED_ROLE_COUNT,
                    )

    def test_rejects_missing_exact_durable_job_proof(self) -> None:
        mutations = {
            "missing-job": lambda member: member["result"].pop("job"),
            "wrong-job-id": lambda member: member["result"]["job"].update(
                {"id": 999}
            ),
            "wrong-payload": lambda member: member["result"]["job"].update(
                {"payload_sha256": "f" * 64}
            ),
            "wrong-release": lambda member: member["result"]["job"].update(
                {"release_id": "b" * 40}
            ),
            "predispatch-job": lambda member: member["result"]["job"].update(
                {"requested_at": "2026-07-25T00:00:59Z"}
            ),
            "postcompletion-analysis": lambda member: member["result"][
                "job"
            ].update({"completed_at": "2026-07-25T00:01:59Z"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                document = self._result_export(
                    "soc-analyst",
                    "soc-newest-unit",
                )
                mutate(document["members"][0])
                document.pop("export_sha256")
                document["export_sha256"] = evaluator.sha256_value(document)
                self._write_private(self.soc_path, document)
                with self.assertRaises(evaluator.CohortEvaluationError):
                    evaluator.load_result_export(
                        self.soc_path,
                        role="soc-analyst",
                        expected_count=evaluator.EXPECTED_ROLE_COUNT,
                    )

    def test_grades_bounded_1_10_and_20_case_cohorts(self) -> None:
        for expected_count, required_pass_count in ((1, 1), (10, 9), (20, 18)):
            with self.subTest(expected_count=expected_count):
                self._write_fixture_documents(
                    expected_count=expected_count,
                    soc_second_outcome="true_positive_suspicious",
                )
                adjudication = self._adjudication(
                    expected_count=expected_count
                )
                for rank, case in enumerate(adjudication["cases"], start=1):
                    score = 90 if rank <= required_pass_count else 80
                    for role in evaluator.SUPPORTED_ROLES:
                        assessment = self._assessment(
                            role,
                            rank,
                            score=score,
                        )
                        assessment["scores"]["occurrence_validity"] -= 5
                        assessment["scores"]["route_trace_integrity"] = 5
                        case["role_assessments"][role] = assessment
                self._write_private(self.adjudication_path, adjudication)

                report = evaluator.evaluate_cohorts(
                    result_paths={
                        "incident-responder": self.ir_path,
                        "soc-analyst": self.soc_path,
                    },
                    adjudication_path=self.adjudication_path,
                    expected_count=expected_count,
                )

                self.assertEqual(report["expected_count"], expected_count)
                self.assertEqual(
                    report["rubric"]["required_pass_count"],
                    required_pass_count,
                )
                for role in evaluator.SUPPORTED_ROLES:
                    gate = report["roles"][role]["aggregate"][
                        "shadow_acceptance_gate"
                    ]
                    self.assertTrue(gate["passed"])
                    self.assertEqual(
                        gate["required_pass_count"], required_pass_count
                    )
                    self.assertEqual(
                        gate["production_promotion_size_met"],
                        expected_count == evaluator.EXPECTED_ROLE_COUNT,
                    )

    def test_expected_count_defaults_to_20_and_rejects_invalid_bounds(
        self,
    ) -> None:
        parser = evaluator.build_parser()
        common = [
            "--result",
            f"incident-responder={self.ir_path}",
            "--result",
            f"soc-analyst={self.soc_path}",
            "--adjudication",
            str(self.adjudication_path),
            "--json-out",
            str(self.root / "result.json"),
            "--markdown-out",
            str(self.root / "result.md"),
        ]
        self.assertEqual(
            parser.parse_args(common).expected_count,
            evaluator.EXPECTED_ROLE_COUNT,
        )
        for invalid_count in (0, evaluator.EXPECTED_ROLE_COUNT + 1):
            with self.subTest(invalid_count=invalid_count):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        parser.parse_args(
                            common
                            + ["--expected-count", str(invalid_count)]
                        )
                with self.assertRaisesRegex(
                    evaluator.CohortEvaluationError,
                    "between 1 and 20",
                ):
                    evaluator.evaluate_cohorts(
                        result_paths={},
                        adjudication_path=self.adjudication_path,
                        expected_count=invalid_count,
                    )


if __name__ == "__main__":
    unittest.main()
