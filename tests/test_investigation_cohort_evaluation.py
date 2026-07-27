#!/usr/bin/env python3
"""Tests for the offline SOC/IR cohort accuracy evaluator."""

from __future__ import annotations

import importlib.util
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


class InvestigationCohortEvaluationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-investigation-evaluation-"
        )
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.stable_ids = ("1" * 20, "2" * 20)
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
        second_outcome: str = "true_positive_suspicious",
        second_read_only: bool = True,
        source_rows_sha256: str = "e" * 64,
    ) -> dict:
        members = []
        expected_route = "codex-cli:gpt-test:high"
        reviewer_route = "codex-cli:gpt-reviewer:xhigh"
        contract = {
            "harness_required": True,
            "harness_mode": "shadow",
            "memory_frozen": True,
            "expected_assigned_route": expected_route,
            "expected_reviewer_route": reviewer_route,
        }
        for rank, stable_id in enumerate(self.stable_ids, start=1):
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
            response_canonical_sha256 = f"{rank + 2:x}" * 64
            tool_call_bindings = [
                {
                    "call_id": f"round-1-pivot-{rank}",
                    "round_number": 1,
                    "query_id": f"pivot-{rank}",
                    "backend": "elastic",
                    "status": "ok",
                    "request_digest": f"{rank + 8:x}" * 64,
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
                    "chain_head_sha256": f"{rank + 4:x}" * 64,
                    "ledger_manifest_bound": True,
                    "ledger_manifest_schema": (
                        "onion-sentinel-harness-ledger-manifest-v2"
                    ),
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
                    "submitted_response_sha256": f"{rank + 6:x}" * 64,
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
                    "dashboard_group_id": f"{rank:x}" * 12,
                    "stable_group_id": stable_id,
                    "representative_alert_id": f"alert-{rank}",
                    "detection": {
                        "rule_name": f"PRIVATE RULE {rank}",
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
                            "response_sha256": str(rank) * 64,
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
                "representative_alert_id": member[
                    "representative_alert_id"
                ],
            }
            for member in members
        ]
        selection = {
            "mode": "imported_rows",
            "source_sha256": source_rows_sha256,
            "source_count": 2,
            "order_preserved": True,
            "ordered_identity_sha256": evaluator.sha256_value(
                ordered_identities
            ),
        }
        frozen_plan = {
            "schema": evaluator.MANIFEST_SCHEMA,
            "cohort_id": cohort_id,
            "agent_role": role,
            "count": 2,
            "created_at": "2026-07-25T00:00:00Z",
            "selection": selection,
            "execution_contract": contract,
            "members": [
                {
                    **identity,
                    "pre_state_sha256": evaluator.sha256_value({}),
                    "dispatch_kind": members[index]["dispatch"]["kind"],
                }
                for index, identity in enumerate(ordered_identities)
            ],
        }
        document = {
            "schema": evaluator.RESULT_SCHEMA,
            "agent_role": role,
            "cohort_id": cohort_id,
            "reason": "Unit-test cohort",
            "count": 2,
            "frozen_at": "2026-07-25T00:00:00Z",
            "exported_at": "2026-07-25T01:00:00Z",
            "source_manifest_sha256": "f" * 64,
            "frozen_plan_sha256": evaluator.sha256_value(frozen_plan),
            "selection": selection,
            "execution_contract": contract,
            "execution_gate": {
                "status": "passed",
                "expected_count": 2,
                "passed_count": 2,
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

    def _adjudication(self) -> dict:
        cases = []
        for rank, stable_id in enumerate(self.stable_ids, start=1):
            cases.append(
                {
                    "stable_group_id": stable_id,
                    "ground_truth": {
                        "labels": self._labels(),
                        "confidence": "high",
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
            "experiment_id": "newest-20-unit",
            "expected_count": 2,
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
        soc_second_outcome: str = "true_positive_malicious",
        ir_second_read_only: bool = True,
    ) -> None:
        self._write_private(
            self.ir_path,
            self._result_export(
                "incident-responder",
                "ir-newest-unit",
                second_read_only=ir_second_read_only,
            ),
        )
        self._write_private(
            self.soc_path,
            self._result_export(
                "soc-analyst",
                "soc-newest-unit",
                second_outcome=soc_second_outcome,
            ),
        )
        self._write_private(
            self.adjudication_path,
            self._adjudication(),
        )

    def test_scores_roles_separately_and_enforces_hard_failures(self) -> None:
        self._write_fixture_documents()

        report = evaluator.evaluate_cohorts(
            result_paths={
                "incident-responder": self.ir_path,
                "soc-analyst": self.soc_path,
            },
            adjudication_path=self.adjudication_path,
            expected_count=2,
        )

        self.assertEqual(report["schema"], evaluator.REPORT_SCHEMA)
        incident = report["roles"]["incident-responder"]
        soc = report["roles"]["soc-analyst"]
        self.assertEqual(
            incident["aggregate"]["classification_counts"],
            {"pass": 1, "needs_review": 0, "fail": 1},
        )
        self.assertEqual(incident["cases"][1]["raw_score"], 95.0)
        self.assertEqual(incident["cases"][1]["effective_score"], 0.0)
        self.assertEqual(
            incident["cases"][1]["hard_failures"],
            ["nonexistent_evidence"],
        )
        self.assertEqual(
            soc["aggregate"]["classification_counts"],
            {"pass": 0, "needs_review": 2, "fail": 0},
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
                expected_count=2,
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
                expected_count=2,
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
            expected_count=2,
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
                expected_count=2,
            )

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
                        expected_count=2,
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
                expected_count=2,
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
            expected_count=2,
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
                expected_count=2,
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
                expected_count=2,
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
                expected_count=2,
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
                expected_count=2,
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
                expected_count=2,
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
                "--expected-count",
                "2",
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
                expected_count=2,
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
                expected_count=2,
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
            expected_count=2,
        )
        self.assertTrue(report["dual_role_execution_gate"]["passed"])


if __name__ == "__main__":
    unittest.main()
