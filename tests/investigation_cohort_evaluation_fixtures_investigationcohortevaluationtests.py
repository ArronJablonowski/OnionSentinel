from __future__ import annotations

from investigation_cohort_evaluation_fixtures import (
    MODULE_PATH,
    Path,
    ROOT,
    SPEC,
    cohort_evaluation_api,
    cohort_evaluation_contracts,
    cohort_evaluation_execution_contract,
    cohort_evaluation_execution_proof,
    cohort_evaluation_private_input,
    cohort_evaluation_query_audit,
    cohort_evaluation_result_loader,
    cohort_evaluation_result_policy,
    cohort_evaluation_service,
    cohort_execution_result,
    contextlib,
    evaluator,
    importlib,
    io,
    json,
    os,
    stat,
    tempfile,
    unittest,
)

class InvestigationCohortEvaluationTestsFixtures(unittest.TestCase):
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
