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

class InvestigationCohortEvaluationTestsEvaluatorUsesExtractedQueryAuditServicesCases:
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


    def test_evaluator_uses_extracted_private_input_and_result_loader(self) -> None:
        self.assertIs(
            evaluator.hash_file,
            cohort_evaluation_private_input.file_sha256,
        )
        self.assertIs(
            evaluator.read_private_json,
            cohort_evaluation_private_input.load_private_json,
        )
        self.assertIs(
            evaluator.normalize_result_file,
            cohort_evaluation_result_loader.load_result_export,
        )


    def test_evaluator_uses_extracted_evaluation_api(self) -> None:
        self.assertIs(
            evaluator.run_cohort_evaluation,
            cohort_evaluation_api.evaluate_cohorts,
        )


    def test_cli_is_thin_service_facade(self) -> None:
        self.assertLessEqual(len(MODULE_PATH.read_text().splitlines()), 250)
        self.assertIs(
            evaluator.evaluate_cohorts,
            cohort_evaluation_service.evaluate_cohorts,
        )
        self.assertIs(
            evaluator.CohortEvaluationError,
            cohort_evaluation_service.CohortEvaluationError,
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


