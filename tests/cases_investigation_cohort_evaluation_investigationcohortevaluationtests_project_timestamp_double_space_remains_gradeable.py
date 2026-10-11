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

class InvestigationCohortEvaluationTestsProjectTimestampDoubleSpaceRemainsGradeableCases:
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
