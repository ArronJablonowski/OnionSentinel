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

class IncidentHarnessCohortTestsRunnerUsesCanonicalQueryAuditServicesCases:
    def test_runner_uses_canonical_query_audit_services(self) -> None:
        self.assertIs(
            cohort.project_query_audit,
            cohort_query_audit_projection.project_query_audit,
        )
        self.assertIs(
            cohort.normalize_query_audit_binding,
            cohort_evaluation_query_audit.query_audit_execution_binding,
        )


    def test_runner_uses_extracted_execution_proof_service(self) -> None:
        self.assertIs(
            cohort.build_execution_proof,
            cohort_execution_proof_service.build_execution_proof,
        )


    def test_runner_uses_extracted_analysis_metadata_loader(self) -> None:
        self.assertIs(
            cohort.load_analysis_metadata,
            cohort_analysis_metadata.load_analysis_metadata,
        )


    def test_runner_uses_extracted_preflight_services(self) -> None:
        self.assertIs(
            cohort.prove_representative_binding,
            cohort_preflight.validate_representative_binding,
        )
        self.assertIs(
            cohort.run_member_preflight,
            cohort_preflight.validate_member_preflight,
        )


    def test_runner_uses_extracted_dispatch_identity_service(self) -> None:
        self.assertIs(
            cohort.derive_dispatch_id,
            cohort_dispatch_identity.deterministic_dispatch_id,
        )


    def test_runner_uses_extracted_manifest_and_private_input_services(self) -> None:
        self.assertIs(
            cohort.calculate_frozen_plan_digest,
            cohort_manifest_contract.frozen_plan_digest,
        )
        self.assertIs(
            cohort.validate_manifest_document,
            cohort_manifest_contract.validate_manifest_document,
        )
        self.assertIs(
            cohort.read_private_manifest,
            cohort_private_input.load_private_manifest,
        )
        self.assertIs(
            cohort.read_private_source_rows,
            cohort_private_input.load_private_source_rows,
        )


    def test_runner_uses_extracted_artifact_services(self) -> None:
        self.assertIs(
            cohort.verify_alert_store_response_sha256,
            cohort_artifact_io.alert_store_response_sha256,
        )
        self.assertIs(
            cohort.persist_private_json,
            cohort_artifact_io.write_private_json,
        )


    def test_runner_uses_extracted_storage_core(self) -> None:
        self.assertIs(
            cohort.open_cohort_database_read_only,
            cohort_storage_core.connect_read_only,
        )
        self.assertIs(
            cohort.calculate_schema_fingerprint,
            cohort_storage_core.schema_fingerprint,
        )
        self.assertIs(cohort.read_group_aliases, cohort_storage_core.load_aliases)
        self.assertIs(cohort.resolve_group_alias, cohort_storage_core.resolve_alias)


    def test_runner_uses_extracted_storage_state(self) -> None:
        self.assertIs(cohort.query_summary_rows, cohort_storage_state.summary_rows)
        self.assertIs(cohort.query_active_jobs, cohort_storage_state.active_jobs)
        self.assertIs(
            cohort.query_analysis_ids_for_group,
            cohort_storage_state.analysis_ids_for_group,
        )
        self.assertIs(
            cohort.build_incident_pre_state,
            cohort_storage_state.incident_pre_state,
        )


    def test_runner_uses_extracted_source_row_contracts(self) -> None:
        self.assertIs(
            cohort.read_source_identity,
            cohort_source_rows.source_identity,
        )
        self.assertIs(
            cohort.project_source_detection,
            cohort_source_rows.source_detection_projection,
        )
        self.assertIs(
            cohort.prove_source_detection,
            cohort_source_rows.validate_source_detection,
        )


    def test_runner_uses_extracted_representative_state(self) -> None:
        self.assertIs(
            cohort.read_current_summary_identity,
            cohort_representative_state.current_summary_identity,
        )
        self.assertIs(
            cohort.read_alert_representative_identity,
            cohort_representative_state.alert_representative_identity,
        )
        self.assertIs(
            cohort.bind_stable_group_key,
            cohort_representative_state.bind_representative_stable_group_key,
        )


    def test_runner_uses_extracted_second_opinion_state(self) -> None:
        self.assertIs(
            cohort.read_second_opinion_metadata,
            cohort_second_opinion_state.second_opinion_metadata,
        )


    def test_runner_uses_extracted_runner_contracts(self) -> None:
        self.assertIs(cohort.CohortError, cohort_runner_contracts.CohortError)
        self.assertIs(cohort.sha256_value, cohort_runner_contracts.sha256_value)
        self.assertEqual(cohort.SCHEMA, cohort_runner_contracts.SCHEMA)


    def test_runner_uses_extracted_dispatch_adapters(self) -> None:
        self.assertIs(
            cohort.validate_loopback_base_url,
            cohort_dispatch_adapters.validate_loopback_base_url,
        )
        self.assertIs(
            cohort.dashboard_post_json,
            cohort_dispatch_adapters.dashboard_post_json,
        )
        self.assertIs(
            cohort.build_adapter_dispatch_request,
            cohort_dispatch_adapters.request_for_member,
        )


    def test_runner_uses_extracted_monitor_adapters(self) -> None:
        self.assertIs(
            cohort.resolve_adapter_job_monitor_state,
            cohort_monitor_adapters.durable_job_monitor_state,
        )
        self.assertIs(
            cohort._reanalysis_monitor_case,
            cohort_monitor_adapters.reanalysis_monitor_case,
        )


    def test_runner_uses_extracted_artifact_adapters(self) -> None:
        self.assertIs(
            cohort.alert_store_response_sha256,
            cohort_artifact_adapters.alert_store_response_sha256,
        )
        self.assertIs(
            cohort.write_private_json,
            cohort_artifact_adapters.write_private_json,
        )
        self.assertIs(
            cohort._digest_bound,
            cohort_artifact_adapters.digest_bound,
        )


    def test_runner_uses_extracted_manifest_adapters(self) -> None:
        self.assertIs(
            cohort.load_private_manifest,
            cohort_manifest_adapters.load_private_manifest,
        )
        self.assertIs(
            cohort.validate_release_id,
            cohort_manifest_adapters.validate_release_id,
        )
        self.assertIs(
            cohort.deterministic_dispatch_id,
            cohort_manifest_adapters.deterministic_dispatch_id,
        )


    def test_runner_uses_extracted_freeze_state_composition(self) -> None:
        self.assertIs(
            cohort.connect_read_only,
            cohort_freeze_state_composition.connect_read_only,
        )
        self.assertIs(
            cohort._summary_rows,
            cohort_freeze_state_composition.summary_rows,
        )
        self.assertIs(
            cohort.validate_member_preflight,
            cohort_freeze_state_composition.validate_member_preflight,
        )


    def test_runner_uses_extracted_runtime_composition(self) -> None:
        self.assertIs(
            cohort.runtime_queue_cohort,
            cohort_runtime_composition.queue_cohort,
        )
        self.assertIs(
            cohort.monitor_cohort_once,
            cohort_runtime_composition.monitor_cohort_once,
        )
        self.assertIs(
            cohort.runtime_harness_execution_proof,
            cohort_runtime_composition.harness_execution_proof,
        )
        self.assertIs(
            cohort.runtime_export_cohort,
            cohort_runtime_composition.export_cohort,
        )


    def test_query_audit_projection_excludes_query_and_result_content(self) -> None:
        projected = cohort._bounded_query_audit_metadata(
            {
                "_incident_query_audit": {
                    "read_only": True,
                    "queries": [
                        {
                            "query_id": "alert-context",
                            "status": "completed",
                            "query": "secret query text",
                            "rows": [{"secret": "result"}],
                            "request_digest": "a" * 64,
                            "result_digest": "b" * 64,
                        }
                    ],
                }
            }
        )
        query = projected["_incident_query_audit"]["queries"][0]
        self.assertEqual(query["query_id"], "alert-context")
        self.assertNotIn("query", query)
        self.assertNotIn("rows", query)


    def test_freeze_selects_newest_distinct_stable_groups_owner_only(self) -> None:
        manifest = self._freeze()

        self.assertEqual(
            [item["dashboard_group_id"] for item in manifest["members"]],
            [self.dashboard_a, self.dashboard_c],
        )
        self.assertEqual(
            [item["stable_group_id"] for item in manifest["members"]],
            [self.stable_one, self.stable_two],
        )
        self.assertEqual(
            [item["stable_group_key"] for item in manifest["members"]],
            ["v2|one", "v2|two"],
        )
        self.assertTrue(
            all(
                item["stable_group_key"]
                == item["detection"]["stable_group_key"]
                for item in manifest["members"]
            )
        )
        self.assertEqual(
            [item["dispatch"]["kind"] for item in manifest["members"]],
            ["escalate", "reanalyze"],
        )
        self.assertEqual(
            stat.S_IMODE(self.manifest_path.stat().st_mode),
            0o600,
        )
        self.assertEqual(
            stat.S_IMODE(self.manifest_path.parent.stat().st_mode),
            0o700,
        )
        loaded = cohort.load_private_manifest(self.manifest_path)
        self.assertEqual(loaded["manifest_sha256"], manifest["manifest_sha256"])


    def test_controlled_profile_cli_pins_exact_independent_routes(self) -> None:
        profile = "onion-sentinel-gpt55-high-gpt56-sol-xhigh-v1"
        parsed = cohort.build_parser().parse_args(
            [
                "freeze",
                "--db",
                str(self.db_path),
                "--manifest",
                str(self.manifest_path),
                "--cohort-id",
                "profile-cli-test",
                "--reason",
                "Validate the exact controlled evaluation profile.",
                "--count",
                "1",
                "--expected-release-id",
                self.release_id,
                "--expected-assigned-route",
                "codex-cli:gpt-5.5:high",
                "--expected-reviewer-route",
                "codex-cli:gpt-5.6-sol:xhigh",
                "--evaluation-profile",
                profile,
            ]
        )
        self.assertEqual(parsed.evaluation_profile, profile)
        frozen = cohort.freeze_cohort(
            self.db_path,
            self.manifest_path,
            cohort_id="profile-freeze-test",
            reason="Freeze the exact controlled evaluation profile.",
            count=1,
            expected_release_id=self.release_id,
            expected_assigned_route="codex-cli:gpt-5.5:high",
            expected_reviewer_route="codex-cli:gpt-5.6-sol:xhigh",
            evaluation_profile=profile,
        )
        self.assertEqual(
            frozen["execution_contract"]["evaluation_profile"], profile
        )

        wrong_manifest = self.root / "wrong-profile-manifest.json"
        with self.assertRaisesRegex(cohort.CohortError, "profile"):
            cohort.freeze_cohort(
                self.db_path,
                wrong_manifest,
                cohort_id="profile-wrong-route-test",
                reason="Reject a profile whose primary route drifted.",
                count=1,
                expected_release_id=self.release_id,
                expected_assigned_route="codex-cli:gpt-5.6-terra:high",
                expected_reviewer_route="codex-cli:gpt-5.6-sol:xhigh",
                evaluation_profile=profile,
            )
        self.assertFalse(wrong_manifest.exists())


    def test_generic_contract_rejects_same_model_different_effort(self) -> None:
        generic = cohort.execution_contract(
            expected_release_id=self.release_id,
            expected_assigned_route="codex-cli:gpt-5.6-terra:high",
            expected_reviewer_route="codex-cli:gpt-5.6-luna:xhigh",
        )
        self.assertEqual(generic["evaluation_profile"], "")
        with self.assertRaisesRegex(cohort.CohortError, "distinct"):
            cohort.execution_contract(
                expected_release_id=self.release_id,
                expected_assigned_route="codex-cli:gpt-5.5:high",
                expected_reviewer_route="codex-cli:gpt-5.5:xhigh",
            )
        with self.assertRaisesRegex(
            cohort_evaluator.CohortEvaluationError,
            "reviewer route contract",
        ):
            cohort_evaluator._execution_contract(
                {
                    **generic,
                    "expected_assigned_route": "codex-cli:gpt-5.5:high",
                    "expected_reviewer_route": "codex-cli:gpt-5.5:xhigh",
                },
                "same-model contract",
            )


    def test_frozen_plan_digest_binds_detection_evidence(self) -> None:
        self._freeze(count=1)
        document = json.loads(
            self.manifest_path.read_text(encoding="utf-8")
        )
        document["members"][0]["detection"]["source_ip"] = "203.0.113.99"
        document.pop("manifest_sha256")
        document["manifest_sha256"] = cohort.sha256_value(document)
        self.manifest_path.write_text(
            json.dumps(document),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen plan digest does not match",
        ):
            cohort.load_private_manifest(self.manifest_path)


    def test_frozen_plan_digest_binds_expected_release(self) -> None:
        self._freeze(count=1)
        document = json.loads(
            self.manifest_path.read_text(encoding="utf-8")
        )
        document["execution_contract"]["expected_release_id"] = "b" * 40
        document.pop("manifest_sha256")
        document["manifest_sha256"] = cohort.sha256_value(document)
        self.manifest_path.write_text(
            json.dumps(document),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "frozen plan digest does not match",
        ):
            cohort.load_private_manifest(self.manifest_path)


    def test_freeze_rejects_missing_stable_group_key(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = ''
            WHERE alert_id = 'alert-a-newest'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "stable_group_key.*missing or malformed",
        ):
            self._freeze(count=1)


    def test_freeze_rejects_oversized_stable_group_key(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = ?
            WHERE alert_id = 'alert-a-newest'
            """,
            ("x" * (cohort.MAX_STABLE_GROUP_KEY_BYTES + 1),),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "bounded stable-group-key contract",
        ):
            self._freeze(count=1)


    def test_freeze_rejects_pending_or_processing_incident_job(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO durable_jobs (
              job_type, dedupe_key, status, attempt_count,
              requested_at, updated_at
            ) VALUES (
              'incident_response_analysis', ?, 'processing', 1,
              '2026-07-25T12:02:00Z', '2026-07-25T12:02:00Z'
            )
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(cohort.CohortError, "pending/processing"):
            self._freeze(count=1)
        self.assertFalse(self.manifest_path.exists())


    def test_freeze_from_rows_preserves_supplied_order_without_reselection(self) -> None:
        source_path = self.root / "frozen-rows.json"
        source_rows = [
            {
                "dashboard_group_id": self.dashboard_c,
                "stable_group_id": self.stable_two,
                "representative_alert_id": "alert-c-existing",
                "case_id": "ir-existing",
                "case_agent_status": "analyzed",
            },
            {
                "dashboard_group_id": self.dashboard_a,
                "stable_group_id": self.stable_one,
                "representative_alert_id": "alert-a-newest",
            },
        ]
        source_path.write_text(json.dumps(source_rows), encoding="utf-8")
        os.chmod(source_path, 0o600)

        manifest = cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="preselected-live-cohort",
            reason="Preserve the exact request-time cohort selection order.",
            expected_count=2,
            expected_release_id=self.release_id,
        )

        self.assertEqual(
            [item["dashboard_group_id"] for item in manifest["members"]],
            [self.dashboard_c, self.dashboard_a],
        )
        self.assertEqual(manifest["selection"]["mode"], "imported_rows")
        self.assertEqual(
            manifest["selection"]["source_sha256"],
            hashlib.sha256(source_path.read_bytes()).hexdigest(),
        )
        self.assertTrue(manifest["selection"]["order_preserved"])


    def test_freeze_from_rows_allows_proven_representative_rotation(
        self,
    ) -> None:
        connection = cohort.connect_read_only(self.db_path)
        try:
            frozen_summary = next(
                row
                for row in cohort._summary_rows(connection)
                if row["group_id"] == self.dashboard_a
            )
        finally:
            connection.close()
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                        "detection": {
                            key: value
                            for key, value in frozen_summary.items()
                            if key != "group_id"
                        },
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        self._rotate_dashboard_a_representative()

        manifest = cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="preselected-live-cohort",
            reason="Preserve a proven frozen alert after summary rotation.",
            expected_count=1,
            expected_release_id=self.release_id,
            agent_role="soc-analyst",
        )

        member = manifest["members"][0]
        self.assertEqual(
            member["representative_alert_id"],
            "alert-a-newest",
        )
        self.assertEqual(
            member["detection"]["timestamp"],
            "2026-07-25T12:00:00Z",
        )
        validated = cohort.queue_cohort(
            self.db_path,
            self.manifest_path,
            base_url="http://127.0.0.1:8766",
            dry_run=True,
        )
        self.assertEqual(validated["state"], "frozen")


    def test_freeze_from_rows_rejects_rotation_without_frozen_evidence(
        self,
    ) -> None:
        source_path = self.root / "frozen-rows.json"
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
        self._rotate_dashboard_a_representative()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "missing immutable fields",
        ):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject unproven representative rotation safely.",
                expected_count=1,
                expected_release_id=self.release_id,
                agent_role="soc-analyst",
            )


    def test_freeze_from_rows_rejects_supplied_stable_group_key_drift(
        self,
    ) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert-a-newest",
                        "detection": {
                            "stable_group_key": "v2|mutated",
                        },
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)

        with self.assertRaisesRegex(
            cohort.CohortError,
            "immutable evidence drift.*stable_group_key",
        ):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject frozen source stable group key drift.",
                expected_count=1,
                expected_release_id=self.release_id,
                agent_role="soc-analyst",
            )


    def test_freeze_from_rows_rejects_identity_or_prestate_drift(self) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_c,
                        "stable_group_id": self.stable_two,
                        "representative_alert_id": "alert-c-existing",
                        "case_id": "ir-wrong",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)

        with self.assertRaisesRegex(cohort.CohortError, "case_id"):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject request-time identity drift before dispatch.",
                expected_count=1,
                expected_release_id=self.release_id,
            )
        self.assertFalse(self.manifest_path.exists())


    def test_freeze_rejects_noncanonical_representative_alert_id(self) -> None:
        connection = self._connect()
        connection.execute(
            """
            UPDATE alert_group_summary
            SET representative_alert_id = 'alert/with/path'
            WHERE group_id = ?
            """,
            (self.dashboard_a,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "invalid representative alert ID",
        ):
            self._freeze(count=1)


    def test_freeze_from_rows_rejects_noncanonical_representative_alert_id(
        self,
    ) -> None:
        source_path = self.root / "frozen-rows.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_a,
                        "stable_group_id": self.stable_one,
                        "representative_alert_id": "alert/with/path",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)

        with self.assertRaisesRegex(
            cohort.CohortError,
            "invalid representative alert ID",
        ):
            cohort.freeze_cohort_from_rows(
                self.db_path,
                source_path,
                self.manifest_path,
                cohort_id="preselected-live-cohort",
                reason="Reject invalid representative identity grammar.",
                expected_count=1,
                expected_release_id=self.release_id,
            )


