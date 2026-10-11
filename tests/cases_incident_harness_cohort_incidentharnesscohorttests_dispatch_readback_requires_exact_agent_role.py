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

class IncidentHarnessCohortTestsDispatchReadbackRequiresExactAgentRoleCases:
    def test_dispatch_readback_requires_exact_agent_role(self) -> None:
        base_manifest = self._freeze(count=1)
        member = base_manifest["members"][0]
        for expected_role in ("soc-analyst", "incident-responder"):
            manifest = json.loads(json.dumps(base_manifest))
            manifest["agent_role"] = expected_role
            payload = {
                "alert_id": member["representative_alert_id"],
                "representative_alert_id": member[
                    "representative_alert_id"
                ],
                "group_id": member["stable_group_id"],
                "stable_group_id": member["stable_group_id"],
                "stable_group_key": cohort._member_stable_group_key(member),
                "dashboard_group_id": member["dashboard_group_id"],
                "cohort_id": manifest["cohort_id"],
                "dispatch_id": cohort.deterministic_dispatch_id(
                    manifest,
                    member,
                ),
                "release_id": manifest["execution_contract"][
                    "expected_release_id"
                ],
                "expected_assigned_route": manifest["execution_contract"][
                    "expected_assigned_route"
                ],
                "expected_reviewer_route": manifest["execution_contract"][
                    "expected_reviewer_route"
                ],
                "reviewer_required": manifest["execution_contract"][
                    "reviewer_required"
                ],
                "agent_role": expected_role,
                "manual_reanalysis": expected_role == "soc-analyst",
            }
            accepted = cohort._validate_dispatch_job_payload(
                manifest,
                member,
                {"payload_json": json.dumps(payload)},
                manual_reanalysis=payload["manual_reanalysis"],
            )
            self.assertEqual(accepted["agent_role"], expected_role)

            for mutation in ("missing", "wrong"):
                with self.subTest(
                    expected_role=expected_role,
                    mutation=mutation,
                ):
                    changed = dict(payload)
                    if mutation == "missing":
                        changed.pop("agent_role")
                    else:
                        changed["agent_role"] = (
                            "incident-responder"
                            if expected_role == "soc-analyst"
                            else "soc-analyst"
                        )
                    with self.assertRaisesRegex(
                        cohort.AmbiguousDispatchError,
                        "payload identity",
                    ):
                        cohort._validate_dispatch_job_payload(
                            manifest,
                            member,
                            {"payload_json": json.dumps(changed)},
                            manual_reanalysis=payload["manual_reanalysis"],
                        )


    def test_queue_rejects_escalation_job_for_a_different_case(self) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def mismatched_case(url, payload):
            result = accepted_poster(url, payload)
            connection = self._connect()
            row = connection.execute(
                """
                SELECT payload_json
                FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.stable_one,),
            ).fetchone()
            job_payload = json.loads(row[0])
            job_payload["case_id"] = "ir-different"
            connection.execute(
                """
                UPDATE durable_jobs
                SET payload_json = ?
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (json.dumps(job_payload), self.stable_one),
            )
            connection.commit()
            connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "payload identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=mismatched_case,
            )


    def test_queue_rejects_reanalysis_job_for_a_different_run(self) -> None:
        self._freeze()
        _calls, accepted_poster = self._api_poster()

        def mismatched_run(url, payload):
            result = accepted_poster(url, payload)
            if url.endswith("/ir-existing/reanalyze"):
                connection = self._connect()
                row = connection.execute(
                    """
                    SELECT payload_json
                    FROM durable_jobs
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (self.stable_two,),
                ).fetchone()
                job_payload = json.loads(row[0])
                job_payload["reanalysis_run_id"] = (
                    "irr-22222222-2222-2222-2222-222222222222"
                )
                connection.execute(
                    """
                    UPDATE durable_jobs
                    SET payload_json = ?
                    WHERE job_type = 'incident_response_analysis'
                      AND dedupe_key = ?
                    """,
                    (json.dumps(job_payload), self.stable_two),
                )
                connection.commit()
                connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "payload identity",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=mismatched_run,
            )


    def test_monitor_rejects_accepted_job_payload_replacement(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        row = connection.execute(
            """
            SELECT payload_json
            FROM durable_jobs
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_one,),
        ).fetchone()
        job_payload = json.loads(row[0])
        job_payload["reason"] = "replacement after accepted readback"
        connection.execute(
            """
            UPDATE durable_jobs
            SET payload_json = ?
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (json.dumps(job_payload), self.stable_one),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "payload changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_rejects_accepted_job_identity_replacement(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            UPDATE durable_jobs
            SET id = id + 100
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "job identity changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_rejects_release_provenance_mutation(self) -> None:
        self._freeze(count=1)
        self._queue()
        manifest = cohort.load_private_manifest(self.manifest_path)
        manifest["members"][0]["dispatch"]["readback"]["release_id"] = "b" * 40
        cohort.write_private_json(
            self.manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "dispatch identity changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_rejects_accepted_dispatch_identity_mutation(self) -> None:
        self._freeze(count=1)
        self._queue()
        manifest = cohort.load_private_manifest(self.manifest_path)
        manifest["members"][0]["dispatch"]["accepted"]["dispatch_id"] = (
            "0" * 64
        )
        cohort.write_private_json(
            self.manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "accepted response dispatch identity changed",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_rejects_stable_group_key_provenance_mutation(self) -> None:
        self._freeze(count=1)
        self._queue()
        manifest = cohort.load_private_manifest(self.manifest_path)
        manifest["members"][0]["dispatch"]["readback"][
            "stable_group_key"
        ] = "v2|different"
        cohort.write_private_json(
            self.manifest_path,
            manifest,
            digest_field="manifest_sha256",
        )

        with self.assertRaisesRegex(
            cohort.CohortError,
            "dispatch identity changed during monitoring",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_reproves_raw_stable_group_key_binding(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            UPDATE alerts
            SET stable_group_key = 'v2|changed-after-acceptance'
            WHERE alert_id = 'alert-a-newest'
            """
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "immutable evidence drift.*stable_group_key",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_keeps_fresh_result_nonterminal_while_job_is_active(
        self,
    ) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, agent_role, generated_at,
              model, model_path, detection_outcome, confidence,
              evidence_hash, response_json, created_at
            ) VALUES (
              'analysis-fresh-active', ?, 'alert-a-newest',
              'incident-responder', '2026-07-25T12:02:00Z',
              'gpt-5.6-sol', 'codex_cli',
              'true_positive_suspicious', 'high', 'evidence-fresh-active',
              '{}', '2026-07-25T12:02:00Z'
            )
            """,
            (self.stable_one,),
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-fresh-active',
                updated_at = '2026-07-25T12:02:00Z'
            WHERE case_id = 'ir-new'
            """
        )
        connection.commit()
        connection.close()

        monitored, terminal = cohort.monitor_cohort_once(
            self.db_path,
            self.manifest_path,
        )

        self.assertFalse(terminal)
        self.assertEqual(
            monitored["members"][0]["monitor"]["state"],
            "queued",
        )
        self.assertEqual(
            monitored["members"][0]["monitor"]["analysis_id"],
            "",
        )


    def test_monitor_rejects_prefreeze_nonlatest_incident_analysis_id(
        self,
    ) -> None:
        connection = self._connect()
        for analysis_id, generated_at in (
            ("analysis-ir-old-nonlatest", "2026-07-25T11:56:00Z"),
            ("analysis-ir-latest-before-freeze", "2026-07-25T11:57:00Z"),
        ):
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role, generated_at,
                  model, model_path, detection_outcome, confidence,
                  evidence_hash, response_json, created_at
                ) VALUES (
                  ?, ?, 'alert-c-existing', 'incident-responder', ?,
                  'gpt-5.6-sol', 'codex_cli',
                  'true_positive_suspicious', 'high', ?, '{}', ?
                )
                """,
                (
                    analysis_id,
                    self.stable_two,
                    generated_at,
                    f"evidence-{analysis_id}",
                    generated_at,
                ),
            )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET latest_analysis_id = 'analysis-ir-latest-before-freeze',
                latest_model = 'gpt-5.6-sol',
                latest_generated_at = '2026-07-25T11:57:00Z',
                updated_at = '2026-07-25T11:57:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.commit()
        connection.close()

        source_path = self.root / "prefreeze-ir-source.json"
        source_path.write_text(
            json.dumps(
                [
                    {
                        "dashboard_group_id": self.dashboard_c,
                        "stable_group_id": self.stable_two,
                        "representative_alert_id": "alert-c-existing",
                    }
                ]
            ),
            encoding="utf-8",
        )
        os.chmod(source_path, 0o600)
        cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="prefreeze-nonlatest-ir-id",
            reason=(
                "Reject a pre-freeze nonlatest Incident Responder analysis."
            ),
            expected_count=1,
            expected_release_id=self.release_id,
        )
        self._queue()

        connection = self._connect()
        connection.execute(
            """
            UPDATE incident_reanalysis_run_cases
            SET status = 'completed',
                analysis_id = 'analysis-ir-old-nonlatest',
                completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-ir-old-nonlatest',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-existing'
            """
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed',
                completed_at = '2026-07-25T12:05:00Z',
                last_completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_two,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "not the exact fresh analysis",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_monitor_rejects_unrelated_group_analysis_alert(self) -> None:
        self._freeze(count=1)
        self._queue()
        connection = self._connect()
        connection.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, agent_role, generated_at,
              model, model_path, detection_outcome, confidence,
              evidence_hash, response_json, created_at
            ) VALUES (
              'analysis-wrong-alert', ?, 'alert-c-existing',
              'incident-responder', '2026-07-25T12:05:00Z',
              'gpt-5.6-sol', 'codex_cli',
              'true_positive_suspicious', 'high', 'evidence-wrong-alert',
              '{}', '2026-07-25T12:05:00Z'
            )
            """,
            (self.stable_one,),
        )
        connection.execute(
            """
            UPDATE incident_response_cases
            SET agent_status = 'analyzed',
                latest_analysis_id = 'analysis-wrong-alert',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE case_id = 'ir-new'
            """
        )
        connection.execute(
            """
            UPDATE durable_jobs
            SET status = 'completed',
                completed_at = '2026-07-25T12:05:00Z',
                last_completed_at = '2026-07-25T12:05:00Z',
                updated_at = '2026-07-25T12:05:00Z'
            WHERE job_type = 'incident_response_analysis'
              AND dedupe_key = ?
            """,
            (self.stable_one,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            cohort.CohortError,
            "not bound to the frozen incident-responder identity",
        ):
            cohort.monitor_cohort_once(
                self.db_path,
                self.manifest_path,
            )


    def test_soc_dispatch_rejects_analysis_race_during_readback(self) -> None:
        source_path = self.root / "soc-race-source.json"
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
        cohort.freeze_cohort_from_rows(
            self.db_path,
            source_path,
            self.manifest_path,
            cohort_id="soc-readback-race",
            reason="Reject a SOC worker result racing controlled readback.",
            expected_count=1,
            expected_release_id=self.release_id,
            agent_role="soc-analyst",
        )
        _calls, poster = self._soc_api_poster(
            create_fresh_analysis=True
        )

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "fresh soc-analyst analysis appeared",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=poster,
            )


    def test_escalation_rejects_analysis_race_during_readback(self) -> None:
        self._freeze(count=1)
        _calls, accepted_poster = self._api_poster()

        def raced(url, payload):
            result = accepted_poster(url, payload)
            connection = self._connect()
            connection.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, agent_role,
                  generated_at, response_json, created_at
                ) VALUES (
                  'analysis-raced-escalation', ?, 'alert-a-newest',
                  'incident-responder', '2026-07-25T12:01:01Z', '{}',
                  '2026-07-25T12:01:01Z'
                )
                """,
                (self.stable_one,),
            )
            connection.commit()
            connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "fresh incident-responder analysis appeared",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=raced,
            )


    def test_reanalysis_rejects_analysis_race_during_readback(self) -> None:
        self._freeze()
        _calls, accepted_poster = self._api_poster()

        def raced(url, payload):
            result = accepted_poster(url, payload)
            if url.endswith("/ir-existing/reanalyze"):
                connection = self._connect()
                connection.execute(
                    """
                    INSERT INTO ai_analysis_runs (
                      analysis_id, group_id, alert_id, agent_role,
                      generated_at, response_json, created_at
                    ) VALUES (
                      'analysis-raced-reanalysis', ?, 'alert-c-existing',
                      'incident-responder', '2026-07-25T12:01:02Z', '{}',
                      '2026-07-25T12:01:02Z'
                    )
                    """,
                    (self.stable_two,),
                )
                connection.commit()
                connection.close()
            return result

        with self.assertRaisesRegex(
            cohort.AmbiguousDispatchError,
            "fresh incident-responder analysis appeared",
        ):
            cohort.queue_cohort(
                self.db_path,
                self.manifest_path,
                base_url="http://127.0.0.1:8766",
                poster=raced,
            )


