from __future__ import annotations

from incident_reanalysis_lineage_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    COHORT_MODULE_PATH,
    COHORT_SPEC,
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    PRIMARY_ROUTE,
    Path,
    REPO_ROOT,
    REVIEWER_ROUTE,
    SCORING_RULES,
    available_port,
    closing,
    cohort,
    dt,
    hashlib,
    importlib,
    json,
    os,
    request_json,
    socket,
    sqlite3,
    subprocess,
    tempfile,
    time,
    unittest,
    urllib,
)

class IncidentReanalysisLineageTestsProcessingIdentityDriftAllowsOldResultNonAuthoritativelyCases:
    def test_processing_identity_drift_allows_old_result_non_authoritatively(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "processing-drift"},
            expected_status=202,
        )
        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_running = self.run_case(first["run_id"])
        new_group_id = "6f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "processing-drift"},
            expected_status=202,
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
        self.assertEqual(
            durable,
            [(self.group_id, "processing"), (new_group_id, "pending")],
        )

        old_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-old-identity-result",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_running["latest_attempt_id"],
                analysis_started_at=first_running["started_at"],
                generated_at=self.generated_at(10),
            ),
        )
        self.assertEqual(old_result["reanalysis_run_id"], first["run_id"])
        self.assertFalse(old_result["reanalysis_authoritative"])
        self.assertEqual(self.incident_case()["agent_status"], "queued")
        self.assertIsNone(self.incident_case()["latest_analysis_id"])
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": first_claim["lease_token"],
            },
        )
        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": new_group_id,
                "status": "processing",
            },
        )
        self.assertEqual(
            second_claim["claim"]["payload"]["reanalysis_run_id"],
            second["run_id"],
        )
        self.assertEqual(self.run_case(second["run_id"])["status"], "running")


    def test_expired_processing_identity_drift_retires_old_queue_owner(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "expiry-drift"},
            expected_status=202,
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_attempt = self.run_case(first["run_id"])["latest_attempt_id"]
        new_group_id = "8f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "expiry-drift"},
            expected_status=202,
        )

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET lease_expires_at = '2000-01-01  00:00:00+00:00'
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
            attempt_status = connection.execute(
                """
                SELECT status FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (first_attempt,),
            ).fetchone()[0]
            executable = connection.execute(
                """
                SELECT COUNT(*) FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND status IN ('pending', 'processing')
                """
            ).fetchone()[0]
        self.assertEqual(
            durable,
            [(self.group_id, "completed"), (new_group_id, "pending")],
        )
        self.assertEqual(attempt_status, "failed")
        self.assertEqual(self.run_case(first["run_id"])["status"], "failed")
        self.assertEqual(self.run_case(second["run_id"])["status"], "queued")
        self.assertEqual(self.incident_case()["agent_status"], "queued")
        self.assertEqual(executable, 1)


    def test_processing_drift_retires_coalesced_superseded_old_rerun(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "coalesced-drift"},
            expected_status=202,
        )
        first_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_running = self.run_case(first["run_id"])
        coalesced = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "coalesced-drift"},
            expected_status=202,
        )
        new_group_id = "9f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        current = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "coalesced-drift"},
            expected_status=202,
        )
        self.assertEqual(self.run_case(coalesced["run_id"])["status"], "skipped")

        self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-coalesced-old-worker",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_running["latest_attempt_id"],
                analysis_started_at=first_running["started_at"],
                generated_at=self.generated_at(10),
            ),
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": first_claim["lease_token"],
            },
        )

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable = connection.execute(
                """
                SELECT dedupe_key, status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                ORDER BY dedupe_key
                """
            ).fetchall()
            executable = connection.execute(
                """
                SELECT COUNT(*) FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND status IN ('pending', 'processing')
                """
            ).fetchone()[0]
        self.assertEqual(
            durable,
            [(self.group_id, "completed"), (new_group_id, "pending")],
        )
        self.assertEqual(self.run_case(first["run_id"])["status"], "completed")
        self.assertEqual(self.run_case(current["run_id"])["status"], "queued")
        self.assertEqual(executable, 1)


    def test_identity_drift_preserves_resolution_and_suppression_review_guards(
        self,
    ) -> None:
        self.seed_failed_review(
            "lineage-prior-incident-review",
            "incident-responder",
        )
        self.seed_failed_review(
            "lineage-prior-soc-review",
            "soc-analyst",
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                  group_id, group_key, representative_alert_id,
                  raw_alert_count, total_seen_count, updated_at
                ) VALUES (?, 'lineage-dashboard-group', ?, 1, 1, ?)
                """,
                (
                    self.dashboard_group_id,
                    self.alert_id,
                    self.generated_at(),
                ),
            )
            connection.commit()
        new_group_id = "7f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "review-drift"},
            expected_status=202,
        )

        resolution = self.post(
            "/incidents/status",
            {
                "case_id": self.case_id,
                "status": "resolved",
                "resolution_reason": "Should require adjudication",
                "updated_by": "unit-test",
            },
            expected_status=409,
        )
        self.assertIn("independent review", resolution["reason"])
        suppression = self.post(
            "/analyst-status",
            {
                "id": self.dashboard_group_id,
                "status": "suppressed",
                "reason": "Should require adjudication",
                "updated_by": "unit-test",
            },
            expected_status=409,
        )
        self.assertIn("independent review", suppression["reason"])
        self.assertEqual(self.incident_case()["status"], "open")


    def test_normal_incident_result_cannot_fallback_to_stale_reanalysis(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "normal-ir-test"},
            expected_status=202,
        )
        run_id = rerun["run_id"]
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET payload_json = ?, status = 'pending', attempt_count = 0,
                    next_attempt_at = '2000-01-01  00:00:00+00:00',
                    lease_expires_at = NULL, lease_token = NULL,
                    processing_started_at = NULL, rerun_requested = 0
                WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?
                """,
                (
                    json.dumps(
                        {
                            "agent_role": "incident-responder",
                            "case_id": self.case_id,
                            "alert_id": self.alert_id,
                            "group_id": self.group_id,
                            "manual_reanalysis": False,
                        }
                    ),
                    self.group_id,
                ),
            )
            connection.commit()
        normal_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        self.assertEqual(self.run_case(run_id)["status"], "failed")

        normal_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-normal-incident",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                # New runners deliberately serialize null for normal IR jobs.
                reanalysis_attempt_id=None,
                analysis_started_at=self.generated_at(),
                generated_at=self.generated_at(5),
            ),
        )
        self.assertIsNone(normal_result["reanalysis_run_id"])
        stale_run = self.run_case(run_id)
        self.assertEqual(stale_run["status"], "failed")
        self.assertIsNone(stale_run["analysis_id"])
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": normal_claim["lease_token"],
            },
        )
