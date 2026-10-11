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

class IncidentReanalysisLineageTestsPreclaimOverlapReturnsReplacementIdentityWithLeaseCases:
    def test_preclaim_overlap_returns_replacement_identity_with_lease(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "preclaim-race"},
            expected_status=202,
        )
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "preclaim-race"},
            expected_status=202,
        )

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )

        self.assertEqual(self.run_case(first["run_id"])["status"], "skipped")
        replacement = self.run_case(second["run_id"])
        self.assertEqual(replacement["status"], "running")
        self.assertEqual(
            claim["claim"]["payload"]["reanalysis_run_id"],
            second["run_id"],
        )
        self.assertEqual(claim["claim"]["case_id"], self.case_id)
        self.assertEqual(
            claim["claim"]["reanalysis_attempt_id"],
            replacement["latest_attempt_id"],
        )
        self.assertEqual(
            claim["claim"]["reanalysis_attempt_id"],
            "ira-"
            + hashlib.sha256(claim["lease_token"].encode("utf-8")).hexdigest()[:40],
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            attempts = connection.execute(
                "SELECT run_id FROM incident_reanalysis_attempts"
            ).fetchall()
        self.assertEqual(attempts, [(second["run_id"],)])


    def test_analysis_commit_ack_binds_raw_submission_and_stored_response(
        self,
    ) -> None:
        payload = self.analysis_payload(
            "commit-ack-binding-analysis",
            model="gpt-5.6-sol",
            model_path="frontier-codex-cli",
            provider="openai-codex",
            reanalysis_attempt_id=None,
            analysis_started_at="2026-07-25T18:00:00Z",
            generated_at="2026-07-25T18:00:01Z",
        )
        payload["response"]["observed_at"] = "2026-07-25T18:00:00Z"
        payload["response"]["summary"] = "Observed café traffic — reviewed."
        payload["response"]["confidence_score"] = 0.0000001
        payload["response"]["serialization_probe"] = {
            "observed_at": "2026-07-25T18:00:00Z",
            "\ue000": "private-use",
            "😀": "astral",
        }

        raw_body = json.dumps(
            payload,
            indent=2,
            sort_keys=False,
        ).encode("utf-8") + b"\n"
        request = urllib.request.Request(
            f"{self.base_url}/analysis/result",
            data=raw_body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            accepted = json.loads(response.read())

        self.assertEqual(accepted["analysis_id"], payload["analysis_id"])
        self.assertEqual(
            accepted["submission_sha256"],
            hashlib.sha256(raw_body).hexdigest(),
        )
        self.assertFalse(accepted.get("idempotent", False))

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            stored_response_json = connection.execute(
                """
                SELECT response_json FROM ai_analysis_runs
                WHERE analysis_id = ?
                """,
                (payload["analysis_id"],),
            ).fetchone()[0]
        stored_response = json.loads(stored_response_json)
        expected_stored_digest = cohort.alert_store_response_sha256(
            stored_response_json
        )
        self.assertEqual(
            accepted["stored_response_sha256"],
            expected_stored_digest,
        )
        self.assertNotEqual(
            stored_response["observed_at"],
            payload["response"]["observed_at"],
        )

        replay_body = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        replay_request = urllib.request.Request(
            f"{self.base_url}/analysis/result",
            data=replay_body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(replay_request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            replay = json.loads(response.read())

        self.assertTrue(replay["idempotent"])
        self.assertEqual(replay["analysis_id"], payload["analysis_id"])
        self.assertEqual(
            replay["submission_sha256"],
            hashlib.sha256(replay_body).hexdigest(),
        )
        self.assertNotEqual(
            replay["submission_sha256"],
            accepted["submission_sha256"],
        )
        self.assertEqual(
            replay["stored_response_sha256"],
            expected_stored_digest,
        )


    def test_analysis_replay_is_read_only_and_provenance_is_immutable(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "idempotency-test"},
            expected_status=202,
        )
        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        running = self.run_case(rerun["run_id"])
        payload = self.analysis_payload(
            "lineage-immutable-analysis",
            model="gpt-5.6-sol",
            model_path="hermes-agent",
            provider="openai-codex",
            reanalysis_attempt_id=running["latest_attempt_id"],
            analysis_started_at=running["started_at"],
            generated_at=self.generated_at(5),
        )
        accepted = self.post("/analysis/result", payload)
        self.assertFalse(accepted.get("idempotent", False))
        self.assertEqual(
            accepted["submission_sha256"],
            hashlib.sha256(
                json.dumps(payload).encode("utf-8")
            ).hexdigest(),
        )
        self.assertRegex(
            accepted["stored_response_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertEqual(
            accepted["analysis_id"],
            payload["analysis_id"],
        )
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            event_count = connection.execute(
                """
                SELECT COUNT(*) FROM incident_response_events
                WHERE case_id = ? AND event_type = 'analysis_completed'
                """,
                (self.case_id,),
            ).fetchone()[0]

        replay = self.post("/analysis/result", payload)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(
            replay["submission_sha256"],
            accepted["submission_sha256"],
        )
        self.assertEqual(
            replay["stored_response_sha256"],
            accepted["stored_response_sha256"],
        )
        mutated = json.loads(json.dumps(payload))
        mutated["model"] = "gpt-5.6-terra"
        rejected = self.post(
            "/analysis/result",
            mutated,
            expected_status=409,
        )
        self.assertIn("immutable fields", rejected["reason"])

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            stored = connection.execute(
                """
                SELECT model, model_path FROM ai_analysis_runs
                WHERE analysis_id = 'lineage-immutable-analysis'
                """
            ).fetchone()
            attempt = connection.execute(
                """
                SELECT analysis_id, executed_model, executed_provider,
                       executed_model_path
                FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (running["latest_attempt_id"],),
            ).fetchone()
            final_event_count = connection.execute(
                """
                SELECT COUNT(*) FROM incident_response_events
                WHERE case_id = ? AND event_type = 'analysis_completed'
                """,
                (self.case_id,),
            ).fetchone()[0]
        self.assertEqual(stored, ("gpt-5.6-sol", "hermes-agent"))
        self.assertEqual(
            attempt,
            (
                "lineage-immutable-analysis",
                "gpt-5.6-sol",
                "openai-codex",
                "hermes-agent",
            ),
        )
        self.assertEqual(final_event_count, event_count)
        self.assertEqual(
            self.incident_case()["latest_model"],
            "gpt-5.6-sol",
        )
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": claim["lease_token"],
            },
        )


    def test_result_bound_attempt_is_retired_during_startup_recovery(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "crash-window-test"},
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
        running = self.run_case(rerun["run_id"])
        self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-crash-window",
                model="gpt-5.6-sol",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=running["latest_attempt_id"],
                analysis_started_at=running["started_at"],
                generated_at=self.generated_at(5),
            ),
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
                SELECT status, attempt_count FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()
            attempts = connection.execute(
                """
                SELECT COUNT(*), MIN(status), MAX(status)
                FROM incident_reanalysis_attempts
                """
            ).fetchone()
        self.assertEqual(durable[0], "completed")
        self.assertEqual(durable[1], 1)
        self.assertEqual(attempts, (1, "completed", "completed"))
        self.assertEqual(self.run_case(rerun["run_id"])["status"], "completed")
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
            expected_status=404,
        )


    def test_startup_recovery_reconciles_retry_and_terminal_expiry(self) -> None:
        rerun = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "expiry-test"},
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
        first_attempt = self.run_case(rerun["run_id"])["latest_attempt_id"]

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
        self.assertEqual(self.run_case(rerun["run_id"])["status"], "queued")
        self.assertEqual(self.incident_case()["agent_status"], "queued")
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            first_status = connection.execute(
                """
                SELECT status FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (first_attempt,),
            ).fetchone()[0]
            connection.execute(
                """
                UPDATE durable_jobs
                SET next_attempt_at = '2000-01-01  00:00:00+00:00'
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.assertEqual(first_status, "failed")

        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        second_attempt = self.run_case(rerun["run_id"])["latest_attempt_id"]
        self.assertNotEqual(first_attempt, second_attempt)
        self.assertEqual(self.incident_case()["agent_status"], "analyzing")

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET lease_expires_at = '2000-01-01  00:00:00+00:00',
                    attempt_count = max_attempts
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            durable_status = connection.execute(
                """
                SELECT status FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (self.group_id,),
            ).fetchone()[0]
            statuses = dict(
                connection.execute(
                    """
                    SELECT attempt_id, status
                    FROM incident_reanalysis_attempts
                    """
                ).fetchall()
            )
        self.assertEqual(durable_status, "failed")
        self.assertEqual(statuses[first_attempt], "failed")
        self.assertEqual(statuses[second_attempt], "failed")
        self.assertEqual(self.run_case(rerun["run_id"])["status"], "failed")
        self.assertEqual(self.incident_case()["agent_status"], "failed")
        self.assertTrue(first_claim["lease_token"])
        self.assertTrue(second_claim["lease_token"])


    def test_recovery_keeps_case_analyzing_for_replacement_lease(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "replacement-recovery"},
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
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "replacement-recovery"},
            expected_status=202,
        )
        replacement_token = "replacement-recovery-lease"
        replacement_attempt = (
            "ira-"
            + hashlib.sha256(replacement_token.encode("utf-8")).hexdigest()[:40]
        )
        replacement_started = self.generated_at()

        self.stop_alert_store()
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET status = 'processing', lease_token = ?,
                    lease_expires_at = '2099-01-01  00:00:00+00:00',
                    processing_started_at = ?, attempt_count = 2,
                    rerun_requested = 0
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (
                    replacement_token,
                    replacement_started,
                    self.group_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO incident_reanalysis_attempts (
                  attempt_id, run_id, case_id, group_id,
                  durable_attempt_count, status, started_at, updated_at
                ) VALUES (?, ?, ?, ?, 2, 'running', ?, ?)
                """,
                (
                    replacement_attempt,
                    second["run_id"],
                    self.case_id,
                    self.group_id,
                    replacement_started,
                    replacement_started,
                ),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_run_cases
                SET status = 'running', latest_attempt_id = ?,
                    started_at = ?, updated_at = ?
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    replacement_attempt,
                    replacement_started,
                    replacement_started,
                    second["run_id"],
                    self.case_id,
                ),
            )
            connection.execute(
                """
                UPDATE incident_response_cases
                SET agent_status = 'failed'
                WHERE case_id = ?
                """,
                (self.case_id,),
            )
            connection.commit()
        self.start_alert_store()

        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            statuses = dict(
                connection.execute(
                    """
                    SELECT attempt_id, status
                    FROM incident_reanalysis_attempts
                    """
                ).fetchall()
            )
        self.assertEqual(statuses[first_attempt], "failed")
        self.assertEqual(statuses[replacement_attempt], "running")
        self.assertEqual(self.run_case(first["run_id"])["status"], "failed")
        self.assertEqual(self.run_case(second["run_id"])["status"], "running")
        self.assertEqual(self.incident_case()["agent_status"], "analyzing")


    def test_stale_worker_result_cannot_attach_to_replacement_lease(self) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "stale-worker-test"},
            expected_status=202,
        )
        first_run = first["run_id"]
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        first_running = self.run_case(first_run)
        first_started_at = first_running["started_at"]
        first_attempt_id = first_running["latest_attempt_id"]

        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "stale-worker-test"},
            expected_status=202,
        )
        second_run = second["run_id"]
        # Model lease recovery without waiting for the production watchdog.
        # The queue payload already belongs to run B while run A's immutable
        # attempt remains in the ledger.
        with closing(sqlite3.connect(self.db_path, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs
                SET status = 'pending', attempt_count = 0,
                    next_attempt_at = '2000-01-01  00:00:00+00:00',
                    lease_expires_at = NULL, lease_token = NULL,
                    processing_started_at = NULL, rerun_requested = 0
                WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?
                """,
                (self.group_id,),
            )
            connection.commit()
        second_claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "processing",
            },
        )
        second_started_at = self.run_case(second_run)["started_at"]
        second_attempt_id = self.run_case(second_run)["latest_attempt_id"]
        self.assertEqual(self.run_case(first_run)["status"], "failed")
        self.assertEqual(self.run_case(second_run)["status"], "running")
        self.assertEqual(self.incident_case()["agent_status"], "analyzing")

        second_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-replacement-worker",
                model="gemma4:31b",
                model_path="ollama",
                reanalysis_attempt_id=second_attempt_id,
                analysis_started_at=second_started_at,
                generated_at=self.generated_at(60),
            ),
        )
        self.assertEqual(second_result["reanalysis_run_id"], second_run)
        self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": self.group_id,
                "status": "completed",
                "lease_token": second_claim["lease_token"],
            },
        )
        self.assertEqual(
            self.incident_case()["latest_analysis_id"],
            "lineage-replacement-worker",
        )

        stale_result = self.post(
            "/analysis/result",
            self.analysis_payload(
                "lineage-stale-worker",
                model="gpt-5.6-terra",
                model_path="frontier-codex-cli",
                reanalysis_attempt_id=first_attempt_id,
                analysis_started_at=first_started_at,
                # A delayed stale result is newer by wall clock but must not
                # replace the case pointer owned by the replacement attempt.
                generated_at=self.generated_at(120),
            ),
        )
        self.assertEqual(stale_result["reanalysis_run_id"], first_run)
        self.assertFalse(stale_result["reanalysis_authoritative"])
        self.assertEqual(self.run_case(first_run)["analysis_id"], "lineage-stale-worker")
        self.assertEqual(
            self.run_case(second_run)["analysis_id"],
            "lineage-replacement-worker",
        )
        current_case = self.incident_case()
        self.assertEqual(
            current_case["latest_analysis_id"],
            "lineage-replacement-worker",
        )
        self.assertEqual(current_case["latest_model"], "gemma4:31b")


    def test_pending_identity_drift_retires_orphan_and_queues_current_group(
        self,
    ) -> None:
        first = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "identity-drift"},
            expected_status=202,
        )
        new_group_id = "5f83e4cd0123456789abcdef"
        self.drift_representative_group(new_group_id)
        second = self.post(
            "/incidents/reanalyze",
            {"case_id": self.case_id, "requested_by": "identity-drift"},
            expected_status=202,
        )

        self.assertEqual(self.incident_case()["group_id"], new_group_id)
        self.assertEqual(self.run_case(first["run_id"])["status"], "skipped")
        second_case = self.run_case(second["run_id"])
        self.assertEqual(second_case["group_id"], new_group_id)
        self.assertEqual(second_case["status"], "queued")
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
        self.assertEqual(executable, 1)

        claim = self.post(
            "/jobs/status",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": new_group_id,
                "status": "processing",
            },
        )
        self.assertEqual(
            claim["claim"]["payload"]["reanalysis_run_id"],
            second["run_id"],
        )
