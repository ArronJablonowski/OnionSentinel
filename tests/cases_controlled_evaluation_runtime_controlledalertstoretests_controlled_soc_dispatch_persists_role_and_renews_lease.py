from __future__ import annotations

from controlled_evaluation_runtime_fixtures import (
    ALERT_STORE,
    ALERT_STORE_DIR,
    BIN_DIR,
    BaseHTTPRequestHandler,
    CONTROLLED_CREDENTIAL_KEYS,
    CONTROLLED_ROUTE_FIELDS,
    DASHBOARD_SERVER,
    EVALUATION_TOKEN,
    INSTALLER_PATH,
    PIPELINE_ADAPTER_PATH,
    PRIMARY_ROUTE,
    Path,
    RELEASE_ID,
    REPLACEMENT_RELEASE_ID,
    REVIEWER_ROUTE,
    ROOT,
    RUNNER_PATH,
    SCHEDULER_PATH,
    SCORING_RULES,
    SimpleNamespace,
    ThreadingHTTPServer,
    available_port,
    closing,
    dt,
    hashlib,
    importlib,
    io,
    json,
    load_python_module,
    mock,
    os,
    process_output,
    raw_request_status,
    request_json,
    request_json_bytes,
    request_status,
    sanitized_environment,
    shutil,
    socket,
    sqlite3,
    startup_failure_diagnostic,
    stop_process,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    unittest,
    urllib,
    write_controlled_route_fixture,
)

class ControlledAlertStoreTestsControlledSocDispatchPersistsRoleAndRenewsLeaseCases:
    def test_controlled_soc_dispatch_persists_role_and_renews_lease(
        self,
    ) -> None:
        dashboard_group_id = "242424242424"
        group_id = "24242424242424242424"
        alert_id = "controlled-soc-dispatch-heartbeat"
        stable_key = "v2|controlled|soc-dispatch-heartbeat"
        dispatch_id = "2" * 64
        timestamp = "2020-01-01 00:00:00+00:00"
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, first_seen, last_seen, alert_json,
                    stable_group_id, stable_group_key, triage_level,
                    filter_status
                ) VALUES (?, ?, ?, ?, ?, ?, 'medium', 'accepted')
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    json.dumps({"alert_id": alert_id}),
                    group_id,
                    stable_key,
                ),
            )
            connection.execute(
                """
                INSERT INTO alert_group_summary (
                    group_id, group_key, representative_alert_id,
                    first_seen, last_seen, raw_alert_count,
                    total_seen_count, triage_level, filter_status, updated_at
                ) VALUES (?, ?, ?, ?, ?, 1, 1, 'medium', 'accepted', ?)
                """,
                (
                    dashboard_group_id,
                    stable_key,
                    alert_id,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()

        self.start_controlled()
        request_payload = {
            "group_id": dashboard_group_id,
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_key,
            "cohort_id": "controlled-cohort-soc-dispatch",
            "dispatch_id": dispatch_id,
            "release_id": RELEASE_ID,
            **CONTROLLED_ROUTE_FIELDS,
            "requested_by": "controlled-runtime-test",
            "reason": "Prove controlled SOC dispatch role survives heartbeat.",
        }
        status, receipt = request_json(
            f"{self.base_url}/ai/request",
            "POST",
            request_payload,
        )
        self.assertEqual(status, 202, receipt)

        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            job_id, payload_json = connection.execute(
                """
                SELECT id, payload_json
                FROM durable_jobs
                WHERE job_type = 'ai_analysis' AND dedupe_key = ?
                """,
                (group_id,),
            ).fetchone()
        stored_payload = json.loads(payload_json)
        self.assertEqual(stored_payload["agent_role"], "soc-analyst")

        claim_status, claim = self.claim_controlled_job(
            job_id=int(job_id),
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(claim_status, 200, claim)
        heartbeat_status, heartbeat = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(heartbeat_status, 200, heartbeat)
        self.assertEqual(
            heartbeat["lease_token"],
            claim["lease_token"],
        )
        release_status, release = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "failed",
                "error": "controlled test releases the lease",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(release_status, 200, release)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("pending", 1, None, None),
            )


    def test_exact_claim_rejects_missing_role_before_acquiring_lease(
        self,
    ) -> None:
        frozen = {
            "group_id": "25252525252525252525",
            "alert_id": "controlled-alert-missing-role",
            "stable_group_key": "v2|controlled|missing-role",
            "dispatch_id": "2" * 63 + "5",
        }
        job_id = self.seed_controlled_job(
            **frozen,
            agent_role=None,
        )
        self.start_controlled()
        status, response = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 409, response)
        self.assertEqual(response["status"], "rejected")
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("pending", 0, None, None),
            )


    def test_controlled_dispatch_rejects_same_model_different_effort(self) -> None:
        case_id = "ir-controlled-same-model-dispatch"
        group_id = "29292929292929292929"
        alert_id = "controlled-alert-same-model-dispatch"
        stable_key = "v2|controlled|same-model-dispatch"
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
        )
        self.start_controlled()
        status, rejected = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            {
                "case_id": case_id,
                "representative_alert_id": alert_id,
                "stable_group_id": group_id,
                "stable_group_key": stable_key,
                "cohort_id": "controlled-same-model-dispatch",
                "dispatch_id": "2" * 63 + "9",
                "release_id": RELEASE_ID,
                "expected_assigned_route": PRIMARY_ROUTE,
                "expected_reviewer_route": "codex-cli:gpt-5.5:xhigh",
                "reviewer_required": True,
                "requested_by": "controlled-runtime-test",
                "reason": "Reject a reviewer using the primary model base.",
            },
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM durable_jobs WHERE dedupe_key = ?",
                    (group_id,),
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT agent_status FROM incident_response_cases "
                    "WHERE case_id = ?",
                    (case_id,),
                ).fetchone()[0],
                "analyzed",
            )


    def test_exact_claim_requires_all_seven_route_bound_fields(self) -> None:
        frozen = {
            "group_id": "30303030303030303030",
            "alert_id": "controlled-alert-seven-field-claim",
            "stable_group_key": "v2|controlled|seven-field-claim",
            "dispatch_id": "3" * 64,
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        base = {
            "job_type": "ai_analysis",
            "dedupe_key": frozen["group_id"],
            "status": "processing",
            "error": "",
            "lease_token": "",
            "retryable": True,
            "expected_job_id": job_id,
            "expected_representative_alert_id": frozen["alert_id"],
            "expected_dispatch_id": frozen["dispatch_id"],
            "expected_stable_group_key": frozen["stable_group_key"],
            **CONTROLLED_ROUTE_FIELDS,
        }
        mutations = {
            "missing-reviewer-route": lambda item: item.pop(
                "expected_reviewer_route"
            ),
            "drifted-reviewer-route": lambda item: item.__setitem__(
                "expected_reviewer_route", "codex-cli:gpt-5.6-terra:xhigh"
            ),
            "same-model-different-effort": lambda item: item.__setitem__(
                "expected_reviewer_route", "codex-cli:gpt-5.5:xhigh"
            ),
            "reviewer-not-required": lambda item: item.__setitem__(
                "reviewer_required", False
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                request = dict(base)
                mutate(request)
                status, rejected = request_json(
                    f"{self.base_url}/jobs/status", "POST", request
                )
                self.assertEqual(status, 409, rejected)
                with closing(sqlite3.connect(self.db, timeout=5)) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT status, attempt_count, lease_token "
                            "FROM durable_jobs WHERE id = ?",
                            (job_id,),
                        ).fetchone(),
                        ("pending", 0, None),
                    )


    def test_claimed_job_rejects_role_drift_before_heartbeat_or_result(
        self,
    ) -> None:
        frozen = {
            "group_id": "26262626262626262626",
            "alert_id": "controlled-alert-role-drift",
            "stable_group_key": "v2|controlled|role-drift",
            "dispatch_id": "2" * 63 + "6",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)

        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored_payload = json.loads(
                connection.execute(
                    "SELECT payload_json FROM durable_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()[0]
            )
            stored_payload["agent_role"] = "SOC-ANALYST"
            connection.execute(
                "UPDATE durable_jobs SET payload_json = ? WHERE id = ?",
                (
                    json.dumps(
                        stored_payload,
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    job_id,
                ),
            )
            connection.commit()

        heartbeat_status, heartbeat = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": frozen["group_id"],
                "status": "processing",
                "error": "",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(heartbeat_status, 409, heartbeat)

        result_payload = self.controlled_result_payload(
            analysis_id="controlled-role-drift-result",
            claim=claim,
        )
        result_status, result = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(result_status, 409, result)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("processing", 1, claim["lease_token"]),
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM ai_analysis_runs
                    WHERE analysis_id = 'controlled-role-drift-result'
                    """
                ).fetchone()[0],
                0,
            )


    def test_controlled_worker_clients_propagate_ephemeral_token(
        self,
    ) -> None:
        frozen = {
            "group_id": "10101010101010101010",
            "alert_id": "controlled-alert-client-token",
            "stable_group_key": "v2|controlled|client-token",
            "dispatch_id": "1" * 63 + "0",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        controlled_environment = {
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
        }
        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            claim = self.scheduler.report_ai_job_status(
                self.base_url,
                frozen["group_id"],
                "processing",
                expected_job_id=job_id,
                expected_representative_alert_id=frozen["alert_id"],
                expected_dispatch_id=frozen["dispatch_id"],
                expected_stable_group_key=frozen["stable_group_key"],
                expected_assigned_route=PRIMARY_ROUTE,
                expected_reviewer_route=REVIEWER_ROUTE,
                reviewer_required=True,
            )
            self.assertIsInstance(
                claim,
                self.scheduler.ClaimedAiLease,
            )
            payload = self.controlled_result_payload(
                analysis_id="controlled-client-token-result",
                claim={
                    "lease_token": str(claim),
                    "claim": {
                        "job_id": claim.job_id,
                        "payload": claim.job_payload,
                    },
                },
            )
            receipt = self.runner.post_analysis_index(
                payload,
                self.base_url,
            )
            self.assertEqual(
                receipt["analysis_id"],
                "controlled-client-token-result",
            )
            replay = self.scheduler.post_controlled_recovery_result(
                payload,
                self.base_url,
                attempts=1,
            )
        self.assertTrue(replay["ok"])
        self.assertEqual(
            replay["analysis_id"],
            "controlled-client-token-result",
        )


    def test_lost_claim_response_replays_same_raw_lease(self) -> None:
        frozen = {
            "group_id": "12121212121212121212",
            "alert_id": "controlled-alert-lost-claim",
            "stable_group_key": "v2|controlled|lost-claim",
            "dispatch_id": "1" * 63 + "2",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()

        # Treat the first successful POST as committed with its response lost.
        first_status, first_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        second_status, second_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(first_status, 200, first_claim)
        self.assertEqual(second_status, 200, second_claim)
        self.assertEqual(second_claim, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("processing", 1, first_claim["lease_token"]),
            )


    def test_exact_claim_replays_after_alert_store_restart(self) -> None:
        frozen = {
            "group_id": "13131313131313131313",
            "alert_id": "controlled-alert-restart-claim",
            "stable_group_key": "v2|controlled|restart-claim",
            "dispatch_id": "1" * 63 + "3",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        first_status, first_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(first_status, 200, first_claim)
        stop_process(self.process)
        self.process = None
        self.start_controlled()

        replay_status, replay_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(replay_status, 200, replay_claim)
        self.assertEqual(replay_claim, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            attempt_count, lease_expires_at = connection.execute(
                """
                SELECT attempt_count, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(attempt_count, 1)
        self.assertGreater(
            dt.datetime.fromisoformat(
                lease_expires_at.replace("Z", "+00:00")
            ).timestamp(),
            time.time(),
        )


    def test_inflight_heartbeat_and_failure_survive_restart_and_expiry(
        self,
    ) -> None:
        frozen = {
            "group_id": "15151515151515151515",
            "alert_id": "controlled-alert-heartbeat-restart",
            "stable_group_key": "v2|controlled|heartbeat-restart",
            "dispatch_id": "1" * 63 + "5",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(job_id=job_id, **frozen)
        self.assertEqual(status, 200, claim)
        stop_process(self.process)
        self.process = None
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "UPDATE durable_jobs SET lease_expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00.000Z", job_id),
            )
            connection.commit()
        self.start_controlled()

        heartbeat_status, heartbeat = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": frozen["group_id"],
                "status": "processing",
                "error": "",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(heartbeat_status, 200, heartbeat)
        self.assertEqual(heartbeat["lease_token"], claim["lease_token"])
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            attempt_count, lease_expires_at = connection.execute(
                """
                SELECT attempt_count, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(attempt_count, 1)
        self.assertGreater(
            dt.datetime.fromisoformat(
                lease_expires_at.replace("Z", "+00:00")
            ).timestamp(),
            time.time(),
        )

        failure_status, failure = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": frozen["group_id"],
                "status": "failed",
                "error": "controlled worker interrupted",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(failure_status, 200, failure)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("pending", 1, None, None),
            )


    def test_production_exact_identity_cannot_replay_processing_lease(
        self,
    ) -> None:
        frozen = {
            "group_id": "16161616161616161616",
            "alert_id": "production-alert-exact-fields",
            "stable_group_key": "v2|production|exact-fields",
            "dispatch_id": "1" * 63 + "6",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_production()
        request_payload = {
            "job_type": "ai_analysis",
            "dedupe_key": frozen["group_id"],
            "status": "processing",
            "error": "",
            "lease_token": "",
            "retryable": True,
            "expected_job_id": job_id,
            "expected_representative_alert_id": frozen["alert_id"],
            "expected_dispatch_id": frozen["dispatch_id"],
            "expected_stable_group_key": frozen["stable_group_key"],
        }
        first_status, first = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            request_payload,
        )
        self.assertEqual(first_status, 200, first)
        self.assertTrue(first["lease_token"])
        self.assertNotIn("job_id", first["claim"])

        replay_status, replay = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            request_payload,
        )
        self.assertEqual(replay_status, 404, replay)
        self.assertIsNone(replay["lease_token"])
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("processing", 1, first["lease_token"]),
            )


    def test_expired_exact_claim_replays_without_new_attempt(self) -> None:
        frozen = {
            "group_id": "14141414141414141414",
            "alert_id": "controlled-alert-expired-claim",
            "stable_group_key": "v2|controlled|expired-claim",
            "dispatch_id": "1" * 63 + "4",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, first_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "UPDATE durable_jobs SET lease_expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00.000Z", job_id),
            )
            connection.commit()

        replay_status, replay_claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(replay_status, 200, replay_claim)
        self.assertEqual(replay_claim, first_claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            attempt_count, lease_expires_at = connection.execute(
                """
                SELECT attempt_count, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(attempt_count, 1)
        self.assertGreater(
            dt.datetime.fromisoformat(
                lease_expires_at.replace("Z", "+00:00")
            ).timestamp(),
            time.time(),
        )


    def test_second_global_claim_is_rejected_without_changing_candidate(
        self,
    ) -> None:
        first = {
            "group_id": "22222222222222222222",
            "alert_id": "controlled-alert-first",
            "stable_group_key": "v2|controlled|first",
            "dispatch_id": "2" * 64,
        }
        second = {
            "group_id": "33333333333333333333",
            "alert_id": "controlled-alert-second",
            "stable_group_key": "v2|controlled|second",
            "dispatch_id": "3" * 64,
        }
        first_id = self.seed_controlled_job(**first)
        second_id = self.seed_controlled_job(**second)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=first_id,
            **first,
        )
        self.assertEqual(status, 200, claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = connection.execute(
                """
                SELECT status, attempt_count, lease_token, lease_expires_at,
                       payload_json, updated_at
                FROM durable_jobs WHERE id = ?
                """,
                (second_id,),
            ).fetchone()
        status, rejected = self.claim_controlled_job(
            job_id=second_id,
            **second,
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            after = connection.execute(
                """
                SELECT status, attempt_count, lease_token, lease_expires_at,
                       payload_json, updated_at
                FROM durable_jobs WHERE id = ?
                """,
                (second_id,),
            ).fetchone()
        self.assertEqual(after, before)
