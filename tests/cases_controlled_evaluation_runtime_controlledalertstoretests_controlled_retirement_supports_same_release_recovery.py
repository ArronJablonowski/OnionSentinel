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

class ControlledAlertStoreTestsControlledRetirementSupportsSameReleaseRecoveryCases:
    def test_controlled_retirement_supports_same_release_recovery(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-same-release",
            dispatch_id=hashlib.sha256(
                b"retirement-same-release"
            ).hexdigest(),
            prior_analysis_id="",
            member_rank=1,
            cohort_size=1,
            retired_release_id=REPLACEMENT_RELEASE_ID,
            replacement_release_id=REPLACEMENT_RELEASE_ID,
        )
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertEqual(
            receipt["identity"]["retired_release_id"],
            REPLACEMENT_RELEASE_ID,
        )
        self.assertEqual(
            receipt["identity"]["replacement_release_id"],
            REPLACEMENT_RELEASE_ID,
        )
        status, replay = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay, receipt)


    def test_controlled_retirement_rank_twenty_is_generic(
        self,
    ) -> None:
        retirement, context = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-rank-twenty",
            dispatch_id=hashlib.sha256(
                b"retirement-rank-twenty"
            ).hexdigest(),
            member_rank=20,
            cohort_size=20,
        )
        self.assertEqual(len(context["completed_members"]), 19)
        self.assertEqual(retirement["absent_dispatch_ids"], [])
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertEqual(receipt["identity"]["member_rank"], 20)
        self.assertEqual(receipt["target_before"]["state"], "pending")
        self.assertEqual(receipt["target_after"]["state"], "retired")
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            job = connection.execute(
                "SELECT status FROM durable_jobs WHERE id = ?",
                (retirement["job_id"],),
            ).fetchone()
        self.assertEqual(job[0], "completed")


    def test_controlled_retirement_replay_rejects_noncanonical_store(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-noncanonical-replay",
            dispatch_id=hashlib.sha256(
                b"retirement-noncanonical-replay"
            ).hexdigest(),
            member_rank=1,
            cohort_size=1,
        )
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE incident_response_events
                SET detail_json = ?
                WHERE case_id = ?
                  AND event_type = 'controlled_evaluation_retired'
                """,
                (
                    json.dumps(receipt, ensure_ascii=False),
                    retirement["case_id"],
                ),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(
            rejected["reason"],
            (
                "controlled evaluation retirement receipt "
                "is not canonical"
            ),
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_middle_rank_is_generic(
        self,
    ) -> None:
        retirement, context = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-rank-ten",
            dispatch_id=hashlib.sha256(
                b"retirement-rank-ten"
            ).hexdigest(),
            member_rank=10,
            cohort_size=20,
        )
        self.assertEqual(len(context["completed_members"]), 9)
        self.assertEqual(len(retirement["absent_dispatch_ids"]), 10)
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertEqual(receipt["identity"]["member_rank"], 10)
        self.assertEqual(receipt["target_before"]["rank"], 10)
        self.assertEqual(receipt["target_after"]["rank"], 10)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            job = connection.execute(
                "SELECT status FROM durable_jobs WHERE id = ?",
                (retirement["job_id"],),
            ).fetchone()
        self.assertEqual(job[0], "completed")


    def test_controlled_retirement_rejects_coercive_numeric_types(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        for field in (
            "job_id",
            "member_rank",
            "cohort_size",
            "expected_attempt_count",
        ):
            for replacement in (str(retirement[field]), True):
                with self.subTest(
                    field=field,
                    replacement_type=type(replacement).__name__,
                ):
                    changed = dict(retirement)
                    changed[field] = replacement
                    status, rejected = request_json(
                        (
                            f"{self.base_url}"
                            "/controlled-evaluations/retire"
                        ),
                        "POST",
                        changed,
                    )
                    self.assertEqual(status, 409, rejected)
                    self.assertEqual(
                        rejected["reason"],
                        (
                            "controlled evaluation retirement identity "
                            "is invalid"
                        ),
                    )
                    with closing(
                        sqlite3.connect(self.db, timeout=5)
                    ) as connection:
                        self.assertEqual(
                            tuple(connection.iterdump()),
                            before,
                        )
        malformed_requests = []
        missing = dict(retirement)
        missing.pop("reason")
        malformed_requests.append(("missing-field", missing))
        extra = dict(retirement)
        extra["unexpected"] = "not allowed"
        malformed_requests.append(("extra-field", extra))
        for label, changed in malformed_requests:
            with self.subTest(malformed=label):
                status, rejected = request_json(
                    (
                        f"{self.base_url}"
                        "/controlled-evaluations/retire"
                    ),
                    "POST",
                    changed,
                )
                self.assertEqual(status, 409, rejected)
                with closing(
                    sqlite3.connect(self.db, timeout=5)
                ) as connection:
                    self.assertEqual(
                        tuple(connection.iterdump()),
                        before,
                    )


    def test_controlled_retirement_rejects_execution_telemetry_drift(
        self,
    ) -> None:
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )
        member = context["completed_members"][0]
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE incident_reanalysis_run_cases
                SET executed_model = 'contradictory-model',
                    executed_provider = 'contradictory-provider',
                    executed_model_path = 'contradictory-path'
                WHERE run_id = ?
                """,
                (member["run_id"],),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_attempts
                SET executed_model = 'contradictory-model',
                    executed_provider = 'contradictory-provider',
                    executed_model_path = 'contradictory-path'
                WHERE run_id = ?
                """,
                (member["run_id"],),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertIn(
            "completed primary-and-reviewer lineage",
            rejected["reason"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_rejects_reviewer_primary_drift(
        self,
    ) -> None:
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )
        member = context["completed_members"][0]
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE ai_second_opinion_runs
                SET primary_model = 'contradictory-model',
                    primary_model_path = 'contradictory-path',
                    primary_outcome = 'contradictory-outcome',
                    primary_confidence = 'contradictory-confidence'
                WHERE analysis_id = ?
                """,
                (member["analysis_id"],),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertIn(
            "completed primary-and-reviewer lineage",
            rejected["reason"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_rejects_contradictory_failure_records(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                UPDATE durable_jobs SET last_error = 'job failure'
                WHERE id = ?
                """,
                (retirement["job_id"],),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_run_cases
                SET latest_error = 'run case failure'
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    retirement["reanalysis_run_id"],
                    retirement["case_id"],
                ),
            )
            connection.execute(
                """
                UPDATE incident_reanalysis_attempts
                SET latest_error = 'attempt failure'
                WHERE attempt_id = ?
                """,
                (retirement["expected_attempt_id"],),
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(
            rejected["reason"],
            (
                "controlled evaluation target failure lineage "
                "is contradictory"
            ),
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_uses_worker_error_normalization(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute(
                """
                UPDATE durable_jobs
                SET last_error = '  Synthetic   controlled worker failure.  '
                WHERE id = ?
                """,
                (retirement["job_id"],),
            )
            connection.commit()
            job_error = connection.execute(
                "SELECT last_error FROM durable_jobs WHERE id = ?",
                (retirement["job_id"],),
            ).fetchone()["last_error"]
            run_case_error = connection.execute(
                """
                SELECT latest_error FROM incident_reanalysis_run_cases
                WHERE run_id = ? AND case_id = ?
                """,
                (
                    retirement["reanalysis_run_id"],
                    retirement["case_id"],
                ),
            ).fetchone()["latest_error"]
            attempt_error = connection.execute(
                """
                SELECT latest_error FROM incident_reanalysis_attempts
                WHERE attempt_id = ?
                """,
                (retirement["expected_attempt_id"],),
            ).fetchone()["latest_error"]
        self.assertNotEqual(job_error, run_case_error)
        self.assertEqual(run_case_error, attempt_error)
        normalized_errors = {
            " ".join(value.strip().split())[:1000]
            for value in (job_error, run_case_error, attempt_error)
        }
        self.assertEqual(
            normalized_errors,
            {"Synthetic controlled worker failure."},
        )
        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        failure = receipt["target_before"]["failure"]
        self.assertNotEqual(
            failure["job"]["raw_sha256"],
            failure["run_case"]["raw_sha256"],
        )
        self.assertEqual(
            failure["job"]["normalized_sha256"],
            failure["run_case"]["normalized_sha256"],
        )
        self.assertEqual(
            failure["job"]["normalized_sha256"],
            failure["attempt"]["normalized_sha256"],
        )
        self.assertNotEqual(
            receipt["lineage_before_sha256"],
            receipt["lineage_after_sha256"],
        )


    def test_controlled_retirement_rolls_back_after_late_failure(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                CREATE TRIGGER inject_controlled_retirement_failure
                BEFORE INSERT ON incident_response_events
                WHEN NEW.event_type = 'controlled_evaluation_retired'
                BEGIN
                  SELECT RAISE(ABORT, 'injected late retirement failure');
                END
                """
            )
            connection.commit()
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 400, rejected)
        self.assertEqual(
            rejected["reason"],
            "SQLITE_CONSTRAINT: injected late retirement failure",
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_rejects_incomplete_completed_lineage(
        self,
    ) -> None:
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )
        missing = context["completed_members"][2]
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                DELETE FROM ai_second_opinion_runs
                WHERE analysis_id = ?
                """,
                (missing["analysis_id"],),
            )
            connection.commit()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertIn(
            "completed primary-and-reviewer lineage",
            rejected["reason"],
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_rejects_nonabsent_later_rank(
        self,
    ) -> None:
        retirement, _ = self.prepare_failed_controlled_retirement()
        timestamp = "2020-01-01T00:01:00Z"
        group_id = "abababababababababab"
        alert_id = "unexpected-controlled-rank-eight"
        job_payload = {
            "agent_role": "incident-responder",
            "case_id": "ir-unexpected-controlled-rank-eight",
            "alert_id": alert_id,
            "group_id": group_id,
            "dashboard_group_id": group_id[:12],
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": "v2|controlled|unexpected-rank-eight",
            "cohort_id": retirement["cohort_id"],
            "dispatch_id": retirement["absent_dispatch_ids"][0],
            "release_id": RELEASE_ID,
            "reanalysis_run_id": "irr-unexpected-controlled-rank-eight",
            "reanalysis_release_id": RELEASE_ID,
            "manual_reanalysis": True,
        }
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO durable_jobs (
                    job_type, dedupe_key, payload_json, status, priority,
                    attempt_count, max_attempts, next_attempt_at,
                    created_at, updated_at, requested_at, rerun_requested
                ) VALUES (
                    'incident_response_analysis', ?, ?, 'pending',
                    1200, 0, 12, ?, ?, ?, ?, 0
                )
                """,
                (
                    group_id,
                    json.dumps(job_payload, separators=(",", ":")),
                    timestamp,
                    timestamp,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(
            rejected["reason"],
            "controlled evaluation cohort job/run census is not exact",
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_retirement_route_is_denied_in_production_mode(
        self,
    ) -> None:
        self.start_production()
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            before = tuple(connection.iterdump())
        status, response = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            {},
        )
        self.assertEqual(status, 403, response)
        self.assertEqual(
            response["reason"],
            (
                "controlled evaluation retirement is unavailable "
                "in production mode"
            ),
        )
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), before)


    def test_controlled_incident_dispatch_is_idempotent_after_lost_response(
        self,
    ) -> None:
        case_id = "ir-controlled-dispatch-replay"
        group_id = "71717171717171717171"
        alert_id = "controlled-incident-dispatch-alert"
        stable_group_key = "v2|controlled|incident-dispatch-replay"
        dispatch_id = "7" * 64
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_group_key,
        )
        self.start_controlled()
        payload = {
            "case_id": case_id,
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "cohort_id": "controlled-cohort-ir-replay",
            "dispatch_id": dispatch_id,
            "release_id": RELEASE_ID,
            **CONTROLLED_ROUTE_FIELDS,
            "requested_by": "controlled-runtime-test",
            "reason": "Prove exact controlled dispatch replay.",
        }

        status, first_receipt = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            payload,
        )
        self.assertEqual(status, 202, first_receipt)
        self.assertTrue(first_receipt["ok"])
        self.assertEqual(first_receipt["case_id"], case_id)
        self.assertEqual(first_receipt["dispatch_id"], dispatch_id)

        def database_snapshot() -> tuple[dict[str, int], tuple[str, ...]]:
            with closing(sqlite3.connect(self.db, timeout=5)) as connection:
                tables = [
                    str(row[0])
                    for row in connection.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                        ORDER BY name
                        """
                    )
                ]
                counts = {
                    table: int(
                        connection.execute(
                            f'SELECT COUNT(*) FROM "{table}"'
                        ).fetchone()[0]
                    )
                    for table in tables
                }
                logical_dump = tuple(connection.iterdump())
            return counts, logical_dump

        after_first = database_snapshot()
        status, replay_receipt = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            payload,
        )
        self.assertEqual(status, 202, replay_receipt)
        self.assertEqual(replay_receipt, first_receipt)
        self.assertEqual(database_snapshot(), after_first)

        conflicting_payload = dict(payload)
        conflicting_payload["reason"] = (
            "The same dispatch cannot be rebound to changed request fields."
        )
        status, conflict = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            conflicting_payload,
        )
        self.assertEqual(status, 409, conflict)
        self.assertEqual(conflict["status"], "rejected")
        self.assertEqual(database_snapshot(), after_first)


    def test_exact_claim_result_atomically_completes_job(self) -> None:
        group_id = "11111111111111111111"
        alert_id = "controlled-alert-happy"
        stable_key = "v2|controlled|happy"
        dispatch_id = "1" * 64
        job_id = self.seed_controlled_job(
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_key,
            dispatch_id=dispatch_id,
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_result_payload(
            analysis_id="controlled-happy-result",
            claim=claim,
        )
        status, result = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 200, result)
        status, rejected = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "failed",
                "error": "must not erase a committed result",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, attempt_count, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("completed", 1, None, None),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-happy-result'"
                ).fetchone()[0],
                1,
            )
