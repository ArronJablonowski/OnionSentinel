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

class ControlledAlertStoreTestsRestartBlocksASecondGlobalProcessingClaimCases:
    def test_restart_blocks_a_second_global_processing_claim(self) -> None:
        first = {
            "group_id": "23232323232323232323",
            "alert_id": "controlled-alert-restart-first",
            "stable_group_key": "v2|controlled|restart-first",
            "dispatch_id": "2" * 63 + "3",
        }
        second = {
            "group_id": "34343434343434343434",
            "alert_id": "controlled-alert-restart-second",
            "stable_group_key": "v2|controlled|restart-second",
            "dispatch_id": "3" * 63 + "4",
        }
        first_id = self.seed_controlled_job(**first)
        second_id = self.seed_controlled_job(**second)
        self.start_controlled()
        self.assertEqual(
            self.claim_controlled_job(job_id=first_id, **first)[0],
            200,
        )
        stop_process(self.process)
        self.process = None
        self.start_controlled()
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


    def test_tampered_bound_result_is_rejected_without_committing(
        self,
    ) -> None:
        group_id = "66666666666666666666"
        alert_id = "controlled-alert-tampered"
        stable_key = "v2|controlled|tampered"
        dispatch_id = "6" * 64
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
            analysis_id="controlled-tampered-result",
            claim=claim,
        )
        result_payload["response"][
            "_analysis_controlled_claim_sha256"
        ] = "0" * 64
        status, rejected = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-tampered-result'"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM durable_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()[0],
                "processing",
            )


    def test_controlled_result_requires_exact_primary_and_reviewer_routes(
        self,
    ) -> None:
        frozen = {
            "group_id": "69696969696969696969",
            "alert_id": "controlled-alert-route-result",
            "stable_group_key": "v2|controlled|route-result",
            "dispatch_id": "6" * 63 + "9",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(job_id=job_id, **frozen)
        self.assertEqual(status, 200, claim)
        base = self.controlled_result_payload(
            analysis_id="controlled-route-result",
            claim=claim,
        )
        mutations = {
            "primary-route": lambda item: item["response"].__setitem__(
                "_analysis_model_route", "codex-cli:gpt-5.6-terra:high"
            ),
            "reviewer-route": lambda item: item["response"][
                "_second_opinion"
            ].__setitem__(
                "model_route", "codex-cli:gpt-5.6-terra:xhigh"
            ),
            "nested-reviewer-route": lambda item: item["response"][
                "_second_opinion"
            ]["response"].__setitem__(
                "_analysis_model_route", "codex-cli:gpt-5.6-terra:xhigh"
            ),
            "same-model-different-effort": lambda item: item["response"][
                "_second_opinion"
            ].__setitem__(
                "model_route", "codex-cli:gpt-5.5:xhigh"
            ),
        }
        for index, (label, mutate) in enumerate(mutations.items(), start=1):
            with self.subTest(label=label):
                candidate = json.loads(json.dumps(base))
                candidate["analysis_id"] = f"controlled-route-result-{index}"
                mutate(candidate)
                result_status, rejected = request_json(
                    f"{self.base_url}/analysis/result",
                    "POST",
                    candidate,
                )
                self.assertEqual(result_status, 409, rejected)
                with closing(sqlite3.connect(self.db, timeout=5)) as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT status, attempt_count, lease_token "
                            "FROM durable_jobs WHERE id = ?",
                            (job_id,),
                        ).fetchone(),
                        ("processing", 1, claim["lease_token"]),
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT COUNT(*) FROM ai_analysis_runs "
                            "WHERE analysis_id = ?",
                            (candidate["analysis_id"],),
                        ).fetchone()[0],
                        0,
                    )


    def test_committed_result_replay_rejects_response_content_change(
        self,
    ) -> None:
        frozen = {
            "group_id": "67676767676767676767",
            "alert_id": "controlled-alert-content-replay",
            "stable_group_key": "v2|controlled|content-replay",
            "dispatch_id": "6" * 63 + "7",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-content-replay",
            claim=claim,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        changed = json.loads(json.dumps(payload))
        changed["response"]["summary"] = (
            "Different content with the same controlled claim digest."
        )
        replay_status, rejected = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            changed,
        )
        self.assertEqual(replay_status, 409, rejected)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored, job = (
                connection.execute(
                    """
                    SELECT response_json FROM ai_analysis_runs
                    WHERE analysis_id = 'controlled-content-replay'
                    """
                ).fetchone()[0],
                connection.execute(
                    """
                    SELECT status, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
            )
        self.assertEqual(
            json.loads(stored)["summary"],
            payload["response"]["summary"],
        )
        self.assertEqual(job, ("completed", None, None))


    def test_exact_result_replays_after_restart_and_expired_claim(
        self,
    ) -> None:
        frozen = {
            "group_id": "68686868686868686868",
            "alert_id": "controlled-alert-expired-result",
            "stable_group_key": "v2|controlled|expired-result",
            "dispatch_id": "6" * 63 + "8",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "UPDATE durable_jobs SET lease_expires_at = ? WHERE id = ?",
                ("2000-01-01T00:00:00.000Z", job_id),
            )
            connection.commit()
        payload = self.controlled_result_payload(
            analysis_id="controlled-expired-result",
            claim=claim,
        )
        first_status, first_result = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(first_status, 200, first_result)
        stop_process(self.process)
        self.process = None
        self.start_controlled()
        replay_status, replay = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            payload,
        )
        self.assertEqual(replay_status, 200, replay)
        self.assertTrue(replay["idempotent"])
        self.assertEqual(
            replay["stored_response_sha256"],
            first_result["stored_response_sha256"],
        )
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


    def test_committed_result_survives_restart_and_spool_recovery(
        self,
    ) -> None:
        group_id = "44444444444444444444"
        alert_id = "controlled-alert-recovery"
        stable_key = "v2|controlled|recovery"
        dispatch_id = "4" * 64
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
            analysis_id="controlled-recovery-result",
            claim=claim,
        )
        evaluation_root = self.runtime / "harness-evaluations" / "rerun11"
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            result_payload,
            queue_dir=queue_dir,
        )

        # The server atomically commits the result and terminal job state, but
        # the worker never observes that response before the service restarts.
        status, committed = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 200, committed)
        stop_process(self.process)
        self.process = None
        self.start_controlled()

        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_stable_group_key=stable_key,
            only_dispatch_id=dispatch_id,
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "ONION_SENTINEL_EVALUATION_MODE": "1",
                    "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                    "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                },
                clear=False,
            ),
            mock.patch.object(
                self.scheduler,
                "run_analysis",
                side_effect=AssertionError(
                    "recovery invoked a second inference"
                ),
            ),
            mock.patch.object(
                self.scheduler,
                "report_ai_job_status",
                side_effect=AssertionError(
                    "controlled result recovery posted a second completion"
                ),
            ),
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )

        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            stored_response_json = connection.execute(
                "SELECT response_json FROM ai_analysis_runs "
                "WHERE analysis_id = 'controlled-recovery-result'"
            ).fetchone()[0]
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-recovery-result'"
                ).fetchone()[0],
                1,
            )
            job = connection.execute(
                """
                SELECT status, lease_token, lease_expires_at
                FROM durable_jobs WHERE id = ?
                """,
                (job_id,),
            ).fetchone()
        self.assertEqual(job, ("completed", None, None))
        lease_token = claim["lease_token"]
        self.assertNotIn(lease_token, stored_response_json)
        for artifact in evaluation_root.rglob("*"):
            if artifact.is_file():
                self.assertNotIn(
                    lease_token,
                    artifact.read_text(
                        encoding="utf-8",
                        errors="replace",
                    ),
                )


    def test_lost_completion_response_uses_exact_terminal_db_proof(
        self,
    ) -> None:
        group_id = "55555555555555555555"
        alert_id = "controlled-alert-terminal-proof"
        stable_key = "v2|controlled|terminal-proof"
        dispatch_id = "5" * 64
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
            analysis_id="controlled-terminal-proof",
            claim=claim,
        )
        evaluation_root = (
            self.runtime / "harness-evaluations" / "terminal-proof"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            result_payload,
            queue_dir=queue_dir,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                result_payload,
            )[0],
            200,
        )
        # Model the single atomic result/completion response being lost.
        stop_process(self.process)
        self.process = None
        self.start_controlled()
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_stable_group_key=stable_key,
            only_dispatch_id=dispatch_id,
        )
        with (
            mock.patch.dict(
                os.environ,
                {
                    "ONION_SENTINEL_EVALUATION_MODE": "1",
                    "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                    "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                },
                clear=False,
            ),
            mock.patch.object(
                self.scheduler,
                "report_ai_job_status",
                side_effect=AssertionError(
                    "controlled result recovery posted a second completion"
                ),
            ),
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )
        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM ai_analysis_runs "
                    "WHERE analysis_id = 'controlled-terminal-proof'"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status, lease_token FROM durable_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone(),
                ("completed", None),
            )


    def test_http_unavailable_recovery_uses_terminal_db_proof(
        self,
    ) -> None:
        frozen = {
            "group_id": "57575757575757575757",
            "alert_id": "controlled-alert-offline-terminal-proof",
            "stable_group_key": "v2|controlled|offline-terminal-proof",
            "dispatch_id": "5" * 63 + "7",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        payload = self.controlled_result_payload(
            analysis_id="controlled-offline-terminal-proof",
            claim=claim,
        )
        evaluation_root = (
            self.runtime
            / "harness-evaluations"
            / "offline-terminal-proof"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            payload,
            queue_dir=queue_dir,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                payload,
            )[0],
            200,
        )
        unavailable_url = self.base_url
        stop_process(self.process)
        self.process = None

        args = SimpleNamespace(
            db=self.db,
            alert_store_url=unavailable_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            },
            clear=False,
        ):
            self.assertTrue(
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
            )

        self.assertFalse(spool_path.exists())
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(
                connection.execute(
                    """
                    SELECT status, lease_token, lease_expires_at
                    FROM durable_jobs WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone(),
                ("completed", None, None),
            )


    def test_deterministic_replay_conflict_never_uses_subset_db_proof(
        self,
    ) -> None:
        frozen = {
            "group_id": "67676767676767676767",
            "alert_id": "controlled-alert-deterministic-conflict",
            "stable_group_key": "v2|controlled|deterministic-conflict",
            "dispatch_id": "6" * 63 + "7",
        }
        job_id = self.seed_controlled_job(**frozen)
        self.start_controlled()
        status, claim = self.claim_controlled_job(
            job_id=job_id,
            **frozen,
        )
        self.assertEqual(status, 200, claim)
        accepted_payload = self.controlled_result_payload(
            analysis_id="controlled-deterministic-conflict",
            claim=claim,
        )
        self.assertEqual(
            request_json(
                f"{self.base_url}/analysis/result",
                "POST",
                accepted_payload,
            )[0],
            200,
        )
        conflicting_payload = json.loads(json.dumps(accepted_payload))
        conflicting_payload["generated_at"] = (
            "2026-07-27 12:02:00+00:00"
        )
        evaluation_root = (
            self.runtime
            / "harness-evaluations"
            / "deterministic-conflict"
        )
        queue_dir = evaluation_root / "analysis-index-pending"
        queue_dir.mkdir(parents=True, mode=0o700)
        evaluation_root.chmod(0o700)
        queue_dir.chmod(0o700)
        spool_path = self.runner.queue_analysis_index(
            conflicting_payload,
            queue_dir=queue_dir,
        )
        args = SimpleNamespace(
            db=self.db,
            alert_store_url=self.base_url,
            only_group_id=frozen["group_id"],
            only_alert_id=frozen["alert_id"],
            only_stable_group_key=frozen["stable_group_key"],
            only_dispatch_id=frozen["dispatch_id"],
        )
        with mock.patch.dict(
            os.environ,
            {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            },
            clear=False,
        ):
            for field, changed_value in (
                ("generated_at", "2026-07-27 12:02:00+00:00"),
                ("model", "different-controlled-model"),
                ("model_path", "different-model-path"),
                ("artifact_path", "/different/evaluation/result.json"),
                ("evidence_hash", "f" * 64),
            ):
                with self.subTest(immutable_field=field):
                    changed_payload = json.loads(
                        json.dumps(accepted_payload)
                    )
                    changed_payload[field] = changed_value
                    changed_recovery = (
                        self.scheduler.validate_controlled_recovery_payload(
                            changed_payload,
                            args,
                        )
                    )
                    self.assertFalse(
                        self.scheduler.controlled_recovery_terminal_success(
                            args,
                            changed_recovery,
                        )
                    )
            recovery = self.scheduler.validate_controlled_recovery_payload(
                conflicting_payload,
                args,
            )
            self.assertFalse(
                self.scheduler.controlled_recovery_terminal_success(
                    args,
                    recovery,
                )
            )
            with self.assertRaisesRegex(RuntimeError, "HTTP 409"):
                self.scheduler.recover_controlled_evaluation_spool(
                    args,
                    evaluation_root,
                )
        self.assertTrue(spool_path.exists())
