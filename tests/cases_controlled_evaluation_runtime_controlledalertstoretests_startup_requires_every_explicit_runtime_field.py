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

class ControlledAlertStoreTestsStartupRequiresEveryExplicitRuntimeFieldCases:
    def test_startup_requires_every_explicit_runtime_field(self) -> None:
        for key in (
            "ALERT_STORE_DB",
            "ALERT_STORE_HOST",
            "ALERT_STORE_PORT",
            "SCORING_RULES_PATH",
            "ONION_SENTINEL_EVALUATION_TOKEN",
        ):
            with self.subTest(key=key):
                environment = self.controlled_environment()
                del environment[key]
                self.assert_startup_rejected(
                    environment,
                    "controlled evaluation requires loopback",
                )


    def test_startup_rejects_production_and_non_loopback_listeners(self) -> None:
        cases = (
            ("production-port", "127.0.0.1", "8787"),
            ("wildcard-host", "0.0.0.0", str(available_port())),
        )
        for label, host, port in cases:
            with self.subTest(case=label):
                environment = self.controlled_environment()
                environment["ALERT_STORE_HOST"] = host
                environment["ALERT_STORE_PORT"] = port
                self.assert_startup_rejected(
                    environment,
                    "controlled evaluation requires loopback",
                )


    def test_startup_rejects_invalid_mode_identity_and_scoring_file(self) -> None:
        invalid_mode = sanitized_environment()
        invalid_mode["ONION_SENTINEL_EVALUATION_MODE"] = "true"
        self.assert_startup_rejected(
            invalid_mode,
            "ONION_SENTINEL_EVALUATION_MODE must be unset, 0, or 1",
        )

        for label, key, value in (
            ("release", "ONION_SENTINEL_RELEASE_ID", "not-a-release"),
            ("token", "ONION_SENTINEL_EVALUATION_TOKEN", "not-a-token"),
            ("privileged-port", "ALERT_STORE_PORT", "1023"),
            ("unsafe-port", "ALERT_STORE_PORT", "65536"),
            ("non-integer-port", "ALERT_STORE_PORT", "not-a-port"),
        ):
            with self.subTest(case=label):
                environment = self.controlled_environment()
                environment[key] = value
                self.assert_startup_rejected(
                    environment,
                    "controlled evaluation requires loopback",
                )

        linked_rules = self.runtime / "linked-scoring-rules.json"
        linked_rules.symlink_to(self.rules)
        environment = self.controlled_environment()
        environment["SCORING_RULES_PATH"] = str(linked_rules)
        self.assert_startup_rejected(
            environment,
            "controlled evaluation scoring rules must be an owner-controlled regular file",
        )

        self.rules.chmod(0o660)
        try:
            self.assert_startup_rejected(
                self.controlled_environment(),
                "controlled evaluation scoring rules must be an owner-controlled regular file",
            )
        finally:
            self.rules.chmod(0o600)


    def test_startup_rejects_sidecars_credentials_and_unsafe_database(self) -> None:
        sidecar = Path(f"{self.db}-journal")
        sidecar.write_bytes(b"")
        try:
            self.assert_startup_rejected(
                self.controlled_environment(),
                "controlled evaluation refuses database recovery sidecar",
            )
        finally:
            sidecar.unlink(missing_ok=True)

        for credential_key in sorted(CONTROLLED_CREDENTIAL_KEYS):
            with self.subTest(credential=credential_key):
                environment = self.controlled_environment()
                environment[credential_key] = "must-not-enter-evaluation"
                self.assert_startup_rejected(
                    environment,
                    "and no configured production credentials",
                )

        self.db.chmod(0o660)
        try:
            self.assert_startup_rejected(
                self.controlled_environment(),
                "database must be an owner-controlled regular file",
            )
        finally:
            self.db.chmod(0o600)

        linked_db = self.runtime / "linked.sqlite3"
        linked_db.symlink_to(self.db)
        environment = self.controlled_environment()
        environment["ALERT_STORE_DB"] = str(linked_db)
        self.assert_startup_rejected(
            environment,
            "database must be an owner-controlled regular file",
        )


    def test_startup_rejects_pre_idempotency_schema_and_index_drift(
        self,
    ) -> None:
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "DROP INDEX "
                "idx_incident_reanalysis_runs_controlled_dispatch"
            )
            connection.execute(
                "ALTER TABLE incident_reanalysis_runs "
                "DROP COLUMN controlled_receipt_json"
            )
            connection.execute(
                "ALTER TABLE incident_reanalysis_runs "
                "DROP COLUMN controlled_dispatch_id"
            )
            connection.commit()
        self.assert_startup_rejected(
            self.controlled_environment(),
            (
                "controlled evaluation schema is missing "
                "incident_reanalysis_runs columns"
            ),
        )

        shutil.copy2(self.template_db, self.db)
        self.db.chmod(0o600)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                "DROP INDEX "
                "idx_incident_reanalysis_runs_controlled_dispatch"
            )
            connection.commit()
        self.assert_startup_rejected(
            self.controlled_environment(),
            (
                "controlled evaluation schema is missing incident "
                "reanalysis dispatch uniqueness"
            ),
        )


    def test_health_route_allowlist_and_lifecycle_are_exact_and_read_only(
        self,
    ) -> None:
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        _status, health = self.start_controlled()

        self.assertEqual(health["service"], "onion-sentinel-alert-store")
        self.assertEqual(health["release_id"], RELEASE_ID)
        self.assertTrue(health["controlled_evaluation"])
        self.assertTrue(health["evaluation_mode"])
        self.assertEqual(health["runtime_mode"], "controlled-evaluation")
        self.assertEqual(health["listen_host"], "127.0.0.1")
        self.assertEqual(health["listen_port"], int(self.base_url.rsplit(":", 1)[1]))
        self.assertTrue(health["accepting_requests"])
        self.assertEqual(health["active_writes"], 0)
        self.assertFalse(health["background_jobs_enabled"])
        self.assertFalse(health["outbound_network_enabled"])
        self.assertFalse(health["worker_wake_signaling_enabled"])
        self.assertEqual(
            health["route_allowlist"],
            sorted(
                [
                    "GET /health",
                    "POST /ai/request",
                    "POST /analysis/result",
                    "POST /controlled-evaluations/retire",
                    "POST /incidents/reanalyze",
                    "POST /jobs/status",
                ]
            ),
        )

        for method, route, payload in (
            ("GET", "/metrics", None),
            ("GET", "/analyst-status", None),
            ("POST", "/alert", {}),
            ("POST", "/enrich", {}),
            ("POST", "/incidents/reanalyze-all", {}),
            ("POST", "/rescore", {}),
        ):
            with self.subTest(method=method, route=route):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    method,
                    payload,
                )
                self.assertEqual(status, 403)
                self.assertEqual(response["status"], "forbidden")

        for method, route, payload in (
            ("GET", "/health?unexpected=1", None),
            ("POST", "/analysis/result?unexpected=1", {}),
            ("POST", "/jobs/status?unexpected=1", {}),
        ):
            with self.subTest(query_route=route):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    method,
                    payload,
                )
                self.assertEqual(status, 403)
                self.assertEqual(response["status"], "forbidden")

        stop_process(self.process)
        self.process = None
        self.assertEqual(
            hashlib.sha256(self.db.read_bytes()).hexdigest(),
            before,
        )
        for suffix in ("-journal", "-wal", "-shm"):
            self.assertFalse(Path(f"{self.db}{suffix}").exists())


    def test_unowned_job_transitions_and_unbound_results_are_rejected(self) -> None:
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        self.start_controlled()
        group_id = "0123456789abcdefabcd"
        cases = (
            (
                "/jobs/status",
                {
                    "job_type": "ai_analysis",
                    "dedupe_key": group_id,
                    "status": "pending",
                    "lease_token": "",
                },
            ),
            (
                "/jobs/status",
                {
                    "job_type": "ai_analysis",
                    "dedupe_key": group_id,
                    "status": "processing",
                    "lease_token": "",
                },
            ),
            (
                "/jobs/status",
                {
                    "job_type": "ai_analysis",
                    "dedupe_key": group_id,
                    "status": "completed",
                    "lease_token": (
                        "11111111-1111-4111-8111-111111111111"
                    ),
                },
            ),
            ("/analysis/result", {}),
            (
                "/analysis/result",
                {
                    "analysis_id": "unbound-evaluation-result",
                    "controlled_job": {
                        "job_id": 1,
                        "job_type": "ai_analysis",
                    },
                },
            ),
        )
        for route, payload in cases:
            with self.subTest(route=route, status=payload.get("status")):
                status, response = request_json(
                    f"{self.base_url}{route}",
                    "POST",
                    payload,
                )
                self.assertEqual(status, 409, response)
                self.assertEqual(response["status"], "rejected")

        stop_process(self.process)
        self.process = None
        self.assertEqual(
            hashlib.sha256(self.db.read_bytes()).hexdigest(),
            before,
        )


    def test_controlled_mutations_require_the_ephemeral_token(self) -> None:
        self.start_controlled()
        before = hashlib.sha256(self.db.read_bytes()).hexdigest()
        payload = {
            "job_type": "ai_analysis",
            "dedupe_key": "0123456789abcdefabcd",
            "status": "processing",
            "lease_token": "",
        }
        for label, token in (
            ("missing", ""),
            ("wrong", "8" * 64),
        ):
            with self.subTest(label=label):
                status, response = request_json(
                    f"{self.base_url}/jobs/status",
                    "POST",
                    payload,
                    evaluation_token=token,
                )
                self.assertEqual(status, 403, response)
                self.assertEqual(
                    response["reason"],
                    "controlled evaluation authorization failed",
                )
        self.assertEqual(
            hashlib.sha256(self.db.read_bytes()).hexdigest(),
            before,
        )


    def test_controlled_retirement_is_exact_atomic_and_idempotent(
        self,
    ) -> None:
        unrelated_group = "91919191919191919191"
        unrelated_job_id = self.seed_controlled_job(
            group_id=unrelated_group,
            alert_id="controlled-retirement-unrelated-alert",
            stable_group_key="v2|controlled|retirement-unrelated",
            dispatch_id="9" * 64,
            cohort_id="controlled-retirement-unrelated",
        )
        retirement, context = (
            self.prepare_failed_controlled_retirement()
        )

        def logical_snapshot() -> tuple[str, ...]:
            with closing(
                sqlite3.connect(self.db, timeout=5)
            ) as connection:
                return tuple(connection.iterdump())

        def one(statement: str, values: tuple = ()) -> dict:
            with closing(
                sqlite3.connect(self.db, timeout=5)
            ) as connection:
                connection.row_factory = sqlite3.Row
                row = connection.execute(statement, values).fetchone()
                self.assertIsNotNone(row)
                return dict(row)

        unrelated_before = one(
            "SELECT * FROM durable_jobs WHERE id = ?",
            (unrelated_job_id,),
        )
        completed_before = [
            {
                "job": one(
                    "SELECT * FROM durable_jobs WHERE id = ?",
                    (member["job_id"],),
                ),
                "run": one(
                    """
                    SELECT * FROM incident_reanalysis_runs
                    WHERE run_id = ?
                    """,
                    (member["run_id"],),
                ),
                "analysis": one(
                    "SELECT * FROM ai_analysis_runs WHERE analysis_id = ?",
                    (member["analysis_id"],),
                ),
                "reviewer": one(
                    """
                    SELECT * FROM ai_second_opinion_runs
                    WHERE analysis_id = ?
                    """,
                    (member["analysis_id"],),
                ),
            }
            for member in context["completed_members"]
        ]
        before_rejection = logical_snapshot()
        wrong_identity = dict(retirement)
        wrong_identity["expected_job_payload_sha256"] = "e" * 64
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            wrong_identity,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(logical_snapshot(), before_rejection)

        for label, token in (
            ("missing", ""),
            ("wrong", "8" * 64),
        ):
            with self.subTest(authentication=label):
                status, rejected = request_json(
                    (
                        f"{self.base_url}"
                        "/controlled-evaluations/retire"
                    ),
                    "POST",
                    retirement,
                    evaluation_token=token,
                )
                self.assertEqual(status, 403, rejected)
                self.assertEqual(
                    rejected["reason"],
                    "controlled evaluation authorization failed",
                )
        self.assertEqual(logical_snapshot(), before_rejection)

        status, receipt = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, receipt)
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["status"], "retired")
        self.assertTrue(receipt["idempotent"])
        self.assertEqual(
            receipt["schema"],
            (
                "onion-sentinel-controlled-evaluation-"
                "retirement-receipt-v1"
            ),
        )
        self.assertEqual(receipt["identity"], retirement)
        self.assertEqual(receipt["case_agent_status"], "analyzed")
        self.assertEqual(receipt["security_onion_access"], "none")
        self.assertFalse(receipt["security_onion_writes_allowed"])
        self.assertEqual(receipt["model_invocations"], 0)
        self.assertFalse(receipt["worker_wake_signaled"])
        self.assertEqual(
            set(receipt),
            {
                "case_agent_status",
                "idempotent",
                "identity",
                "job_after_sha256",
                "job_before_sha256",
                "lineage_after_sha256",
                "lineage_before_sha256",
                "model_invocations",
                "ok",
                "receipt_sha256",
                "retired_at",
                "retirement_id",
                "schema",
                "security_onion_access",
                "security_onion_writes_allowed",
                "skip_reason",
                "status",
                "target_after",
                "target_before",
                "worker_wake_signaled",
            },
        )
        self.assertRegex(
            receipt["lineage_before_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertRegex(
            receipt["lineage_after_sha256"],
            r"^[a-f0-9]{64}$",
        )
        self.assertNotEqual(
            receipt["lineage_before_sha256"],
            receipt["lineage_after_sha256"],
        )
        target_before = receipt["target_before"]
        target_after = receipt["target_after"]
        self.assertEqual(target_before["state"], "pending")
        self.assertEqual(target_after["state"], "retired")
        self.assertTrue(
            target_before["job"]["processing_started_at"]
        )
        self.assertTrue(target_before["attempt"]["started_at"])
        self.assertTrue(target_before["attempt"]["completed_at"])
        self.assertIsNone(
            target_after["job"]["processing_started_at"]
        )
        self.assertIsNone(
            target_after["failure"]["job"]["raw_sha256"]
        )
        self.assertIsNone(
            target_after["failure"]["run_case"]["raw_sha256"]
        )
        self.assertEqual(
            target_before["failure"]["attempt"]["raw_sha256"],
            target_after["failure"]["attempt"]["raw_sha256"],
        )
        self.assertEqual(
            target_before["failure"]["job"]["normalized_sha256"],
            target_before["failure"]["run_case"][
                "normalized_sha256"
            ],
        )
        self.assertEqual(
            target_before["failure"]["job"]["normalized_sha256"],
            target_before["failure"]["attempt"]["normalized_sha256"],
        )
        unsigned = dict(receipt)
        embedded = unsigned.pop("receipt_sha256")
        canonical = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self.assertEqual(
            embedded,
            hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        )

        job = one(
            "SELECT * FROM durable_jobs WHERE id = ?",
            (retirement["job_id"],),
        )
        self.assertEqual(job["status"], "completed")
        self.assertEqual(int(job["attempt_count"]), 1)
        self.assertIsNone(job["lease_token"])
        self.assertIsNone(job["lease_expires_at"])
        self.assertIsNone(job["last_error"])
        self.assertIsNone(job["processing_started_at"])
        self.assertEqual(int(job["rerun_requested"]), 0)
        self.assertEqual(job["completed_at"], receipt["retired_at"])
        self.assertEqual(
            job["last_completed_at"],
            receipt["retired_at"],
        )
        self.assertEqual(job["updated_at"], receipt["retired_at"])

        run = one(
            "SELECT * FROM incident_reanalysis_runs WHERE run_id = ?",
            (retirement["reanalysis_run_id"],),
        )
        self.assertEqual(run["status"], "partial")
        self.assertIsNotNone(run["completed_at"])
        run_case = one(
            """
            SELECT * FROM incident_reanalysis_run_cases
            WHERE run_id = ? AND case_id = ?
            """,
            (
                retirement["reanalysis_run_id"],
                retirement["case_id"],
            ),
        )
        self.assertEqual(run_case["status"], "skipped")
        self.assertEqual(
            run_case["skip_reason"],
            receipt["skip_reason"],
        )
        self.assertIsNone(run_case["latest_error"])
        self.assertIsNone(run_case["analysis_id"])
        attempt = one(
            """
            SELECT * FROM incident_reanalysis_attempts
            WHERE attempt_id = ?
            """,
            (retirement["expected_attempt_id"],),
        )
        self.assertEqual(attempt["status"], "failed")
        self.assertEqual(
            int(attempt["durable_attempt_count"]),
            retirement["expected_attempt_count"],
        )
        self.assertIsNone(attempt["analysis_id"])
        incident = one(
            "SELECT * FROM incident_response_cases WHERE case_id = ?",
            (retirement["case_id"],),
        )
        self.assertEqual(incident["agent_status"], "analyzed")
        self.assertEqual(
            incident["latest_analysis_id"],
            retirement["expected_prior_analysis_id"],
        )
        self.assertIsNone(incident["latest_error"])
        event = one(
            """
            SELECT COUNT(*) AS count
            FROM incident_response_events
            WHERE case_id = ?
              AND event_type = 'controlled_evaluation_retired'
            """,
            (retirement["case_id"],),
        )
        self.assertEqual(int(event["count"]), 1)
        self.assertEqual(
            one(
                "SELECT * FROM durable_jobs WHERE id = ?",
                (unrelated_job_id,),
            ),
            unrelated_before,
        )
        completed_after = [
            {
                "job": one(
                    "SELECT * FROM durable_jobs WHERE id = ?",
                    (member["job_id"],),
                ),
                "run": one(
                    """
                    SELECT * FROM incident_reanalysis_runs
                    WHERE run_id = ?
                    """,
                    (member["run_id"],),
                ),
                "analysis": one(
                    "SELECT * FROM ai_analysis_runs WHERE analysis_id = ?",
                    (member["analysis_id"],),
                ),
                "reviewer": one(
                    """
                    SELECT * FROM ai_second_opinion_runs
                    WHERE analysis_id = ?
                    """,
                    (member["analysis_id"],),
                ),
            }
            for member in context["completed_members"]
        ]
        self.assertEqual(completed_after, completed_before)
        after_first = logical_snapshot()

        status, replay = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            retirement,
        )
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay, receipt)
        self.assertEqual(logical_snapshot(), after_first)

        conflict = dict(retirement)
        conflict["reason"] = (
            "A changed reason cannot reuse the retired lineage identity."
        )
        status, rejected = request_json(
            f"{self.base_url}/controlled-evaluations/retire",
            "POST",
            conflict,
        )
        self.assertEqual(status, 409, rejected)
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(logical_snapshot(), after_first)
        self.assertEqual(
            context["claim"]["claim"]["reanalysis_attempt_id"],
            retirement["expected_attempt_id"],
        )


    def test_controlled_retirement_rank_one_replays_exact_scalars_and_bytes(
        self,
    ) -> None:
        reason = (
            "Retire rank one after failure observed at "
            "2026-07-28T12:34:56Z without rewriting this timestamp."
        )
        retirement, _ = self.prepare_failed_controlled_retirement(
            cohort_id="controlled-retirement-rank-one",
            dispatch_id=hashlib.sha256(b"retirement-rank-one").hexdigest(),
            prior_analysis_id="",
            member_rank=1,
            cohort_size=20,
            retirement_reason=reason,
        )
        endpoint = (
            f"{self.base_url}/controlled-evaluations/retire"
        )
        status, first_bytes = request_json_bytes(
            endpoint,
            retirement,
        )
        self.assertEqual(status, 200, first_bytes)
        first = json.loads(first_bytes)
        self.assertEqual(
            first_bytes,
            json.dumps(
                first,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8"),
        )
        self.assertEqual(
            first["identity"]["expected_prior_analysis_id"],
            "",
        )
        self.assertEqual(first["identity"]["reason"], reason)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            after_first = tuple(connection.iterdump())
            stored = connection.execute(
                """
                SELECT detail_json FROM incident_response_events
                WHERE case_id = ?
                  AND event_type = 'controlled_evaluation_retired'
                """,
                (retirement["case_id"],),
            ).fetchone()[0]
        self.assertEqual(stored.encode("utf-8"), first_bytes)
        stop_process(self.process)
        self.process = None
        self.start_controlled(
            release_id=REPLACEMENT_RELEASE_ID,
        )
        endpoint = (
            f"{self.base_url}/controlled-evaluations/retire"
        )
        status, replay_bytes = request_json_bytes(
            endpoint,
            retirement,
        )
        self.assertEqual(status, 200, replay_bytes)
        self.assertEqual(replay_bytes, first_bytes)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            self.assertEqual(tuple(connection.iterdump()), after_first)
