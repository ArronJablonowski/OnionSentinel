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

class ControlledAlertStoreTestsFixtures(unittest.TestCase):
    """Exercise the service boundary against a fully initialized temp schema."""


    @classmethod
    def setUpClass(cls) -> None:
        if not (ALERT_STORE_DIR / "node_modules" / "sqlite3").is_dir():
            raise unittest.SkipTest(
                "run npm ci in n8n/alert_store to install sqlite3"
            )
        cls.template = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-template-"
        )
        # macOS exposes /var through a /private/var symlink.  Controlled mode
        # intentionally rejects paths whose spelling is not already canonical.
        cls.template_root = Path(cls.template.name).resolve()
        cls.template_db = cls.template_root / "alerts.sqlite3"
        cls.template_rules = cls.template_root / "scoring_rules.json"
        shutil.copyfile(SCORING_RULES, cls.template_rules)
        cls.template_rules.chmod(0o600)
        cls._initialize_template_database()
        cls.scheduler = load_python_module(
            "controlled_evaluation_recovery_e2e",
            SCHEDULER_PATH,
        )
        cls.runner = load_python_module(
            "controlled_evaluation_result_spool_e2e",
            RUNNER_PATH,
        )


    @classmethod
    def tearDownClass(cls) -> None:
        cls.template.cleanup()


    @classmethod
    def _initialize_template_database(cls) -> None:
        port = available_port()
        log_file = tempfile.TemporaryFile(mode="w+t", encoding="utf-8")
        environment = {
            **sanitized_environment(),
            "ONION_SENTINEL_EVALUATION_MODE": "0",
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
            "ALERT_STORE_DB": str(cls.template_db),
            "SCORING_RULES_PATH": str(cls.template_rules),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(port),
            "ALERT_STORE_BEACON_PATHS": str(
                cls.template_root / "beacon.json"
            ),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(
                cls.template_root / "beacon-history.json"
            ),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
            "ALERT_STORE_DISK_START_MAX_USED_PERCENT": "99.8",
            "ALERT_STORE_DISK_HARD_MAX_USED_PERCENT": "99.9",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "N8N_POST_COMMIT_INTERVAL_MS": "600000",
            "DURABLE_JOB_RECOVERY_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
            "AI_ANALYSIS_WAKE_PATH": str(
                cls.template_root / "run" / "ai-analysis.wake"
            ),
            "PCAP_ANALYSIS_WAKE_PATH": str(
                cls.template_root / "run" / "pcap-analysis.wake"
            ),
        }
        process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    break
                try:
                    if request_json(
                        f"http://127.0.0.1:{port}/health"
                    )[0] == 200:
                        break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.05)
            else:
                raise AssertionError(
                    "template alert-store did not become healthy: "
                    + process_output(log_file)
                )
            if process.poll() is not None:
                raise AssertionError(
                    "template alert-store exited early: "
                    + process_output(log_file)
                )
        finally:
            stop_process(process, graceful=False)
        with closing(
            sqlite3.connect(cls.template_db, timeout=5)
        ) as connection:
            connection.execute("PRAGMA journal_mode = DELETE")
            integrity = connection.execute(
                "PRAGMA integrity_check"
            ).fetchone()[0]
            if integrity != "ok":
                raise AssertionError(f"template SQLite integrity: {integrity}")
            connection.commit()
        cls.template_db.chmod(0o600)
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(f"{cls.template_db}{suffix}")
            if sidecar.exists():
                raise AssertionError(
                    f"template retained SQLite recovery sidecar {sidecar}"
                )
        log_file.close()


    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-controlled-alert-store-"
        )
        self.runtime = Path(self.temporary.name).resolve()
        self.db = self.runtime / "alerts.sqlite3"
        self.rules = self.runtime / "scoring_rules.json"
        shutil.copyfile(self.template_db, self.db)
        shutil.copyfile(self.template_rules, self.rules)
        self.db.chmod(0o600)
        self.rules.chmod(0o600)
        self.process: subprocess.Popen | None = None
        self.log_file = tempfile.TemporaryFile(
            mode="w+t",
            encoding="utf-8",
        )


    def tearDown(self) -> None:
        if self.process is not None:
            stop_process(self.process)
        self.log_file.close()
        self.temporary.cleanup()


    def controlled_environment(
        self,
        *,
        port: int | None = None,
        release_id: str = RELEASE_ID,
    ) -> dict[str, str]:
        return {
            **sanitized_environment(),
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_RELEASE_ID": release_id,
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
            "ALERT_STORE_DB": str(self.db),
            "SCORING_RULES_PATH": str(self.rules),
            "ALERT_STORE_HOST": "127.0.0.1",
            "ALERT_STORE_PORT": str(port or available_port()),
            "ALERT_STORE_BEACON_PATHS": str(
                self.runtime / "beacon.json"
            ),
            "ALERT_STORE_BEACON_HISTORY_PATHS": str(
                self.runtime / "beacon-history.json"
            ),
            "AI_ANALYSIS_WAKE_PATH": str(
                self.runtime / "run" / "ai-analysis.wake"
            ),
            "PCAP_ANALYSIS_WAKE_PATH": str(
                self.runtime / "run" / "pcap-analysis.wake"
            ),
            "ALERT_STORE_DISK_MIN_FREE_BYTES": "0",
        }


    def assert_startup_rejected(
        self,
        environment: dict[str, str],
        message: str,
    ) -> None:
        result = subprocess.run(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=environment,
            text=True,
            capture_output=True,
            timeout=8,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(message, output)


    def start_controlled(
        self,
        *,
        release_id: str = RELEASE_ID,
    ) -> tuple[int, dict]:
        port = available_port()
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=self.controlled_environment(
                port=port,
                release_id=release_id,
            ),
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                status, health = request_json(f"{base_url}/health")
                if status == 200:
                    self.base_url = base_url
                    return status, health
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        self.fail(
            "controlled alert-store did not become healthy: "
            + process_output(self.log_file)
        )


    def start_production(self) -> tuple[int, dict]:
        port = available_port()
        environment = self.controlled_environment(port=port)
        environment.update({
            "ONION_SENTINEL_EVALUATION_MODE": "0",
            "TELEGRAM_OUTBOX_AUTOSTART": "0",
            "ENRICHMENT_WORKER_INTERVAL_MS": "600000",
            "N8N_POST_COMMIT_INTERVAL_MS": "600000",
            "DURABLE_JOB_RECOVERY_INTERVAL_MS": "600000",
            "PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS": "3600",
        })
        self.process = subprocess.Popen(
            ["node", str(ALERT_STORE)],
            cwd=ALERT_STORE_DIR,
            env=environment,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                status, health = request_json(f"{base_url}/health")
                if status == 200:
                    self.base_url = base_url
                    return status, health
            except (OSError, urllib.error.URLError):
                time.sleep(0.05)
        self.fail(
            "production-mode alert-store did not become healthy: "
            + process_output(self.log_file)
        )


    def seed_controlled_job(
        self,
        *,
        group_id: str,
        alert_id: str,
        stable_group_key: str,
        dispatch_id: str,
        cohort_id: str = "controlled-cohort-11",
        agent_role: str | None = "soc-analyst",
    ) -> int:
        timestamp = "2020-01-01 00:00:00+00:00"
        job_payload = {
            "alert_id": alert_id,
            "representative_alert_id": alert_id,
            "group_id": group_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": RELEASE_ID,
            **CONTROLLED_ROUTE_FIELDS,
        }
        if agent_role is not None:
            job_payload["agent_role"] = agent_role
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
                    stable_group_key,
                ),
            )
            cursor = connection.execute(
                """
                INSERT INTO durable_jobs (
                    job_type, dedupe_key, payload_json, status, priority,
                    attempt_count, max_attempts, next_attempt_at, created_at,
                    updated_at, requested_at, rerun_requested
                ) VALUES (
                    'ai_analysis', ?, ?, 'pending', 100, 0, 8, ?, ?, ?, ?, 0
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
            return int(cursor.lastrowid)


    def seed_controlled_incident_case(
        self,
        *,
        case_id: str,
        group_id: str,
        alert_id: str,
        stable_group_key: str,
        prior_analysis_id: str = "",
    ) -> None:
        timestamp = "2020-01-01 00:00:00+00:00"
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.execute(
                """
                INSERT INTO alerts (
                    alert_id, first_seen, last_seen, alert_json,
                    stable_group_id, stable_group_key, triage_level,
                    filter_status
                ) VALUES (?, ?, ?, ?, ?, ?, 'critical', 'accepted')
                """,
                (
                    alert_id,
                    timestamp,
                    timestamp,
                    json.dumps({"alert_id": alert_id}),
                    group_id,
                    stable_group_key,
                ),
            )
            connection.execute(
                """
                INSERT INTO incident_response_cases (
                    case_id, group_id, dashboard_group_id,
                    representative_alert_id, status, agent_status,
                    escalated_at, updated_at, escalated_by, reason
                ) VALUES (
                    ?, ?, ?, ?, 'open', 'analyzed', ?, ?,
                    'controlled-test', 'Controlled dispatch replay test'
                )
                """,
                (
                    case_id,
                    group_id,
                    group_id[:12],
                    alert_id,
                    timestamp,
                    timestamp,
                ),
            )
            if prior_analysis_id:
                connection.execute(
                    """
                    INSERT INTO ai_analysis_runs (
                        analysis_id, group_id, alert_id, agent_role,
                        generated_at, model, model_path, response_json,
                        created_at
                    ) VALUES (
                        ?, ?, ?, 'incident-responder', ?, 'prior-model',
                        'frontier-codex-cli', '{}', ?
                    )
                    """,
                    (
                        prior_analysis_id,
                        group_id,
                        alert_id,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.execute(
                    """
                    UPDATE incident_response_cases
                    SET latest_analysis_id = ?, latest_model = 'prior-model',
                        latest_generated_at = ?
                    WHERE case_id = ?
                    """,
                    (prior_analysis_id, timestamp, case_id),
                )
            connection.commit()


    def complete_controlled_retirement_member_lifecycle(
        self,
        *,
        rank: int,
        cohort_id: str,
        dispatch_id: str,
    ) -> dict:
        group_id = f"{rank:02x}" * 10
        case_id = f"ir-controlled-retirement-completed-{rank}"
        alert_id = f"controlled-retirement-completed-alert-{rank}"
        stable_group_key = (
            f"v2|controlled|retirement-completed-{rank}"
        )
        analysis_id = f"controlled-retirement-analysis-{rank}"
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_group_key,
        )
        status, accepted = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            {
                "case_id": case_id,
                "representative_alert_id": alert_id,
                "stable_group_id": group_id,
                "stable_group_key": stable_group_key,
                "cohort_id": cohort_id,
                "dispatch_id": dispatch_id,
                "release_id": RELEASE_ID,
                **CONTROLLED_ROUTE_FIELDS,
                "requested_by": "controlled-retirement-test",
                "reason": (
                    "Complete a real controlled claim/result lifecycle."
                ),
            },
        )
        self.assertEqual(status, 202, accepted)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            job = connection.execute(
                """
                SELECT * FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (group_id,),
            ).fetchone()
        self.assertIsNotNone(job)
        status, claim = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": int(job["id"]),
                "expected_representative_alert_id": alert_id,
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": stable_group_key,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )
        self.assertEqual(status, 200, claim)
        result_payload = self.controlled_incident_result_payload(
            analysis_id=analysis_id,
            claim=claim,
        )
        status, indexed = request_json(
            f"{self.base_url}/analysis/result",
            "POST",
            result_payload,
        )
        self.assertEqual(status, 200, indexed)
        self.assertTrue(indexed["second_opinion_recorded"])
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            completed = connection.execute(
                "SELECT * FROM durable_jobs WHERE id = ?",
                (int(job["id"]),),
            ).fetchone()
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(int(completed["attempt_count"]), 1)
        self.assertTrue(completed["processing_started_at"])
        return {
            "rank": rank,
            "dispatch_id": dispatch_id,
            "job_id": int(job["id"]),
            "run_id": accepted["run_id"],
            "analysis_id": analysis_id,
        }


    def prepare_failed_controlled_retirement(
        self,
        *,
        case_id: str = "ir-controlled-retirement",
        group_id: str = "81818181818181818181",
        alert_id: str = "controlled-retirement-alert",
        stable_group_key: str = "v2|controlled|retirement",
        cohort_id: str = "controlled-cohort-retirement",
        dispatch_id: str = "8" * 64,
        prior_analysis_id: str = "controlled-prior-ir-analysis",
        member_rank: int = 7,
        cohort_size: int = 20,
        retired_release_id: str = RELEASE_ID,
        replacement_release_id: str = REPLACEMENT_RELEASE_ID,
        retirement_reason: str = (
            "Retire the failed controlled evaluation before a fresh cohort."
        ),
    ) -> tuple[dict, dict]:
        self.seed_controlled_incident_case(
            case_id=case_id,
            group_id=group_id,
            alert_id=alert_id,
            stable_group_key=stable_group_key,
            prior_analysis_id=prior_analysis_id,
        )
        self.start_controlled(release_id=retired_release_id)
        dispatch = {
            "case_id": case_id,
            "representative_alert_id": alert_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "cohort_id": cohort_id,
            "dispatch_id": dispatch_id,
            "release_id": retired_release_id,
            **CONTROLLED_ROUTE_FIELDS,
            "requested_by": "controlled-retirement-test",
            "reason": "Create one exact failed controlled attempt.",
        }
        status, accepted = request_json(
            f"{self.base_url}/incidents/reanalyze",
            "POST",
            dispatch,
        )
        self.assertEqual(status, 202, accepted)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            job = connection.execute(
                """
                SELECT * FROM durable_jobs
                WHERE job_type = 'incident_response_analysis'
                  AND dedupe_key = ?
                """,
                (group_id,),
            ).fetchone()
        self.assertIsNotNone(job)
        status, claim = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": int(job["id"]),
                "expected_representative_alert_id": alert_id,
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": stable_group_key,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )
        self.assertEqual(status, 200, claim)
        self.assertEqual(
            claim["claim"]["reanalysis_run_id"],
            accepted["run_id"],
        )
        status, failed = request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "incident_response_analysis",
                "dedupe_key": group_id,
                "status": "failed",
                "error": "Synthetic controlled worker failure.",
                "lease_token": claim["lease_token"],
                "retryable": True,
            },
        )
        self.assertEqual(status, 200, failed)
        with closing(sqlite3.connect(self.db, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            pending = connection.execute(
                "SELECT * FROM durable_jobs WHERE id = ?",
                (int(job["id"]),),
            ).fetchone()
        self.assertEqual(pending["status"], "pending")
        self.assertEqual(int(pending["attempt_count"]), 1)
        completed_members = [
            self.complete_controlled_retirement_member_lifecycle(
                rank=rank,
                cohort_id=cohort_id,
                dispatch_id=hashlib.sha256(
                    f"{cohort_id}:completed:{rank}".encode("utf-8")
                ).hexdigest(),
            )
            for rank in range(1, member_rank)
        ]
        absent_dispatch_ids = [
            hashlib.sha256(
                f"{cohort_id}:absent:{rank}".encode("utf-8")
            ).hexdigest()
            for rank in range(member_rank + 1, cohort_size + 1)
        ]
        stop_process(self.process)
        self.process = None
        self.start_controlled(
            release_id=replacement_release_id,
        )
        request = {
            "schema": (
                "onion-sentinel-controlled-evaluation-retirement-v1"
            ),
            "absent_dispatch_ids": absent_dispatch_ids,
            "case_id": case_id,
            "cohort_id": cohort_id,
            "cohort_size": cohort_size,
            "completed_dispatch_ids": [
                member["dispatch_id"] for member in completed_members
            ],
            "dispatch_id": dispatch_id,
            "expected_attempt_count": 1,
            "expected_attempt_id": claim["claim"][
                "reanalysis_attempt_id"
            ],
            "expected_job_payload_sha256": hashlib.sha256(
                str(pending["payload_json"]).encode("utf-8")
            ).hexdigest(),
            "expected_prior_analysis_id": prior_analysis_id,
            "failure_attestation_sha256": "a" * 64,
            "job_id": int(job["id"]),
            "manifest_sha256": "b" * 64,
            "member_rank": member_rank,
            "reanalysis_run_id": accepted["run_id"],
            "reason": retirement_reason,
            "replacement_release_id": replacement_release_id,
            "representative_alert_id": alert_id,
            "retired_release_id": retired_release_id,
            "stable_group_id": group_id,
            "stable_group_key": stable_group_key,
            "start_sha256": "d" * 64,
        }
        return request, {
            "accepted": accepted,
            "claim": claim,
            "completed_members": completed_members,
            "pending": dict(pending),
        }


    def claim_controlled_job(
        self,
        *,
        job_id: int,
        group_id: str,
        alert_id: str,
        stable_group_key: str,
        dispatch_id: str,
    ) -> tuple[int, dict]:
        return request_json(
            f"{self.base_url}/jobs/status",
            "POST",
            {
                "job_type": "ai_analysis",
                "dedupe_key": group_id,
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": job_id,
                "expected_representative_alert_id": alert_id,
                "expected_dispatch_id": dispatch_id,
                "expected_stable_group_key": stable_group_key,
                **CONTROLLED_ROUTE_FIELDS,
            },
        )


    def controlled_result_payload(
        self,
        *,
        analysis_id: str,
        claim: dict,
    ) -> dict:
        claimed_job = claim["claim"]
        job_payload = claimed_job["payload"]
        identity = {
            "job_id": int(claimed_job["job_id"]),
            "job_type": "ai_analysis",
            "lease_token": claim["lease_token"],
            "cohort_id": job_payload["cohort_id"],
            "dispatch_id": job_payload["dispatch_id"],
            "representative_alert_id": (
                job_payload["representative_alert_id"]
            ),
            "stable_group_id": job_payload["stable_group_id"],
            "stable_group_key": job_payload["stable_group_key"],
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": "",
            "release_id": RELEASE_ID,
            **CONTROLLED_ROUTE_FIELDS,
        }
        claim_digest = hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        response = {
            "detection_outcome": "Inconclusive",
            "bluf": "Controlled evaluation synthetic result.",
            "summary": "Synthetic result used only for lifecycle testing.",
            "confidence": "low",
            "_analysis_evaluation_memory_frozen": True,
            "_analysis_controlled_claim_sha256": claim_digest,
            "_analysis_model_route": PRIMARY_ROUTE,
            "_second_opinion": {
                "status": "completed",
                "model_route": REVIEWER_ROUTE,
                "response": {"_analysis_model_route": REVIEWER_ROUTE},
            },
        }
        return {
            "analysis_id": analysis_id,
            "alert_id": identity["representative_alert_id"],
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": None,
            "generated_at": "2026-07-27 12:01:00+00:00",
            "model": "synthetic-controlled-model",
            "model_path": "frontier-codex-cli",
            "artifact_path": "/controlled/evaluation/result.json",
            "evidence_hash": "e" * 64,
            "response": response,
            "controlled_job": identity,
        }


    def controlled_incident_result_payload(
        self,
        *,
        analysis_id: str,
        claim: dict,
    ) -> dict:
        claimed_job = claim["claim"]
        job_payload = claimed_job["payload"]
        identity = {
            "job_id": int(claimed_job["job_id"]),
            "job_type": "incident_response_analysis",
            "lease_token": claim["lease_token"],
            "cohort_id": job_payload["cohort_id"],
            "dispatch_id": job_payload["dispatch_id"],
            "representative_alert_id": (
                job_payload["representative_alert_id"]
            ),
            "stable_group_id": job_payload["stable_group_id"],
            "stable_group_key": job_payload["stable_group_key"],
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": claimed_job[
                "reanalysis_attempt_id"
            ],
            "release_id": RELEASE_ID,
            **CONTROLLED_ROUTE_FIELDS,
        }
        claim_digest = hashlib.sha256(
            json.dumps(
                identity,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        generated_at = dt.datetime.now(
            dt.timezone.utc
        ).isoformat()
        response = {
            "detection_outcome": "Inconclusive",
            "bluf": "Controlled incident lifecycle result.",
            "summary": (
                "Synthetic content with a real durable lifecycle."
            ),
            "confidence": "low",
            "_analysis_provider": "codex-cli",
            "_analysis_model_route": PRIMARY_ROUTE,
            "_analysis_evaluation_memory_frozen": True,
            "_analysis_controlled_claim_sha256": claim_digest,
            "_second_opinion": {
                "trigger": "required",
                "status": "completed",
                "model_route": REVIEWER_ROUTE,
                "error": "",
                "runtime_seconds": 0.25,
                "response": {
                    "detection_outcome": "Inconclusive",
                    "confidence": "low",
                    "_analysis_model": (
                        "synthetic-controlled-reviewer"
                    ),
                    "_analysis_model_path": "frontier-codex-cli",
                    "_analysis_model_route": REVIEWER_ROUTE,
                },
                "comparison": {
                    "agreement": "agree",
                    "material_disagreement": False,
                    "disputed_fields": [],
                },
                "memory_writeback": {"accepted": 0},
            },
        }
        return {
            "analysis_id": analysis_id,
            "alert_id": identity["representative_alert_id"],
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": identity[
                "reanalysis_attempt_id"
            ],
            "generated_at": generated_at,
            "model": "synthetic-controlled-primary",
            "provider": "codex-cli",
            "model_path": "frontier-codex-cli",
            "artifact_path": "/controlled/evaluation/result.json",
            "evidence_hash": "e" * 64,
            "response": response,
            "controlled_job": identity,
        }


