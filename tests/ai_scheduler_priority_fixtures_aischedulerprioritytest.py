from __future__ import annotations

from ai_scheduler_priority_fixtures import (
    CONTROLLED_ROUTE_FIELDS,
    DEPLOYED_RELEASE,
    PRIMARY_ROUTE,
    Path,
    REPO_ROOT,
    REVIEWER_ROUTE,
    SCHEDULER_PATH,
    SimpleNamespace,
    importlib,
    io,
    json,
    load_scheduler,
    mock,
    os,
    sqlite3,
    tempfile,
    unittest,
    write_controlled_route_fixture,
)

class AiSchedulerPriorityTestFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.scheduler = load_scheduler()
        self.tempdir = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                timestamp TEXT,
                rule_name TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                triage_level TEXT,
                triage_score INTEGER,
                filter_status TEXT,
                routing TEXT,
                suppression_key TEXT
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE alert_group_summary (
                group_id TEXT PRIMARY KEY
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE alert_group_alias (
                legacy_group_id TEXT PRIMARY KEY,
                stable_group_id TEXT NOT NULL
            )
            """
        )
        self.args = SimpleNamespace(
            levels="critical,high,medium,low,informational",
            hours=87600,
            include_tests=True,
            analysis_dir=Path(self.tempdir.name),
            provider_lane="any",
            ai_settings_file=Path(self.tempdir.name) / "ai_model_settings.json",
        )


    def tearDown(self) -> None:
        self.conn.close()
        self.tempdir.cleanup()


    def recovery_databases(
        self,
        alert_path: Path | None = None,
        harness_path: Path | None = None,
    ) -> tuple[sqlite3.Connection, sqlite3.Connection]:
        alert_conn = sqlite3.connect(str(alert_path) if alert_path else ":memory:")
        harness_conn = sqlite3.connect(
            str(harness_path) if harness_path else ":memory:"
        )
        alert_conn.row_factory = sqlite3.Row
        harness_conn.row_factory = sqlite3.Row
        alert_conn.executescript(
            """
            CREATE TABLE durable_jobs (
                id INTEGER PRIMARY KEY,
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                lease_token TEXT,
                processing_started_at TEXT
            );
            CREATE TABLE ai_analysis_runs (
                analysis_id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                agent_role TEXT NOT NULL,
                generated_at TEXT NOT NULL
            );
            CREATE TABLE incident_response_cases (
                case_id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                agent_status TEXT NOT NULL,
                latest_analysis_id TEXT,
                latest_error TEXT
            );
            """
        )
        harness_conn.executescript(
            """
            CREATE TABLE harness_runs (
                run_id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL,
                stage TEXT NOT NULL,
                assigned_route TEXT NOT NULL,
                completed_at TEXT
            );
            """
        )
        return alert_conn, harness_conn


    def insert_terminal_recovery_fixture(
        self,
        alert_conn: sqlite3.Connection,
        harness_conn: sqlite3.Connection,
        *,
        job_type: str = "incident_response_analysis",
        route: str = PRIMARY_ROUTE,
        generated_at: str = "2026-08-05T14:05:00Z",
    ) -> None:
        role = (
            "incident-responder"
            if job_type == "incident_response_analysis"
            else "soc-analyst"
        )
        group_id = "recovery-group"
        alert_id = "recovery-alert"
        run_id = "recovery-analysis"
        case_id = "ir-recovery" if job_type == "incident_response_analysis" else ""
        payload = {
            "agent_role": role,
            "group_id": group_id,
            "alert_id": alert_id,
            "expected_assigned_route": route,
        }
        if case_id:
            payload["case_id"] = case_id
        alert_conn.execute(
            "INSERT INTO durable_jobs VALUES (1, ?, ?, 'processing', ?, ?, ?)",
            (
                job_type,
                group_id,
                json.dumps(payload),
                "exact-recovery-lease",
                "2026-08-05T14:00:00Z",
            ),
        )
        alert_conn.execute(
            "INSERT INTO ai_analysis_runs VALUES (?, ?, ?, ?, ?)",
            (run_id, group_id, alert_id, role, generated_at),
        )
        if case_id:
            alert_conn.execute(
                "INSERT INTO incident_response_cases VALUES (?, ?, 'analyzed', ?, NULL)",
                (case_id, group_id, run_id),
            )
        harness_conn.execute(
            "INSERT INTO harness_runs VALUES (?, ?, ?, ?, ?, 'succeeded', 'complete', ?, ?)",
            (
                run_id,
                group_id,
                case_id,
                alert_id,
                role,
                route,
                "2026-08-05T14:06:00Z",
            ),
        )
        alert_conn.commit()
        harness_conn.commit()


    def insert_alert(
        self,
        alert_id: str,
        severity: str,
        last_seen: str,
        score: int = 80,
        rule_name: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts (
                alert_id, first_seen, last_seen, timestamp, rule_name, source_ip,
                destination_ip, triage_level, triage_score, filter_status, routing,
                suppression_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted', 'analyst-review', NULL)
            """,
            (
                alert_id,
                last_seen,
                last_seen,
                last_seen,
                rule_name or f"{severity} test detection {alert_id}",
                source_ip or f"192.0.2.{len(alert_id)}",
                destination_ip or f"198.51.100.{len(alert_id)}",
                severity,
                score,
            ),
        )


    def enable_indexed_scheduler(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_key TEXT")
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                id INTEGER PRIMARY KEY,
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                priority INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 8,
                next_attempt_at TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0,
                requested_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE ai_analysis_runs (
                id INTEGER PRIMARY KEY,
                group_id TEXT NOT NULL,
                alert_id TEXT,
                generated_at TEXT NOT NULL
            )
            """
        )


    def set_stable_group(self, alert_id: str, group_id: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET stable_group_id = ?, stable_group_key = ? WHERE alert_id = ?",
            (group_id, f"key:{group_id}", alert_id),
        )


    def insert_indexed_job(
        self,
        group_id: str,
        *,
        payload: dict | None = None,
        job_type: str = "ai_analysis",
        priority: int = 0,
        status: str = "pending",
        next_attempt_at: str = "2020-01-01  00:00:00Z",
        processing_started_at: str | None = None,
        rerun_requested: int = 0,
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO durable_jobs (
                job_type, dedupe_key, status, payload_json, priority,
                attempt_count, max_attempts, next_attempt_at,
                processing_started_at, rerun_requested, requested_at
            ) VALUES (?, ?, ?, ?, ?, 0, 8, ?, ?, ?, ?)
            """,
            (
                job_type,
                group_id,
                status,
                json.dumps(payload or {}),
                priority,
                next_attempt_at,
                processing_started_at,
                rerun_requested,
                next_attempt_at,
            ),
        )


    def run_indexed_worker_once(
        self,
        *,
        severity: str,
        payload: dict | None = None,
        claimed_payload: dict | None = None,
        claimed_payload_available: bool = True,
        claim_available: bool = True,
        claimed_job_type: str | None = None,
        claimed_resolved_key: str | None = None,
        register_claimed_alert: bool = True,
        job_type: str = "ai_analysis",
        analysis_threshold: str = "medium",
        incident_threshold: str = "disabled",
        only_group_id: str = "",
        only_alert_id: str = "",
        only_stable_group_key: str = "",
        only_dispatch_id: str = "",
        current_alert_group_key: str | None = None,
        controlled_evaluation: bool | None = None,
        build_prompt_error: BaseException | None = None,
        analysis_process: object | None = None,
    ) -> dict[str, object]:
        """Run one indexed job through main() with inference boundaries mocked."""
        if controlled_evaluation is None:
            controlled_evaluation = bool(only_group_id)
        self.enable_indexed_scheduler()
        alert_id = f"{job_type}-{severity}-threshold-alert"
        group_id = only_group_id or f"{job_type}-{severity}-threshold-group"
        frozen_group_key = (
            only_stable_group_key
            or (f"key:{group_id}" if only_group_id else "")
        )
        queued_payload = dict(payload or {})
        if only_group_id:
            controlled_agent_role = (
                "incident-responder"
                if job_type == "incident_response_analysis"
                else "soc-analyst"
            )
            queued_payload.setdefault("alert_id", alert_id)
            queued_payload.setdefault("representative_alert_id", alert_id)
            queued_payload.setdefault("group_id", group_id)
            queued_payload.setdefault("stable_group_id", group_id)
            queued_payload.setdefault("stable_group_key", frozen_group_key)
            queued_payload.setdefault("dispatch_id", only_dispatch_id)
            queued_payload.setdefault("release_id", DEPLOYED_RELEASE)
            queued_payload.setdefault("agent_role", controlled_agent_role)
            for field, value in CONTROLLED_ROUTE_FIELDS.items():
                queued_payload.setdefault(field, value)
        self.insert_alert(alert_id, severity, "2026-07-24  12:00:00Z", 80)
        self.set_stable_group(alert_id, group_id)
        if current_alert_group_key is not None:
            self.conn.execute(
                "UPDATE alerts SET stable_group_key = ? WHERE alert_id = ?",
                (current_alert_group_key, alert_id),
            )
        self.insert_indexed_job(
            group_id,
            payload=queued_payload,
            job_type=job_type,
        )
        if claimed_payload and register_claimed_alert:
            claimed_alert_ids = {
                str(claimed_payload.get(field) or "").strip()
                for field in ("alert_id", "representative_alert_id")
                if str(claimed_payload.get(field) or "").strip()
            }
            for claimed_alert_id in claimed_alert_ids:
                if claimed_alert_id == alert_id:
                    continue
                self.insert_alert(
                    claimed_alert_id,
                    severity,
                    "2026-07-24  12:00:01Z",
                    80,
                )
                self.set_stable_group(claimed_alert_id, group_id)
        self.conn.commit()

        root = Path(self.tempdir.name).resolve()
        controlled_home = root / "controlled-home"
        controlled_runtime = (
            controlled_home
            / "n8n-local"
            / "harness-evaluations"
            / "scheduler-test"
        )
        if controlled_evaluation:
            controlled_runtime.mkdir(parents=True, mode=0o700)
            controlled_runtime.parent.chmod(0o700)
            controlled_runtime.chmod(0o700)
        worker_root = controlled_runtime if controlled_evaluation else root
        runtime_directories = {
            name: worker_root / name
            for name in (
                "prompts",
                "analysis",
                "prior-analysis",
                "pcap-analysis",
                "rollups",
                "agent-memory",
                "incident-evidence",
                "investigation-pivots",
                "tmp",
            )
        }
        for path in runtime_directories.values():
            path.mkdir(mode=0o700, exist_ok=True)
            path.chmod(0o700)
        db_path = worker_root / "alerts.sqlite3"
        disk_conn = sqlite3.connect(db_path)
        try:
            self.conn.backup(disk_conn)
        finally:
            disk_conn.close()
        db_path.chmod(0o600)

        settings_path = worker_root / "ai_model_settings.json"
        settings = {
            "soc_analyst_analysis_min_severity": analysis_threshold,
            "soc_analyst_incident_min_severity": incident_threshold,
        }
        if controlled_evaluation:
            controlled_agent_role = (
                "incident-responder"
                if job_type == "incident_response_analysis"
                else "soc-analyst"
            )
            settings.update(
                {
                    "agent_models": {
                        controlled_agent_role: PRIMARY_ROUTE,
                    },
                    "agent_second_opinion_models": {
                        controlled_agent_role: REVIEWER_ROUTE,
                    },
                    "codex_cli_models": [
                        {
                            "model": "gpt-5.5",
                            "reasoning_effort": "high",
                            "enabled": True,
                        },
                        {
                            "model": "gpt-5.6-sol",
                            "reasoning_effort": "xhigh",
                            "enabled": True,
                        },
                    ],
                }
            )
        settings_path.write_text(
            json.dumps(settings),
            encoding="utf-8",
        )
        settings_path.chmod(0o600)
        harness_policy_path = worker_root / "investigation_harness_policy.json"
        harness_policy_path.write_text("{}\n", encoding="utf-8")
        harness_policy_path.chmod(0o600)
        detection_playbooks_path = worker_root / "detection_playbooks.json"
        detection_playbooks_path.write_text("{}\n", encoding="utf-8")
        detection_playbooks_path.chmod(0o600)
        investigation_skills_path = worker_root / "investigation_skills.json"
        investigation_skills_path.write_text("{}\n", encoding="utf-8")
        investigation_skills_path.chmod(0o600)
        shared_memory_path = worker_root / "shared-agent-memory.md"
        shared_memory_path.write_text("\n", encoding="utf-8")
        shared_memory_path.chmod(0o600)
        asset_inventory_path = worker_root / "asset-inventory.json"
        asset_inventory_path.write_text("{}\n", encoding="utf-8")
        asset_inventory_path.chmod(0o600)
        live_osquery_path = worker_root / "live-osquery.json"
        live_osquery_path.write_text(
            '{"enabled":false}\n',
            encoding="utf-8",
        )
        live_osquery_path.chmod(0o600)
        disagreement_prompt_path = worker_root / "disagreement.md"
        disagreement_prompt_path.write_text("\n", encoding="utf-8")
        disagreement_prompt_path.chmod(0o600)
        for role_name in ("soc_analyst", "incident_responder"):
            for suffix in ("system_prompt.md", "second_opinion_prompt.md"):
                prompt = worker_root / f"{role_name}_{suffix}"
                prompt.write_text("\n", encoding="utf-8")
                prompt.chmod(0o600)
        for role_name in ("soc-analyst", "incident-responder"):
            memory = runtime_directories["agent-memory"] / f"{role_name}-memory.md"
            memory.write_text("\n", encoding="utf-8")
            memory.chmod(0o600)
        relay_config_path = write_controlled_route_fixture(
            worker_root,
            controlled_home,
        )
        args = SimpleNamespace(
            db=db_path,
            prompt_dir=runtime_directories["prompts"],
            analysis_dir=runtime_directories["analysis"],
            prior_analysis_dir=runtime_directories["prior-analysis"],
            pcap_analysis_dir=runtime_directories["pcap-analysis"],
            rollup_dir=runtime_directories["rollups"],
            agent_memory_dir=runtime_directories["agent-memory"],
            shared_memory_file=shared_memory_path,
            asset_inventory_file=asset_inventory_path,
            incident_evidence_dir=runtime_directories["incident-evidence"],
            incident_evidence_config=relay_config_path,
            investigation_pivot_dir=runtime_directories[
                "investigation-pivots"
            ],
            live_osquery_config=live_osquery_path,
            disagreement_adjudicator_prompt_file=disagreement_prompt_path,
            ai_settings_file=settings_path,
            investigation_harness_policy=harness_policy_path,
            detection_playbooks=detection_playbooks_path,
            investigation_skills=investigation_skills_path,
            provider_lane="any",
            lock_file=worker_root / "worker.lock",
            wake_file=worker_root / "worker.wake",
            levels="critical,high,medium,low,informational",
            hours=87600,
            max_per_run=1,
            only_group_id=only_group_id,
            only_alert_id=only_alert_id,
            only_stable_group_key=frozen_group_key,
            only_dispatch_id=only_dispatch_id,
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            model=None,
            timeout=30,
            max_prompt_bytes=1024 * 1024,
            portal_wake_file=worker_root / "portal.wake",
            no_portal_refresh=True,
            alert_store_url=(
                "http://127.0.0.1:18787"
                if controlled_evaluation
                else "http://127.0.0.1:8787"
            ),
            include_tests=True,
            dry_run=False,
        )

        def status_transition(
            _base_url: str,
            _group_id: str,
            status: str,
            _error: str = "",
            _lease_token: str = "",
            *,
            lease_token: str = "",
            job_type: str = "ai_analysis",
            retryable: bool = True,
            expected_job_id: int = 0,
            expected_representative_alert_id: str = "",
            expected_dispatch_id: str = "",
            expected_stable_group_key: str = "",
            expected_assigned_route: str = "",
            expected_reviewer_route: str = "",
            reviewer_required: bool = False,
        ) -> bool | str:
            del lease_token, retryable
            if status != "processing":
                return True
            if not claim_available:
                contention_conn = sqlite3.connect(db_path)
                try:
                    contention_conn.execute(
                        """
                        UPDATE durable_jobs
                        SET status = 'processing',
                            processing_started_at = ?
                        WHERE dedupe_key = ?
                        """,
                        ("2026-07-24  12:00:02Z", group_id),
                    )
                    contention_conn.commit()
                finally:
                    contention_conn.close()
                return False
            authoritative_payload = dict(
                claimed_payload
                if claimed_payload is not None
                else queued_payload
            )
            authoritative_payload.setdefault("alert_id", alert_id)
            authoritative_payload.setdefault("group_id", group_id)
            if only_group_id:
                authoritative_payload.setdefault(
                    "representative_alert_id",
                    queued_payload.get("representative_alert_id", alert_id),
                )
                authoritative_payload.setdefault("stable_group_id", group_id)
                authoritative_payload.setdefault(
                    "stable_group_key",
                    frozen_group_key,
                )
                authoritative_payload.setdefault(
                    "dispatch_id",
                    only_dispatch_id,
                )
                authoritative_payload.setdefault(
                    "release_id",
                    DEPLOYED_RELEASE,
                )
                authoritative_payload.setdefault(
                    "agent_role",
                    queued_payload["agent_role"],
                )
                authoritative_payload.setdefault(
                    "expected_assigned_route",
                    expected_assigned_route,
                )
                authoritative_payload.setdefault(
                    "expected_reviewer_route",
                    expected_reviewer_route,
                )
                authoritative_payload.setdefault(
                    "reviewer_required",
                    reviewer_required,
                )
            return self.scheduler.ClaimedAiLease(
                "threshold-test-lease",
                job_payload=(
                    authoritative_payload
                    if claimed_payload_available
                    else {}
                ),
                job_type=(
                    claimed_job_type
                    if claimed_job_type is not None
                    else job_type
                ),
                resolved_key=(
                    claimed_resolved_key
                    if claimed_resolved_key is not None
                    else group_id
                ),
                job_id=expected_job_id,
                reanalysis_attempt_id=(
                    self.scheduler.job_reanalysis_attempt_id(
                        authoritative_payload,
                        "threshold-test-lease",
                    )
                    if job_type == "incident_response_analysis"
                    else ""
                ),
            )

        prompt_path = root / "prompt.json"
        incident_evidence_path = root / "incident-evidence.json"
        completed_process = (
            analysis_process
            if analysis_process is not None
            else SimpleNamespace(
                returncode=0,
                stdout="",
                stderr="",
            )
        )
        worker_stderr = io.StringIO()
        worker_stdout = io.StringIO()
        worker_environment = {
            "ONION_SENTINEL_EVALUATION_MODE": (
                "1" if controlled_evaluation else "0"
            ),
            "ONION_SENTINEL_RELEASE_ID": DEPLOYED_RELEASE,
        }
        if controlled_evaluation:
            worker_environment.update(
                {
                    "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(
                        controlled_runtime
                    ),
                    "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "1",
                    "ONION_SENTINEL_EVALUATION_TOKEN": "f" * 64,
                    "TMPDIR": str(runtime_directories["tmp"]),
                }
            )
        with (
            mock.patch.object(self.scheduler, "parse_args", return_value=args),
            mock.patch.object(self.scheduler, "HOME", controlled_home),
            mock.patch.object(self.scheduler.tempfile, "tempdir", None),
            mock.patch.object(self.scheduler, "require_runtime_capacity"),
            mock.patch.object(self.scheduler, "consume_wake_marker"),
            mock.patch.object(self.scheduler, "flush_deferred_analysis_results"),
            mock.patch.object(self.scheduler, "reconcile_worker_state", return_value=0),
            mock.patch.object(
                self.scheduler,
                "report_ai_job_status",
                side_effect=status_transition,
            ) as report_status,
            mock.patch.object(
                self.scheduler,
                "collect_incident_evidence",
                return_value=incident_evidence_path,
            ) as collect_incident_evidence,
            mock.patch.object(
                self.scheduler,
                "build_prompt",
                return_value=prompt_path,
                side_effect=build_prompt_error,
            ) as build_prompt,
            mock.patch.object(
                self.scheduler,
                "run_analysis",
                return_value=completed_process,
            ) as run_analysis,
            mock.patch.object(self.scheduler, "signal_dashboard_refresh"),
            mock.patch.object(self.scheduler.sys, "stderr", worker_stderr),
            mock.patch.object(self.scheduler.sys, "stdout", worker_stdout),
            mock.patch.dict(
                os.environ,
                worker_environment,
            ),
        ):
            return_code = self.scheduler.main()

        return {
            "return_code": return_code,
            "report_status": report_status,
            "collect_incident_evidence": collect_incident_evidence,
            "build_prompt": build_prompt,
            "run_analysis": run_analysis,
            "group_id": group_id,
            "stderr": worker_stderr.getvalue(),
            "stdout": worker_stdout.getvalue(),
        }
