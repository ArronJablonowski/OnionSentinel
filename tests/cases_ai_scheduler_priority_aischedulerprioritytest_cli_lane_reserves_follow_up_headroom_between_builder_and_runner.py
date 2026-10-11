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

class AiSchedulerPriorityTestCliLaneReservesFollowUpHeadroomBetweenBuilderAndRunnerCases:
    def test_cli_lane_reserves_follow_up_headroom_between_builder_and_runner(
        self,
    ) -> None:
        settings_path = Path(self.tempdir.name) / "custom-ai-settings.json"
        harness_policy_path = (
            Path(self.tempdir.name) / "investigation-harness-policy.json"
        )
        settings_path.write_text(
            json.dumps(
                {
                    "codex_cli_models": [
                        {
                            "model": "gpt-5.5",
                            "reasoning_effort": "high",
                            "enabled": True,
                        }
                    ],
                    "agent_models": {
                        "soc-analyst": "codex-cli:gpt-5.5:high",
                    },
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            prompt_dir=Path(self.tempdir.name) / "prompts",
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            include_tests=False,
            analysis_dir=Path(self.tempdir.name) / "analysis",
            timeout=600,
            max_prompt_bytes=1024 * 1024,
            alert_store_url="http://127.0.0.1:8787",
            ai_settings_file=settings_path,
            investigation_harness_policy=harness_policy_path,
            detection_playbooks=(
                Path(self.tempdir.name) / "detection-playbooks.json"
            ),
            provider_lane="cli",
            model=None,
        )
        args.prompt_dir.mkdir()
        prompt_path = args.prompt_dir / "prompt.json"
        prompt_path.write_text("{}", encoding="utf-8")

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        self.assertEqual(
            self.scheduler.effective_initial_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES,
        )
        completed = SimpleNamespace(
            returncode=0,
            stdout=str(prompt_path) + "\n",
            stderr="",
        )
        with mock.patch.object(
            self.scheduler,
            "run_command",
            return_value=completed,
        ) as run:
            self.assertEqual(
                self.scheduler.build_prompt(
                    "synthetic-alert",
                    args,
                    {"agent_role": "soc-analyst"},
                ),
                prompt_path,
            )
        builder_command = run.call_args.args[0]
        self.assertEqual(
            builder_command[
                builder_command.index("--max-package-bytes") + 1
            ],
            str(self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES),
        )
        self.assertEqual(
            builder_command[
                builder_command.index("--detection-playbooks") + 1
            ],
            str(args.detection_playbooks),
        )
        prompt_path.write_bytes(
            b"x"
            * (
                self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES
                + 1
            )
        )
        with (
            mock.patch.object(
                self.scheduler,
                "run_command",
                return_value=completed,
            ),
            self.assertRaisesRegex(
                RuntimeError,
                "prompt package exceeded the "
                f"{self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES}-byte",
            ),
        ):
            self.scheduler.build_prompt(
                "synthetic-alert",
                args,
                {"agent_role": "soc-analyst"},
            )
        command = self.scheduler.analysis_command(
            Path(self.tempdir.name) / "prompt.json",
            args,
            agent_role="soc-analyst",
        )
        self.assertEqual(
            command[command.index("--max-prompt-bytes") + 1],
            str(self.scheduler.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES),
        )
        self.assertEqual(
            command[command.index("--investigation-harness-policy") + 1],
            str(harness_policy_path),
        )


    def test_local_lane_retains_operator_prompt_package_budget(self) -> None:
        args = SimpleNamespace(
            max_prompt_bytes=1024 * 1024,
            provider_lane="ollama",
            ai_settings_file=Path(self.tempdir.name) / "missing-settings.json",
        )

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            1024 * 1024,
        )


    def test_codex_second_opinion_also_clamps_prompt_package_budget(self) -> None:
        settings_path = Path(self.tempdir.name) / "reviewer-settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "agent_models": {
                        "soc-analyst": "ollama:local-primary",
                    },
                    "agent_second_opinion_models": {
                        "soc-analyst": "codex-cli:gpt-5.6-sol:xhigh",
                    },
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            max_prompt_bytes=1024 * 1024,
            ai_settings_file=settings_path,
        )

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        self.assertEqual(
            self.scheduler.effective_initial_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            self.scheduler.CODEX_CLI_INITIAL_PROMPT_PACKAGE_BYTES,
        )


    def test_prompt_builder_and_runner_share_custom_role_prompt_directory(self) -> None:
        root = Path(self.tempdir.name)
        config_dir = root / "custom-config"
        config_dir.mkdir()
        settings_path = config_dir / "ai_model_settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "agent_models": {
                        "incident-responder": "codex-cli:gpt-5.5:high",
                    },
                }
            ),
            encoding="utf-8",
        )
        prompt_path = root / "prompts" / "prompt.json"
        prompt_path.parent.mkdir()
        prompt_path.write_text("{}", encoding="utf-8")
        args = SimpleNamespace(
            prompt_dir=prompt_path.parent,
            related_limit=8,
            correlation_limit=8,
            correlation_min_score=15,
            max_prompt_bytes=1024 * 1024,
            ai_settings_file=settings_path,
            detection_playbooks=root / "detection-playbooks.json",
            include_tests=False,
        )
        completed = SimpleNamespace(
            returncode=0,
            stdout=str(prompt_path) + "\n",
            stderr="",
        )

        with mock.patch.object(
            self.scheduler,
            "run_command",
            return_value=completed,
        ) as run:
            returned = self.scheduler.build_prompt(
                "synthetic-alert",
                args,
                {"agent_role": "incident-responder"},
            )

        command = run.call_args.args[0]
        self.assertEqual(returned, prompt_path)
        self.assertEqual(
            command[command.index("--system-prompt-file") + 1],
            str(
                self.scheduler.role_prompt_file(
                    config_dir,
                    "incident-responder",
                )
            ),
        )
        self.assertEqual(
            command[command.index("--second-opinion-prompt-file") + 1],
            str(
                self.scheduler.role_second_opinion_prompt_file(
                    config_dir,
                    "incident-responder",
                )
            ),
        )


    def test_hermes_only_route_keeps_its_separate_prompt_budget(self) -> None:
        settings_path = Path(self.tempdir.name) / "hermes-settings.json"
        settings_path.write_text(
            json.dumps(
                {
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:medium",
                    },
                    "agent_second_opinion_models": {
                        "soc-analyst": "",
                    },
                }
            ),
            encoding="utf-8",
        )
        args = SimpleNamespace(
            max_prompt_bytes=1024 * 1024,
            ai_settings_file=settings_path,
        )

        self.assertEqual(
            self.scheduler.effective_prompt_package_limit(
                args,
                agent_role="soc-analyst",
            ),
            1024 * 1024,
        )


    def test_indexed_contract_rejects_partial_schema(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_key TEXT")
        self.conn.execute("CREATE TABLE durable_jobs (id INTEGER)")
        self.conn.execute("CREATE TABLE ai_analysis_runs (id INTEGER)")

        self.assertFalse(self.scheduler.indexed_scheduler_available(self.conn))


    def test_indexed_manual_rerun_preempts_backlog_and_prior_analysis(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("manual-low", "low", "2020-01-01  00:00:00Z", 10)
        self.insert_alert("automatic-critical", "critical", "2026-07-19  11:00:00Z", 99)
        self.set_stable_group("manual-low", "manual-group")
        self.set_stable_group("automatic-critical", "critical-group")
        self.conn.execute(
            "UPDATE alerts SET filter_status = 'suppressed' WHERE alert_id = 'manual-low'"
        )
        self.conn.execute(
            "INSERT INTO ai_analysis_runs (group_id, alert_id, generated_at) VALUES (?, ?, ?)",
            ("manual-group", "manual-low", "2026-07-19  10:00:00Z"),
        )
        self.insert_indexed_job("manual-group", payload={"manual_reanalysis": True})
        self.args.hours = 1
        self.args.levels = "critical"
        self.conn.commit()

        selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "manual-low")
        self.assertEqual(selected["request_bucket"], 0)


    def test_indexed_pending_rerun_is_not_hidden_by_prior_selection(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("rerun-alert", "high", "2026-07-19  11:00:00Z", 90)
        self.set_stable_group("rerun-alert", "rerun-group")
        self.insert_indexed_job("rerun-group", payload={"manual_reanalysis": True})
        self.conn.commit()

        selected = self.scheduler.select_next_alert_indexed(
            self.conn,
            self.args,
            {"rerun-group"},
        )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "rerun-alert")


    def test_indexed_controlled_run_selects_only_exact_stable_group(self) -> None:
        self.enable_indexed_scheduler()
        target_group = "0123456789abcdefabcd"
        other_group = "fedcba9876543210abcd"
        self.insert_alert("target-low", "low", "2026-07-19  10:00:00Z", 10)
        self.insert_alert(
            "other-critical",
            "critical",
            "2026-07-19  11:00:00Z",
            100,
        )
        self.set_stable_group("target-low", target_group)
        self.set_stable_group("other-critical", other_group)
        self.insert_indexed_job(
            target_group,
            payload={"manual_reanalysis": True},
        )
        self.insert_indexed_job(
            other_group,
            payload={"manual_reanalysis": True},
        )
        self.args.only_group_id = target_group
        self.conn.commit()

        selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)

        self.assertIsNotNone(selected)
        self.assertEqual(selected["stable_group_id"], target_group)
        self.assertEqual(selected["alert_id"], "target-low")


    def test_controlled_run_rejects_malformed_stable_group(self) -> None:
        self.enable_indexed_scheduler()
        self.args.only_group_id = "not-a-stable-group"

        with self.assertRaisesRegex(SystemExit, "one exact 20-hex"):
            self.scheduler.select_next_alert_indexed(self.conn, self.args)


    def test_indexed_queue_preserves_severity_and_due_time(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("critical-old", "critical", "2026-07-19  09:00:00Z", 50)
        self.insert_alert("high-new", "high", "2026-07-19  11:00:00Z", 100)
        self.insert_alert("future-manual", "low", "2026-07-19  11:30:00Z", 100)
        for alert_id, group_id in (
            ("critical-old", "critical-group"),
            ("high-new", "high-group"),
            ("future-manual", "future-group"),
        ):
            self.set_stable_group(alert_id, group_id)
        self.insert_indexed_job("critical-group")
        self.insert_indexed_job("high-group")
        self.insert_indexed_job(
            "future-group",
            payload={"manual_reanalysis": True},
            next_attempt_at="2999-01-01  00:00:00Z",
        )
        self.conn.commit()

        first = self.scheduler.select_next_alert_indexed(self.conn, self.args)
        self.conn.execute(
            "UPDATE durable_jobs SET status = 'completed' WHERE dedupe_key = ?",
            ("critical-group",),
        )
        self.conn.commit()
        second = self.scheduler.select_next_alert_indexed(
            self.conn, self.args, {"critical-group"},
        )

        self.assertEqual(first["alert_id"], "critical-old")
        self.assertEqual(second["alert_id"], "high-new")


    def test_indexed_queue_prevents_incident_role_from_starving_soc_analysis(
        self,
    ) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert(
            "soc-medium",
            "medium",
            "2026-07-31  12:00:00-06:00",
            60,
        )
        self.insert_alert(
            "incident-medium",
            "medium",
            "2026-07-31  12:20:00-06:00",
            60,
        )
        self.set_stable_group("soc-medium", "soc-medium-group")
        self.set_stable_group("incident-medium", "incident-medium-group")
        self.insert_indexed_job(
            "soc-medium-group",
            payload={"agent_role": "soc-analyst"},
            priority=2,
            next_attempt_at="2026-07-31  12:00:00-06:00",
        )
        self.insert_indexed_job(
            "incident-medium-group",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
            priority=102,
            next_attempt_at="2026-07-31  12:20:00-06:00",
        )
        self.conn.commit()

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-31  12:30:00-06:00",
        ):
            selected = self.scheduler.select_next_alert_indexed(
                self.conn,
                self.args,
            )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "soc-medium")
        self.assertEqual(selected["durable_job_type"], "ai_analysis")
        self.assertEqual(selected["fairness_bucket"], 0)


    def test_indexed_queue_keeps_severity_ahead_of_cross_role_age_fairness(
        self,
    ) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert(
            "soc-medium-old",
            "medium",
            "2026-07-31  11:00:00-06:00",
            60,
        )
        self.insert_alert(
            "incident-critical-new",
            "critical",
            "2026-07-31  12:25:00-06:00",
            95,
        )
        self.set_stable_group("soc-medium-old", "soc-medium-old-group")
        self.set_stable_group(
            "incident-critical-new",
            "incident-critical-new-group",
        )
        self.insert_indexed_job(
            "soc-medium-old-group",
            payload={"agent_role": "soc-analyst"},
            next_attempt_at="2026-07-31  11:00:00-06:00",
        )
        self.insert_indexed_job(
            "incident-critical-new-group",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
            next_attempt_at="2026-07-31  12:25:00-06:00",
        )
        self.conn.commit()

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-31  12:30:00-06:00",
        ):
            selected = self.scheduler.select_next_alert_indexed(
                self.conn,
                self.args,
            )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "incident-critical-new")
        self.assertEqual(
            selected["durable_job_type"],
            "incident_response_analysis",
        )


    def test_indexed_queue_uses_subsecond_due_clock(self) -> None:
        self.enable_indexed_scheduler()
        group_id = "0123456789abcdefabcd"
        self.insert_alert(
            "subsecond-alert",
            "high",
            "2026-07-28  02:24:29-06:00",
            90,
        )
        self.set_stable_group("subsecond-alert", group_id)
        self.insert_indexed_job(
            group_id,
            payload={"manual_reanalysis": True},
            next_attempt_at="2026-07-28  02:24:29.438-06:00",
        )
        self.conn.commit()

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-28  02:24:29.437-06:00",
        ):
            self.assertIsNone(
                self.scheduler.select_next_alert_indexed(
                    self.conn,
                    self.args,
                )
            )

        with mock.patch.object(
            self.scheduler,
            "project_now_precise",
            return_value="2026-07-28  02:24:29.500-06:00",
        ):
            selected = self.scheduler.select_next_alert_indexed(
                self.conn,
                self.args,
            )

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "subsecond-alert")


    def test_indexed_reconciliation_requires_current_run_and_no_rerun(self) -> None:
        self.enable_indexed_scheduler()
        for alert_id, group_id in (
            ("current", "current-group"),
            ("stale", "stale-group"),
            ("rerun", "rerun-group"),
        ):
            self.insert_alert(alert_id, "high", "2026-07-19  11:00:00Z")
            self.set_stable_group(alert_id, group_id)
        self.insert_indexed_job(
            "current-group", processing_started_at="2026-07-19  10:00:00Z",
        )
        self.insert_indexed_job(
            "stale-group", processing_started_at="2026-07-19  10:00:00Z",
        )
        self.insert_indexed_job(
            "rerun-group", processing_started_at="2026-07-19  10:00:00Z", rerun_requested=1,
        )
        self.insert_indexed_job(
            "orphan-group", processing_started_at="2026-07-19  10:00:00Z",
        )
        self.conn.executemany(
            "INSERT INTO ai_analysis_runs (group_id, generated_at) VALUES (?, ?)",
            [
                ("current-group", "2026-07-19  10:01:00Z"),
                ("stale-group", "2026-07-19  09:59:00Z"),
                ("rerun-group", "2026-07-19  10:01:00Z"),
            ],
        )
        self.conn.commit()

        reconciled = self.scheduler.indexed_reconcilable_ai_job_ids(self.conn)

        self.assertEqual(reconciled, {"current-group", "orphan-group"})


    def test_drains_each_severity_newest_first_before_lower_severity(self) -> None:
        self.insert_alert("medium-newest", "medium", "2026-07-03  00:50:00Z", 90)
        self.insert_alert("high-newer-than-critical", "high", "2026-07-03  00:55:00Z", 90)
        self.insert_alert("critical-old", "critical", "2026-07-03  00:10:00Z", 70)
        self.insert_alert("critical-new", "critical", "2026-07-03  00:20:00Z", 60)
        self.insert_alert("low-newest", "low", "2026-07-03  01:00:00Z", 100)
        self.conn.commit()

        selected_groups: set[str] = set()
        selected_ids: list[str] = []
        for _ in range(5):
            selected = self.scheduler.select_next_alert(self.conn, self.args, set(), selected_groups)
            self.assertIsNotNone(selected)
            selected_ids.append(selected["alert_id"])
            selected_groups.add(self.scheduler.alert_group_key(selected))

        self.assertEqual(
            selected_ids,
            [
                "critical-new",
                "critical-old",
                "high-newer-than-critical",
                "medium-newest",
                "low-newest",
            ],
        )


    def test_orphaned_pending_jobs_are_reconciled_without_touching_active_groups(self) -> None:
        self.insert_alert(
            "active-alert",
            "high",
            "2026-07-03  01:00:00Z",
            rule_name="Active detection",
            source_ip="192.0.2.10",
            destination_ip="198.51.100.10",
        )
        active_row = self.conn.execute("SELECT * FROM alerts WHERE alert_id = 'active-alert'").fetchone()
        active_id = self.scheduler.alert_group_id(self.scheduler.alert_group_key(active_row))
        self.conn.execute("INSERT INTO alert_group_summary (group_id) VALUES (?)", (active_id,))
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        self.conn.executemany(
            "INSERT INTO durable_jobs (job_type, dedupe_key, status) VALUES ('ai_analysis', ?, 'pending')",
            [(active_id,), ("orphaned-group-id",)],
        )
        self.conn.commit()

        orphaned = self.scheduler.orphaned_pending_ai_job_ids(self.conn)

        self.assertEqual(orphaned, {"orphaned-group-id"})


    def test_stable_queue_identity_remains_active_through_legacy_alias(self) -> None:
        self.conn.execute("INSERT INTO alert_group_summary (group_id) VALUES ('legacy-group')")
        self.conn.execute(
            "INSERT INTO alert_group_alias (legacy_group_id, stable_group_id) VALUES (?, ?)",
            ("legacy-group", "stable-group"),
        )
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        self.conn.executemany(
            "INSERT INTO durable_jobs (job_type, dedupe_key, status) VALUES ('ai_analysis', ?, 'pending')",
            [("stable-group",), ("orphaned-group",)],
        )
        self.conn.commit()

        orphaned = self.scheduler.orphaned_pending_ai_job_ids(self.conn)

        self.assertEqual(orphaned, {"orphaned-group"})


    def test_selected_alert_preserves_stable_queue_identity(self) -> None:
        self.conn.execute("ALTER TABLE alerts ADD COLUMN stable_group_id TEXT")
        self.insert_alert(
            "stable-alert",
            "high",
            "2026-07-03  01:00:00Z",
            rule_name="Stable identity detection",
        )
        self.conn.execute(
            "UPDATE alerts SET stable_group_id = ? WHERE alert_id = ?",
            ("stable-v2-group", "stable-alert"),
        )
        self.conn.commit()

        selected = self.scheduler.select_next_alert(self.conn, self.args, set(), set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["stable_group_id"], "stable-v2-group")


    def test_pending_durable_intent_forces_reanalysis_of_current_artifact(self) -> None:
        self.insert_alert(
            "durable-rerun-alert",
            "high",
            "2026-07-03  01:00:00Z",
            rule_name="Durable rerun detection",
            source_ip="192.0.2.20",
            destination_ip="198.51.100.20",
        )
        row = self.conn.execute("SELECT * FROM alerts WHERE alert_id = ?", ("durable-rerun-alert",)).fetchone()
        group_id = self.scheduler.alert_group_id(self.scheduler.alert_group_key(row))
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.execute(
            "INSERT INTO durable_jobs (job_type, dedupe_key, status) VALUES ('ai_analysis', ?, 'pending')",
            (group_id,),
        )
        self.conn.commit()
        with tempfile.TemporaryDirectory() as tmpdir:
            analysis_dir = Path(tmpdir)
            (analysis_dir / "current-local-ai-analysis.json").write_text(
                json.dumps({"alert_id": "durable-rerun-alert"}),
                encoding="utf-8",
            )
            self.args.analysis_dir = analysis_dir
            analyzed = self.scheduler.analyzed_alert_ids(analysis_dir)
            selected = self.scheduler.select_next_alert(self.conn, self.args, analyzed, set())

        self.assertIsNotNone(selected)
        self.assertEqual(selected["alert_id"], "durable-rerun-alert")


    def test_artifact_reconciliation_does_not_erase_fresh_pending_intent(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE durable_jobs (
                job_type TEXT NOT NULL,
                dedupe_key TEXT NOT NULL,
                status TEXT NOT NULL,
                processing_started_at TEXT,
                rerun_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.conn.executemany(
            """
            INSERT INTO durable_jobs (
                job_type, dedupe_key, status, processing_started_at, rerun_requested
            ) VALUES ('ai_analysis', ?, 'pending', ?, ?)
            """,
            [
                ("fresh-evidence", None, 0),
                ("missed-completion-callback", "2026-07-03  00:00:00Z", 0),
                ("latched-rerun", "2026-07-03  00:00:00Z", 1),
            ],
        )
        self.conn.commit()

        reconciled = self.scheduler.reconcilable_completed_ai_job_ids(
            self.conn,
            {"fresh-evidence", "missed-completion-callback", "latched-rerun"},
        )

        self.assertEqual(reconciled, {"missed-completion-callback"})
