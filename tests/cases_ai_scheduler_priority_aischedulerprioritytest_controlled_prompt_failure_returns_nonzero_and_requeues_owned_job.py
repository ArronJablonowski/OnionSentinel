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

class AiSchedulerPriorityTestControlledPromptFailureReturnsNonzeroAndRequeuesOwnedJobCases:
    def test_controlled_prompt_failure_returns_nonzero_and_requeues_owned_job(
        self,
    ) -> None:
        group_id = "1123456789abcdefabcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "1" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
            build_prompt_error=RuntimeError("prompt builder failed rc=1"),
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(failed.args[3], "prompt builder failed rc=1")
        self.assertEqual(failed.args[4], "threshold-test-lease")
        self.assertIs(failed.kwargs["retryable"], True)
        self.assertIn('"controlled_evaluation": "selected_job_failed"', result["stderr"])
        self.assertIn(f'"stable_group_id": "{group_id}"', result["stderr"])


    def test_controlled_analysis_failure_returns_nonzero_after_retry_callback(
        self,
    ) -> None:
        group_id = "2123456789abcdefabcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "2" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
            analysis_process=SimpleNamespace(
                returncode=7,
                stdout="",
                stderr="provider connection closed unexpectedly",
            ),
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["run_analysis"].assert_called_once()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(
            failed.args[3],
            "provider connection closed unexpectedly",
        )
        self.assertIs(failed.kwargs["retryable"], True)
        self.assertIn('"controlled_evaluation": "selected_job_failed"', result["stderr"])


    def test_production_prompt_failure_keeps_retry_and_scheduler_exit_semantics(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            build_prompt_error=RuntimeError("prompt builder failed rc=1"),
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(failed.args[3], "prompt builder failed rc=1")
        self.assertIs(failed.kwargs["retryable"], True)
        self.assertNotIn("selected_job_failed", result["stderr"])


    def test_controlled_worker_rejects_replaced_claim_alert_before_prompt(
        self,
    ) -> None:
        group_id = "0123456789abcdefabcd"
        expected_alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "b" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "alert_id": "replacement-alert",
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=expected_alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("alert identity", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )


    def test_controlled_incident_worker_rejects_dispatch_drift_before_evidence(
        self,
    ) -> None:
        group_id = "fedcba9876543210abcd"
        alert_id = "incident_response_analysis-critical-threshold-alert"
        expected_dispatch_id = "c" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": True,
                "dispatch_id": expected_dispatch_id,
            },
            claimed_payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": True,
                "dispatch_id": "d" * 64,
            },
            job_type="incident_response_analysis",
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=expected_dispatch_id,
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("dispatch identity did not match", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )


    def test_controlled_worker_rejects_mismatched_candidate_without_claim(self) -> None:
        group_id = "abcdef0123456789abcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "e" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "alert_id": "ordinary-replacement-alert",
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(result["return_code"], 0)
        result["report_status"].assert_not_called()
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertNotIn("selected_job_failed", result["stderr"])


    def test_controlled_worker_rejects_release_mismatch_before_claim(self) -> None:
        group_id = "abcdef0123456789abcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "9" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
                "release_id": "e" * 40,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(result["return_code"], 0)
        result["report_status"].assert_not_called()
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertNotIn("selected_job_failed", result["stderr"])


    def test_controlled_worker_releases_only_owned_lease_on_release_drift(
        self,
    ) -> None:
        group_id = "bbcdef0123456789abcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "8" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
                "release_id": "e" * 40,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("release_id did not match", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )


    def test_controlled_worker_requeues_owned_lease_when_alert_key_drifts(
        self,
    ) -> None:
        group_id = "bcdef0123456789abcde"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "f" * 64
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True, "dispatch_id": dispatch_id},
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
            current_alert_group_key="key:post-queue-drift",
        )

        self.assertEqual(
            result["return_code"],
            self.scheduler.CONTROLLED_SELECTED_JOB_FAILURE_EXIT_CODE,
        )
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("stable group key is invalid", released.args[3])
        self.assertIs(released.kwargs["retryable"], True)
        self.assertIn(
            '"controlled_evaluation": "selected_job_failed"',
            result["stderr"],
        )


    def test_worker_rejects_invalid_claimed_and_current_stable_group_key(
        self,
    ) -> None:
        invalid_key = "v2|bad\x00group"
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "stable_group_key": invalid_key,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "stable_group_key": invalid_key,
            },
            current_alert_group_key=invalid_key,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        released = result["report_status"].call_args_list[-1]
        self.assertEqual(released.args[2], "failed")
        self.assertIn("stable group key is invalid", released.args[3])


    def test_incident_responder_low_job_bypasses_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": True,
                "reanalysis_run_id": "irr-11111111-1111-1111-1111-111111111111",
                "case_id": "ir-threshold-test",
            },
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_called_once()
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            self.scheduler.incident_reanalysis_attempt_id("threshold-test-lease"),
        )


    def test_normal_incident_escalation_does_not_receive_reanalysis_attempt_id(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
            incident_threshold="low",
        )

        self.assertEqual(result["return_code"], 0)
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            "",
        )


    def test_automatic_incident_below_independent_floor_is_retired(self) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "agent_role": "incident-responder",
                "manual_reanalysis": False,
            },
            job_type="incident_response_analysis",
            analysis_threshold="informational",
            incident_threshold="high",
        )

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        retired = result["report_status"].call_args_list[-1]
        self.assertEqual(retired.args[2], "failed")
        self.assertIn("automatic incident response skipped", retired.args[3])
        self.assertIs(retired.kwargs["retryable"], False)


    def test_legacy_manual_incident_escalation_without_run_id_runs_unbound(
        self,
    ) -> None:
        """Old escalation rows used manual_reanalysis without a run ledger."""
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "agent_role": "incident-responder",
                "case_id": "ir-legacy-escalation",
                "manual_reanalysis": True,
            },
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_called_once()
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            "",
        )


    def test_incident_worker_uses_claim_identity_when_payload_changes_preclaim(
        self,
    ) -> None:
        selected_payload = {
            "agent_role": "incident-responder",
            "manual_reanalysis": True,
            "reanalysis_run_id": "irr-11111111-1111-1111-1111-111111111111",
            "case_id": "ir-selected-run",
            "alert_id": "selected-alert",
        }
        claimed_payload = {
            "agent_role": "incident-responder",
            "manual_reanalysis": True,
            "reanalysis_run_id": "irr-22222222-2222-2222-2222-222222222222",
            "case_id": "ir-replacement-run",
            "alert_id": "replacement-alert",
        }

        result = self.run_indexed_worker_once(
            severity="critical",
            payload=selected_payload,
            claimed_payload=claimed_payload,
            job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        self.assertEqual(
            result["collect_incident_evidence"].call_args.args[0],
            "replacement-alert",
        )
        self.assertEqual(
            result["build_prompt"].call_args.args[0],
            "replacement-alert",
        )
        self.assertEqual(
            result["build_prompt"].call_args.args[2]["reanalysis_run_id"],
            claimed_payload["reanalysis_run_id"],
        )
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            self.scheduler.incident_reanalysis_attempt_id(
                "threshold-test-lease"
            ),
        )


    def test_indexed_provider_lanes_claim_only_assigned_agent_roles(self) -> None:
        self.enable_indexed_scheduler()
        self.insert_alert("soc-alert", "high", "2026-07-19  11:00:00Z", 90)
        self.insert_alert("ir-alert", "high", "2026-07-19  10:00:00Z", 90)
        self.set_stable_group("soc-alert", "soc-group")
        self.set_stable_group("ir-alert", "ir-group")
        self.insert_indexed_job(
            "soc-group",
            payload={"agent_role": "soc-analyst"},
        )
        self.insert_indexed_job(
            "ir-group",
            payload={"agent_role": "incident-responder"},
            job_type="incident_response_analysis",
        )
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [
                        {
                            "model": "gpt-5.6-sol",
                            "reasoning_effort": "high",
                            "enabled": True,
                        }
                    ],
                    "agent_models": {
                        "soc-analyst": "ollama:local-model",
                        "incident-responder": "codex-cli:gpt-5.6-sol:high",
                    }
                }
            ),
            encoding="utf-8",
        )
        self.conn.commit()

        self.args.provider_lane = "cli"
        cli_selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)
        self.args.provider_lane = "ollama"
        ollama_selected = self.scheduler.select_next_alert_indexed(self.conn, self.args)

        self.assertEqual(cli_selected["alert_id"], "ir-alert")
        self.assertEqual(ollama_selected["alert_id"], "soc-alert")


    def test_cli_lane_rejects_malformed_or_disabled_exact_routes(self) -> None:
        settings_path = self.args.ai_settings_file
        for route, roster in (
            (
                "codex-cli:gpt-5.6-sol:ultra",
                [{"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True}],
            ),
            (
                "codex-cli:gpt-5.6-sol:high",
                [{"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": False}],
            ),
            (
                "codex-cli:not allowed:high",
                [{"model": "not allowed", "reasoning_effort": "high", "enabled": True}],
            ),
            (
                "codex-cli:gpt-9-unknown:high",
                [{"model": "gpt-9-unknown", "reasoning_effort": "high", "enabled": True}],
            ),
        ):
            with self.subTest(route=route, roster=roster):
                settings_path.write_text(
                    json.dumps(
                        {
                            "codex_cli_models": roster,
                            "agent_models": {"soc-analyst": route},
                        }
                    ),
                    encoding="utf-8",
                )
                self.assertEqual(self.scheduler.cli_agent_roles(settings_path), set())


    def test_cli_lane_includes_enabled_hermes_but_not_openclaw(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": True,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "medium",
                    "openclaw_enabled": True,
                    "openclaw_model": "openai/gpt-5.6-terra",
                    "openclaw_reasoning_effort": "high",
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:medium",
                        "incident-responder": "openclaw:openai/gpt-5.6-terra:high",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            {"soc-analyst"},
        )


    def test_cli_lane_rejects_unsupported_hermes_reasoning_effort(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": True,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "xhigh",
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:xhigh",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            set(),
        )


    def test_local_openclaw_route_stays_out_of_hosted_cli_lane(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": False,
                    "openclaw_enabled": True,
                    "openclaw_model": "ollama/gemma4:26b-mlx",
                    "openclaw_reasoning_effort": "medium",
                    "agent_models": {
                        "soc-analyst": "openclaw:ollama/gemma4:26b-mlx:medium",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            set(),
        )


    def test_unsupported_openclaw_routes_never_enter_hosted_cli_lane(self) -> None:
        for model in ("local/gpt-oss:20b", "lmstudio/gpt-oss:20b"):
            route = f"openclaw:{model}:medium"
            with self.subTest(model=model):
                self.args.ai_settings_file.write_text(
                    json.dumps(
                        {
                            "codex_cli_models": [],
                            "hermes_agent_enabled": False,
                            "openclaw_enabled": True,
                            "openclaw_model": model,
                            "openclaw_reasoning_effort": "medium",
                            "agent_models": {"soc-analyst": route},
                        }
                    ),
                    encoding="utf-8",
                )

                self.assertEqual(
                    self.scheduler.cli_agent_roles(
                        self.args.ai_settings_file
                    ),
                    set(),
                )


    def test_disabled_harnesses_never_enter_hosted_cli_lane(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps(
                {
                    "codex_cli_models": [],
                    "hermes_agent_enabled": False,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "xhigh",
                    "openclaw_enabled": False,
                    "openclaw_model": "openai/gpt-5.6-terra",
                    "openclaw_reasoning_effort": "high",
                    "agent_models": {
                        "soc-analyst": "hermes-agent:gpt-5.6-sol:xhigh",
                        "incident-responder": "openclaw:openai/gpt-5.6-terra:high",
                    },
                }
            ),
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.cli_agent_roles(self.args.ai_settings_file),
            set(),
        )


    def test_analysis_child_uses_scheduler_settings_and_prompt_limit(self) -> None:
        settings_path = Path(self.tempdir.name) / "custom-ai-settings.json"
        harness_policy_path = (
            Path(self.tempdir.name) / "investigation-harness-policy.json"
        )
        args = SimpleNamespace(
            analysis_dir=Path(self.tempdir.name) / "analysis",
            timeout=600,
            max_prompt_bytes=1024 * 1024,
            alert_store_url="http://127.0.0.1:8787",
            ai_settings_file=settings_path,
            investigation_harness_policy=harness_policy_path,
            model=None,
        )

        command = self.scheduler.analysis_command(
            Path(self.tempdir.name) / "prompt.json",
            args,
            reanalysis_attempt_id="ira-" + ("a" * 40),
        )

        self.assertEqual(
            command[command.index("--ai-settings-file") + 1],
            str(settings_path),
        )
        self.assertEqual(
            command[command.index("--investigation-harness-policy") + 1],
            str(harness_policy_path),
        )
        self.assertEqual(
            command[command.index("--max-prompt-bytes") + 1],
            str(1024 * 1024),
        )
        self.assertEqual(
            command[command.index("--reanalysis-attempt-id") + 1],
            "ira-" + ("a" * 40),
        )


