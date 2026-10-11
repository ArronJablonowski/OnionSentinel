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

class AiSchedulerPriorityTestTerminalSuccessRecoveryProvesExactIrCommitCases:
    def test_terminal_success_recovery_proves_exact_ir_commit(self) -> None:
        alert_conn, harness_conn = self.recovery_databases()
        try:
            self.insert_terminal_recovery_fixture(alert_conn, harness_conn)
            candidates = self.scheduler.terminal_success_recovery_candidates(
                alert_conn,
                harness_conn,
                "cli",
            )
            self.assertEqual(len(candidates), 1)
            self.assertEqual(candidates[0]["job_type"], "incident_response_analysis")
            self.assertEqual(candidates[0]["lease_token"], "exact-recovery-lease")

            alert_conn.execute(
                "UPDATE incident_response_cases SET latest_analysis_id = 'different-analysis'"
            )
            alert_conn.commit()
            self.assertEqual(
                self.scheduler.terminal_success_recovery_candidates(
                    alert_conn,
                    harness_conn,
                    "cli",
                ),
                [],
            )
        finally:
            harness_conn.close()
            alert_conn.close()


    def test_terminal_success_recovery_enforces_lane_and_attempt_time(self) -> None:
        for route, lane, generated_at, expected_count in (
            (PRIMARY_ROUTE, "cli", "2026-08-05T14:05:00Z", 1),
            (PRIMARY_ROUTE, "ollama", "2026-08-05T14:05:00Z", 0),
            ("ollama:gemma4:31b", "ollama", "2026-08-05T13:59:59Z", 0),
        ):
            with self.subTest(route=route, lane=lane, generated_at=generated_at):
                alert_conn, harness_conn = self.recovery_databases()
                try:
                    self.insert_terminal_recovery_fixture(
                        alert_conn,
                        harness_conn,
                        job_type="ai_analysis",
                        route=route,
                        generated_at=generated_at,
                    )
                    candidates = self.scheduler.terminal_success_recovery_candidates(
                        alert_conn,
                        harness_conn,
                        lane,
                    )
                    self.assertEqual(len(candidates), expected_count)
                finally:
                    harness_conn.close()
                    alert_conn.close()


    def test_terminal_success_recovery_reports_exact_owned_lease(self) -> None:
        root = Path(self.tempdir.name)
        alert_path = root / "alerts-recovery.sqlite3"
        harness_path = root / "harness-recovery.sqlite3"
        alert_conn, harness_conn = self.recovery_databases(
            alert_path,
            harness_path,
        )
        self.insert_terminal_recovery_fixture(alert_conn, harness_conn)
        harness_conn.close()
        alert_conn.close()
        args = SimpleNamespace(
            db=alert_path,
            harness_db=harness_path,
            provider_lane="cli",
            alert_store_url="http://127.0.0.1:8787",
        )
        with mock.patch.object(
            self.scheduler,
            "report_ai_job_status",
            return_value=True,
        ) as report_status:
            recovered = self.scheduler.reconcile_terminal_success_durable_jobs(args)

        self.assertEqual(recovered, 1)
        report_status.assert_called_once_with(
            "http://127.0.0.1:8787",
            "recovery-group",
            "completed",
            lease_token="exact-recovery-lease",
            job_type="incident_response_analysis",
        )


    def test_deterministic_context_and_prompt_size_failures_are_not_retried(self) -> None:
        for detail in (
            "Codex CLI analysis failed: model context window exhausted",
            "prompt package remains above 1048576 bytes after deterministic compaction",
            "InvestigationQueryError: investigation query prompt projection exceeds its cumulative byte budget",
            "command stderr exceeded the 1048576-byte limit",
            "Codex CLI analysis failed: provider authentication failed",
            "Codex CLI analysis failed: configured model is unavailable or unauthorized",
            "incident reanalysis claim did not return its server-authoritative job identity",
            "incident reanalysis lease identity did not match its server-bound attempt",
            "durable AI claim job identity is invalid",
            "durable AI claim group identity is invalid",
            "durable AI claim alert identity is invalid",
            "controlled AI run requires a durable AI job claim",
            "controlled AI run identity arguments are incomplete",
            "controlled AI claim group identity did not match --only-group-id",
            "controlled AI claim alert identity did not match --only-alert-id",
            "controlled AI claim dispatch identity did not match --only-dispatch-id",
            "controlled AI claim release_id did not match the deployed runtime",
        ):
            self.assertFalse(self.scheduler.ai_failure_is_retryable(detail))

        for detail in (
            "prompt builder failed rc=1",
            "durable AI claim did not return its server-authoritative job identity",
            "Codex CLI analysis failed: provider rate or usage limit reached",
            "Codex CLI analysis failed: provider connection closed unexpectedly",
        ):
            self.assertTrue(self.scheduler.ai_failure_is_retryable(detail))


    def test_controlled_run_arguments_require_complete_frozen_identity(self) -> None:
        group_id = "0123456789abcdefabcd"
        alert_id = ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-1"
        stable_group_key = "v2|frozen-group-key"
        dispatch_id = "a" * 64

        with mock.patch(
            "sys.argv",
            [
                str(SCHEDULER_PATH),
                "--only-group-id",
                group_id,
                "--only-alert-id",
                alert_id,
                "--only-stable-group-key",
                stable_group_key,
                "--only-dispatch-id",
                dispatch_id,
            ],
        ):
            args = self.scheduler.parse_args()

        self.assertEqual(args.only_group_id, group_id)
        self.assertEqual(args.only_alert_id, alert_id)
        self.assertEqual(args.only_stable_group_key, stable_group_key)
        self.assertEqual(args.only_dispatch_id, dispatch_id)

        incomplete = (
            ("--only-group-id", group_id),
            ("--only-alert-id", alert_id),
            ("--only-dispatch-id", dispatch_id),
            (
                "--only-group-id",
                group_id,
                "--only-alert-id",
                alert_id,
            ),
            (
                "--only-group-id",
                group_id,
                "--only-dispatch-id",
                dispatch_id,
            ),
            (
                "--only-alert-id",
                alert_id,
                "--only-dispatch-id",
                dispatch_id,
            ),
        )
        for cli_args in incomplete:
            with self.subTest(cli_args=cli_args), mock.patch(
                "sys.argv",
                [str(SCHEDULER_PATH), *cli_args],
            ), mock.patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.scheduler.parse_args()


    def test_maintenance_drain_marker_requires_owner_only_regular_file(self) -> None:
        marker = Path(self.tempdir.name) / "maintenance-drain"
        self.assertEqual(
            self.scheduler.maintenance_drain_active(marker),
            (False, ""),
        )

        marker.write_text("operator maintenance\n", encoding="utf-8")
        marker.chmod(0o600)
        active, detail = self.scheduler.maintenance_drain_active(marker)
        self.assertTrue(active)
        self.assertEqual(detail, "maintenance drain requested")

        marker.chmod(0o644)
        active, detail = self.scheduler.maintenance_drain_active(marker)
        self.assertTrue(active)
        self.assertIn("not owner-only", detail)

        marker.unlink()
        marker.mkdir()
        active, detail = self.scheduler.maintenance_drain_active(marker)
        self.assertTrue(active)
        self.assertIn("not a regular file", detail)


    def test_drain_file_cli_override_is_parsed(self) -> None:
        marker = Path(self.tempdir.name) / "custom-maintenance-drain"
        with mock.patch(
            "sys.argv",
            [str(SCHEDULER_PATH), "--drain-file", str(marker)],
        ):
            args = self.scheduler.parse_args()
        self.assertEqual(args.drain_file, marker)


    def test_maintenance_drain_exits_before_controlled_token_or_database(self) -> None:
        marker = Path(self.tempdir.name) / "maintenance-drain"
        marker.write_text("deployment\n", encoding="utf-8")
        marker.chmod(0o600)
        args = SimpleNamespace(drain_file=marker)
        with mock.patch.object(
            self.scheduler,
            "parse_args",
            return_value=args,
        ), mock.patch.object(
            self.scheduler,
            "controlled_evaluation_runtime",
            side_effect=AssertionError("drain must precede controlled token use"),
        ), mock.patch("sys.stdout", io.StringIO()) as stdout:
            self.assertEqual(self.scheduler.main(), 0)
        self.assertIn("no additional AI work will be claimed", stdout.getvalue())


    def test_controlled_run_arguments_reject_unbounded_or_noncanonical_ids(
        self,
    ) -> None:
        group_id = "0123456789abcdefabcd"
        stable_group_key = "v2|frozen-group-key"
        valid_dispatch_id = "a" * 64
        invalid_id_sets = (
            ("alert/with/path", valid_dispatch_id),
            ("a" * 257, valid_dispatch_id),
            ("valid-alert", "A" * 64),
            ("valid-alert", "a" * 63),
        )

        for alert_id, dispatch_id in invalid_id_sets:
            with self.subTest(
                alert_id=alert_id,
                dispatch_id=dispatch_id,
            ), mock.patch(
                "sys.argv",
                [
                    str(SCHEDULER_PATH),
                    "--only-group-id",
                    group_id,
                    "--only-alert-id",
                    alert_id,
                    "--only-stable-group-key",
                    stable_group_key,
                    "--only-dispatch-id",
                    dispatch_id,
                ],
            ), mock.patch("sys.stderr", io.StringIO()):
                with self.assertRaises(SystemExit):
                    self.scheduler.parse_args()

        with mock.patch(
            "sys.argv",
            [
                str(SCHEDULER_PATH),
                "--only-group-id",
                group_id,
                "--only-alert-id",
                "valid-alert",
                "--only-stable-group-key",
                "x" * 2049,
                "--only-dispatch-id",
                valid_dispatch_id,
            ],
        ), mock.patch("sys.stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                self.scheduler.parse_args()


    def test_controlled_stable_group_key_uses_utf8_bytes_and_rejects_nul(
        self,
    ) -> None:
        group_id = "0123456789abcdefabcd"
        alert_id = "valid-alert"
        dispatch_id = "a" * 64
        exact_multibyte_key = "\u00e9" * 1024
        self.assertEqual(len(exact_multibyte_key.encode("utf-8")), 2048)
        self.assertTrue(
            self.scheduler.valid_controlled_stable_group_key(
                exact_multibyte_key
            )
        )

        with mock.patch(
            "sys.argv",
            [
                str(SCHEDULER_PATH),
                "--only-group-id",
                group_id,
                "--only-alert-id",
                alert_id,
                "--only-stable-group-key",
                exact_multibyte_key,
                "--only-dispatch-id",
                dispatch_id,
            ],
        ):
            args = self.scheduler.parse_args()
        self.assertEqual(args.only_stable_group_key, exact_multibyte_key)

        invalid_keys = (
            "\u00e9" * 1025,
            "v2|bad\x00group",
            "\ud800",
        )
        for invalid_key in invalid_keys:
            with self.subTest(invalid_key=repr(invalid_key)):
                self.assertFalse(
                    self.scheduler.valid_controlled_stable_group_key(
                        invalid_key
                    )
                )
                with mock.patch(
                    "sys.argv",
                    [
                        str(SCHEDULER_PATH),
                        "--only-group-id",
                        group_id,
                        "--only-alert-id",
                        alert_id,
                        "--only-stable-group-key",
                        invalid_key,
                        "--only-dispatch-id",
                        dispatch_id,
                    ],
                ), mock.patch("sys.stderr", io.StringIO()):
                    with self.assertRaises(SystemExit):
                        self.scheduler.parse_args()


    def test_runtime_release_attestation_uses_literal_env_file_fallback(
        self,
    ) -> None:
        env_path = Path(self.tempdir.name) / ".env"
        env_path.write_text(
            "# runtime metadata\n"
            f"ONION_SENTINEL_RELEASE_ID={DEPLOYED_RELEASE}\n",
            encoding="utf-8",
        )

        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={},
                env_path=env_path,
            ),
            DEPLOYED_RELEASE,
        )
        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={"ONION_SENTINEL_RELEASE_ID": "e" * 40},
                env_path=env_path,
            ),
            "e" * 40,
        )
        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={"ONION_SENTINEL_RELEASE_ID": ""},
                env_path=env_path,
            ),
            "",
        )
        env_path.write_text(
            f"ONION_SENTINEL_RELEASE_ID={DEPLOYED_RELEASE}\n"
            f"ONION_SENTINEL_RELEASE_ID={'e' * 40}\n",
            encoding="utf-8",
        )
        self.assertEqual(
            self.scheduler.current_runtime_release_id(
                environ={},
                env_path=env_path,
            ),
            "",
        )


    def test_failure_status_contract_marks_deterministic_failure_non_retryable(self) -> None:
        response = io.BytesIO(b'{"ok":true}')
        response.status = 200
        with mock.patch.object(
            self.scheduler.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            reported = self.scheduler.report_ai_job_status(
                "http://127.0.0.1:8787",
                "stable-group",
                "failed",
                "model context window exhausted",
                "lease-token",
                job_type="incident_response_analysis",
                retryable=False,
            )

        self.assertTrue(reported)
        request = urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertIs(payload["retryable"], False)
        self.assertEqual(payload["error"], "model context window exhausted")


    def test_processing_status_returns_server_bound_ai_claim(self) -> None:
        response = io.BytesIO(
            json.dumps(
                {
                    "ok": True,
                    "lease_token": "claim-lease",
                    "dedupe_key": "outer-group",
                    "claim": {
                        "job_id": 41,
                        "job_type": "ai_analysis",
                        "dedupe_key": "claimed-group",
                        "payload": {
                            "group_id": "claimed-group",
                            "alert_id": "claimed-alert",
                        },
                    },
                }
            ).encode("utf-8")
        )
        response.status = 200
        with mock.patch.object(
            self.scheduler.urllib.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            claimed = self.scheduler.report_ai_job_status(
                "http://127.0.0.1:8787",
                "requested-group",
                "processing",
                expected_job_id=41,
                expected_representative_alert_id="claimed-alert",
                expected_dispatch_id="a" * 64,
                expected_stable_group_key="v2|claimed-group",
                **CONTROLLED_ROUTE_FIELDS,
            )

        self.assertIsInstance(claimed, self.scheduler.ClaimedAiLease)
        self.assertEqual(claimed, "claim-lease")
        self.assertEqual(claimed.job_type, "ai_analysis")
        self.assertEqual(claimed.resolved_key, "claimed-group")
        self.assertEqual(claimed.job_id, 41)
        self.assertEqual(
            claimed.job_payload,
            {
                "group_id": "claimed-group",
                "alert_id": "claimed-alert",
            },
        )
        request_payload = json.loads(
            urlopen.call_args.args[0].data.decode("utf-8")
        )
        self.assertEqual(request_payload["expected_job_id"], 41)
        self.assertEqual(
            request_payload["expected_representative_alert_id"],
            "claimed-alert",
        )
        self.assertEqual(
            request_payload["expected_stable_group_key"],
            "v2|claimed-group",
        )
        self.assertEqual(
            request_payload["expected_assigned_route"],
            PRIMARY_ROUTE,
        )
        self.assertEqual(
            request_payload["expected_reviewer_route"],
            REVIEWER_ROUTE,
        )
        self.assertIs(request_payload["reviewer_required"], True)


    def test_missing_analysis_threshold_preserves_all_severity_behavior(self) -> None:
        self.args.ai_settings_file.write_text(
            json.dumps({"soc_analyst_pcap_min_severity": "medium"}),
            encoding="utf-8",
        )

        levels = self.scheduler.configured_analysis_levels(
            self.args.ai_settings_file,
            self.args.levels,
        )

        self.assertEqual(
            levels,
            ["critical", "high", "medium", "low", "informational"],
        )


    def test_analysis_watchdog_allows_bounded_multi_turn_investigation(self) -> None:
        args = SimpleNamespace(
            analysis_dir=Path(self.tempdir.name),
            timeout=240,
            alert_store_url="http://127.0.0.1:8767",
            ai_settings_file=Path(self.tempdir.name) / "ai_model_settings.json",
            investigation_harness_policy=(
                Path(self.tempdir.name) / "investigation_harness_policy.json"
            ),
            model="",
        )
        completed = SimpleNamespace(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            self.scheduler,
            "run_command",
            return_value=completed,
        ) as run_command:
            result = self.scheduler.run_analysis(
                Path(self.tempdir.name) / "prompt.json",
                args,
            )

        self.assertIs(result, completed)
        self.assertEqual(
            run_command.call_args.kwargs["timeout_seconds"],
            (args.timeout * 5) + 300,
        )


    def test_pending_automatic_low_job_is_retired_without_inference_at_medium(self) -> None:
        result = self.run_indexed_worker_once(severity="low")

        self.assertEqual(result["return_code"], 0)
        result["collect_incident_evidence"].assert_not_called()
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        transitions = [
            (
                call.args[2],
                call.kwargs.get("lease_token", ""),
                call.kwargs.get("job_type"),
            )
            for call in result["report_status"].call_args_list
        ]
        self.assertEqual(
            transitions,
            [
                ("processing", "", "ai_analysis"),
                ("completed", "threshold-test-lease", "ai_analysis"),
            ],
        )


    def test_automatic_medium_job_runs_at_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(severity="medium")

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["run_analysis"].call_args.kwargs["reanalysis_attempt_id"],
            "",
        )


    def test_lost_durable_claim_is_logged_as_contention_not_failure(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="medium",
            claim_available=False,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertEqual(
            [call.args[2] for call in result["report_status"].call_args_list],
            ["processing"],
        )
        self.assertIn("claim contention", result["stdout"])
        self.assertNotIn("failed", result["stderr"])


    def test_manual_analyze_low_job_bypasses_medium_threshold(self) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"manual_reanalysis": True},
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()


    def test_soc_worker_uses_coalesced_claim_payload_before_threshold_decision(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={
                "manual_reanalysis": False,
                "related_limit": 8,
            },
            claimed_payload={
                "manual_reanalysis": True,
                "related_limit": 500,
            },
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        claimed = result["build_prompt"].call_args.args[2]
        self.assertIs(claimed["manual_reanalysis"], True)
        self.assertEqual(claimed["related_limit"], 500)


    def test_soc_worker_retires_coalesced_automatic_job_below_threshold(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="low",
            payload={"manual_reanalysis": True},
            claimed_payload={"manual_reanalysis": False},
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        self.assertEqual(
            [call.args[2] for call in result["report_status"].call_args_list],
            ["processing", "completed"],
        )


    def test_soc_worker_rejects_claim_with_mismatched_group_identity(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload={"manual_reanalysis": True},
            claimed_resolved_key="different-stable-group",
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("group identity is invalid", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], False)


    def test_payload_less_rolling_deploy_claim_remains_retryable(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload_available=False,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("server-authoritative job identity", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], True)


    def test_soc_worker_rejects_claim_with_mismatched_job_identity(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload={"manual_reanalysis": True},
            claimed_job_type="incident_response_analysis",
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("job identity is invalid", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], False)


    def test_soc_worker_rejects_claim_with_unknown_alert_identity(
        self,
    ) -> None:
        result = self.run_indexed_worker_once(
            severity="critical",
            payload={"manual_reanalysis": True},
            claimed_payload={
                "manual_reanalysis": True,
                "alert_id": "not-in-alert-store",
            },
            register_claimed_alert=False,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_not_called()
        result["run_analysis"].assert_not_called()
        failed = result["report_status"].call_args_list[-1]
        self.assertEqual(failed.args[2], "failed")
        self.assertIn("alert identity is invalid", failed.args[3])
        self.assertIs(failed.kwargs["retryable"], False)


    def test_controlled_worker_runs_only_for_exact_claim_identity(self) -> None:
        group_id = "0123456789abcdefabcd"
        alert_id = "ai_analysis-critical-threshold-alert"
        dispatch_id = "a" * 64

        result = self.run_indexed_worker_once(
            severity="critical",
            payload={
                "manual_reanalysis": True,
                "dispatch_id": dispatch_id,
            },
            only_group_id=group_id,
            only_alert_id=alert_id,
            only_dispatch_id=dispatch_id,
        )

        self.assertEqual(result["return_code"], 0)
        result["build_prompt"].assert_called_once()
        result["run_analysis"].assert_called_once()
        self.assertEqual(
            result["build_prompt"].call_args.args[0],
            alert_id,
        )
