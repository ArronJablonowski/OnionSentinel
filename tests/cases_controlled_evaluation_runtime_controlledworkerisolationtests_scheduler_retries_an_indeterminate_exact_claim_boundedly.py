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

class ControlledWorkerIsolationTestsSchedulerRetriesAnIndeterminateExactClaimBoundedlyCases:
    def test_scheduler_retries_an_indeterminate_exact_claim_boundedly(
        self,
    ) -> None:
        response = io.BytesIO(
            json.dumps(
                {
                    "ok": True,
                    "lease_token": (
                        "77777777-7777-4777-8777-777777777777"
                    ),
                    "dedupe_key": "7" * 20,
                    "claim": {
                        "job_id": 7,
                        "job_type": "ai_analysis",
                        "dedupe_key": "7" * 20,
                        "payload": {
                            "group_id": "7" * 20,
                            "representative_alert_id": (
                                "controlled-alert-claim-retry"
                            ),
                        },
                    },
                }
            ).encode("utf-8")
        )
        response.status = 200
        with (
            mock.patch.object(
                self.scheduler.urllib.request,
                "urlopen",
                side_effect=[
                    urllib.error.URLError("lost response"),
                    response,
                ],
            ) as urlopen,
            mock.patch.object(self.scheduler.time, "sleep"),
        ):
            claim = self.scheduler.report_ai_job_status(
                "http://127.0.0.1:18787",
                "7" * 20,
                "processing",
                expected_job_id=7,
                expected_representative_alert_id=(
                    "controlled-alert-claim-retry"
                ),
                expected_dispatch_id="7" * 64,
                expected_stable_group_key="v2|controlled|claim-retry",
                expected_assigned_route="codex-cli:gpt-5.5:high",
                expected_reviewer_route="codex-cli:gpt-5.6-sol:xhigh",
                reviewer_required=True,
            )
        self.assertEqual(
            claim,
            "77777777-7777-4777-8777-777777777777",
        )
        self.assertEqual(urlopen.call_count, 2)
        self.assertEqual(
            urlopen.call_args_list[0].args[0].data,
            urlopen.call_args_list[1].args[0].data,
        )


    def test_controlled_route_contract_rejects_before_transport_or_analysis(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings_path = Path(temporary) / "ai-settings.json"
            assigned = "codex-cli:gpt-5.5:high"
            reviewer = "codex-cli:gpt-5.6-sol:xhigh"
            settings = {
                "agent_models": {"soc-analyst": assigned},
                "agent_second_opinion_models": {"soc-analyst": reviewer},
                "codex_cli_models": [
                    {"model": "gpt-5.5", "reasoning_effort": "high", "enabled": True},
                    {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": True},
                ],
            }
            settings_path.write_text(json.dumps(settings), encoding="utf-8")
            args = SimpleNamespace(
                only_group_id="7" * 20,
                only_alert_id="controlled-alert-route",
                only_stable_group_key="v2|controlled|route",
                only_dispatch_id="7" * 64,
                ai_settings_file=settings_path,
            )
            base_payload = {
                "alert_id": args.only_alert_id,
                "representative_alert_id": args.only_alert_id,
                "group_id": args.only_group_id,
                "stable_group_id": args.only_group_id,
                "stable_group_key": args.only_stable_group_key,
                "dispatch_id": args.only_dispatch_id,
                "release_id": RELEASE_ID,
                "agent_role": "soc-analyst",
                "expected_assigned_route": assigned,
                "expected_reviewer_route": reviewer,
                "reviewer_required": True,
            }
            selected = {"durable_job_id": 17}
            environment = {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID}
            with mock.patch.dict(os.environ, environment, clear=False):
                exact = self.scheduler.controlled_claim_expectations(
                    args, selected, dict(base_payload)
                )
            self.assertEqual(exact["expected_assigned_route"], assigned)
            self.assertEqual(exact["expected_reviewer_route"], reviewer)
            self.assertIs(exact["reviewer_required"], True)

            mutations = {
                "missing": lambda value: value.pop("expected_reviewer_route"),
                "tampered": lambda value: value.__setitem__(
                    "expected_reviewer_route", "codex-cli:gpt-5.6-terra:xhigh"
                ),
                "alias": lambda value: value.__setitem__(
                    "expected_assigned_route", "codex-cli"
                ),
                "hermes": lambda value: value.__setitem__(
                    "expected_assigned_route", "hermes-agent:gpt-5.5:high"
                ),
                "openclaw": lambda value: value.__setitem__(
                    "expected_assigned_route", "openclaw:gpt-5.5:high"
                ),
                "reviewer-false": lambda value: value.__setitem__(
                    "reviewer_required", False
                ),
                "same-model-different-effort": lambda value: value.__setitem__(
                    "expected_reviewer_route", "codex-cli:gpt-5.5:xhigh"
                ),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    candidate = dict(base_payload)
                    mutate(candidate)
                    with (
                        mock.patch.object(self.scheduler.urllib.request, "urlopen") as transport,
                        mock.patch.object(self.scheduler, "collect_incident_evidence") as collector,
                        mock.patch.object(self.scheduler, "run_analysis") as model,
                        mock.patch.dict(os.environ, environment, clear=False),
                    ):
                        with self.assertRaises(self.scheduler.ControlledClaimRejected):
                            self.scheduler.controlled_claim_expectations(
                                args, selected, candidate
                            )
                    transport.assert_not_called()
                    collector.assert_not_called()
                    model.assert_not_called()


    def test_runner_route_recheck_precedes_relay_and_model_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings_path = Path(temporary) / "ai-settings.json"
            assigned = "codex-cli:gpt-5.5:high"
            reviewer = "codex-cli:gpt-5.6-sol:xhigh"
            settings = {
                "agent_models": {"incident-responder": assigned},
                "agent_second_opinion_models": {"incident-responder": reviewer},
                "codex_cli_models": [
                    {"model": "gpt-5.5", "reasoning_effort": "high", "enabled": True},
                    {"model": "gpt-5.6-sol", "reasoning_effort": "xhigh", "enabled": True},
                ],
            }
            settings_path.write_text(json.dumps(settings), encoding="utf-8")
            args = SimpleNamespace(ai_settings_file=settings_path)
            identity = {
                "agent_role": "incident-responder",
                "expected_assigned_route": assigned,
                "expected_reviewer_route": reviewer,
                "reviewer_required": True,
            }
            self.runner.require_controlled_evaluation_routes(
                identity, args, settings, "incident-responder"
            )
            tampered = dict(identity)
            tampered["expected_assigned_route"] = "codex-cli:gpt-5.6-terra:high"
            with (
                mock.patch.object(self.runner, "prepare_live_osquery_context") as relay,
                mock.patch.object(self.runner, "analyze_model_route") as model,
            ):
                with self.assertRaises(SystemExit):
                    self.runner.require_controlled_evaluation_routes(
                        tampered, args, settings, "incident-responder"
                    )
            relay.assert_not_called()
            model.assert_not_called()
            same_model = dict(identity)
            same_model["expected_reviewer_route"] = "codex-cli:gpt-5.5:xhigh"
            with (
                mock.patch.object(self.runner, "prepare_live_osquery_context") as relay,
                mock.patch.object(self.runner, "analyze_model_route") as model,
            ):
                with self.assertRaises(SystemExit):
                    self.runner.require_controlled_evaluation_routes(
                        same_model, args, settings, "incident-responder"
                    )
            relay.assert_not_called()
            model.assert_not_called()


    def test_scheduler_strict_settings_rejection_precedes_transport_and_analysis(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settings_path = Path(temporary) / "ai-settings.json"
            args = SimpleNamespace(
                only_group_id="8" * 20,
                only_alert_id="controlled-alert-strict-settings",
                only_stable_group_key="v2|controlled|strict-settings",
                only_dispatch_id="8" * 64,
                ai_settings_file=settings_path,
            )
            payload = {
                "alert_id": args.only_alert_id,
                "representative_alert_id": args.only_alert_id,
                "group_id": args.only_group_id,
                "stable_group_id": args.only_group_id,
                "stable_group_key": args.only_stable_group_key,
                "dispatch_id": args.only_dispatch_id,
                "release_id": RELEASE_ID,
                "agent_role": "incident-responder",
                **CONTROLLED_ROUTE_FIELDS,
            }
            base = {
                "agent_models": {"incident-responder": PRIMARY_ROUTE},
                "agent_second_opinion_models": {
                    "incident-responder": REVIEWER_ROUTE
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
            invalid_settings = {
                "duplicate-roster": {
                    **base,
                    "codex_cli_models": base["codex_cli_models"]
                    + [dict(base["codex_cli_models"][0])],
                },
                "malformed-roster": {
                    **base,
                    "codex_cli_models": ["not-an-object"],
                },
                "unsupported-model": {
                    **base,
                    "codex_cli_models": [
                        {
                            "model": "unsupported-model",
                            "reasoning_effort": "high",
                            "enabled": True,
                        }
                    ],
                },
                "mismatched-assignment": {
                    **base,
                    "agent_models": {
                        "incident-responder": "codex-cli:gpt-5.6-terra:high"
                    },
                },
            }
            environment = {"ONION_SENTINEL_RELEASE_ID": RELEASE_ID}
            for label, document in invalid_settings.items():
                with self.subTest(label=label):
                    settings_path.write_text(
                        json.dumps(document), encoding="utf-8"
                    )
                    with (
                        mock.patch.object(
                            self.scheduler.urllib.request, "urlopen"
                        ) as transport,
                        mock.patch.object(
                            self.scheduler, "collect_incident_evidence"
                        ) as collector,
                        mock.patch.object(
                            self.scheduler, "run_analysis"
                        ) as model,
                        mock.patch.dict(os.environ, environment, clear=False),
                    ):
                        with self.assertRaises(
                            self.scheduler.ControlledClaimRejected
                        ):
                            self.scheduler.controlled_claim_expectations(
                                args, {"durable_job_id": 18}, payload
                            )
                    transport.assert_not_called()
                    collector.assert_not_called()
                    model.assert_not_called()


    def test_controlled_model_override_fails_before_any_work(self) -> None:
        args = SimpleNamespace(model="override-model")
        with (
            mock.patch.dict(
                os.environ,
                {"ONION_SENTINEL_EVALUATION_MODE": "1"},
                clear=False,
            ),
            mock.patch.object(self.scheduler.urllib.request, "urlopen") as transport,
            mock.patch.object(self.scheduler, "collect_incident_evidence") as collector,
            mock.patch.object(self.scheduler, "run_analysis") as model,
        ):
            with self.assertRaisesRegex(SystemExit, "forbids --model"):
                self.scheduler.controlled_evaluation_runtime(args)
        transport.assert_not_called()
        collector.assert_not_called()
        model.assert_not_called()
        with mock.patch.dict(
            os.environ,
            {"ONION_SENTINEL_EVALUATION_MODE": "0"},
            clear=False,
        ):
            self.assertIsNone(self.scheduler.controlled_evaluation_runtime(args))


    def test_controlled_generate_prompt_fails_before_any_work(self) -> None:
        args = SimpleNamespace(
            model="",
            generate_prompt=True,
            alert_store_url="http://127.0.0.1:18787",
        )
        with (
            mock.patch.dict(
                os.environ,
                {"ONION_SENTINEL_EVALUATION_MODE": "1"},
                clear=False,
            ),
            mock.patch.object(self.runner, "generate_prompt") as generate,
            mock.patch.object(self.runner, "prepare_live_osquery_context") as relay,
            mock.patch.object(self.runner, "analyze_model_route") as model,
        ):
            with self.assertRaisesRegex(SystemExit, "forbids --generate-prompt"):
                self.runner.controlled_evaluation_runtime(args)
        generate.assert_not_called()
        relay.assert_not_called()
        model.assert_not_called()


    def test_scheduler_requires_exact_frozen_owner_only_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary).resolve()
            home = temporary_root / "home"
            parent = home / "n8n-local" / "harness-evaluations"
            runtime = parent / "test-run"
            runtime.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
            runtime.chmod(0o700)
            directories = {
                name: runtime / name
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
            for path in directories.values():
                path.mkdir(mode=0o700)
            settings = runtime / "ai_model_settings.json"
            harness_policy = runtime / "investigation_harness_policy.json"
            detection_playbooks = runtime / "detection_playbooks.json"
            investigation_skills = runtime / "investigation_skills.json"
            shared_memory = runtime / "shared-agent-memory.md"
            asset_inventory = runtime / "asset_inventory.database-export.json"
            live_osquery = runtime / "live-osquery.json"
            disagreement_prompt = runtime / "disagreement_adjudicator_system_prompt.md"
            database = runtime / "alerts.sqlite3"
            runtime_files = (
                settings,
                harness_policy,
                detection_playbooks,
                investigation_skills,
                shared_memory,
                asset_inventory,
                disagreement_prompt,
                database,
                runtime / "soc_analyst_system_prompt.md",
                runtime / "soc_analyst_second_opinion_prompt.md",
                runtime / "incident_responder_system_prompt.md",
                runtime / "incident_responder_second_opinion_prompt.md",
                directories["agent-memory"] / "soc-analyst-memory.md",
                directories["agent-memory"] / "incident-responder-memory.md",
            )
            for path in runtime_files:
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            live_osquery.write_text(
                '{"enabled":false}\n',
                encoding="utf-8",
            )
            live_osquery.chmod(0o600)
            relay_config, _, _ = write_controlled_route_fixture(
                runtime,
                home,
            )
            args = SimpleNamespace(
                db=database,
                prompt_dir=directories["prompts"],
                analysis_dir=directories["analysis"],
                prior_analysis_dir=directories["prior-analysis"],
                pcap_analysis_dir=directories["pcap-analysis"],
                rollup_dir=directories["rollups"],
                agent_memory_dir=directories["agent-memory"],
                shared_memory_file=shared_memory,
                asset_inventory_file=asset_inventory,
                incident_evidence_dir=directories["incident-evidence"],
                incident_evidence_config=relay_config,
                investigation_pivot_dir=directories["investigation-pivots"],
                live_osquery_config=live_osquery,
                disagreement_adjudicator_prompt_file=disagreement_prompt,
                lock_file=runtime / "worker.lock",
                wake_file=runtime / "worker.wake",
                portal_wake_file=runtime / "dashboard.wake",
                alert_store_url="http://127.0.0.1:18787",
                only_group_id="0123456789abcdefabcd",
                only_alert_id="synthetic-controlled-alert",
                only_stable_group_key="v2|synthetic|controlled",
                only_dispatch_id="a" * 64,
                max_per_run=1,
                ai_settings_file=settings,
                investigation_harness_policy=harness_policy,
                detection_playbooks=detection_playbooks,
                investigation_skills=investigation_skills,
            )
            environment = {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(runtime),
                "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "1",
                "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "TMPDIR": str(directories["tmp"]),
            }
            with (
                mock.patch.object(self.scheduler, "HOME", home),
                mock.patch.object(self.scheduler.tempfile, "tempdir", None),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                self.assertEqual(
                    self.scheduler.controlled_evaluation_runtime(args),
                    runtime,
                )
                args.analysis_dir = temporary_root / "global-analysis"
                with self.assertRaisesRegex(
                    SystemExit,
                    "analysis output directory",
                ):
                    self.scheduler.controlled_evaluation_runtime(args)

            args.analysis_dir = directories["analysis"]
            args.investigation_harness_policy = (
                temporary_root / "global-harness-policy.json"
            )
            args.investigation_harness_policy.write_text(
                "{}\n",
                encoding="utf-8",
            )
            args.investigation_harness_policy.chmod(0o600)
            with (
                mock.patch.object(self.scheduler, "HOME", home),
                mock.patch.object(self.scheduler.tempfile, "tempdir", None),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                with self.assertRaisesRegex(
                    SystemExit,
                    "harness policy",
                ):
                    self.scheduler.controlled_evaluation_runtime(args)

            args.investigation_harness_policy = harness_policy
            environment["ONION_SENTINEL_EVALUATION_FREEZE_MEMORY"] = "0"
            with (
                mock.patch.object(self.scheduler, "HOME", home),
                mock.patch.object(self.scheduler.tempfile, "tempdir", None),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                with self.assertRaisesRegex(
                    SystemExit,
                    "requires one exact frozen job",
                ):
                    self.scheduler.controlled_evaluation_runtime(args)


    def test_controlled_scheduler_does_not_reconcile_global_jobs(self) -> None:
        args = SimpleNamespace(
            only_group_id="0123456789abcdefabcd",
            db=Path("/must/not/be/opened.sqlite3"),
        )
        with (
            mock.patch.object(
                self.scheduler.sqlite3,
                "connect",
                side_effect=AssertionError(
                    "controlled worker opened the global database"
                ),
            ),
            mock.patch.object(
                self.scheduler,
                "reconcile_completed_ai_jobs",
                side_effect=AssertionError(
                    "controlled worker reconciled global durable jobs"
                ),
            ),
        ):
            self.assertEqual(
                self.scheduler.reconcile_worker_state(
                    args,
                    True,
                    controlled_evaluation=True,
                ),
                0,
            )


    def test_scheduler_propagates_every_frozen_context_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            prompt_path = root / "prompts" / "prompt.json"
            prompt_path.parent.mkdir(mode=0o700)
            prompt_path.write_text("{}\n", encoding="utf-8")
            args = SimpleNamespace(
                db=root / "alerts.sqlite3",
                prompt_dir=root / "prompts",
                analysis_dir=root / "analysis-output",
                prior_analysis_dir=root / "prior-analysis",
                pcap_analysis_dir=root / "pcap-analysis",
                rollup_dir=root / "rollups",
                agent_memory_dir=root / "agent-memory",
                shared_memory_file=root / "shared-agent-memory.md",
                asset_inventory_file=root / "asset-inventory.json",
                incident_evidence_config=root / "incident-evidence.json",
                investigation_pivot_dir=root / "investigation-pivots",
                live_osquery_config=root / "live-osquery.json",
                disagreement_adjudicator_prompt_file=root / "disagreement.md",
                ai_settings_file=root / "config" / "ai_model_settings.json",
                investigation_harness_policy=root / "harness-policy.json",
                detection_playbooks=root / "detection-playbooks.json",
                investigation_skills=root / "investigation-skills.json",
                related_limit=8,
                correlation_limit=8,
                correlation_min_score=15,
                timeout=900,
                max_prompt_bytes=1024 * 1024,
                model="",
                include_tests=False,
                alert_store_url="http://127.0.0.1:18787",
            )
            completed = SimpleNamespace(
                returncode=0,
                stdout=f"{prompt_path}\n",
                stderr="",
            )
            with (
                mock.patch.object(
                    self.scheduler,
                    "effective_initial_prompt_package_limit",
                    return_value=384 * 1024,
                ),
                mock.patch.object(
                    self.scheduler,
                    "run_command",
                    return_value=completed,
                ) as run_command,
            ):
                self.scheduler.build_prompt(
                    "alert-1",
                    args,
                    {"agent_role": "incident-responder"},
                )
            builder_command = run_command.call_args.args[0]

            def command_value(command: list[str], flag: str) -> str:
                return command[command.index(flag) + 1]

            expected_builder_paths = {
                "--db": args.db,
                "--rollup-dir": args.rollup_dir,
                "--agent-memory-file": (
                    args.agent_memory_dir / "incident-responder-memory.md"
                ),
                "--shared-memory-file": args.shared_memory_file,
                "--pcap-analysis-dir": args.pcap_analysis_dir,
                "--analysis-dir": args.prior_analysis_dir,
                "--asset-inventory-file": args.asset_inventory_file,
            }
            for flag, expected in expected_builder_paths.items():
                with self.subTest(builder_flag=flag):
                    self.assertEqual(
                        command_value(builder_command, flag),
                        str(expected),
                    )

            analysis_command = self.scheduler.analysis_command(
                prompt_path,
                args,
                agent_role="incident-responder",
            )
            expected_runner_paths = {
                "--prompt-dir": args.prompt_dir,
                "--live-osquery-config": args.live_osquery_config,
                "--incident-evidence-config": args.incident_evidence_config,
                "--investigation-pivot-dir": args.investigation_pivot_dir,
                "--disagreement-adjudicator-prompt-file": (
                    args.disagreement_adjudicator_prompt_file
                ),
                "--system-prompt-file": (
                    args.ai_settings_file.parent
                    / "incident_responder_system_prompt.md"
                ),
                "--second-opinion-prompt-file": (
                    args.ai_settings_file.parent
                    / "incident_responder_second_opinion_prompt.md"
                ),
            }
            for flag, expected in expected_runner_paths.items():
                with self.subTest(runner_flag=flag):
                    self.assertEqual(
                        command_value(analysis_command, flag),
                        str(expected),
                    )


    def test_run_local_controlled_paths_never_fall_back_to_home(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary).resolve()
            home = temporary_root / "home"
            parent = home / "n8n-local" / "harness-evaluations"
            runtime = parent / "test-run"
            runtime.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
            runtime.chmod(0o700)
            directories = {
                name: runtime / name
                for name in (
                    "prompts",
                    "analysis",
                    "investigation-pivots",
                    "tmp",
                )
            }
            for path in directories.values():
                path.mkdir(mode=0o700)
            files = {
                name: runtime / name
                for name in (
                    "prompt.json",
                    "ai-settings.json",
                    "harness-policy.json",
                    "system.md",
                    "reviewer.md",
                    "disagreement.md",
                    "live-osquery.json",
                )
            }
            for path in files.values():
                path.write_text("{}\n", encoding="utf-8")
                path.chmod(0o600)
            files["live-osquery.json"].write_text(
                '{"enabled":false}\n',
                encoding="utf-8",
            )
            relay_config, _, _ = write_controlled_route_fixture(
                runtime,
                home,
            )
            args = SimpleNamespace(
                alert_store_url="http://127.0.0.1:18787",
                prompt_dir=directories["prompts"],
                out_dir=directories["analysis"],
                investigation_pivot_dir=directories["investigation-pivots"],
                prompt_package=files["prompt.json"],
                ai_settings_file=files["ai-settings.json"],
                investigation_harness_policy=files["harness-policy.json"],
                system_prompt_file=files["system.md"],
                second_opinion_prompt_file=files["reviewer.md"],
                disagreement_adjudicator_prompt_file=files["disagreement.md"],
                live_osquery_config=files["live-osquery.json"],
                incident_evidence_config=relay_config,
                response_json=None,
            )
            environment = {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(runtime),
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "TMPDIR": str(directories["tmp"]),
            }
            with (
                mock.patch.object(self.runner, "HOME", home),
                mock.patch.object(self.runner.tempfile, "tempdir", None),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                self.assertEqual(
                    self.runner.controlled_evaluation_runtime(args),
                    (True, runtime),
                )
                production_config = (
                    home / "n8n-local" / "config" / "live-osquery.json"
                )
                production_config.parent.mkdir(parents=True, mode=0o700)
                production_config.write_text(
                    '{"enabled":true}\n',
                    encoding="utf-8",
                )
                production_config.chmod(0o600)
                args.live_osquery_config = production_config
                with self.assertRaisesRegex(
                    SystemExit,
                    "live OSQuery config",
                ):
                    self.runner.controlled_evaluation_runtime(args)

            with mock.patch.object(
                self.runner,
                "load_live_osquery_config",
                return_value={"enabled": False, "allowed_agent_roles": []},
            ) as loader:
                self.runner.prepare_live_osquery_context(
                    {},
                    "incident-responder",
                    files["live-osquery.json"],
                )
            loader.assert_called_once_with(files["live-osquery.json"])


