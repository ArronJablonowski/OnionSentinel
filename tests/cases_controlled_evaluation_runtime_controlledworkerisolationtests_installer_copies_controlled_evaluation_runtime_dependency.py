from __future__ import annotations

from installer_source_fixture import read_installer_source

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

class ControlledWorkerIsolationTestsInstallerCopiesControlledEvaluationRuntimeDependencyCases:
    def test_installer_copies_controlled_evaluation_runtime_dependency(
        self,
    ) -> None:
        installer = read_installer_source(INSTALLER_PATH)
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/controlled_evaluation_isolation.py" '
            '"$STACK_DIR/bin/controlled_evaluation_isolation.py"',
            installer,
        )


    def test_run_local_requires_memory_freeze_before_any_result_identity(
        self,
    ) -> None:
        with (
            mock.patch.object(
                self.runner,
                "parse_args",
                return_value=SimpleNamespace(
                    alert_store_url="http://127.0.0.1:18787",
                ),
            ),
            mock.patch.object(
                self.runner,
                "controlled_evaluation_runtime",
                return_value=(True, Path("/tmp/controlled-evaluation-test")),
            ),
            mock.patch.dict(
                os.environ,
                {
                    "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "0",
                },
                clear=False,
            ),
            mock.patch.object(
                self.runner,
                "controlled_evaluation_result_identity",
            ) as result_identity,
        ):
            with self.assertRaisesRegex(
                SystemExit,
                "controlled evaluation requires "
                "ONION_SENTINEL_EVALUATION_FREEZE_MEMORY=1",
            ):
                self.runner.main()
        result_identity.assert_not_called()


    def test_ephemeral_token_is_removed_before_unrelated_children(
        self,
    ) -> None:
        controlled_environment = {
            "ONION_SENTINEL_EVALUATION_MODE": "1",
            "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
        }
        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            self.assertEqual(
                self.scheduler.consume_controlled_evaluation_token(True),
                EVALUATION_TOKEN,
            )
            self.assertNotIn(
                "ONION_SENTINEL_EVALUATION_TOKEN",
                os.environ,
            )
            self.assertEqual(
                self.scheduler.alert_store_mutation_headers()[
                    "X-Onion-Sentinel-Evaluation-Token"
                ],
                EVALUATION_TOKEN,
            )

        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            self.assertEqual(
                self.runner.consume_controlled_evaluation_token(True),
                EVALUATION_TOKEN,
            )
            self.assertNotIn(
                "ONION_SENTINEL_EVALUATION_TOKEN",
                os.environ,
            )


    def test_controlled_lease_is_removed_from_process_environment_before_models(
        self,
    ) -> None:
        controlled_environment = {
            "ONION_SENTINEL_EVALUATION_JOB_ID": "7",
            "ONION_SENTINEL_EVALUATION_JOB_TYPE": "ai_analysis",
            "ONION_SENTINEL_EVALUATION_LEASE_TOKEN": (
                "77777777-7777-4777-8777-777777777777"
            ),
            "ONION_SENTINEL_EVALUATION_COHORT_ID": "controlled-cohort-11",
            "ONION_SENTINEL_EVALUATION_DISPATCH_ID": "7" * 64,
            "ONION_SENTINEL_EVALUATION_REPRESENTATIVE_ALERT_ID": (
                "controlled-alert-env"
            ),
            "ONION_SENTINEL_EVALUATION_STABLE_GROUP_ID": "7" * 20,
            "ONION_SENTINEL_EVALUATION_STABLE_GROUP_KEY": (
                "v2|controlled|environment"
            ),
            "ONION_SENTINEL_EVALUATION_AGENT_ROLE": "soc-analyst",
            "ONION_SENTINEL_EVALUATION_REANALYSIS_ATTEMPT_ID": "",
            "ONION_SENTINEL_EVALUATION_RELEASE_ID": RELEASE_ID,
            "ONION_SENTINEL_EVALUATION_EXPECTED_ASSIGNED_ROUTE": (
                "codex-cli:gpt-5.5:high"
            ),
            "ONION_SENTINEL_EVALUATION_EXPECTED_REVIEWER_ROUTE": (
                "codex-cli:gpt-5.6-sol:xhigh"
            ),
            "ONION_SENTINEL_EVALUATION_REVIEWER_REQUIRED": "1",
            "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
        }
        result_keys = tuple(
            self.runner.CONTROLLED_RESULT_ENVIRONMENT.values()
        )
        with mock.patch.dict(
            os.environ,
            controlled_environment,
            clear=False,
        ):
            identity = self.runner.controlled_evaluation_result_identity(
                True,
                reanalysis_attempt_id="",
            )
            self.assertEqual(
                identity["lease_token"],
                controlled_environment[
                    "ONION_SENTINEL_EVALUATION_LEASE_TOKEN"
                ],
            )
            for environment_key in result_keys:
                self.assertNotIn(environment_key, os.environ)


    def test_run_local_runtime_must_be_owner_only_and_under_evaluation_root(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary).resolve()
            home = temporary_root / "home"
            parent = home / "n8n-local" / "harness-evaluations"
            runtime = parent / "test-run"
            runtime.mkdir(parents=True, mode=0o700)
            parent.chmod(0o700)
            runtime.chmod(0o700)
            controlled_tmp = runtime / "tmp"
            controlled_tmp.mkdir(mode=0o700)
            controlled_tmp.chmod(0o700)
            environment = {
                "ONION_SENTINEL_EVALUATION_MODE": "1",
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR": str(runtime),
                "ONION_SENTINEL_EVALUATION_TOKEN": EVALUATION_TOKEN,
                "TMPDIR": str(controlled_tmp),
            }
            with (
                mock.patch.object(self.runner, "HOME", home),
                mock.patch.object(self.runner.tempfile, "tempdir", None),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                self.assertEqual(
                    self.runner.controlled_evaluation_runtime(
                        "http://127.0.0.1:18787"
                    ),
                    (True, runtime),
                )
                for unsafe_origin in (
                    "http://127.0.0.1:0",
                    "http://127.0.0.1:8787",
                    "http://example.invalid:18787",
                    "http://127.0.0.1:18787/analysis/result",
                ):
                    with self.subTest(unsafe_origin=unsafe_origin):
                        with self.assertRaisesRegex(
                            SystemExit,
                            "alternate loopback",
                        ):
                            self.runner.controlled_evaluation_runtime(
                                unsafe_origin
                            )
                runtime.chmod(0o750)
                with self.assertRaisesRegex(
                    SystemExit,
                    "must be owner-only",
                ):
                    self.runner.controlled_evaluation_runtime(
                        "http://127.0.0.1:18787"
                    )

            outside = temporary_root / "outside"
            outside.mkdir(mode=0o700)
            environment[
                "ONION_SENTINEL_EVALUATION_RUNTIME_DIR"
            ] = str(outside)
            with (
                mock.patch.object(self.runner, "HOME", home),
                mock.patch.object(self.runner.tempfile, "tempdir", None),
                mock.patch.dict(os.environ, environment, clear=False),
            ):
                with self.assertRaisesRegex(SystemExit, "is unsafe"):
                    self.runner.controlled_evaluation_runtime(
                        "http://127.0.0.1:18787"
                    )


    def test_controlled_tmpdir_rejects_unisolated_paths_and_pins_valid_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            runtime = root / "evaluation"
            controlled_tmp = runtime / "tmp"
            outside = root / "outside"
            permissive = runtime / "permissive"
            runtime.mkdir(mode=0o700)
            controlled_tmp.mkdir(mode=0o700)
            outside.mkdir(mode=0o700)
            permissive.mkdir(mode=0o755)
            linked = runtime / "linked"
            linked.symlink_to(controlled_tmp, target_is_directory=True)
            failures = (
                ("", "explicit canonical"),
                (str(outside), "inside the evaluation runtime"),
                (str(linked), "canonical owner-private"),
                (str(permissive), "canonical owner-private"),
            )
            for module in (self.scheduler, self.runner):
                for supplied, expected in failures:
                    with self.subTest(
                        module=module.__name__,
                        tmpdir=supplied or "missing",
                    ):
                        with (
                            mock.patch.object(module.tempfile, "tempdir", None),
                            mock.patch.dict(
                                os.environ,
                                {"TMPDIR": supplied},
                                clear=False,
                            ),
                        ):
                            with self.assertRaisesRegex(ValueError, expected):
                                module.pin_controlled_tmpdir(runtime)
                with (
                    mock.patch.object(module.tempfile, "tempdir", None),
                    mock.patch.dict(
                        os.environ,
                        {"TMPDIR": str(controlled_tmp)},
                        clear=False,
                    ),
                ):
                    self.assertEqual(
                        module.pin_controlled_tmpdir(runtime),
                        controlled_tmp,
                    )
                    self.assertEqual(module.tempfile.tempdir, str(controlled_tmp))
                    self.assertEqual(os.environ["TMPDIR"], str(controlled_tmp))


    def test_controlled_relay_route_is_exact_bounded_and_runtime_owned(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            runtime = root / "evaluation"
            runtime.mkdir(mode=0o700)
            route, _, _ = write_controlled_route_fixture(runtime, home)
            baseline = json.loads(route.read_text(encoding="utf-8"))
            outside_route = root / "outside-incident-evidence.json"
            outside_route.write_text(
                json.dumps(baseline) + "\n",
                encoding="utf-8",
            )
            outside_route.chmod(0o600)
            rogue_key_dir = root / "rogue-key"
            rogue_key_dir.mkdir(mode=0o700)
            rogue_key = (
                rogue_key_dir
                / "onion-sentinel-incident-evidence_ed25519"
            )
            rogue_key.write_text("synthetic-rogue-key\n", encoding="utf-8")
            rogue_key.chmod(0o600)
            outside_known_hosts = home / ".ssh" / "known_hosts"
            outside_known_hosts.write_text(
                "synthetic-global-known-host\n",
                encoding="utf-8",
            )
            outside_known_hosts.chmod(0o600)
            wrong_known_hosts = runtime / "known_hosts"
            wrong_known_hosts.write_text(
                "synthetic-wrong-known-host-name\n",
                encoding="utf-8",
            )
            wrong_known_hosts.chmod(0o600)
            nested_known_hosts_dir = runtime / "nested"
            nested_known_hosts_dir.mkdir(mode=0o700)
            nested_known_hosts = nested_known_hosts_dir / "relay_known_hosts"
            nested_known_hosts.write_text(
                "synthetic-nested-known-host\n",
                encoding="utf-8",
            )
            nested_known_hosts.chmod(0o600)
            for module in (self.scheduler, self.runner):
                route.write_text(
                    json.dumps(baseline) + "\n",
                    encoding="utf-8",
                )
                route.chmod(0o600)
                with self.subTest(module=module.__name__, case="valid"):
                    self.assertEqual(
                        module.validate_controlled_incident_evidence_route(
                            route,
                            runtime,
                            expected_home=home,
                        ),
                        baseline,
                    )
                with self.subTest(module=module.__name__, case="outside"):
                    with self.assertRaisesRegex(ValueError, "must stay inside"):
                        module.validate_controlled_incident_evidence_route(
                            outside_route,
                            runtime,
                            expected_home=home,
                        )
                for field, value, expected in (
                    ("host", "10.88.8.9", "exact read-only route"),
                    ("ssh_user", "root", "exact read-only route"),
                    (
                        "investigation_query_contract",
                        "onion-sentinel-investigation-pivots-v1",
                        "exact read-only route",
                    ),
                    (
                        "max_response_bytes",
                        (8 * 1024 * 1024) + 1,
                        "bounded transport limit",
                    ),
                    ("ssh_key", str(rogue_key), "path is not approved"),
                    (
                        "known_hosts",
                        str(outside_known_hosts),
                        "path is not approved",
                    ),
                    (
                        "known_hosts",
                        str(wrong_known_hosts),
                        "path is not approved",
                    ),
                    (
                        "known_hosts",
                        str(nested_known_hosts),
                        "path is not approved",
                    ),
                ):
                    with self.subTest(
                        module=module.__name__,
                        case=f"tampered-{field}",
                    ):
                        tampered = dict(baseline)
                        tampered[field] = value
                        route.write_text(
                            json.dumps(tampered) + "\n",
                            encoding="utf-8",
                        )
                        route.chmod(0o600)
                        with self.assertRaisesRegex(ValueError, expected):
                            module.validate_controlled_incident_evidence_route(
                                route,
                                runtime,
                                expected_home=home,
                            )
            route.write_text(
                json.dumps(baseline) + "\n",
                encoding="utf-8",
            )
            route.chmod(0o600)


    def test_controlled_codex_primary_and_reviewer_use_explicit_tmp_parent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary).resolve()
            controlled_tmp = runtime / "tmp"
            controlled_tmp.mkdir(mode=0o700)
            invocations: list[dict[str, object]] = []

            def fake_run(command, **kwargs):
                final_path = Path(
                    command[command.index("--output-last-message") + 1]
                )
                final_path.write_text("{}\n", encoding="utf-8")
                invocations.append({"command": command, **kwargs})
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            args = SimpleNamespace(
                timeout=30,
                max_response_bytes=1024 * 1024,
            )
            transport = (
                {"prompt_package": {"response_schema": {}}},
                "{}",
            )
            with (
                mock.patch.object(
                    self.runner,
                    "_CONTROLLED_EVALUATION_TMPDIR",
                    controlled_tmp,
                ),
                mock.patch.object(
                    self.runner,
                    "resolve_codex_cli",
                    return_value="/usr/bin/true",
                ),
                mock.patch.object(
                    self.runner,
                    "prepare_codex_cli_transport",
                    return_value=transport,
                ),
                mock.patch.object(
                    self.runner,
                    "run_bounded_command",
                    side_effect=fake_run,
                ),
                mock.patch.dict(
                    os.environ,
                    {"TMPDIR": str(controlled_tmp)},
                    clear=False,
                ),
            ):
                self.runner.cloud_cli_chat(
                    {},
                    args,
                    {},
                    model="gpt-5.5",
                    reasoning_effort="high",
                )
                self.runner.cloud_cli_chat(
                    {},
                    args,
                    {},
                    model="gpt-5.6-sol",
                    reasoning_effort="xhigh",
                    independent_review=True,
                )

            self.assertEqual(len(invocations), 2)
            for invocation in invocations:
                cwd = Path(invocation["cwd"])
                cwd.relative_to(controlled_tmp)
                environment = invocation["env"]
                self.assertEqual(environment["TMPDIR"], str(controlled_tmp))
                command = invocation["command"]
                self.assertEqual(
                    Path(command[command.index("-C") + 1]),
                    cwd,
                )


    def test_direct_controlled_run_local_requires_isolated_out_dir(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            evaluation_root = root / "evaluation"
            evaluation_root.mkdir(mode=0o700)
            inside = evaluation_root / "analysis"
            outside = root / "global-analysis"
            self.assertEqual(
                self.runner.controlled_evaluation_output_dir(
                    inside,
                    evaluation_root,
                ),
                inside,
            )
            with self.assertRaisesRegex(
                SystemExit,
                "out_dir must stay inside",
            ):
                self.runner.controlled_evaluation_output_dir(
                    outside,
                    evaluation_root,
                )

            args = SimpleNamespace(
                out_dir=outside,
                reanalysis_attempt_id="",
                alert_store_url="http://127.0.0.1:18787",
            )
            with (
                mock.patch.object(
                    self.runner,
                    "parse_args",
                    return_value=args,
                ),
                mock.patch.object(
                    self.runner,
                    "controlled_evaluation_runtime",
                    return_value=(True, evaluation_root),
                ),
                mock.patch.dict(
                    os.environ,
                    {"ONION_SENTINEL_EVALUATION_FREEZE_MEMORY": "1"},
                    clear=False,
                ),
                mock.patch.object(
                    self.runner,
                    "controlled_evaluation_result_identity",
                ) as result_identity,
            ):
                with self.assertRaisesRegex(
                    SystemExit,
                    "out_dir must stay inside",
                ):
                    self.runner.main()
            result_identity.assert_not_called()


    def test_mode_off_exact_target_runs_real_runner_without_controlled_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home"
            home.mkdir(mode=0o700)
            database = root / "alerts.sqlite3"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE marker (id INTEGER)")
                connection.commit()
            settings = root / "ai-settings.json"
            settings.write_text("{}", encoding="utf-8")
            prompt = root / "mode-off-prompt.json"
            prompt.write_text(
                json.dumps(
                    {
                        "package_type": "deliberately-invalid-offline-package",
                    }
                ),
                encoding="utf-8",
            )
            group_id = "abababababababababab"
            alert_id = "mode-off-exact-target"
            stable_group_key = "v2|mode-off|exact-target"
            dispatch_id = "a" * 64
            job_payload = {
                "alert_id": alert_id,
                "representative_alert_id": alert_id,
                "group_id": group_id,
                "stable_group_id": group_id,
                "stable_group_key": stable_group_key,
                "dispatch_id": dispatch_id,
                "release_id": RELEASE_ID,
                "manual_reanalysis": True,
            }
            selected = {
                "alert_id": alert_id,
                "stable_group_id": group_id,
                "queue_group_key": stable_group_key,
                "durable_job_type": "ai_analysis",
                "has_durable_intent": 1,
                "durable_job_id": 17,
                "durable_payload_json": json.dumps(job_payload),
                "rule_name": "Mode-off exact target",
                "triage_level": "critical",
                "triage_score": 100,
                "last_seen": "2026-07-27  12:00:00+00:00",
                "queue_time": "2026-07-27  12:00:00+00:00",
            }
            args = SimpleNamespace(
                db=database,
                prompt_dir=root / "prompts",
                analysis_dir=root / "analysis",
                pcap_analysis_dir=root / "pcap-analysis",
                incident_evidence_dir=root / "incident-evidence",
                incident_evidence_config=root / "incident-evidence.json",
                ai_settings_file=settings,
                provider_lane="any",
                lock_file=root / "scheduler.lock",
                wake_file=root / "scheduler.wake",
                levels="critical,high,medium,low,informational",
                hours=87600,
                max_per_run=1,
                only_group_id=group_id,
                only_alert_id=alert_id,
                only_stable_group_key=stable_group_key,
                only_dispatch_id=dispatch_id,
                related_limit=8,
                correlation_limit=8,
                correlation_min_score=15,
                model=None,
                timeout=1,
                max_prompt_bytes=1024 * 1024,
                portal_wake_file=root / "dashboard.wake",
                no_portal_refresh=True,
                alert_store_url="http://127.0.0.1:9",
                include_tests=True,
                dry_run=False,
            )

            def status_transition(
                _base_url: str,
                _group_id: str,
                status: str,
                error: str = "",
                lease_token: str = "",
                **kwargs,
            ):
                del error, lease_token, kwargs
                if status == "processing":
                    return self.scheduler.ClaimedAiLease(
                        "17171717-1717-4171-8171-171717171717",
                        job_payload=job_payload,
                        job_type="ai_analysis",
                        resolved_key=group_id,
                        job_id=17,
                    )
                return True

            environment = sanitized_environment()
            environment.update(
                {
                    "HOME": str(home),
                    "ONION_SENTINEL_EVALUATION_MODE": "0",
                    "ONION_SENTINEL_RELEASE_ID": RELEASE_ID,
                }
            )
            for environment_key in (
                self.runner.CONTROLLED_RESULT_ENVIRONMENT.values()
            ):
                environment.pop(environment_key, None)

            original_flush = (
                self.scheduler.flush_deferred_analysis_results
            )
            with (
                mock.patch.object(
                    self.scheduler,
                    "parse_args",
                    return_value=args,
                ),
                mock.patch.object(
                    self.scheduler,
                    "require_runtime_capacity",
                ),
                mock.patch.object(
                    self.scheduler,
                    "indexed_scheduler_available",
                    return_value=True,
                ),
                mock.patch.object(
                    self.scheduler,
                    "flush_deferred_analysis_results",
                    wraps=original_flush,
                ) as flush_deferred,
                mock.patch.object(
                    self.scheduler,
                    "reconcile_worker_state",
                    return_value=0,
                ) as reconcile,
                mock.patch.object(
                    self.scheduler,
                    "select_next_alert_indexed",
                    return_value=selected,
                ),
                mock.patch.object(
                    self.scheduler,
                    "report_ai_job_status",
                    side_effect=status_transition,
                ) as report_status,
                mock.patch.object(
                    self.scheduler,
                    "claimed_durable_ai_job",
                    return_value=(
                        job_payload,
                        alert_id,
                        group_id,
                        "critical",
                    ),
                ),
                mock.patch.object(
                    self.scheduler,
                    "build_prompt",
                    return_value=prompt,
                ),
                mock.patch.dict(os.environ, environment, clear=True),
            ):
                self.assertEqual(self.scheduler.main(), 0)

            flush_deferred.assert_called_once_with(args)
            self.assertEqual(reconcile.call_count, 2)
            for call in reconcile.call_args_list:
                self.assertIs(
                    call.kwargs["controlled_evaluation"],
                    False,
                )
            failure = report_status.call_args_list[-1]
            self.assertEqual(failure.args[2], "failed")
            self.assertIn(
                "unexpected prompt package type",
                failure.args[3],
            )
            self.assertNotIn(
                "controlled result identity requires",
                failure.args[3],
            )


