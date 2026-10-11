from __future__ import annotations

from ai_model_routing_fixtures import (
    BIN_DIR,
    ExitStack,
    PIPELINE_ADAPTERS,
    Path,
    REPO_ROOT,
    RUNNER_PATH,
    ThreadPoolExecutor,
    build_agent_memory_context_contract,
    copy,
    hashlib,
    importlib,
    io,
    json,
    load_runner,
    mock,
    sys,
    tempfile,
    unittest,
)

class AiModelRoutingTestsHermesRouteIsToolEmptyIsolatedAndRecordsProvenanceCases:
    def test_hermes_route_is_tool_empty_isolated_and_records_provenance(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = {
            **self.runner.default_ai_settings(),
            "hermes_agent_enabled": True,
            "hermes_agent_path": "/usr/local/bin/hermes",
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
        }
        captured: dict[str, object] = {}

        def fake_run(command, **kwargs):
            captured["command"] = list(command)
            captured["stdin_text"] = kwargs.get("stdin_text")
            captured["env"] = dict(kwargs.get("env") or {})
            captured["cwd"] = kwargs.get("cwd")
            hermes_home = Path(captured["env"]["HERMES_HOME"])
            captured["config"] = (hermes_home / "config.yaml").read_text(
                encoding="utf-8"
            )
            captured["config_mode"] = (
                (hermes_home / "config.yaml").stat().st_mode & 0o777
            )
            captured["auth"] = json.loads(
                (hermes_home / "auth.json").read_text(encoding="utf-8")
            )
            captured["auth_mode"] = (
                (hermes_home / "auth.json").stat().st_mode & 0o777
            )
            captured["directory_modes"] = {
                key: Path(captured["env"][key]).stat().st_mode & 0o777
                for key in (
                    "HOME",
                    "CODEX_HOME",
                    "HERMES_HOME",
                    "XDG_CONFIG_HOME",
                    "XDG_CACHE_HOME",
                    "XDG_DATA_HOME",
                    "XDG_STATE_HOME",
                    "XDG_RUNTIME_DIR",
                    "TMPDIR",
                )
            }
            usage_path = Path(command[command.index("--usage-file") + 1])
            usage_path.write_text(
                json.dumps(
                    {
                        "completed": True,
                        "failed": False,
                        "provider": "openai-codex",
                        "model": "gpt-5.6-sol",
                    }
                ),
                encoding="utf-8",
            )
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": '{"summary":"Hermes synthetic result"}',
                    "stderr": "",
                },
            )()

        with tempfile.TemporaryDirectory() as temp_name:
            auth_file = Path(temp_name) / "auth.json"
            auth_file.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "active_provider": "nous",
                        "providers": {
                            "openai-codex": {
                                "tokens": {
                                    "access_token": "dedicated-test-token",
                                },
                            },
                            "nous": {"access_token": "must-not-copy"},
                        },
                        "credential_pool": {
                            "openai-codex": [
                                {
                                    "id": "codex-test",
                                    "access_token": "dedicated-pool-token",
                                },
                            ],
                            "nous": [
                                {
                                    "id": "nous-test",
                                    "access_token": "must-not-copy",
                                },
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )
            auth_file.chmod(0o600)
            with (
                mock.patch.object(
                    self.runner,
                    "DEFAULT_HERMES_AUTH_FILE",
                    auth_file,
                ),
                mock.patch.object(
                    self.runner,
                    "resolve_cli_harness",
                    return_value="/usr/local/bin/hermes",
                ),
                mock.patch.object(
                    self.runner,
                    "run_bounded_command",
                    side_effect=fake_run,
                ),
                mock.patch.object(
                    self.runner,
                    "_unload_ollama_model",
                ),
            ):
                response = self.runner.analyze_model_route(
                    "hermes-agent:gpt-5.6-sol:medium",
                    {
                        "response_schema": {"type": "object"},
                        "alert": {"rule_name": "Synthetic"},
                    },
                    args,
                    settings,
                )
                captured["dedicated_auth"] = json.loads(
                    auth_file.read_text(encoding="utf-8")
                )
                captured["dedicated_auth_mode"] = (
                    auth_file.stat().st_mode & 0o777
                )
                captured["auth_lock_mode"] = (
                    (auth_file.parent / "auth.lock").stat().st_mode & 0o777
                )

        command = captured["command"]
        self.assertEqual(command[0], "/usr/local/bin/hermes")
        self.assertIn("--oneshot", command)
        self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-sol")
        self.assertEqual(
            command[command.index("--provider") + 1],
            "openai-codex",
        )
        self.assertEqual(
            command[command.index("--toolsets") + 1],
            "context_engine",
        )
        self.assertIn("--safe-mode", command)
        self.assertNotIn("--ignore-rules", command)
        self.assertNotIn("terminal", command)
        self.assertNotIn("browser", command)
        self.assertIsNone(captured["stdin_text"])
        payload = json.loads(command[command.index("--oneshot") + 1])
        self.assertEqual(payload["reasoning_effort"], "medium")
        self.assertEqual(
            payload["prompt_package"]["alert"]["rule_name"],
            "Synthetic",
        )
        self.assertNotIn("HERMES_IGNORE_RULES", captured["env"])
        self.assertEqual(
            captured["env"]["HOME"],
            str(Path(captured["env"]["HERMES_HOME"]) / "home"),
        )
        self.assertEqual(
            captured["env"]["CODEX_HOME"],
            str(Path(captured["env"]["HOME"]) / ".codex"),
        )
        self.assertEqual(
            captured["env"]["HERMES_REAL_HOME"],
            captured["env"]["HOME"],
        )
        self.assertEqual(captured["env"]["PYTHON_DOTENV_DISABLED"], "1")
        for key in (
            "HOME",
            "CODEX_HOME",
            "HERMES_HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        ):
            self.assertTrue(
                Path(captured["env"][key]).is_relative_to(captured["cwd"]),
                key,
            )
        self.assertEqual(set(captured["directory_modes"].values()), {0o700})
        self.assertEqual(captured["config_mode"], 0o600)
        self.assertFalse(captured["cwd"].exists())
        self.assertIn("context:\n  engine: compressor", captured["config"])
        self.assertNotIn("max_turns:", captured["config"])
        self.assertNotIn("reasoning_effort:", captured["config"])
        self.assertIn("memory_enabled: false", captured["config"])
        self.assertIn("user_profile_enabled: false", captured["config"])
        self.assertIn("home_mode: profile", captured["config"])
        self.assertNotIn("tools:", captured["config"])
        self.assertEqual(
            set(captured["auth"]["providers"]),
            {"openai-codex"},
        )
        self.assertEqual(
            set(captured["auth"]["credential_pool"]),
            {"openai-codex"},
        )
        self.assertEqual(captured["auth"]["active_provider"], "openai-codex")
        self.assertEqual(captured["auth_mode"], 0o600)
        self.assertEqual(captured["dedicated_auth"], captured["auth"])
        self.assertEqual(captured["dedicated_auth_mode"], 0o600)
        self.assertEqual(captured["auth_lock_mode"], 0o600)
        self.assertIn("--usage-file", command)
        self.assertEqual(response["_analysis_model"], "gpt-5.6-sol")
        self.assertEqual(response["_analysis_model_path"], "hermes-agent")
        self.assertEqual(response["_analysis_provider"], "openai-codex")
        self.assertEqual(response["_analysis_harness"], "hermes-agent")


    def test_hermes_dedicated_auth_never_falls_back_to_user_stores(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = {
            **self.runner.default_ai_settings(),
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
        }
        with tempfile.TemporaryDirectory() as temp_name:
            temporary = Path(temp_name)
            dedicated = temporary / "private" / "hermes-agent" / "auth.json"
            for fallback in (
                temporary / ".hermes" / "auth.json",
                temporary / ".codex" / "auth.json",
            ):
                fallback.parent.mkdir(parents=True)
                fallback.write_text(
                    json.dumps(
                        {
                            "providers": {
                                "openai-codex": {
                                    "tokens": {"access_token": "fallback-token"},
                                },
                            },
                        }
                    ),
                    encoding="utf-8",
                )
                fallback.chmod(0o600)
            with (
                mock.patch.object(
                    self.runner,
                    "DEFAULT_HERMES_AUTH_FILE",
                    dedicated,
                ),
                mock.patch.object(
                    self.runner,
                    "resolve_cli_harness",
                    return_value="/usr/local/bin/hermes",
                ),
                mock.patch.object(self.runner, "run_bounded_command") as run,
                self.assertRaisesRegex(
                    SystemExit,
                    "dedicated authentication is unavailable",
                ),
            ):
                self.runner.hermes_agent_chat(
                    {},
                    args,
                    settings,
                    model="gpt-5.6-sol",
                    reasoning_effort="medium",
                )

        run.assert_not_called()


    def test_hermes_dedicated_auth_requires_regular_owner_only_file(self) -> None:
        valid_store = {
            "providers": {
                "openai-codex": {
                    "tokens": {"access_token": "dedicated-test-token"},
                },
            },
        }
        with tempfile.TemporaryDirectory() as temp_name:
            temporary = Path(temp_name)
            auth_file = temporary / "auth.json"
            auth_file.write_text(json.dumps(valid_store), encoding="utf-8")
            auth_file.chmod(0o640)
            with self.assertRaisesRegex(
                self.runner.RuntimeArtifactError,
                "mode 0600",
            ):
                self.runner._load_dedicated_hermes_auth(auth_file)

            auth_file.chmod(0o600)
            symlink = temporary / "linked-auth.json"
            symlink.symlink_to(auth_file)
            with self.assertRaisesRegex(
                self.runner.RuntimeArtifactError,
                "regular file",
            ):
                self.runner._load_dedicated_hermes_auth(symlink)


    def test_hermes_persists_rotated_auth_atomically_on_command_failure(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = {
            **self.runner.default_ai_settings(),
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
        }

        def fake_failure(_command, **kwargs):
            isolated_auth = Path(kwargs["env"]["HERMES_HOME"]) / "auth.json"
            rotated = json.loads(isolated_auth.read_text(encoding="utf-8"))
            rotated["providers"]["openai-codex"]["tokens"][
                "access_token"
            ] = "rotated-test-token"
            rotated["providers"]["unexpected"] = {
                "access_token": "must-not-persist",
            }
            isolated_auth.write_text(json.dumps(rotated), encoding="utf-8")
            return type(
                "Completed",
                (),
                {
                    "returncode": 7,
                    "stdout": "",
                    "stderr": "synthetic provider failure",
                },
            )()

        with tempfile.TemporaryDirectory() as temp_name:
            auth_file = Path(temp_name) / "auth.json"
            auth_file.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "providers": {
                            "openai-codex": {
                                "tokens": {
                                    "access_token": "initial-test-token",
                                },
                            },
                            "nous": {"access_token": "must-not-persist"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            auth_file.chmod(0o600)
            with (
                mock.patch.object(
                    self.runner,
                    "DEFAULT_HERMES_AUTH_FILE",
                    auth_file,
                ),
                mock.patch.object(
                    self.runner,
                    "resolve_cli_harness",
                    return_value="/usr/local/bin/hermes",
                ),
                mock.patch.object(
                    self.runner,
                    "run_bounded_command",
                    side_effect=fake_failure,
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "Hermes Agent exited with code 7",
                ),
            ):
                self.runner.hermes_agent_chat(
                    {},
                    args,
                    settings,
                    model="gpt-5.6-sol",
                    reasoning_effort="medium",
                )

            persisted = json.loads(auth_file.read_text(encoding="utf-8"))
            self.assertEqual(
                persisted["providers"]["openai-codex"]["tokens"][
                    "access_token"
                ],
                "rotated-test-token",
            )
            self.assertEqual(set(persisted["providers"]), {"openai-codex"})
            self.assertEqual(auth_file.stat().st_mode & 0o777, 0o600)
            self.assertFalse(
                any(auth_file.parent.glob(f".{auth_file.name}.*.tmp"))
            )


    def test_hermes_usage_provenance_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            usage_path = Path(temp_name) / "usage.json"
            cases = (
                (
                    {
                        "completed": False,
                        "failed": False,
                        "provider": "openai-codex",
                        "model": "gpt-5.6-sol",
                    },
                    "completed invocation",
                ),
                (
                    {
                        "completed": True,
                        "failed": True,
                        "provider": "openai-codex",
                        "model": "gpt-5.6-sol",
                    },
                    "completed invocation",
                ),
                (
                    {
                        "completed": True,
                        "failed": False,
                        "provider": "openai",
                        "model": "gpt-5.6-sol",
                    },
                    "different provider/model",
                ),
                (
                    {
                        "completed": True,
                        "failed": False,
                        "provider": "openai-codex",
                        "model": "gpt-5.6-terra",
                    },
                    "different provider/model",
                ),
            )
            for usage, expected in cases:
                with self.subTest(usage=usage):
                    usage_path.write_text(
                        json.dumps(usage),
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(SystemExit, expected):
                        self.runner._verified_hermes_usage(
                            usage_path,
                            expected_model="gpt-5.6-sol",
                        )


    def test_openclaw_infer_uses_ephemeral_profile_and_observed_provenance(
        self,
    ) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = {
            **self.runner.default_ai_settings(),
            "openclaw_enabled": True,
            "openclaw_path": "/usr/local/bin/openclaw",
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "high",
        }
        captured: dict[str, object] = {}
        envelope = {
            "ok": True,
            "provider": "ollama",
            "model": "gemma4:26b-mlx",
            "outputs": [
                {"text": '{"summary":"OpenClaw synthetic result"}'},
            ],
        }

        def fake_run(command, **kwargs):
            captured["command"] = list(command)
            captured["kwargs"] = kwargs
            environment = dict(kwargs["env"])
            captured["env"] = environment
            captured["cwd"] = Path(kwargs["cwd"])
            config_path = Path(environment["OPENCLAW_CONFIG_PATH"])
            captured["config"] = json.loads(
                config_path.read_text(encoding="utf-8")
            )
            captured["config_mode"] = config_path.stat().st_mode & 0o777
            captured["directory_modes"] = {
                key: Path(environment[key]).stat().st_mode & 0o777
                for key in (
                    "HOME",
                    "CODEX_HOME",
                    "OPENCLAW_STATE_DIR",
                    "OPENCLAW_OAUTH_DIR",
                    "OPENCLAW_AGENT_DIR",
                    "OPENCLAW_WORKSPACE_DIR",
                    "XDG_CONFIG_HOME",
                    "XDG_CACHE_HOME",
                    "XDG_DATA_HOME",
                    "XDG_STATE_HOME",
                    "XDG_RUNTIME_DIR",
                    "TMPDIR",
                )
            }
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(envelope),
                    "stderr": "",
                },
            )()

        with tempfile.TemporaryDirectory() as operator_home_name:
            operator_home = Path(operator_home_name)
            operator_state = operator_home / ".openclaw"
            operator_state.mkdir(mode=0o700)
            (operator_state / "openclaw.json").write_text(
                '{"operator_profile_marker":"must-not-load"}',
                encoding="utf-8",
            )
            with (
                mock.patch.dict(
                    self.runner.os.environ,
                    {
                        "HOME": str(operator_home),
                        "XDG_CONFIG_HOME": str(operator_home / "xdg-config"),
                        "OPENAI_API_KEY": "operator-secret-must-not-copy",
                    },
                    clear=False,
                ),
                mock.patch.object(
                    self.runner,
                    "resolve_cli_harness",
                    return_value="/usr/local/bin/openclaw",
                ),
                mock.patch.object(
                    self.runner,
                    "run_bounded_command",
                    side_effect=fake_run,
                ),
            ):
                response = self.runner.analyze_model_route(
                    "openclaw:ollama/gemma4:26b-mlx:high",
                    {
                        "response_schema": {"type": "object"},
                        "alert": {"rule_name": "Synthetic"},
                    },
                    args,
                    settings,
                )

        command = captured["command"]
        self.assertEqual(
            command[:5],
            [
                "/usr/local/bin/openclaw",
                "infer",
                "model",
                "run",
                "--local",
            ],
        )
        self.assertEqual(
            command[command.index("--model") + 1],
            "ollama/gemma4:26b-mlx",
        )
        self.assertEqual(command[command.index("--thinking") + 1], "high")
        self.assertIn("--json", command)
        self.assertNotIn("agent", command)
        self.assertNotIn("stdin_text", captured["kwargs"])
        environment = captured["env"]
        working_directory = captured["cwd"]
        self.assertEqual(environment["HOME"], environment["OPENCLAW_HOME"])
        self.assertNotEqual(environment["HOME"], str(operator_home))
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["OLLAMA_API_KEY"], "ollama-local")
        self.assertEqual(environment["OPENCLAW_OFFLINE"], "1")
        self.assertNotIn("OPENCLAW_LOAD_SHELL_ENV", environment)
        self.assertEqual(environment["HTTP_PROXY"], "")
        self.assertEqual(environment["HTTPS_PROXY"], "")
        self.assertEqual(environment["NO_PROXY"], "127.0.0.1,localhost,::1")
        for key in (
            "HOME",
            "CODEX_HOME",
            "OPENCLAW_STATE_DIR",
            "OPENCLAW_CONFIG_PATH",
            "OPENCLAW_OAUTH_DIR",
            "OPENCLAW_AGENT_DIR",
            "OPENCLAW_WORKSPACE_DIR",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_RUNTIME_DIR",
            "TMPDIR",
        ):
            self.assertTrue(
                Path(environment[key]).is_relative_to(working_directory),
                key,
            )
        self.assertEqual(captured["config"], {})
        self.assertEqual(captured["config_mode"], 0o600)
        self.assertEqual(set(captured["directory_modes"].values()), {0o700})
        self.assertFalse(working_directory.exists())
        prompt = json.loads(command[command.index("--prompt") + 1])
        self.assertEqual(
            prompt["prompt_package"]["alert"]["rule_name"],
            "Synthetic",
        )
        self.assertEqual(
            response["_analysis_model"],
            "ollama/gemma4:26b-mlx",
        )
        self.assertEqual(response["_analysis_model_path"], "openclaw")
        self.assertEqual(response["_analysis_provider"], "ollama")
        self.assertEqual(response["_analysis_harness"], "openclaw")


    def test_openclaw_rejects_observed_model_mismatch(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = {
            **self.runner.default_ai_settings(),
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "xhigh",
        }
        completed = type(
            "Completed",
            (),
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "ok": True,
                        "provider": "anthropic",
                        "model": "claude-sonnet-4",
                        "outputs": [{"text": '{"summary":"wrong model"}'}],
                    }
                ),
                "stderr": "",
            },
        )()

        with (
            mock.patch.object(
                self.runner,
                "resolve_cli_harness",
                return_value="/usr/local/bin/openclaw",
            ),
            mock.patch.object(
                self.runner,
                "run_bounded_command",
                return_value=completed,
            ),
            mock.patch.object(
                self.runner,
                "_unload_ollama_model",
            ),
            self.assertRaisesRegex(
                SystemExit,
                "different provider/model",
            ),
        ):
            self.runner.analyze_model_route(
                "openclaw:ollama/gemma4:26b-mlx:xhigh",
                {"response_schema": {"type": "object"}},
                args,
                settings,
            )


    def test_openclaw_hosted_route_fails_before_executable_resolution(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = {
            **self.runner.default_ai_settings(),
            "openclaw_enabled": True,
            "openclaw_model": "openai/gpt-5.6-sol",
            "openclaw_reasoning_effort": "high",
        }
        with (
            mock.patch.object(self.runner, "resolve_cli_harness") as resolve,
            mock.patch.object(self.runner, "run_bounded_command") as run,
            self.assertRaisesRegex(
                SystemExit,
                "explicit ollama/<model> routes only",
            ),
        ):
            self.runner.openclaw_infer_chat(
                {},
                args,
                settings,
                model="openai/gpt-5.6-sol",
                reasoning_effort="high",
            )
        resolve.assert_not_called()
        run.assert_not_called()


