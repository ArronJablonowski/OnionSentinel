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

class AiModelRoutingTestsSuppliedEndpointPathIsRemovedFromGapListsCases:
    def test_supplied_endpoint_path_is_removed_from_gap_lists(self) -> None:
        prompt = self.trusted_endpoint_executable_prompt()
        response = {
            "evidence_gaps": [
                (
                    "Endpoint process executable path, code-signing status, "
                    "command line, and parent lineage are not supplied."
                ),
                "Structured authorization is not supplied.",
            ],
            "additional_evidence_needed": [
                (
                    "Microsoft Update Assistant executable path, signing "
                    "status, hash, and command line."
                )
            ],
            "incident_response_report": {
                "evidence_gaps": ["The executable path is missing."],
                "constraints": ["PCAP is unavailable."],
            },
        }

        reconciled = self.runner.reconcile_supplied_endpoint_evidence_gaps(
            response,
            prompt,
        )

        self.assertEqual(
            reconciled["evidence_gaps"][0],
            (
                "Endpoint process code-signing status, command line, and "
                "parent lineage are not supplied."
            ),
        )
        self.assertEqual(
            reconciled["additional_evidence_needed"][0],
            "Microsoft Update Assistant signing status, hash, and command line.",
        )
        self.assertEqual(
            reconciled["incident_response_report"]["evidence_gaps"],
            [],
        )
        self.assertEqual(
            reconciled["incident_response_report"]["constraints"],
            ["PCAP is unavailable."],
        )
        self.assertEqual(
            reconciled["_endpoint_evidence_gap_reconciliation"],
            {
                "schema": (
                    "onion-sentinel-endpoint-evidence-gap-reconciliation-v1"
                ),
                "executable_path_supplied": True,
                "rewritten_gap_count": 2,
                "removed_gap_count": 1,
            },
        )


    def test_truncated_endpoint_result_does_not_reconcile_gap(self) -> None:
        prompt = self.trusted_endpoint_executable_prompt()
        prompt["investigation_query_results"]["rounds"][0]["results"][0][
            "evidence"
        ]["results"][0]["truncated"] = True
        response = {
            "evidence_gaps": ["The executable path is missing."],
        }

        reconciled = self.runner.reconcile_supplied_endpoint_evidence_gaps(
            response,
            prompt,
        )

        self.assertEqual(
            reconciled["evidence_gaps"],
            ["The executable path is missing."],
        )
        self.assertNotIn(
            "_endpoint_evidence_gap_reconciliation",
            reconciled,
        )


    def test_repo_template_assigns_approved_models_to_every_agent(self) -> None:
        settings_path = REPO_ROOT / "n8n" / "config" / "ai_model_settings.json"
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        primary = "ollama:devstral-small-2:24b-instruct-2512-q4_K_M"
        reviewer = "ollama:gemma4:31b"

        self.assertEqual(
            settings["enabled_ollama_models"],
            ["devstral-small-2:24b-instruct-2512-q4_K_M", "gemma4:31b"],
        )
        self.assertEqual(
            settings["agent_models"],
            {
                role: ("codex-cli:gpt-5.5:medium" if role == "incident-responder" else primary)
                for role in self.runner.CYBER_SECURITY_AGENT_ROLES
            },
        )
        self.assertTrue(settings["gpt_cli_enabled"])
        self.assertEqual(settings["mode"], "hybrid")
        self.assertEqual(settings["cloud_provider"], "codex-cli")
        self.assertEqual(settings["codex_cli_model"], "gpt-5.5")
        self.assertEqual(settings["codex_cli_reasoning_effort"], "medium")
        self.assertEqual(
            settings["codex_cli_models"],
            [
                {
                    "enabled": model in {"gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra"},
                    "model": model,
                    "reasoning_effort": (
                        "xhigh" if model == "gpt-5.6-sol" else "medium"
                    ),
                }
                for model in self.runner.CODEX_CLI_MODEL_CATALOG
            ],
        )
        self.assertEqual(
            settings["agent_second_opinion_models"],
            {
                role: (
                    "codex-cli:gpt-5.6-sol:xhigh"
                    if role == "incident-responder"
                    else reviewer
                )
                for role in self.runner.CYBER_SECURITY_AGENT_ROLES
            },
        )
        self.assertEqual(
            settings["agent_adjudicator_models"],
            {
                role: "codex-cli:gpt-5.6-terra:medium"
                for role in self.runner.CYBER_SECURITY_AGENT_ROLES
            },
        )


    def test_parser_defaults_do_not_override_saved_model_roster(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "ai_model_settings.json"
            path.write_text(json.dumps({
                "enabled_ollama_models": ["primary:latest", "fallback:latest"],
                "ollama_url": "http://127.0.0.1:22468",
            }), encoding="utf-8")
            with mock.patch.object(sys, "argv", ["run-local-ai-analysis.py"]):
                args = self.runner.parse_args()
            args.ai_settings_file = path

            settings = self.runner.effective_ai_settings(args)

        self.assertEqual(settings["enabled_ollama_models"], ["primary:latest", "fallback:latest"])
        self.assertEqual(settings["ollama_url"], "http://127.0.0.1:22468")
        self.assertEqual(
            settings["agent_models"],
            {role: "ollama:primary:latest" for role in self.runner.CYBER_SECURITY_AGENT_ROLES},
        )
        self.assertEqual(
            settings["agent_second_opinion_models"],
            {role: "" for role in self.runner.CYBER_SECURITY_AGENT_ROLES},
        )


    def test_legacy_hybrid_settings_migrate_to_provider_roster(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "ai_model_settings.json"
            path.write_text(json.dumps({
                "mode": "hybrid",
                "ollama_model": "legacy:latest",
                "cloud_command": "gpt-cli analyze",
            }), encoding="utf-8")

            settings = self.runner.load_ai_settings(path)

        self.assertEqual(settings["enabled_ollama_models"], ["legacy:latest"])
        self.assertTrue(settings["gpt_cli_enabled"])
        self.assertEqual(settings["mode"], "hybrid")
        self.assertEqual(
            settings["agent_models"],
            {role: "ollama:legacy:latest" for role in self.runner.CYBER_SECURITY_AGENT_ROLES},
        )
        self.assertEqual(settings["cloud_command"], "")
        self.assertEqual(settings["codex_cli_model"], "gpt-5.5")
        self.assertEqual(
            [entry["model"] for entry in settings["codex_cli_models"]],
            list(self.runner.CODEX_CLI_MODEL_CATALOG),
        )
        self.assertTrue(settings["codex_cli_models"][0]["enabled"])
        self.assertTrue(all(not entry["enabled"] for entry in settings["codex_cli_models"][1:]))


    def test_runner_rejects_codex_models_outside_the_fixed_catalog(self) -> None:
        settings = self.runner.default_ai_settings()

        with self.assertRaisesRegex(
            self.runner.RuntimeArtifactError,
            "supported catalog",
        ):
            self.runner.normalize_codex_cli_settings(
                settings,
                {
                    "codex_cli_models": [
                        {
                            "model": "gpt-9-unknown",
                            "reasoning_effort": "medium",
                            "enabled": True,
                        }
                    ]
                },
            )


    def test_ollama_chat_request_keeps_model_for_bounded_follow_up(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "temperature": 0.1,
                "max_predict_tokens": 4096,
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        captured: dict[str, object] = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with (
            mock.patch.object(self.runner.urllib.request, "urlopen", side_effect=fake_urlopen),
            mock.patch.object(
                self.runner,
                "read_bounded_json",
                return_value={"message": {"content": '{"summary":"Local result"}'}},
            ),
        ):
            response = self.runner._ollama_request(
                {"response_schema": {"type": "object"}},
                args,
                {
                    "ollama_model": "reviewer:latest",
                    "ollama_url": "http://127.0.0.1:11434",
                },
                "Analyze",
            )

        body = captured["body"]
        self.assertIsInstance(body, dict)
        self.assertEqual(body["model"], "reviewer:latest")
        self.assertNotIn("keep_alive", body)
        self.assertFalse(body["stream"])
        self.assertEqual(body["format"], "json")
        self.assertEqual(body["options"]["num_predict"], 4096)
        self.assertEqual(captured["timeout"], 60)
        self.assertEqual(response["_analysis_model"], "reviewer:latest")
        self.assertEqual(response["_analysis_model_path"], "ollama")
        self.assertEqual(response["_analysis_provider"], "ollama")


    def test_ollama_exchange_unloads_once_after_all_model_turns(self) -> None:
        args = type("Args", (), {"timeout": 60})()
        settings = {"ollama_url": "http://127.0.0.1:11434"}
        completed = {"summary": "complete"}
        with tempfile.TemporaryDirectory() as temp_name:
            lock_path = Path(temp_name) / "ollama.lock"
            with (
                mock.patch.object(
                    self.runner,
                    "DEFAULT_OLLAMA_INFERENCE_LOCK",
                    lock_path,
                ),
                mock.patch.object(
                    self.runner,
                    "_ollama_chat_for_model_unlocked",
                    return_value=completed,
                ) as exchange,
                mock.patch.object(
                    self.runner,
                    "_unload_ollama_model",
                ) as unload,
            ):
                response = self.runner._ollama_chat_for_model(
                    {},
                    args,
                    settings,
                    "reviewer:latest",
                )

        self.assertIs(response, completed)
        exchange.assert_called_once()
        unload.assert_called_once_with(
            settings,
            "reviewer:latest",
            timeout=60.0,
        )


    def test_ollama_unload_uses_zero_keep_alive_without_inference(self) -> None:
        captured: dict[str, object] = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'{"done":true}'

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse()

        with mock.patch.object(
            self.runner.urllib.request,
            "urlopen",
            side_effect=fake_urlopen,
        ):
            self.runner._unload_ollama_model(
                {"ollama_url": "http://127.0.0.1:11434"},
                "reviewer:latest",
                timeout=60,
            )

        self.assertEqual(captured["url"], "http://127.0.0.1:11434/api/generate")
        self.assertEqual(
            captured["body"],
            {
                "model": "reviewer:latest",
                "stream": False,
                "keep_alive": 0,
            },
        )
        self.assertEqual(captured["timeout"], 30.0)


    def test_soc_analyst_runs_only_its_assigned_ollama_model(self) -> None:
        args = type("Args", (), {})()
        settings = {
            **self.runner.default_ai_settings(),
            "mode": "hybrid",
            "enabled_ollama_models": ["primary:latest", "assigned:latest"],
            "gpt_cli_enabled": True,
            "cloud_command": "gpt-cli analyze",
            "agent_models": {
                role: ("ollama:assigned:latest" if role == "soc-analyst" else "ollama:primary:latest")
                for role in self.runner.CYBER_SECURITY_AGENT_ROLES
            },
        }
        local_response = {
            "summary": "assigned model",
            "_analysis_model": "assigned:latest",
            "_analysis_model_path": "ollama",
            "_analysis_provider": "ollama",
        }

        with (
            mock.patch.object(self.runner, "effective_ai_settings", return_value=settings),
            mock.patch.object(self.runner, "_ollama_chat_for_model", return_value=local_response) as local,
            mock.patch.object(self.runner, "cloud_cli_chat") as cloud,
        ):
            response = self.runner.analyze_with_config({}, args)

        self.assertEqual(response, local_response)
        local.assert_called_once_with(
            {},
            args,
            settings,
            "assigned:latest",
            system_prompt_file=None,
            independent_review=False,
        )
        cloud.assert_not_called()


    def test_soc_analyst_can_be_assigned_to_codex_cli(self) -> None:
        args = type("Args", (), {})()
        settings = {
            **self.runner.default_ai_settings(),
            "enabled_ollama_models": ["primary:latest"],
            "gpt_cli_enabled": True,
            "cloud_command": "gpt-cli analyze",
            "codex_cli_models": [
                {
                    "model": "gpt-5.5",
                    "reasoning_effort": "medium",
                    "enabled": True,
                },
            ],
            "agent_models": {
                role: ("codex-cli" if role == "soc-analyst" else "ollama:primary:latest")
                for role in self.runner.CYBER_SECURITY_AGENT_ROLES
            },
        }
        cloud_response = {
            "summary": "assigned GPT CLI",
            "_analysis_model": "gpt-5.5",
            "_analysis_model_path": "frontier-codex-cli",
            "_analysis_provider": "codex-cli",
        }

        with (
            mock.patch.object(self.runner, "effective_ai_settings", return_value=settings),
            mock.patch.object(self.runner, "cloud_cli_chat", return_value=cloud_response) as cloud,
            mock.patch.object(self.runner, "_ollama_chat_for_model") as local,
        ):
            response = self.runner.analyze_with_config({}, args)

        self.assertEqual(response, cloud_response)
        cloud.assert_called_once_with(
            {},
            args,
            settings,
            model="gpt-5.5",
            reasoning_effort="medium",
            system_prompt_file=None,
            independent_review=False,
        )
        local.assert_not_called()


    def test_codex_route_uses_fixed_ephemeral_read_only_argv(self) -> None:
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
            "cloud_command": "sh -c 'this must never execute'",
            "codex_cli_model": "gpt-5.5",
            "codex_cli_reasoning_effort": "medium",
        }
        prompt_package = {"response_schema": {"type": "object"}, "alert": {"rule_name": "Synthetic"}}
        seen_command = []

        def fake_run(command, **kwargs):
            seen_command.extend(command)
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text('{"summary":"Codex synthetic result"}', encoding="utf-8")
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        with (
            mock.patch.object(self.runner, "resolve_codex_cli", return_value="/usr/local/bin/codex"),
            mock.patch.object(self.runner, "run_bounded_command", side_effect=fake_run),
        ):
            response = self.runner.cloud_cli_chat(prompt_package, args, settings)

        self.assertEqual(response["summary"], "Codex synthetic result")
        self.assertEqual(response["_analysis_model"], "gpt-5.5")
        self.assertEqual(response["_analysis_provider"], "codex-cli")
        self.assertEqual(seen_command[:2], ["/usr/local/bin/codex", "exec"])
        self.assertIn("--sandbox", seen_command)
        self.assertIn("read-only", seen_command)
        self.assertIn("--ephemeral", seen_command)
        self.assertIn("--ignore-user-config", seen_command)
        self.assertIn("--ignore-rules", seen_command)
        self.assertNotIn("sh", seen_command)
        self.assertNotIn("this must never execute", " ".join(seen_command))


    def test_codex_rejects_oversized_runtime_package_before_spawn(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        prompt_package = {
            "response_schema": {"type": "object"},
            "alert": {
                "rule_name": "Synthetic",
                "oversized_runtime_evidence": "x"
                * self.runner.CODEX_CLI_MAX_STDIN_BYTES,
            },
        }
        with (
            mock.patch.object(
                self.runner,
                "resolve_codex_cli",
                return_value="/usr/local/bin/codex",
            ),
            mock.patch.object(self.runner, "run_bounded_command") as run,
            self.assertRaisesRegex(
                SystemExit,
                "Codex CLI runtime prompt package exceeded the "
                f"{self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES}-byte",
            ),
        ):
            self.runner.cloud_cli_chat(
                prompt_package,
                args,
                self.runner.default_ai_settings(),
            )

        run.assert_not_called()


    def test_codex_runtime_package_and_stdin_boundaries_are_exact(self) -> None:
        args = type("Args", (), {})()

        def exact_padding(container: dict, key: str, target: int) -> str:
            baseline = json.loads(json.dumps(container))
            baseline[key] = ""
            overhead = len(json.dumps(
                baseline,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"))
            self.assertGreaterEqual(target, overhead)
            return "x" * (target - overhead)

        package = {"padding": ""}
        package["padding"] = exact_padding(
            package,
            "padding",
            self.runner.CODEX_CLI_MAX_PROMPT_PACKAGE_BYTES,
        )
        package_payload = {
            "task": "bounded task",
            "system_prompt": "bounded system",
            "prompt_package": package,
        }
        with mock.patch.object(
            self.runner,
            "cli_analysis_payload",
            return_value=package_payload,
        ):
            _payload, serialized = (
                self.runner.prepare_codex_cli_transport({}, args)
            )
        self.assertLessEqual(
            len(serialized.encode("utf-8")),
            self.runner.CODEX_CLI_MAX_STDIN_BYTES,
        )

        oversized_package = copy.deepcopy(package_payload)
        oversized_package["prompt_package"]["padding"] += "x"
        with (
            mock.patch.object(
                self.runner,
                "cli_analysis_payload",
                return_value=oversized_package,
            ),
            self.assertRaisesRegex(
                SystemExit,
                "runtime prompt package exceeded",
            ),
        ):
            self.runner.prepare_codex_cli_transport({}, args)

        stdin_payload = {
            "task": "",
            "system_prompt": "",
            "prompt_package": {"response_schema": {}},
        }
        stdin_payload["task"] = exact_padding(
            stdin_payload,
            "task",
            self.runner.CODEX_CLI_MAX_STDIN_BYTES,
        )
        with mock.patch.object(
            self.runner,
            "cli_analysis_payload",
            return_value=stdin_payload,
        ):
            _payload, serialized = (
                self.runner.prepare_codex_cli_transport({}, args)
            )
        self.assertEqual(
            len(serialized.encode("utf-8")),
            self.runner.CODEX_CLI_MAX_STDIN_BYTES,
        )

        oversized_stdin = copy.deepcopy(stdin_payload)
        oversized_stdin["task"] += "x"
        with (
            mock.patch.object(
                self.runner,
                "cli_analysis_payload",
                return_value=oversized_stdin,
            ),
            self.assertRaisesRegex(
                SystemExit,
                "complete transport exceeds",
            ),
        ):
            self.runner.prepare_codex_cli_transport({}, args)


    def test_codex_uses_canonical_incident_prompt_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            config_dir = Path(temp_name)
            settings_path = config_dir / "ai_model_settings.json"
            settings_path.write_text("{}", encoding="utf-8")
            incident_prompt = self.runner.role_prompt_file(
                config_dir,
                "incident-responder",
            )
            incident_prompt.write_text(
                "INCIDENT RESPONDER CANONICAL MARKER",
                encoding="utf-8",
            )
            soc_prompt = self.runner.role_prompt_file(config_dir, "soc-analyst")
            soc_prompt.write_text(
                "SOC ANALYST WRONG MARKER",
                encoding="utf-8",
            )
            args = type(
                "Args",
                (),
                {
                    "ai_settings_file": settings_path,
                    "system_prompt_file": soc_prompt,
                },
            )()
            original = {
                "agent_role": "incident-responder",
                "instructions": {
                    "role": "INCIDENT RESPONDER CANONICAL MARKER",
                    "grounding": ["Use supplied evidence."],
                },
                "response_schema": {"type": "object"},
            }

            payload, serialized = self.runner.prepare_codex_cli_transport(
                original,
                args,
            )

        self.assertEqual(
            payload["system_prompt"],
            "INCIDENT RESPONDER CANONICAL MARKER",
        )
        self.assertNotIn("role", payload["prompt_package"]["instructions"])
        self.assertEqual(
            original["instructions"]["role"],
            "INCIDENT RESPONDER CANONICAL MARKER",
        )
        self.assertEqual(
            serialized.count("INCIDENT RESPONDER CANONICAL MARKER"),
            1,
        )
        self.assertNotIn("SOC ANALYST WRONG MARKER", serialized)


    def test_codex_fails_closed_on_embedded_role_prompt_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            config_dir = Path(temp_name)
            settings_path = config_dir / "ai_model_settings.json"
            settings_path.write_text("{}", encoding="utf-8")
            self.runner.role_prompt_file(
                config_dir,
                "incident-responder",
            ).write_text("CANONICAL INCIDENT ROLE", encoding="utf-8")
            args = type(
                "Args",
                (),
                {"ai_settings_file": settings_path},
            )()
            with self.assertRaisesRegex(
                SystemExit,
                "role instructions do not match",
            ):
                self.runner.prepare_codex_cli_transport(
                    {
                        "agent_role": "incident-responder",
                        "instructions": {"role": "STALE OR FOREIGN ROLE"},
                    },
                    args,
                )


    def test_codex_reviewer_requires_its_canonical_role_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            config_dir = Path(temp_name)
            settings_path = config_dir / "ai_model_settings.json"
            settings_path.write_text("{}", encoding="utf-8")
            args = type(
                "Args",
                (),
                {"ai_settings_file": settings_path},
            )()

            with self.assertRaisesRegex(
                SystemExit,
                "canonical incident-responder system prompt is unavailable",
            ):
                self.runner.prepare_codex_cli_transport(
                    {
                        "agent_role": "incident-responder",
                        "response_schema": {"type": "object"},
                    },
                    args,
                    independent_review=True,
                )


    def test_codex_reviewer_oversize_uses_same_pre_spawn_gate(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        with (
            mock.patch.object(
                self.runner,
                "resolve_codex_cli",
                return_value="/usr/local/bin/codex",
            ),
            mock.patch.object(self.runner, "run_bounded_command") as run,
            self.assertRaisesRegex(
                SystemExit,
                "Codex CLI runtime prompt package exceeded",
            ),
        ):
            self.runner.cloud_cli_chat(
                {
                    "response_schema": {"type": "object"},
                    "review_contract": {
                        "case_id": "case-oversized-review",
                        "evidence_hash": "a" * 64,
                    },
                    "oversized_review_evidence": "x"
                    * self.runner.CODEX_CLI_MAX_STDIN_BYTES,
                },
                args,
                self.runner.default_ai_settings(),
                independent_review=True,
            )

        run.assert_not_called()


