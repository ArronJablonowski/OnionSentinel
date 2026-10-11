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

class AiModelRoutingTestsCodexFollowUpVariantsUseSamePreSpawnGateCases:
    def test_codex_follow_up_variants_use_same_pre_spawn_gate(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        for marker in (
            "investigation_follow_up",
            "investigation_query_planning_retry",
            "live_osquery_follow_up",
        ):
            with self.subTest(marker=marker):
                prompt_package = {
                    marker: {"active": True},
                    "response_schema": {"type": "object"},
                    "oversized_follow_up_evidence": "x"
                    * self.runner.CODEX_CLI_MAX_STDIN_BYTES,
                }
                with (
                    mock.patch.object(
                        self.runner,
                        "resolve_codex_cli",
                        return_value="/usr/local/bin/codex",
                    ),
                    mock.patch.object(
                        self.runner,
                        "run_bounded_command",
                    ) as run,
                    self.assertRaisesRegex(
                        SystemExit,
                        "Codex CLI runtime prompt package exceeded",
                    ),
                ):
                    self.runner.cloud_cli_chat(
                        prompt_package,
                        args,
                        self.runner.default_ai_settings(),
                    )
                run.assert_not_called()


    def test_codex_reviewer_uses_strict_output_schema_and_explicit_effort(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = self.runner.default_ai_settings()
        seen_command: list[str] = []
        prompt_package = {
            "response_schema": {
                "review_case_id": "string",
                "review_evidence_hash": "lowercase SHA-256",
                "observables_used": [{"kind": "ip|domain|host|user|community_id", "value": "string"}],
            },
            "review_contract": {
                "case_id": "case-1",
                "evidence_hash": "a" * 64,
            },
        }

        def fake_run(command, **kwargs):
            seen_command.extend(command)
            schema_path = Path(command[command.index("--output-schema") + 1])
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            self.assertEqual(schema["additionalProperties"], False)
            self.assertEqual(
                schema["properties"]["review_evidence_hash"]["pattern"],
                "^[a-f0-9]{64}$",
            )
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text(
                json.dumps(
                    {
                        "review_case_id": "case-1",
                        "review_evidence_hash": "a" * 64,
                        "observables_used": [],
                    }
                ),
                encoding="utf-8",
            )
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        with (
            mock.patch.object(self.runner, "resolve_codex_cli", return_value="/usr/local/bin/codex"),
            mock.patch.object(self.runner, "run_bounded_command", side_effect=fake_run),
        ):
            self.runner.cloud_cli_chat(
                prompt_package,
                args,
                settings,
                model="gpt-5.6-sol",
                reasoning_effort="xhigh",
                independent_review=True,
            )

        self.assertIn("--output-schema", seen_command)
        self.assertIn("--ephemeral", seen_command)
        self.assertIn('model_reasoning_effort="xhigh"', seen_command)


    def test_codex_failure_summary_does_not_persist_prompt_transcript(self) -> None:
        stderr = "\n".join(
            [
                "OpenAI Codex v0.145.0",
                "user",
                '{"prompt_package":{"sensitive_evidence":"must-not-leak"}}',
                "ERROR: Codex ran out of room in the model's context window. Start a new thread.",
            ]
        )

        summary = self.runner.summarize_codex_cli_failure(stderr, 1)

        self.assertEqual(summary, "model context window exhausted")
        self.assertNotIn("sensitive_evidence", summary)


    def test_codex_failure_summary_uses_only_terminal_error_line(self) -> None:
        stderr = "\n".join(
            [
                "OpenAI Codex v0.145.0",
                '{"prompt_package":{"secret":"must-not-leak","note":"context window"}}',
                "ERROR: provider transport closed unexpectedly",
            ]
        )

        summary = self.runner.summarize_codex_cli_failure(stderr, 1)

        self.assertEqual(summary, "provider error: provider transport closed unexpectedly")
        self.assertNotIn("must-not-leak", summary)


    def test_codex_nonzero_exit_raises_only_sanitized_terminal_cause(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        completed = type(
            "Completed",
            (),
            {
                "returncode": 1,
                "stdout": "",
                "stderr": "\n".join(
                    [
                        "OpenAI Codex v0.145.0",
                        '{"prompt_package":{"secret":"must-not-leak"}}',
                        "ERROR: Codex ran out of room in the model's context window.",
                    ]
                ),
            },
        )()

        with (
            mock.patch.object(self.runner, "resolve_codex_cli", return_value="/usr/local/bin/codex"),
            mock.patch.object(self.runner, "run_bounded_command", return_value=completed),
            self.assertRaisesRegex(
                SystemExit,
                "^Codex CLI analysis failed: model context window exhausted$",
            ) as raised,
        ):
            self.runner.cloud_cli_chat(
                {"response_schema": {"type": "object"}},
                args,
                self.runner.default_ai_settings(),
            )

        self.assertNotIn("must-not-leak", str(raised.exception))


    def test_exact_codex_route_overrides_global_model_and_effort(self) -> None:
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
            "codex_cli_model": "legacy-model",
            "codex_cli_reasoning_effort": "low",
            "codex_cli_models": [
                {
                    "model": "gpt-5.6-sol",
                    "reasoning_effort": "xhigh",
                    "enabled": True,
                },
            ],
        }
        seen_command = []

        def fake_run(command, **kwargs):
            seen_command.extend(command)
            output_path = Path(command[command.index("--output-last-message") + 1])
            output_path.write_text('{"summary":"Exact route"}', encoding="utf-8")
            return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        with (
            mock.patch.object(self.runner, "resolve_codex_cli", return_value="/usr/local/bin/codex"),
            mock.patch.object(self.runner, "run_bounded_command", side_effect=fake_run),
        ):
            response = self.runner.analyze_model_route(
                "codex-cli:gpt-5.6-sol:xhigh",
                {"response_schema": {"type": "object"}},
                args,
                settings,
            )

        self.assertEqual(response["_analysis_model"], "gpt-5.6-sol")
        self.assertEqual(seen_command[seen_command.index("--model") + 1], "gpt-5.6-sol")
        self.assertIn('model_reasoning_effort="xhigh"', seen_command)


    def test_missing_harness_settings_default_to_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            settings_path = Path(temp_name) / "ai_model_settings.json"
            settings_path.write_text(
                json.dumps({
                    "enabled_ollama_models": ["local:latest"],
                    "openclaw_agent_id": "../legacy-agent",
                }),
                encoding="utf-8",
            )

            settings = self.runner.load_ai_settings(settings_path)

        self.assertIs(settings["hermes_agent_enabled"], False)
        self.assertIs(settings["openclaw_enabled"], False)
        self.assertNotIn("openclaw_agent_id", settings)
        self.assertNotIn(
            "hermes-agent:",
            " ".join(self.runner.enabled_agent_model_routes(settings)),
        )
        self.assertNotIn(
            "openclaw:",
            " ".join(self.runner.enabled_agent_model_routes(settings)),
        )


    def test_enabled_harnesses_add_only_their_exact_routes(self) -> None:
        settings = self.runner.default_ai_settings()
        self.runner.normalize_cli_harness_settings(
            settings,
            {
                "hermes_agent_enabled": True,
                "hermes_agent_model": "gpt-5.6-sol",
                "hermes_agent_reasoning_effort": "medium",
                "openclaw_enabled": True,
                "openclaw_model": "ollama/gemma4:26b-mlx",
                "openclaw_reasoning_effort": "high",
            },
        )

        routes = self.runner.enabled_agent_model_routes(settings)

        self.assertIn("hermes-agent:gpt-5.6-sol:medium", routes)
        self.assertIn("openclaw:ollama/gemma4:26b-mlx:high", routes)
        self.assertEqual(
            [route for route in routes if route.startswith("hermes-agent:")],
            ["hermes-agent:gpt-5.6-sol:medium"],
        )
        self.assertEqual(
            [route for route in routes if route.startswith("openclaw:")],
            ["openclaw:ollama/gemma4:26b-mlx:high"],
        )


    def test_hermes_settings_reject_unenforced_reasoning_efforts(self) -> None:
        for effort in ("low", "high", "xhigh"):
            with (
                self.subTest(effort=effort),
                self.assertRaisesRegex(
                    self.runner.RuntimeArtifactError,
                    "supports medium reasoning effort only",
                ),
            ):
                self.runner.normalize_cli_harness_settings(
                    self.runner.default_ai_settings(),
                    {
                        "hermes_agent_enabled": True,
                        "hermes_agent_model": "gpt-5.6-sol",
                        "hermes_agent_reasoning_effort": effort,
                    },
                )


    def test_openclaw_settings_reject_non_ollama_provider_routes(self) -> None:
        for model in (
            "openai/gpt-5.6-sol",
            "openai-codex/gpt-5.6-sol",
            "local/gpt-oss:20b",
            "lmstudio/gpt-oss:20b",
        ):
            with (
                self.subTest(model=model),
                self.assertRaisesRegex(
                    self.runner.RuntimeArtifactError,
                    "explicit ollama/<model> routes only",
                ),
            ):
                self.runner.normalize_cli_harness_settings(
                    self.runner.default_ai_settings(),
                    {
                        "openclaw_enabled": True,
                        "openclaw_model": model,
                    },
                )


    def test_onion_sentinel_harness_requires_policy_and_eligible_routes(
        self,
    ) -> None:
        cases = (
            {
                "label": "policy disabled",
                "enabled": False,
                "primary": "codex-cli:gpt-5.6-sol:high",
                "reviewer": "ollama:gemma4:31b",
                "expected": False,
                "reason": "investigation harness policy is disabled",
            },
            {
                "label": "codex primary and ollama reviewer",
                "enabled": True,
                "primary": "codex-cli:gpt-5.6-sol:high",
                "reviewer": "ollama:gemma4:31b",
                "expected": True,
                "reason": "policy enabled and selected routes are eligible",
            },
            {
                "label": "ollama primary and codex reviewer",
                "enabled": True,
                "primary": "ollama:devstral-small-2:24b",
                "reviewer": "codex-cli:gpt-5.6-sol:xhigh",
                "expected": True,
                "reason": "policy enabled and selected routes are eligible",
            },
            {
                "label": "Hermes primary",
                "enabled": True,
                "primary": "hermes-agent:gpt-5.6-sol:medium",
                "reviewer": "ollama:gemma4:31b",
                "expected": False,
                "reason": "assigned route uses the external hermes-agent harness",
            },
            {
                "label": "OpenClaw primary",
                "enabled": True,
                "primary": "openclaw:ollama/gemma4:26b-mlx:high",
                "reviewer": "",
                "expected": False,
                "reason": "assigned route uses the external openclaw harness",
            },
            {
                "label": "Hermes reviewer",
                "enabled": True,
                "primary": "ollama:devstral-small-2:24b",
                "reviewer": "hermes-agent:gpt-5.6-sol:medium",
                "expected": False,
                "reason": "second-opinion route uses the external hermes-agent harness",
            },
            {
                "label": "OpenClaw reviewer",
                "enabled": True,
                "primary": "codex-cli:gpt-5.5:medium",
                "reviewer": "openclaw:ollama/gemma4:26b-mlx:xhigh",
                "expected": False,
                "reason": "second-opinion route uses the external openclaw harness",
            },
            {
                "label": "provider-like text inside an ordinary route",
                "enabled": True,
                "primary": "ollama:openclaw-model:latest",
                "reviewer": "codex-cli:hermes-agent-compatible:medium",
                "expected": True,
                "reason": "policy enabled and selected routes are eligible",
            },
        )
        for case in cases:
            with self.subTest(case["label"]):
                allowed, reason = (
                    self.runner.should_start_onion_sentinel_harness(
                        policy_enabled=case["enabled"],
                        assigned_route=case["primary"],
                        reviewer_route=case["reviewer"],
                    )
                )
                self.assertIs(allowed, case["expected"])
                self.assertEqual(reason, case["reason"])


    def test_external_agent_harness_detection_is_exact_and_fail_closed(
        self,
    ) -> None:
        self.assertEqual(
            self.runner.external_agent_harness_provider("hermes-agent"),
            "hermes-agent",
        )
        self.assertEqual(
            self.runner.external_agent_harness_provider(
                "HERMES-AGENT:gpt-5.6-sol:medium"
            ),
            "hermes-agent",
        )
        self.assertEqual(
            self.runner.external_agent_harness_provider("openclaw:malformed"),
            "openclaw",
        )
        self.assertEqual(
            self.runner.external_agent_harness_provider(
                "ollama:openclaw-model:latest"
            ),
            "",
        )
        self.assertEqual(
            self.runner.external_agent_harness_provider(
                "codex-cli:hermes-agent-compatible:medium"
            ),
            "",
        )


    def test_controlled_evaluation_can_freeze_memory_without_changing_baseline(
        self,
    ) -> None:
        self.assertEqual(
            self.runner.apply_evaluation_memory_freeze(
                True,
                "eligible after authoritative analysis commit",
                freeze_enabled=False,
            ),
            (
                True,
                "eligible after authoritative analysis commit",
            ),
        )
        self.assertEqual(
            self.runner.apply_evaluation_memory_freeze(
                True,
                "eligible after authoritative analysis commit",
                freeze_enabled=True,
            ),
            (
                False,
                "controlled harness evaluation froze memory writeback",
            ),
        )
        self.assertEqual(
            self.runner.apply_evaluation_memory_freeze(
                False,
                "reviewer disagreement",
                freeze_enabled=True,
            ),
            (
                False,
                "controlled harness evaluation froze memory writeback",
            ),
        )


    def test_each_harness_dispatches_every_agent_role_without_provider_fallback(
        self,
    ) -> None:
        args = type("Args", (), {})()
        harnesses = (
            {
                "name": "hermes-agent",
                "route": "hermes-agent:gpt-5.6-sol:medium",
                "model": "gpt-5.6-sol",
                "effort": "medium",
                "provider": "openai-codex",
                "adapter": "hermes_agent_chat",
            },
            {
                "name": "openclaw",
                "route": "openclaw:ollama/gemma4:26b-mlx:high",
                "model": "ollama/gemma4:26b-mlx",
                "effort": "high",
                "provider": "ollama",
                "adapter": "openclaw_infer_chat",
            },
        )
        for harness in harnesses:
            for role in self.runner.CYBER_SECURITY_AGENT_ROLES:
                with self.subTest(harness=harness["name"], role=role):
                    settings = self.runner.default_ai_settings()
                    settings.update({
                        "hermes_agent_enabled": harness["name"] == "hermes-agent",
                        "hermes_agent_model": "gpt-5.6-sol",
                        "hermes_agent_reasoning_effort": "medium",
                        "openclaw_enabled": harness["name"] == "openclaw",
                        "openclaw_model": "ollama/gemma4:26b-mlx",
                        "openclaw_reasoning_effort": "high",
                    })
                    settings["agent_models"][role] = harness["route"]
                    prompt = {
                        "agent_role": role,
                        "system_prompt_file": f"/synthetic/{role}-system.md",
                        "second_opinion_system_prompt_file": (
                            f"/synthetic/{role}-review.md"
                        ),
                        "agent_memory_file": f"/synthetic/{role}-memory.md",
                    }
                    observed = {
                        "_analysis_model": harness["model"],
                        "_analysis_model_path": harness["name"],
                        "_analysis_provider": harness["provider"],
                        "_analysis_harness": harness["name"],
                    }
                    with (
                        mock.patch.object(
                            self.runner,
                            "hermes_agent_chat",
                            return_value=observed,
                        ) as hermes_adapter,
                        mock.patch.object(
                            self.runner,
                            "openclaw_infer_chat",
                            return_value=observed,
                        ) as openclaw_adapter,
                        mock.patch.object(
                            self.runner,
                            "cloud_cli_chat",
                        ) as codex_adapter,
                        mock.patch.object(
                            self.runner,
                            "_ollama_chat_for_model",
                        ) as ollama_adapter,
                        mock.patch.object(
                            self.runner,
                            "apply_investigation_query_loop",
                            side_effect=lambda _prompt, response, *_args, **_kwargs: response,
                        ) as query_loop,
                    ):
                        result = self.runner.analyze_with_config(
                            prompt,
                            args,
                            agent_role=role,
                            settings=settings,
                        )

                    selected = (
                        hermes_adapter
                        if harness["adapter"] == "hermes_agent_chat"
                        else openclaw_adapter
                    )
                    unselected = (
                        openclaw_adapter
                        if selected is hermes_adapter
                        else hermes_adapter
                    )
                    selected.assert_called_once()
                    self.assertIs(selected.call_args.args[0], prompt)
                    self.assertEqual(
                        selected.call_args.kwargs["model"],
                        harness["model"],
                    )
                    self.assertEqual(
                        selected.call_args.kwargs["reasoning_effort"],
                        harness["effort"],
                    )
                    unselected.assert_not_called()
                    codex_adapter.assert_not_called()
                    ollama_adapter.assert_not_called()
                    query_loop.assert_called_once()
                    self.assertEqual(query_loop.call_args.args[4], role)
                    self.assertIs(result, observed)
                    index = self.runner.analysis_index_payload(
                        f"synthetic-{harness['name']}-{role}",
                        prompt,
                        result,
                        "",
                        "2026-07-25  10:00:00-06:00",
                        "2026-07-25  10:00:01-06:00",
                        Path("/tmp/synthetic-result.json"),
                    )
                    self.assertEqual(index["agent_role"], role)
                    self.assertEqual(index["provider"], harness["provider"])
                    self.assertEqual(index["harness"], harness["name"])


    def test_disabled_harness_routes_cannot_dispatch(self) -> None:
        args = type(
            "Args",
            (),
            {
                "system_prompt_file": Path("/tmp/nonexistent-system-prompt.md"),
                "timeout": 60,
                "max_response_bytes": 1024 * 1024,
            },
        )()
        settings = self.runner.default_ai_settings()

        for route, expected in (
            (
                "hermes-agent:gpt-5.6-sol:medium",
                "Configured analysis model route is not enabled",
            ),
            (
                "openclaw:ollama/gemma4:26b-mlx:xhigh",
                "Configured analysis model route is not enabled",
            ),
        ):
            with (
                self.subTest(route=route),
                mock.patch.object(self.runner, "resolve_cli_harness") as resolve,
                self.assertRaisesRegex(SystemExit, expected),
            ):
                self.runner.analyze_model_route(
                    route,
                    {"response_schema": {"type": "object"}},
                    args,
                    settings,
                )
            resolve.assert_not_called()


    def test_hermes_nonmedium_route_fails_before_execution(self) -> None:
        settings = {
            **self.runner.default_ai_settings(),
            "hermes_agent_enabled": True,
            "hermes_agent_model": "gpt-5.6-sol",
            "hermes_agent_reasoning_effort": "medium",
        }
        with (
            mock.patch.object(self.runner, "resolve_cli_harness") as resolve,
            self.assertRaisesRegex(
                SystemExit,
                "Configured analysis model route is not enabled",
            ),
        ):
            self.runner.analyze_model_route(
                "hermes-agent:gpt-5.6-sol:xhigh",
                {"response_schema": {"type": "object"}},
                type("Args", (), {})(),
                settings,
            )
        resolve.assert_not_called()
