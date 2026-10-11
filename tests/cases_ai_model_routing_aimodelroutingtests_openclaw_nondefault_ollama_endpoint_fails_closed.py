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

class AiModelRoutingTestsOpenclawNondefaultOllamaEndpointFailsClosedCases:
    def test_openclaw_nondefault_ollama_endpoint_fails_closed(self) -> None:
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
            "openclaw_reasoning_effort": "high",
            "ollama_url": "http://10.77.7.99:11434",
        }
        with (
            mock.patch.object(self.runner, "resolve_cli_harness") as resolve,
            self.assertRaisesRegex(
                SystemExit,
                "only the loopback Ollama endpoint",
            ),
        ):
            self.runner._openclaw_infer_unlocked(
                {},
                args,
                settings,
                model="ollama/gemma4:26b-mlx",
                reasoning_effort="high",
            )
        resolve.assert_not_called()


    def test_local_openclaw_serializes_and_unloads_ollama_model(self) -> None:
        args = type("Args", (), {"timeout": 45})()
        settings = {
            **self.runner.default_ai_settings(),
            "openclaw_enabled": True,
            "openclaw_model": "ollama/gemma4:26b-mlx",
            "openclaw_reasoning_effort": "medium",
        }
        completed = {"summary": "local OpenClaw"}
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
                    "_openclaw_infer_unlocked",
                    return_value=completed,
                ) as infer,
                mock.patch.object(
                    self.runner,
                    "_unload_ollama_model",
                ) as unload,
            ):
                response = self.runner.openclaw_infer_chat(
                    {},
                    args,
                    settings,
                    model="ollama/gemma4:26b-mlx",
                    reasoning_effort="medium",
                )

            self.assertTrue(lock_path.is_file())
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)

        self.assertIs(response, completed)
        infer.assert_called_once()
        unload.assert_called_once_with(
            settings,
            "gemma4:26b-mlx",
            timeout=45.0,
        )


    def test_openclaw_ollama_route_still_uses_hosted_evidence_boundary(self) -> None:
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
            "openclaw_reasoning_effort": "medium",
        }
        captured: dict[str, object] = {}

        def fake_run(command, **_kwargs):
            captured["prompt"] = json.loads(
                command[command.index("--prompt") + 1]
            )
            return type(
                "Completed",
                (),
                {
                    "returncode": 0,
                    "stdout": json.dumps(
                        {
                            "ok": True,
                            "provider": "ollama",
                            "model": "gemma4:26b-mlx",
                            "outputs": [
                                {"text": '{"summary":"local harness result"}'},
                            ],
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
                side_effect=fake_run,
            ),
        ):
            self.runner._openclaw_infer_unlocked(
                {
                    "response_schema": {"type": "object"},
                    "raw_payload": "must-not-cross-harness-boundary",
                },
                args,
                settings,
                model="ollama/gemma4:26b-mlx",
                reasoning_effort="medium",
            )

        self.assertTrue(
            self.runner.model_route_is_hosted(
                "openclaw:ollama/gemma4:26b-mlx:medium",
                settings,
            )
        )
        self.assertTrue(
            self.runner.openclaw_model_uses_ollama_runtime(
                "ollama/gemma4:26b-mlx"
            )
        )
        prompt_package = captured["prompt"]["prompt_package"]
        self.assertNotIn("raw_payload", prompt_package)
        self.assertNotIn(
            "must-not-cross-harness-boundary",
            json.dumps(captured["prompt"]),
        )


    def test_harness_identity_collides_with_same_underlying_reviewer_model(self) -> None:
        settings = {
            **self.runner.default_ai_settings(),
            "codex_cli_model": "gpt-5.6-sol",
        }

        codex = self.runner.model_route_identity(
            "codex-cli:gpt-5.6-sol:medium",
            settings,
        )

        self.assertEqual(
            codex,
            self.runner.model_route_identity(
                "hermes-agent:gpt-5.6-sol:medium",
                settings,
            ),
        )
        self.assertEqual(
            codex,
            self.runner.model_route_identity(
                "openclaw:openai-codex/gpt-5.6-sol:high",
                settings,
            ),
        )
        self.assertNotEqual(
            codex,
            self.runner.model_route_identity(
                "openclaw:openai/gpt-5.6-sol:high",
                settings,
            ),
        )


    def test_running_log_separates_assignment_from_observed_execution(self) -> None:
        settings = self.runner.default_ai_settings()
        settings.update({
            "enabled_ollama_models": ["previous-local:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            ],
            "gpt_cli_enabled": True,
        })
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:high"

        record = self.runner.build_llm_log_record(
            run_id="synthetic-running",
            status="running",
            started_at="2026-07-24  10:00:00-06:00",
            finished_at=None,
            runtime_seconds=None,
            prompt_path=Path("/tmp/synthetic-prompt.json"),
            prompt_package={
                "agent_role": "soc-analyst",
                "alert": {"alert_id": "synthetic-alert"},
            },
            settings=settings,
            response=None,
            json_path=None,
            md_path=None,
            resource_monitor=self.runner.SystemResourceMonitor(),
        )

        self.assertEqual(record["mode"], "")
        self.assertEqual(record["model"], "")
        self.assertEqual(record["model_path"], "")
        self.assertEqual(record["agent_role"], "soc-analyst")
        self.assertEqual(record["model_route"], "")
        self.assertFalse(record["model_started"])
        self.assertEqual(record["assigned_model"], "gpt-5.6-sol")
        self.assertEqual(record["assigned_model_path"], "frontier-codex-cli")
        self.assertEqual(
            record["assigned_model_route"],
            "codex-cli:gpt-5.6-sol:high",
        )
        self.assertNotEqual(record["assigned_model"], "previous-local:latest")
        self.assertEqual(record["active_phase"], "preparing")
        self.assertEqual(record["active_model"], "")
        self.assertEqual(record["active_model_path"], "")
        self.assertEqual(record["active_model_route"], "")
        self.assertEqual(record["active_provider"], "")

        started = self.runner.current_analysis_phase_record(
            record,
            settings,
            phase="primary_analysis",
            model_route=record["assigned_model_route"],
        )
        self.assertEqual(started["active_model"], "gpt-5.6-sol")
        self.assertEqual(started["active_model_path"], "frontier-codex-cli")
        self.assertEqual(
            started["active_model_route"],
            "codex-cli:gpt-5.6-sol:high",
        )
        self.assertEqual(started["active_provider"], "codex-cli")


    def test_failed_log_without_runtime_observation_does_not_claim_assigned_model(self) -> None:
        settings = self.runner.default_ai_settings()
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:high"

        record = self.runner.build_llm_log_record(
            run_id="synthetic-failure",
            status="failure",
            started_at="2026-07-24  10:00:00-06:00",
            finished_at="2026-07-24  10:00:01-06:00",
            runtime_seconds=1,
            prompt_path=Path("/tmp/synthetic-prompt.json"),
            prompt_package={"agent_role": "soc-analyst"},
            settings=settings,
            response=None,
            json_path=None,
            md_path=None,
            resource_monitor=self.runner.SystemResourceMonitor(),
            error="prompt validation failed",
        )

        self.assertFalse(record["model_started"])
        self.assertEqual(record["model"], "")
        self.assertEqual(record["model_path"], "")
        self.assertEqual(record["model_route"], "")
        self.assertEqual(record["assigned_model"], "gpt-5.6-sol")
        self.assertEqual(
            record["assigned_model_route"],
            "codex-cli:gpt-5.6-sol:high",
        )


    def test_current_phase_switches_to_reviewer_without_relabeling_primary(self) -> None:
        settings = self.runner.default_ai_settings()
        settings.update({
            "enabled_ollama_models": ["reviewer:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            ],
            "gpt_cli_enabled": True,
        })
        primary_route = "codex-cli:gpt-5.6-sol:high"
        primary = {
            "log_id": "synthetic-running",
            "status": "running",
            "model": "gpt-5.6-sol",
            "model_path": "frontier-codex-cli",
            "model_route": primary_route,
            "alert": {"primary_alert_id": "synthetic-alert"},
            "started_at": "2026-07-24  10:00:00-06:00",
        }

        active_path = Path("/tmp/synthetic-active-analysis.json")
        with mock.patch.object(self.runner, "atomic_write_json") as write:
            reviewing = self.runner.publish_current_analysis_phase(
                primary,
                settings,
                phase="second_opinion",
                model_route="ollama:reviewer:latest",
                trigger_reason="The primary model reported low confidence.",
                active_record_path=active_path,
            )

        write.assert_called_once_with(active_path, reviewing)
        self.assertEqual(reviewing["model"], "gpt-5.6-sol")
        self.assertEqual(reviewing["model_route"], primary_route)
        self.assertEqual(reviewing["active_phase"], "second_opinion")
        self.assertEqual(reviewing["active_model"], "reviewer:latest")
        self.assertEqual(reviewing["active_model_path"], "ollama")
        self.assertEqual(reviewing["active_model_route"], "ollama:reviewer:latest")
        self.assertEqual(reviewing["active_provider"], "ollama")

        post_processing = self.runner.current_analysis_phase_record(
            reviewing,
            settings,
            phase="post_processing",
            trigger_reason=reviewing["second_opinion_trigger"],
        )
        self.assertEqual(post_processing["model"], "gpt-5.6-sol")
        self.assertEqual(post_processing["model_route"], primary_route)
        self.assertEqual(post_processing["active_phase"], "post_processing")
        self.assertEqual(post_processing["active_model"], "")
        self.assertEqual(post_processing["active_model_path"], "")
        self.assertEqual(post_processing["active_model_route"], "")
        self.assertEqual(post_processing["active_provider"], "")


    def test_concurrent_atomic_status_writes_never_share_a_temp_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            target = Path(temp_name) / "current-analysis.json"
            payloads = [
                {"writer": writer, "body": "x" * 4096}
                for writer in range(32)
            ]
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(
                    executor.map(
                        lambda payload: self.runner.atomic_write_json(target, payload),
                        payloads,
                    )
                )

            written = json.loads(target.read_text(encoding="utf-8"))
            self.assertIn(written, payloads)
            self.assertEqual(list(target.parent.glob("*.tmp")), [])


    def test_index_flush_quarantines_permanent_rejection_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            queue_dir = root / "pending"
            quarantine_dir = root / "quarantine"
            poison = {
                "analysis_id": "a-poison-analysis",
                "response": {"summary": "sensitive payload content"},
            }
            valid = {
                "analysis_id": "b-valid-analysis",
                "response": {"summary": "later valid result"},
            }
            self.runner.queue_analysis_index(poison, queue_dir)
            self.runner.queue_analysis_index(valid, queue_dir)
            submitted = []

            def submit(payload, _url):
                if payload["analysis_id"] == "a-poison-analysis":
                    raise self.runner.AnalysisIndexSubmissionError(
                        "analysis index HTTP 409",
                        retryable=False,
                        status_code=409,
                        response_sha256="a" * 64,
                    )
                submitted.append(payload["analysis_id"])

            with mock.patch.object(
                self.runner,
                "post_analysis_index",
                side_effect=submit,
            ):
                published, failed, quarantined = (
                    self.runner.flush_analysis_index_queue(
                        "http://127.0.0.1:8787",
                        queue_dir=queue_dir,
                        quarantine_dir=quarantine_dir,
                    )
                )

            self.assertEqual((published, failed, quarantined), (1, 0, 1))
            self.assertEqual(submitted, ["b-valid-analysis"])
            self.assertEqual(list(queue_dir.glob("*.json")), [])
            rejected = list(quarantine_dir.glob("*.rejected.json"))
            metadata = list(quarantine_dir.glob("*.metadata.json"))
            self.assertEqual(len(rejected), 1)
            self.assertEqual(len(metadata), 1)
            self.assertEqual(quarantine_dir.stat().st_mode & 0o777, 0o700)
            self.assertEqual(rejected[0].stat().st_mode & 0o777, 0o600)
            audit_text = metadata[0].read_text(encoding="utf-8")
            audit = json.loads(audit_text)
            self.assertEqual(audit["http_status"], 409)
            self.assertEqual(
                audit["classification"],
                "deterministic_submission_rejection",
            )
            self.assertRegex(audit["payload_sha256"], r"^[a-f0-9]{64}$")
            self.assertNotIn("sensitive payload content", audit_text)
            self.assertNotIn("a-poison-analysis", audit_text)


    def test_index_flush_preserves_order_on_transient_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            queue_dir = root / "pending"
            quarantine_dir = root / "quarantine"
            for analysis_id in ("a-transient-analysis", "b-later-analysis"):
                self.runner.queue_analysis_index(
                    {"analysis_id": analysis_id, "response": {}},
                    queue_dir,
                )

            transient = self.runner.AnalysisIndexSubmissionError(
                "analysis index HTTP 503",
                retryable=True,
                status_code=503,
            )
            with mock.patch.object(
                self.runner,
                "post_analysis_index",
                side_effect=transient,
            ) as submit:
                result = self.runner.flush_analysis_index_queue(
                    "http://127.0.0.1:8787",
                    queue_dir=queue_dir,
                    quarantine_dir=quarantine_dir,
                )

            self.assertEqual(result, (0, 1, 0))
            self.assertEqual(submit.call_count, 1)
            self.assertEqual(
                [path.name for path in sorted(queue_dir.glob("*.json"))],
                ["a-transient-analysis.json", "b-later-analysis.json"],
            )
            self.assertFalse(quarantine_dir.exists())


    def test_index_http_errors_are_classified_without_response_content(self) -> None:
        secret_body = b'{"error":"sensitive server detail"}'
        for status_code, retryable in ((409, False), (429, True), (503, True)):
            with self.subTest(status_code=status_code):
                http_error = self.runner.urllib.error.HTTPError(
                    "http://127.0.0.1:8787/analysis/result",
                    status_code,
                    "rejected",
                    {},
                    io.BytesIO(secret_body),
                )
                with (
                    mock.patch.object(
                        self.runner.urllib.request,
                        "urlopen",
                        side_effect=http_error,
                    ),
                    self.assertRaises(
                        self.runner.AnalysisIndexSubmissionError
                    ) as raised,
                ):
                    self.runner.post_analysis_index(
                        {"analysis_id": "synthetic", "response": {}},
                        "http://127.0.0.1:8787",
                    )

                self.assertEqual(raised.exception.status_code, status_code)
                self.assertIs(raised.exception.retryable, retryable)
                self.assertEqual(
                    raised.exception.response_sha256,
                    self.runner.hashlib.sha256(secret_body).hexdigest(),
                )
                self.assertNotIn(
                    "sensitive server detail",
                    str(raised.exception),
                )
                self.assertTrue(http_error.fp.closed)


    def test_active_analysis_path_is_scoped_to_one_sanitized_run_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            active_dir = Path(temp_name) / "active"
            path = self.runner.active_analysis_record_path(
                "../../unsafe run id",
                active_dir,
            )

        self.assertEqual(path.parent, active_dir)
        self.assertEqual(path.suffix, ".json")
        self.assertNotIn("/", path.name)
        self.assertNotIn("..", path.name)


    def test_completed_log_keeps_primary_model_and_omits_transient_active_fields(self) -> None:
        settings = self.runner.default_ai_settings()
        settings.update({
            "enabled_ollama_models": ["reviewer:latest"],
            "codex_cli_models": [
                {"model": "gpt-5.6-sol", "reasoning_effort": "high", "enabled": True},
            ],
            "gpt_cli_enabled": True,
        })
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:high"
        response = {
            "_analysis_model": "gpt-5.6-sol",
            "_analysis_model_path": "frontier-codex-cli",
            "_second_opinion": {
                "model_route": "ollama:reviewer:latest",
                "response": {
                    "_analysis_model": "reviewer:latest",
                    "_analysis_model_path": "ollama",
                },
            },
        }

        record = self.runner.build_llm_log_record(
            run_id="synthetic-complete",
            status="success",
            started_at="2026-07-24  10:00:00-06:00",
            finished_at="2026-07-24  10:01:00-06:00",
            runtime_seconds=60,
            prompt_path=Path("/tmp/synthetic-prompt.json"),
            prompt_package={
                "agent_role": "soc-analyst",
                "alert": {"alert_id": "synthetic-alert"},
            },
            settings=settings,
            response=response,
            json_path=Path("/tmp/synthetic-result.json"),
            md_path=Path("/tmp/synthetic-result.md"),
            resource_monitor=self.runner.SystemResourceMonitor(),
        )

        self.assertEqual(record["model"], "gpt-5.6-sol")
        self.assertEqual(record["model_path"], "frontier-codex-cli")
        self.assertEqual(record["model_route"], "codex-cli:gpt-5.6-sol:high")
        self.assertNotIn("active_phase", record)
        self.assertNotIn("active_model", record)
        self.assertNotIn("active_model_route", record)


    def test_codex_settings_reject_arbitrary_executable_and_effort(self) -> None:
        for payload in (
            {"codex_cli_path": "codex --dangerous"},
            {"codex_cli_path": "/tmp/not-codex"},
            {"codex_cli_reasoning_effort": "unbounded"},
        ):
            settings = self.runner.default_ai_settings()
            with self.assertRaisesRegex(self.runner.RuntimeArtifactError, "Codex CLI"):
                self.runner.normalize_codex_cli_settings(settings, payload)


    def test_codex_resolution_falls_back_to_user_local_bin_for_launchagents(self) -> None:
        expected = Path.home() / ".local" / "bin" / "codex"

        def is_file(path: Path) -> bool:
            return path == expected

        with (
            mock.patch.object(self.runner.shutil, "which", return_value=None),
            mock.patch.object(self.runner.Path, "is_file", autospec=True, side_effect=is_file),
            mock.patch.object(self.runner.os, "access", return_value=True),
        ):
            resolved = self.runner.resolve_codex_cli({"codex_cli_path": "codex"})

        self.assertEqual(resolved, str(expected))


    def test_disabled_agent_assignment_falls_back_to_first_enabled_route(self) -> None:
        settings = self.runner.default_ai_settings()

        self.runner.apply_model_roster(settings, {
            "enabled_ollama_models": ["approved:latest"],
            "gpt_cli_enabled": False,
            "agent_models": {"soc-analyst": "ollama:disabled:latest"},
        })

        self.assertEqual(
            settings["agent_models"],
            {role: "ollama:approved:latest" for role in self.runner.CYBER_SECURITY_AGENT_ROLES},
        )


    def test_runner_preserves_codex_model_when_reasoning_effort_changes(self) -> None:
        settings = self.runner.default_ai_settings()
        self.runner.normalize_codex_cli_settings(settings, {
            "codex_cli_models": [
                {
                    "model": "gpt-5.6-terra",
                    "reasoning_effort": "xhigh",
                    "enabled": True,
                }
            ],
        })

        self.runner.apply_model_roster(settings, {
            "enabled_ollama_models": ["primary:latest"],
            "agent_models": {
                "soc-analyst": "codex-cli:gpt-5.6-terra:medium",
            },
        })

        self.assertEqual(
            settings["agent_models"]["soc-analyst"],
            "codex-cli:gpt-5.6-terra:xhigh",
        )


    def test_second_opinion_assignments_must_be_enabled_and_differ_from_primary(self) -> None:
        settings = self.runner.default_ai_settings()

        self.runner.apply_model_roster(settings, {
            "enabled_ollama_models": ["primary:latest", "reviewer:latest"],
            "gpt_cli_enabled": False,
            "agent_models": {"soc-analyst": "ollama:primary:latest"},
            "agent_second_opinion_models": {
                "soc-analyst": "ollama:reviewer:latest",
                "incident-responder": "ollama:primary:latest",
                "siem-engineer": "ollama:disabled:latest",
            },
        })

        self.assertEqual(settings["agent_second_opinion_models"]["soc-analyst"], "ollama:reviewer:latest")
        self.assertEqual(settings["agent_second_opinion_models"]["incident-responder"], "")
        self.assertEqual(settings["agent_second_opinion_models"]["siem-engineer"], "")


    def test_adjudicator_assignments_must_be_enabled_and_independent(self) -> None:
        settings = self.runner.default_ai_settings()

        self.runner.apply_model_roster(settings, {
            "enabled_ollama_models": [
                "primary:latest",
                "reviewer:latest",
                "adjudicator:latest",
            ],
            "gpt_cli_enabled": False,
            "agent_models": {"soc-analyst": "ollama:primary:latest"},
            "agent_second_opinion_models": {
                "soc-analyst": "ollama:reviewer:latest",
                "siem-engineer": "ollama:reviewer:latest",
            },
            "agent_adjudicator_models": {
                "soc-analyst": "ollama:adjudicator:latest",
                "incident-responder": "ollama:primary:latest",
                "siem-engineer": "ollama:reviewer:latest",
                "threat-hunter": "ollama:disabled:latest",
            },
        })

        self.assertEqual(
            settings["agent_adjudicator_models"]["soc-analyst"],
            "ollama:adjudicator:latest",
        )
        self.assertEqual(settings["agent_adjudicator_models"]["incident-responder"], "")
        self.assertEqual(settings["agent_adjudicator_models"]["siem-engineer"], "")
        self.assertEqual(settings["agent_adjudicator_models"]["threat-hunter"], "")


