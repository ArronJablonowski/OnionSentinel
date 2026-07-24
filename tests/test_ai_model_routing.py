#!/usr/bin/env python3
"""Contract tests for provider rosters and exact per-agent model routing."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"


def load_runner():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("run_local_ai_analysis_model_routing", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class AiModelRoutingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

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
                    "enabled": model == "gpt-5.5",
                    "model": model,
                    "reasoning_effort": "medium",
                }
                for model in self.runner.CODEX_CLI_MODEL_CATALOG
            ],
        )
        self.assertEqual(
            settings["agent_second_opinion_models"],
            {role: reviewer for role in self.runner.CYBER_SECURITY_AGENT_ROLES},
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

    def test_ollama_uses_enabled_models_as_ordered_failover(self) -> None:
        args = type("Args", (), {})()
        settings = {"enabled_ollama_models": ["primary:latest", "fallback:latest"]}
        completed = {"summary": "completed", "_analysis_model": "fallback:latest"}

        with mock.patch.object(
            self.runner,
            "_ollama_chat_for_model",
            side_effect=[SystemExit("primary unavailable"), completed],
        ) as analyze:
            response = self.runner.ollama_chat({}, args, settings)

        self.assertEqual(response, completed)
        self.assertEqual([call.args[3] for call in analyze.call_args_list], ["primary:latest", "fallback:latest"])

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
        local_response = {"summary": "assigned model"}

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
            "agent_models": {
                role: ("codex-cli" if role == "soc-analyst" else "ollama:primary:latest")
                for role in self.runner.CYBER_SECURITY_AGENT_ROLES
            },
        }
        cloud_response = {"summary": "assigned GPT CLI"}

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
        self.assertNotIn("sh", seen_command)
        self.assertNotIn("this must never execute", " ".join(seen_command))

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

    def test_running_log_metadata_uses_exact_assigned_codex_route(self) -> None:
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

        self.assertEqual(record["mode"], "codex-cli")
        self.assertEqual(record["model"], "gpt-5.6-sol")
        self.assertEqual(record["model_path"], "frontier-codex-cli")
        self.assertEqual(record["agent_role"], "soc-analyst")
        self.assertEqual(record["model_route"], "codex-cli:gpt-5.6-sol:high")
        self.assertNotEqual(record["model"], "previous-local:latest")
        self.assertEqual(record["active_phase"], "primary_analysis")
        self.assertEqual(record["active_model"], "gpt-5.6-sol")
        self.assertEqual(record["active_model_path"], "frontier-codex-cli")
        self.assertEqual(record["active_model_route"], "codex-cli:gpt-5.6-sol:high")
        self.assertEqual(record["active_provider"], "codex-cli")

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

    def test_ollama_second_opinion_uses_explicit_independent_review_task(self) -> None:
        args = type("Args", (), {})()
        prompt_package = {
            "alert": {"rule_name": "Synthetic TLS alert"},
            "response_schema": {"type": "object"},
        }

        with (
            mock.patch.object(
                self.runner,
                "_ollama_request",
                return_value={"summary": "Independent review"},
            ) as request,
            mock.patch.object(self.runner, "_unload_ollama_model"),
        ):
            result = self.runner._ollama_chat_for_model(
                prompt_package,
                args,
                {},
                "reviewer:latest",
                independent_review=True,
            )

        self.assertEqual(result["summary"], "Independent review")
        evidence = request.call_args.args[0]
        task = request.call_args.args[3]
        self.assertNotIn("primary_analysis", json.dumps(evidence))
        self.assertIn("Independently analyze", task)
        self.assertIn("intentionally been withheld", task)
        self.assertIn("do not request another opinion", task)

    def test_low_confidence_primary_runs_configured_second_opinion(self) -> None:
        reviewer_prompt = Path("/tmp/synthetic-soc-reviewer-prompt.md")
        args = type("Args", (), {"second_opinion_prompt_file": reviewer_prompt})()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response({
            "confidence": "low",
            "detection_outcome": "inconclusive",
            "summary": "Primary assessment",
        })
        secondary = {
            "confidence": "high",
            "detection_outcome": "true_positive_suspicious",
            "bluf": "True Positive - Suspicious: independent review.",
            "summary": "Independent review",
        }
        phases: list[tuple[str, str, str]] = []

        with mock.patch.object(self.runner, "analyze_model_route", return_value=secondary) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append((phase, route, trigger)),
            )

        analyze.assert_called_once_with(
            "ollama:reviewer:latest",
            {},
            args,
            settings,
            system_prompt_file=reviewer_prompt,
            independent_review=True,
        )
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(result["_second_opinion"]["response"]["confidence"], "high")
        self.assertFalse(result["_second_opinion"]["response"]["second_opinion_recommended"])
        self.assertEqual(
            result["_second_opinion"]["comparison"]["agreement"],
            "material_disagreement",
        )
        self.assertEqual(
            phases,
            [
                (
                    "second_opinion",
                    "ollama:reviewer:latest",
                    "The primary model reported low confidence.",
                ),
                (
                    "post_processing",
                    "",
                    "The primary model reported low confidence.",
                ),
            ],
        )

    def test_comparison_distinguishes_full_advisory_and_material_disagreement(self) -> None:
        primary = {
            "detection_outcome": "true_positive_suspicious",
            "confidence": "high",
            "escalation_needed": True,
            "tuning_recommendation": "Keep enabled",
            "correlation_assessment": {"correlation_found": True},
        }
        full = self.runner.compare_analysis_results(primary, dict(primary))
        self.assertEqual(full["agreement"], "agreement")
        self.assertFalse(full["material_disagreement"])

        advisory_reviewer = {
            **primary,
            "confidence": "medium",
            "tuning_recommendation": "Monitor before tuning",
        }
        advisory = self.runner.compare_analysis_results(primary, advisory_reviewer)
        self.assertEqual(advisory["agreement"], "partial_disagreement")
        self.assertFalse(advisory["material_disagreement"])
        self.assertTrue(all(not item["material"] for item in advisory["disputed_fields"]))

        material_reviewer = {**primary, "escalation_needed": False}
        material = self.runner.compare_analysis_results(primary, material_reviewer)
        self.assertEqual(material["agreement"], "material_disagreement")
        self.assertTrue(material["material_disagreement"])
        self.assertIn("escalation_needed", {item["field"] for item in material["disputed_fields"]})

    def test_reviewer_memory_requires_high_confidence_full_agreement(self) -> None:
        completed = {
            "status": "completed",
            "response": {"confidence": "high", "memory_candidates": [{"finding": "synthetic"}]},
            "comparison": {"agreement": "agreement", "material_disagreement": False},
        }
        self.assertEqual(
            self.runner.second_opinion_memory_eligibility(completed),
            (True, "high-confidence independent agreement"),
        )

        for mutation, expected in (
            ({"response": {"confidence": "medium"}}, "confidence"),
            ({"comparison": {"agreement": "partial_disagreement", "material_disagreement": False}}, "agree"),
            ({"comparison": {"agreement": "material_disagreement", "material_disagreement": True}}, "agree"),
        ):
            candidate = {**completed, **mutation}
            eligible, reason = self.runner.second_opinion_memory_eligibility(candidate)
            self.assertFalse(eligible)
            self.assertIn(expected, reason)

    def test_confident_primary_does_not_spend_second_model_call(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response({
            "confidence": "high",
            "detection_outcome": "true_positive_authorized_benign",
            "summary": "Supported conclusion",
        })
        phases: list[tuple[str, str, str]] = []

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append((phase, route, trigger)),
            )

        self.assertIs(result, primary)
        self.assertNotIn("_second_opinion", result)
        analyze.assert_not_called()
        self.assertEqual(phases, [("post_processing", "", "")])

    def test_string_false_does_not_request_second_opinion(self) -> None:
        response = self.runner.validate_response({
            **self.runner.DEFAULT_RESPONSE_VALUES,
            "confidence": "high",
            "detection_outcome": "informational_no_action",
            "second_opinion_recommended": "false",
            "hosted_second_opinion_recommended": "false",
        })

        self.assertFalse(response["second_opinion_recommended"])
        self.assertFalse(response["hosted_second_opinion_recommended"])
        self.assertEqual(self.runner.second_opinion_trigger(response), "")

    def test_second_opinion_failure_preserves_primary_analysis(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response({
            "confidence": "low",
            "detection_outcome": "inconclusive",
            "summary": "Primary result must survive",
        })

        with mock.patch.object(self.runner, "analyze_model_route", side_effect=SystemExit("reviewer timeout")):
            result = self.runner.apply_configured_second_opinion({}, primary, args, settings, "soc-analyst")

        self.assertEqual(result["summary"], "Primary result must survive")
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn("reviewer timeout", result["_second_opinion"]["error"])

    def test_phase_status_failure_does_not_block_configured_reviewer(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/synthetic-reviewer-prompt.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response({
            "confidence": "low",
            "detection_outcome": "inconclusive",
            "summary": "Primary result",
        })
        secondary = {
            "confidence": "high",
            "detection_outcome": "inconclusive",
            "summary": "Reviewer result",
        }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            return_value=secondary,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=mock.Mock(side_effect=OSError("status file unavailable")),
            )

        analyze.assert_called_once()
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(result["_second_opinion"]["response"]["summary"], "Reviewer result")

    def test_cli_model_override_routes_soc_analyst_to_exact_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "ai_model_settings.json"
            path.write_text(json.dumps({
                "enabled_ollama_models": ["saved:latest"],
                "gpt_cli_enabled": False,
            }), encoding="utf-8")
            with mock.patch.object(sys, "argv", ["run-local-ai-analysis.py", "--model", "override:latest"]):
                args = self.runner.parse_args()
            args.ai_settings_file = path

            settings = self.runner.effective_ai_settings(args)

        self.assertEqual(settings["enabled_ollama_models"], ["override:latest"])
        self.assertEqual(settings["agent_models"]["soc-analyst"], "ollama:override:latest")

    def test_settings_reject_empty_provider_roster(self) -> None:
        settings = self.runner.default_ai_settings()

        with self.assertRaisesRegex(self.runner.RuntimeArtifactError, "at least one"):
            self.runner.apply_model_roster(settings, {
                "enabled_ollama_models": [],
                "gpt_cli_enabled": False,
            })


if __name__ == "__main__":
    unittest.main()
