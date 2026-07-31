#!/usr/bin/env python3
"""Contract tests for provider rosters and exact per-agent model routing."""
from __future__ import annotations

import copy
from contextlib import ExitStack
import importlib.util
import io
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

    def complete_response(self, **overrides):
        response = {
            **self.runner.DEFAULT_RESPONSE_VALUES,
            "bluf": "Inconclusive: synthetic evidence requires review.",
            "summary": "Synthetic complete response.",
            "likely_meaning": "Synthetic activity.",
            "severity_reasoning": "Synthetic severity rationale.",
            "alert_frequency_assessment": "One synthetic observation.",
            "evidence_used": ["alert.synthetic:E1", "alert.synthetic:E2"],
            "evidence_gaps": [],
            "confidence": "medium",
            "confidence_score": 0.65,
            "detection_outcome": "inconclusive",
            "escalation_needed": False,
            "tuning_recommendation": "needs_more_data",
            "tuning_reason": "Synthetic fixture requires more data.",
        }
        response.update(overrides)
        return response

    def complete_incident_report(self, **overrides):
        report = {
            "executive_bluf": "Synthetic fact-grounded incident bottom line.",
            "detection_outcome_reasoning": "Synthetic factored-verdict reasoning.",
            "scope": "Synthetic bounded incident scope.",
            "affected_systems": ["host-a supported by synthetic evidence"],
            "constraints": [],
            "methodology": ["Reviewed the supplied synthetic evidence."],
            "factual_timeline": [
                {
                    "timestamp": "2026-07-24T12:00:00-06:00",
                    "event": "Synthetic event observed.",
                    "source_pack": "alert_context",
                    "query_digest": "a" * 64,
                    "confidence": "high",
                },
            ],
            "security_onion_findings": ["Synthetic Security Onion finding."],
            "osquery_findings": ["No endpoint OSQuery evidence supplied."],
            "pcap_findings": ["Synthetic PCAP finding."],
            "host_findings": ["No host telemetry supplied."],
            "correlation_findings": ["No supported correlation."],
            "containment_recommendations": ["Preserve evidence."],
            "eradication_recommendations": ["Defer pending confirmation."],
            "recovery_recommendations": ["Defer pending confirmation."],
            "follow_up_queries": ["Collect the missing discriminator."],
            "evidence_gaps": ["No endpoint telemetry supplied."],
            "conclusion": "Synthetic fact-grounded conclusion.",
            "confidence": "high",
            "confidence_score": 0.9,
        }
        report.update(overrides)
        return report

    def complete_incident_prompt(self, **overrides):
        prompt = {
            "agent_role": "incident-responder",
            "incident_response_evidence": {
                "coverage_note": "Complete synthetic alert firing window.",
                "security_onion_response": {
                    "complete": True,
                    "partial": False,
                    "semantic_validity": {
                        "controls_valid": True,
                        "semantic_valid": True,
                    },
                    "results": [],
                },
            },
        }
        prompt.update(overrides)
        return prompt

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

    def test_openclaw_rejects_foreign_provider_with_expected_namespaced_model(
        self,
    ) -> None:
        with self.assertRaisesRegex(SystemExit, "different provider/model"):
            self.runner._verified_openclaw_observation(
                {
                    "provider": "openai",
                    "model": "ollama/gemma4:26b-mlx",
                },
                "ollama/gemma4:26b-mlx",
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

    def test_bounded_adjudicator_uses_closed_shadow_contract(self) -> None:
        prompt_file = Path("/tmp/synthetic-disagreement-adjudicator.md")
        args = type(
            "Args",
            (),
            {"disagreement_adjudicator_prompt_file": prompt_file},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
            "adjudicator:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = (
            "ollama:reviewer:latest"
        )
        settings["agent_adjudicator_models"]["soc-analyst"] = (
            "ollama:adjudicator:latest"
        )
        comparison = {
            "primary": {"detection_outcome": "inconclusive"},
            "reviewer": {"detection_outcome": "true_positive_suspicious"},
            "disputed_fields": [
                {
                    "field": "detection_outcome",
                    "primary": "inconclusive",
                    "reviewer": "true_positive_suspicious",
                    "material": True,
                }
            ],
            "material_disagreement": True,
        }
        phases: list[tuple[str, str, str]] = []

        def adjudicated(route, package, *unused_args, **unused_kwargs):
            contract = package["adjudication_contract"]
            return {
                "adjudication_case_id": contract["case_id"],
                "adjudication_evidence_hash": contract["evidence_hash"],
                "decision": "unresolved",
                "confidence": "medium",
                "confidence_score": 0.55,
                "resolved_fields": [],
                "remaining_disagreements": ["detection_outcome"],
                "evidence_used": ["alert:synthetic-adjudication"],
                "rationale": "The bounded alert evidence does not distinguish the positions.",
                "additional_evidence_needed": ["Collect endpoint process evidence."],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=adjudicated,
        ) as analyze:
            result = self.runner.run_bounded_disagreement_adjudication(
                {"alert": {"alert_id": "synthetic-adjudication"}},
                self.complete_response(),
                self.complete_response(),
                comparison,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append(
                    (phase, route, trigger)
                ),
            )

        analyze.assert_called_once()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["decision"], "unresolved")
        self.assertEqual(result["mode"], "shadow")
        self.assertFalse(result["automation_authorized"])
        self.assertTrue(result["human_adjudication_required"])
        self.assertEqual(analyze.call_args.args[0], "ollama:adjudicator:latest")
        self.assertTrue(analyze.call_args.kwargs["independent_review"])
        self.assertEqual(analyze.call_args.kwargs["system_prompt_file"], prompt_file)
        self.assertNotIn(
            "second_opinion_review",
            analyze.call_args.args[1],
        )
        self.assertEqual(phases[0][0], "disagreement_adjudication")

    def test_adjudicator_rejects_a_synthetic_compromise_position(self) -> None:
        package = {
            "adjudication_contract": {
                "case_id": "case-1",
                "evidence_hash": "a" * 64,
                "allowed_decisions": [
                    "primary_supported",
                    "reviewer_supported",
                    "unresolved",
                ],
                "disputed_fields": ["detection_outcome"],
                "material_fields": ["detection_outcome"],
            },
            "evidence_reference_contract": {
                "references": [
                    {"ref": "alert:case-1", "corroborating": True},
                ],
            },
        }
        response = {
            "adjudication_case_id": "case-1",
            "adjudication_evidence_hash": "a" * 64,
            "decision": "compromise_consensus",
            "confidence": "medium",
            "confidence_score": 0.5,
            "resolved_fields": [],
            "remaining_disagreements": ["detection_outcome"],
            "evidence_used": ["alert:case-1"],
            "rationale": "Synthetic compromise is outside the contract.",
            "additional_evidence_needed": [],
        }

        with self.assertRaisesRegex(
            self.runner.DisagreementAdjudicationValidationError,
            "closed vocabulary",
        ):
            self.runner.validate_disagreement_adjudication(response, package)

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
        primary = self.runner.validate_response(self.complete_response(
            confidence="low",
            confidence_score=0.3,
            detection_outcome="inconclusive",
            summary="Primary assessment",
        ))
        secondary = self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_suspicious",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="suspicious",
            handling="escalate",
            duplicate_of=None,
            hypotheses=[],
            evidence_used=["alert", "alert:synthetic-review"],
            bluf="True Positive - Suspicious: independent review.",
            summary="Independent review",
            escalation_needed=True,
        )
        phases: list[tuple[str, str, str]] = []

        def reviewed_response(route, review_package, *unused_args, **unused_kwargs):
            contract = review_package["review_contract"]
            return {
                **secondary,
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(self.runner, "analyze_model_route", side_effect=reviewed_response) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "synthetic-review"}},
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=lambda phase, route, trigger: phases.append((phase, route, trigger)),
            )

        analyze.assert_called_once()
        self.assertEqual(analyze.call_args.args[0], "ollama:reviewer:latest")
        self.assertEqual(
            analyze.call_args.args[1]["second_opinion_review"]["mode"],
            "blind_independent",
        )
        self.assertIs(analyze.call_args.args[2], args)
        self.assertIs(analyze.call_args.args[3], settings)
        self.assertEqual(analyze.call_args.kwargs["system_prompt_file"], reviewer_prompt)
        self.assertTrue(analyze.call_args.kwargs["independent_review"])
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(result["_second_opinion"]["response"]["confidence"], "medium")
        self.assertEqual(
            result["_second_opinion"]["response"]["_confidence_calibration"][
                "evidence_signals"
            ]["corroborating_evidence_source_count"],
            1,
        )
        self.assertFalse(result["_second_opinion"]["response"]["second_opinion_recommended"])
        self.assertEqual(
            result["_second_opinion"]["comparison"]["agreement"],
            "material_disagreement",
        )
        self.assertFalse(
            result["_second_opinion"]["automation_authorization"][
                "authorized"
            ]
        )
        self.assertEqual(
            result["_second_opinion"]["automation_authorization"][
                "reason_code"
            ],
            "material_disagreement",
        )
        self.assertEqual(result["final_disposition_status"], "disputed_pending_human")
        self.assertTrue(result["escalation_needed"])
        self.assertEqual(result["detection_outcome"], "inconclusive")
        self.assertEqual(result["activity_disposition"], "unknown")
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertTrue(result["bluf"].startswith("DISPUTED"))
        self.assertTrue(result["_material_disagreement_gate"]["applied"])
        self.assertEqual(result["tuning_recommendation"], "needs_more_data")
        self.assertEqual(result["recommended_tuning_actions"], [])
        self.assertEqual(result["memory_candidates"], [])
        self.assertTrue(result["_automation_controls"]["tuning_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])
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

    def test_reviewer_foreign_case_retries_once_then_fails_closed(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                handling="contain",
                memory_candidates=[
                    {
                        "scope": "agent",
                        "category": "investigation_pivot",
                        "finding": "Synthetic reusable lesson with enough bounded detail.",
                        "use_when": "A later synthetic alert needs the same discriminator.",
                        "evidence_basis": ["Synthetic evidence."],
                        "confidence": "medium",
                        "tags": ["synthetic"],
                        "ttl_days": 30,
                    }
                ],
            )
        )
        invalid = {
            **self.complete_response(),
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "escalate",
            "duplicate_of": None,
            "confidence_score": 0.9,
            "hypotheses": [],
            "review_case_id": "foreign-case",
            "review_evidence_hash": "b" * 64,
            "observables_used": [{"kind": "ip", "value": "10.0.0.50"}],
        }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            return_value=invalid,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "current-case", "source_ip": "192.0.2.10"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["memory_candidates"], [])
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])

    def test_reviewer_invalid_evidence_retries_once_then_fails_closed(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                handling="contain",
            )
        )

        def invalid_response(_route, review_package, *_args, **_kwargs):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["query:invented-digest"],
                ),
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "suspicious",
                "handling": "escalate",
                "duplicate_of": None,
                "hypotheses": [],
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=invalid_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "current-case"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn(
            "outside the current contract",
            result["_second_opinion"]["error"],
        )
        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])

    def test_controlled_evaluation_reviewer_gate_allows_first_or_repaired_response(
        self,
    ) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        prompt_package = {"alert": {"alert_id": "evaluation-review-case"}}

        def candidate(review_package, *, valid):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=[
                        "alert",
                        "alert:evaluation-review-case",
                    ],
                    event_status="unknown",
                    detection_validity="unknown",
                    activity_disposition="unknown",
                    handling="investigate",
                    duplicate_of=None,
                    hypotheses=[],
                ),
                "review_case_id": (
                    contract["case_id"] if valid else "foreign-case"
                ),
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        for repaired in (False, True):
            with self.subTest(repaired=repaired):
                primary = self.runner.validate_response(
                    self.complete_response(
                        confidence="low",
                        confidence_score=0.3,
                        detection_outcome="inconclusive",
                    ),
                    prompt_package,
                )
                trigger = self.runner.second_opinion_trigger(
                    primary,
                    prompt_package,
                )
                calls = 0

                def reviewed_response(
                    _route,
                    review_package,
                    *_args,
                    **_kwargs,
                ):
                    nonlocal calls
                    calls += 1
                    return candidate(
                        review_package,
                        valid=not repaired or calls == 2,
                    )

                with mock.patch.object(
                    self.runner,
                    "analyze_model_route",
                    side_effect=reviewed_response,
                ):
                    response = self.runner.apply_configured_second_opinion(
                        prompt_package,
                        primary,
                        args,
                        settings,
                        "soc-analyst",
                    )

                reviewer = (
                    self.runner.precommit_controlled_evaluation_reviewer_gate(
                        prompt_package,
                        response,
                        settings,
                        "soc-analyst",
                        trigger_reason=trigger,
                        freeze_enabled=True,
                    )
                )
                self.assertIs(
                    reviewer,
                    response["_second_opinion"]["response"],
                )
                self.assertEqual(calls, 2 if repaired else 1)
                self.assertEqual(
                    response["_second_opinion"]["attempts"],
                    2 if repaired else 1,
                )
                self.assertEqual(
                    len(response["_second_opinion"]["validation_failures"]),
                    1 if repaired else 0,
                )

    def test_controlled_evaluation_two_invalid_reviews_stop_before_result_commit(
        self,
    ) -> None:
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        primary = self.complete_response(
            confidence="low",
            confidence_score=0.3,
            detection_outcome="inconclusive",
        )

        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            prompt_path = root / "prompt.json"
            out_dir = root / "results"
            prompt_path.write_text(
                json.dumps(
                    {
                        "package_type": "soc-ai-investigation-prompt",
                        "agent_role": "soc-analyst",
                        "alert": {"alert_id": "two-invalid-reviews"},
                    }
                ),
                encoding="utf-8",
            )
            args = self.runner.argparse.Namespace(
                flush_index_only=False,
                alert_store_url="http://127.0.0.1:8766",
                generate_prompt=False,
                prompt_package=prompt_path,
                prompt_dir=root,
                max_prompt_bytes=self.runner.DEFAULT_MAX_PROMPT_BYTES,
                response_json=None,
                max_response_bytes=self.runner.DEFAULT_MAX_JSON_ARTIFACT_BYTES,
                investigation_harness_policy=root / "policy.json",
                investigation_harness_db=root / "harness.sqlite3",
                reanalysis_attempt_id="controlled-evaluation-attempt",
                second_opinion_prompt_file=root / "reviewer.md",
                system_prompt_file=root / "primary.md",
                out_dir=out_dir,
                stdout=False,
            )
            policy = mock.Mock(enabled=True, mode="shadow")
            harness = mock.Mock()
            harness.policy.mode = "shadow"
            monitor = mock.Mock()

            def invalid_reviewer(
                _route,
                review_package,
                *_args,
                **_kwargs,
            ):
                contract = review_package["review_contract"]
                return {
                    **self.complete_response(
                        evidence_used=[
                            "alert",
                            "alert:two-invalid-reviews",
                        ],
                        event_status="unknown",
                        detection_validity="unknown",
                        activity_disposition="unknown",
                        handling="investigate",
                        duplicate_of=None,
                        hypotheses=[],
                    ),
                    "review_case_id": "foreign-case",
                    "review_evidence_hash": contract["evidence_hash"],
                    "observables_used": [],
                }

            with ExitStack() as stack:
                stack.enter_context(
                    mock.patch.dict(
                        self.runner.os.environ,
                        {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "parse_args",
                        return_value=args,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "flush_analysis_index_queue",
                        return_value=(0, 0, 0),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "effective_ai_settings",
                        return_value=settings,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "prepare_live_osquery_context",
                        return_value=None,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "load_investigation_harness_policy",
                        return_value=policy,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "should_start_onion_sentinel_harness",
                        return_value=(True, "synthetic"),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "start_harness_run",
                        return_value=harness,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "SystemResourceMonitor",
                        return_value=monitor,
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "active_analysis_record_path",
                        return_value=root / "active.json",
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "build_llm_log_record",
                        return_value={},
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "publish_current_analysis_phase",
                        return_value={},
                    )
                )
                stack.enter_context(
                    mock.patch.object(self.runner, "atomic_write_json")
                )
                stack.enter_context(
                    mock.patch.object(self.runner, "append_jsonl")
                )
                stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "analyze_with_config",
                        return_value=primary,
                    )
                )
                analyze = stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "analyze_model_route",
                        side_effect=invalid_reviewer,
                    )
                )
                write = stack.enter_context(
                    mock.patch.object(self.runner, "write_outputs")
                )
                queue = stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "queue_analysis_index",
                    )
                )
                commit = stack.enter_context(
                    mock.patch.object(
                        self.runner,
                        "post_analysis_index",
                    )
                )
                stack.enter_context(
                    self.assertRaisesRegex(
                        self.runner.ControlledEvaluationReviewerGateError,
                        "produced no validated response",
                    )
                )
                self.runner.main()

            self.assertEqual(analyze.call_count, 2)
            write.assert_not_called()
            queue.assert_not_called()
            commit.assert_not_called()
            self.assertFalse(out_dir.exists())

        # Outside a frozen evaluation the same advisory failure remains
        # production-compatible and does not raise the precommit exception.
        reviewer = self.runner.precommit_controlled_evaluation_reviewer_gate(
            {"alert": {"alert_id": "two-invalid-reviews"}},
            {
                "_second_opinion": {
                    "status": "failed",
                    "trigger": "synthetic",
                }
            },
            settings,
            "soc-analyst",
            trigger_reason="synthetic",
            freeze_enabled=False,
        )
        self.assertIsNone(reviewer)

    def test_elasticsearch_alert_id_suffix_is_not_a_community_id(self) -> None:
        alert_id = (
            ".ds-logs-suricata.alerts-so-2026.07.24-000001-"
            "000535:XuBJm58BIwAfe8Cpckf6"
        )
        prompt_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": alert_id}}
        )
        contract = prompt_package["review_contract"]
        response = {
            **self.complete_response(
                summary=f"Reviewed Elasticsearch alert document {alert_id}.",
                evidence_used=["alert", f"alert:{alert_id}"],
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
            ),
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        validated = self.runner.validate_reviewer_response(
            response,
            prompt_package,
        )

        self.assertTrue(validated["_review_contract_validation"]["valid"])
        community_id = "1:Y9R9syXYWvDIRM6pRrzmcXHA1c4="
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(community_id),
            [community_id],
        )
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(
                "01:Y9R9syXYWvDIRM6pRrzmcXHA1c4="
            ),
            [],
        )
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(
                "1:Y9R9syXYWvDIRM6pRrzmcXHA1c5="
            ),
            [],
        )
        self.assertEqual(
            self.runner.REVIEW_COMMUNITY_ID_RE.findall(alert_id),
            [],
        )

    def test_dns_query_schema_path_is_not_a_foreign_domain(self) -> None:
        prompt_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "dns-query-schema-path"}}
        )
        contract = prompt_package["review_contract"]
        response = {
            **self.complete_response(
                summary=(
                    "The dns.query field was unavailable, so the event "
                    "remains inconclusive."
                ),
                evidence_used=[
                    "alert",
                    "alert:dns-query-schema-path",
                ],
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
            ),
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        validated = self.runner.validate_reviewer_response(
            response,
            prompt_package,
        )

        self.assertTrue(validated["_review_contract_validation"]["valid"])

    def test_reviewed_query_field_paths_are_not_foreign_domains(self) -> None:
        prompt_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "reviewed-query-field-paths"}}
        )
        contract = prompt_package["review_contract"]
        response = {
            **self.complete_response(
                summary=(
                    "The dns.query, dns.query.name, tls.server.name, "
                    "http.virtual_host, and network.community_id fields were "
                    "checked without asserting new observable values."
                ),
                evidence_used=[
                    "alert",
                    "alert:reviewed-query-field-paths",
                ],
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
            ),
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        validated = self.runner.validate_reviewer_response(
            response,
            prompt_package,
        )

        self.assertTrue(validated["_review_contract_validation"]["valid"])
        for field in (
            "dns.query",
            "dns.query.name",
            "tls.server.name",
            "http.virtual_host",
            "network.community_id",
        ):
            self.assertIn(field, self.runner.REVIEW_KNOWN_FIELD_PATHS)

    def test_foreign_community_retry_records_bounded_attempt_telemetry(
        self,
    ) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                detection_outcome="inconclusive",
            )
        )
        allowed_community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        foreign_community_id = "1:Y9R9syXYWvDIRM6pRrzmcXHA1c4="
        repair_packages: list[dict] = []
        repair_prompt_serializations: list[str] = []

        def invalid_response(_route, review_package, *_args, **_kwargs):
            if isinstance(review_package.get("review_contract_repair"), dict):
                repair_packages.append(
                    json.loads(
                        json.dumps(
                            review_package["review_contract_repair"]
                        )
                    )
                )
                repair_prompt_serializations.append(
                    json.dumps(
                        review_package,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                )
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["alert", "alert:community-id-case"],
                    summary=(
                        "The supplied evidence included Community ID "
                        f"{foreign_community_id}."
                    ),
                ),
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "suspicious",
                "handling": "escalate",
                "duplicate_of": None,
                "hypotheses": [],
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=invalid_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {
                        "alert_id": "community-id-case",
                        "community_id": allowed_community_id,
                    },
                },
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertEqual(result["_second_opinion"]["attempts"], 2)
        failures = result["_second_opinion"]["validation_failures"]
        self.assertEqual(len(failures), 2)
        self.assertEqual(
            [failure["attempt"] for failure in failures],
            [1, 2],
        )
        self.assertEqual(
            [failure["call_id"] for failure in failures],
            ["independent-review-1", "independent-review-2"],
        )
        self.assertNotEqual(
            failures[0]["input_digest"],
            failures[1]["input_digest"],
        )
        self.assertEqual(
            failures[0]["output_digest"],
            failures[1]["output_digest"],
        )
        for failure in failures:
            self.assertEqual(
                failure["schema"],
                self.runner.REVIEW_VALIDATION_FAILURE_SCHEMA,
            )
            self.assertEqual(failure["status"], "validation-failed")
            self.assertIn("foreign community ID", failure["message"])
            self.assertIn(foreign_community_id, failure["message"])
            self.assertRegex(failure["input_digest"], r"^[a-f0-9]{64}$")
            self.assertRegex(failure["output_digest"], r"^[a-f0-9]{64}$")
            self.assertLessEqual(
                len(failure["message"]),
                self.runner.REVIEW_VALIDATION_MESSAGE_MAX,
            )
            self.assertNotIn("response", failure)
            self.assertNotIn("candidate", failure)

        self.assertEqual(len(repair_packages), 1)
        repair = repair_packages[0]
        self.assertIn(
            "outside review_contract.allowed_observables",
            repair["validation_errors"],
        )
        self.assertNotIn(
            foreign_community_id,
            repair["validation_errors"],
        )
        guidance = " ".join(repair["field_guidance"])
        self.assertIn("Elastic index/document identifiers", guidance)
        self.assertIn("not Community IDs", guidance)
        self.assertIn("allowed_observables", guidance)
        self.assertIn("do not repeat", guidance.lower())
        self.assertEqual(len(repair_prompt_serializations), 1)
        self.assertNotIn(
            foreign_community_id,
            repair_prompt_serializations[0],
        )

    def test_reviewer_repair_category_does_not_echo_foreign_domain(self) -> None:
        rejected = "discord.com"
        category = self.runner.reviewer_repair_error_category(
            "reviewer used foreign observables: domain:"
            + rejected
            + "; reviewer introduced foreign domain or FQDN value(s): "
            + rejected
        )

        self.assertIn(
            "outside review_contract.allowed_observables",
            category,
        )
        self.assertNotIn(rejected, category)
        guidance = " ".join(
            self.runner.reviewer_repair_guidance(
                "reviewer used foreign observables: domain:"
                + rejected
                + "; reviewer introduced foreign domain or FQDN value(s): "
                + rejected
            )
        )
        self.assertNotIn(rejected, guidance)
        self.assertIn("do not repeat", guidance.lower())

    def test_reviewer_observable_overflow_cannot_hide_foreign_host(self) -> None:
        review_package = self.runner.independent_reviewer_package(
            {
                "alert": {
                    "alert_id": "observable-overflow-case",
                    "host": "allowedhost",
                },
            }
        )
        contract = review_package["review_contract"]
        allowed_host = next(
            item
            for item in contract["allowed_observables"]
            if item["kind"] == "host"
        )
        response = {
            **self.complete_response(
                summary="The endpoint foreignhost performed the material activity.",
                evidence_used=["alert", "alert:observable-overflow-case"],
                confidence="high",
                confidence_score=0.9,
            ),
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "hypotheses": [],
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            # Duplicate valid entries previously filled the validated prefix,
            # allowing the foreign final entry into the full-list membership set.
            "observables_used": [
                dict(allowed_host)
                for _ in range(self.runner.REVIEW_OBSERVABLE_MAX)
            ] + [{"kind": "host", "value": "foreignhost"}],
        }

        with self.assertRaisesRegex(
            self.runner.ReviewerValidationError,
            "observables_used exceeds the maximum",
        ):
            self.runner.validate_reviewer_response(response, review_package)

    def test_reviewer_consequential_arrays_reject_overflow(self) -> None:
        review_package = self.runner.independent_reviewer_package(
            {"alert": {"alert_id": "review-array-overflow-case"}}
        )
        contract = review_package["review_contract"]
        base = {
            **self.complete_response(
                evidence_used=["alert", "alert:review-array-overflow-case"],
            ),
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "hypotheses": [],
            "review_case_id": contract["case_id"],
            "review_evidence_hash": contract["evidence_hash"],
            "observables_used": [],
        }

        for field, value, expected in (
            (
                "evidence_used",
                ["alert"] * (self.runner.REVIEW_EVIDENCE_USED_MAX + 1),
                "evidence_used exceeds the maximum",
            ),
            (
                "hypotheses",
                [{}] * (self.runner.REVIEW_HYPOTHESES_MAX + 1),
                "hypotheses exceeds the maximum",
            ),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    self.runner.ReviewerValidationError,
                    expected,
                ):
                    self.runner.validate_reviewer_response(
                        {**base, field: value},
                        review_package,
                    )

    def test_reviewer_foreign_narrative_domain_fails_closed(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(confidence="low", confidence_score=0.3)
        )
        repair_prompt_serializations: list[str] = []

        def invalid_response(_route, review_package, *_args, **_kwargs):
            if isinstance(review_package.get("review_contract_repair"), dict):
                repair_prompt_serializations.append(
                    json.dumps(
                        review_package,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                )
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["alert", "alert:domain-case"],
                    summary="The supplied evidence proves contact with foreign.example.",
                ),
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "suspicious",
                "handling": "escalate",
                "duplicate_of": None,
                "hypotheses": [],
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=invalid_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {
                        "alert_id": "domain-case",
                        "domain": "allowed.example",
                    }
                },
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn(
            "foreign domain or FQDN",
            result["_second_opinion"]["error"],
        )
        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertEqual(len(repair_prompt_serializations), 1)
        self.assertNotIn(
            "foreign.example",
            repair_prompt_serializations[0],
        )

    def test_reviewer_foreign_ip_retry_prompt_is_value_free(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(confidence="low", confidence_score=0.3)
        )
        foreign_ip = "203.0.113.77"
        repair_prompt_serializations: list[str] = []
        attempts = 0

        def reviewed_response(_route, review_package, *_args, **_kwargs):
            nonlocal attempts
            attempts += 1
            contract = review_package["review_contract"]
            if attempts == 2:
                repair_prompt_serializations.append(
                    json.dumps(
                        review_package,
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    )
                )
            return {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.9,
                    evidence_used=["alert", "alert:ip-case"],
                    summary=(
                        f"The supplied evidence proves contact with {foreign_ip}."
                        if attempts == 1
                        else "The supplied evidence remains suspicious."
                    ),
                ),
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "suspicious",
                "handling": "escalate",
                "duplicate_of": None,
                "hypotheses": [],
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {
                        "alert_id": "ip-case",
                        "source_ip": "192.0.2.10",
                    }
                },
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(analyze.call_count, 2)
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(len(repair_prompt_serializations), 1)
        self.assertNotIn(foreign_ip, repair_prompt_serializations[0])
        repair = json.loads(repair_prompt_serializations[0])[
            "review_contract_repair"
        ]
        self.assertIn(
            "outside review_contract.allowed_observables",
            repair["validation_errors"],
        )
        self.assertIn(
            "do not repeat",
            " ".join(repair["field_guidance"]).lower(),
        )

    def test_grounded_medium_confidence_agreement_cannot_unblock_automation(self) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = ["primary:latest", "reviewer:latest"]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        verdict = {
            "detection_outcome": "inconclusive",
            "event_status": "unknown",
            "detection_validity": "unknown",
            "activity_disposition": "unknown",
            "handling": "investigate",
            "duplicate_of": None,
            "hypotheses": [],
            "escalation_needed": False,
        }
        primary = self.runner.validate_response(
            self.complete_response(
                **verdict,
                confidence="low",
                confidence_score=0.3,
            )
        )

        def reviewed_response(_route, review_package, *_args, **_kwargs):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    **verdict,
                    confidence="medium",
                    confidence_score=0.65,
                    evidence_used=["alert", "alert:current-case"],
                ),
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ):
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "current-case"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertNotIn("error", result["_second_opinion"])
        self.assertEqual(
            result["_second_opinion"]["comparison"]["agreement"],
            "partial_disagreement",
        )
        authorization = result["_second_opinion"][
            "automation_authorization"
        ]
        self.assertFalse(authorization["authorized"])
        self.assertEqual(
            authorization["reason_code"],
            "reviewer_confidence_below_automation_threshold",
        )
        self.assertFalse(
            authorization["automatic_closure_authorized"]
        )
        self.assertFalse(authorization["containment_authorized"])
        self.assertFalse(authorization["tuning_authorized"])
        self.assertFalse(
            authorization["memory_writeback_authorized"]
        )
        self.assertEqual(
            result["final_disposition_status"],
            "review_completed_not_authorized",
        )
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertFalse(result["escalation_needed"])
        self.assertEqual(
            result["tuning_recommendation"],
            "needs_more_data",
        )
        self.assertEqual(result["recommended_tuning_actions"], [])
        self.assertEqual(result["memory_candidates"], [])
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])
        self.assertTrue(result["_automation_controls"]["tuning_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])

    def test_medium_review_of_consequential_primary_blocks_every_control(
        self,
    ) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        verdict = {
            "detection_outcome": "true_positive_suspicious",
            "event_status": "observed",
            "detection_validity": "matched_intent",
            "activity_disposition": "suspicious",
            "handling": "contain",
            "duplicate_of": None,
            "hypotheses": [],
            "escalation_needed": True,
            "tuning_recommendation": "suppress",
            "recommended_tuning_actions": [
                "Suppress this synthetic detection."
            ],
        }
        primary = self.runner.validate_response(
            self.complete_response(
                **verdict,
                confidence="high",
                confidence_score=0.9,
            )
        )

        def reviewed_response(
            _route,
            review_package,
            *_args,
            **_kwargs,
        ):
            contract = review_package["review_contract"]
            return {
                **self.complete_response(
                    **verdict,
                    confidence="medium",
                    confidence_score=0.65,
                    evidence_used=["alert", "alert:consequential-case"],
                ),
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ):
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "consequential-case"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        self.assertEqual(result["_second_opinion"]["status"], "completed")
        authorization = result["_second_opinion"][
            "automation_authorization"
        ]
        self.assertFalse(authorization["authorized"])
        self.assertTrue(
            authorization["consequential_automation_requested"]
        )
        self.assertEqual(
            result["final_disposition_status"],
            "review_completed_not_authorized",
        )
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(
            result["tuning_recommendation"],
            "needs_more_data",
        )
        self.assertEqual(result["recommended_tuning_actions"], [])
        self.assertEqual(result["memory_candidates"], [])
        for key in (
            "automatic_closure_blocked",
            "containment_blocked",
            "tuning_blocked",
            "memory_writeback_blocked",
            "requires_human_review",
        ):
            self.assertTrue(result["_automation_controls"][key])

    def test_saved_response_required_review_fails_closed(self) -> None:
        saved_input = self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="contain",
                escalation_needed=False,
                memory_candidates=[
                    {
                        "scope": "agent",
                        "category": "response_lesson",
                        "confidence": "high",
                        "finding": "Synthetic containment pattern must remain review-gated.",
                        "use_when": "When the same synthetic alert recurs.",
                        "evidence_basis": ["alert:synthetic-saved-response"],
                    }
                ],
                _second_opinion={
                    "status": "completed",
                    "response": {"confidence": "high"},
                    "comparison": {
                        "agreement": "agreement",
                        "material_disagreement": False,
                    },
                },
                _analysis_model="spoofed-model",
                _analysis_model_path="frontier-codex-cli",
                _analysis_model_route="codex-cli:spoofed-model:xhigh",
                _analysis_provider="codex-cli",
                _automation_controls={"memory_writeback_blocked": False},
            )
        sanitized = self.runner.sanitize_saved_response_input(saved_input)
        self.assertFalse(any(key.startswith("_") for key in sanitized))
        primary = self.runner.validate_response(
            sanitized
        )
        self.assertTrue(primary["memory_candidates"])

        result = self.runner.apply_saved_response_review_gate(
            {"alert": {"alert_id": "synthetic-saved-response"}},
            primary,
        )

        self.assertEqual(result["final_disposition_status"], "review_required_failed")
        self.assertEqual(result["confidence"], "low")
        self.assertLessEqual(result["confidence_score"], 0.39)
        self.assertEqual(result["handling"], "investigate")
        self.assertEqual(result["memory_candidates"], [])
        self.assertEqual(
            result["_analysis_input_mode"],
            self.runner.SAVED_RESPONSE_INPUT_MODE,
        )
        self.assertNotIn("_analysis_model", result)
        self.assertNotIn("_analysis_model_path", result)
        self.assertNotIn("_analysis_model_route", result)
        self.assertNotIn("_analysis_provider", result)
        self.assertEqual(result["_second_opinion"]["status"], "review_required_failed")
        self.assertIn("consequential", result["_second_opinion"]["trigger"].lower())
        self.assertTrue(result["_automation_controls"]["automatic_closure_blocked"])
        self.assertTrue(result["_automation_controls"]["containment_blocked"])
        self.assertTrue(result["_automation_controls"]["tuning_blocked"])
        self.assertTrue(result["_automation_controls"]["memory_writeback_blocked"])

        settings = self.runner.default_ai_settings()
        settings["agent_models"]["soc-analyst"] = "ollama:assigned-only"
        log_record = self.runner.build_llm_log_record(
            run_id="synthetic-saved-response",
            status="success",
            started_at="2026-07-24  10:00:00-06:00",
            finished_at="2026-07-24  10:00:01-06:00",
            runtime_seconds=1,
            prompt_path=Path("/tmp/synthetic-prompt.json"),
            prompt_package={
                "agent_role": "soc-analyst",
                "alert": {"alert_id": "synthetic-saved-response"},
            },
            settings=settings,
            response=result,
            json_path=Path("/tmp/synthetic-result.json"),
            md_path=Path("/tmp/synthetic-result.md"),
            resource_monitor=self.runner.SystemResourceMonitor(),
        )
        self.assertEqual(log_record["input_mode"], "saved_response")
        self.assertFalse(log_record["model_started"])
        self.assertEqual(log_record["model"], "")
        self.assertEqual(log_record["model_path"], "")
        self.assertEqual(log_record["model_route"], "")
        self.assertEqual(log_record["assigned_model"], "assigned-only")

        index_payload = self.runner.analysis_index_payload(
            "synthetic-saved-response",
            {"agent_role": "soc-analyst", "alert": {"alert_id": "saved-alert"}},
            result,
            "",
            "2026-07-24  10:00:00-06:00",
            "2026-07-24  10:00:01-06:00",
            Path("/tmp/synthetic-result.json"),
        )
        self.assertIsNone(index_payload["model"])
        self.assertIsNone(index_payload["model_path"])
        self.assertIsNone(index_payload["provider"])
        self.assertIsNone(index_payload["harness"])
        self.assertEqual(index_payload["input_mode"], "saved_response")

        observed_payload = self.runner.analysis_index_payload(
            "synthetic-hermes-response",
            {"agent_role": "soc-analyst", "alert": {"alert_id": "observed"}},
            {
                "_analysis_model": "gpt-5.6-sol",
                "_analysis_model_path": "hermes-agent",
                "_analysis_provider": "openai-codex",
                "_analysis_harness": "hermes-agent",
            },
            "",
            "2026-07-24  10:00:00-06:00",
            "2026-07-24  10:00:01-06:00",
            Path("/tmp/synthetic-hermes-result.json"),
        )
        self.assertEqual(observed_payload["provider"], "openai-codex")
        self.assertEqual(observed_payload["harness"], "hermes-agent")

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

    def test_tuning_only_material_disagreement_preserves_agreed_verdict(
        self,
    ) -> None:
        primary = self.complete_response(
            confidence="medium",
            confidence_score=0.68,
            detection_outcome="informational_no_action",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="benign",
            handling="no_action",
            escalation_needed=False,
            tuning_recommendation="suppress",
            bluf="Informational package-management activity.",
            summary="The activity is benign but not formally authorized.",
        )
        reviewer = {
            **primary,
            "tuning_recommendation": "none",
        }
        comparison = self.runner.compare_analysis_results(
            primary,
            reviewer,
        )

        self.assertTrue(comparison["material_disagreement"])
        result = self.runner.apply_material_disagreement_gate(
            primary,
            reviewer,
            comparison,
        )

        self.assertEqual(result["detection_outcome"], "informational_no_action")
        self.assertEqual(result["activity_disposition"], "benign")
        self.assertEqual(result["handling"], "no_action")
        self.assertEqual(result["confidence"], "medium")
        self.assertFalse(result["escalation_needed"])
        self.assertTrue(result["bluf"].startswith("DISPUTED TUNING"))
        self.assertEqual(
            result["_material_disagreement_gate"]["scope"],
            "control_only",
        )
        self.assertTrue(
            result["_material_disagreement_gate"]["verdict_preserved"]
        )

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

    def test_memory_writeback_is_staged_until_authoritative_commit(self) -> None:
        candidate = {
            "scope": "agent",
            "category": "investigation_pivot",
            "finding": (
                "Correlate TLS SNI with certificate and destination history."
            ),
            "use_when": "A later TLS alert has the same infrastructure.",
            "evidence_basis": ["Zeek and alert evidence independently agreed."],
            "confidence": "medium",
            "tags": ["tls", "zeek"],
            "ttl_days": 30,
        }
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            role_memory = root / "role.md"
            shared_memory = root / "shared.md"
            receipt_dir = root / "receipts"
            role_memory.write_text("# Role Memory\n", encoding="utf-8")
            shared_memory.write_text("# Shared Memory\n", encoding="utf-8")

            plan = self.runner.memory_writeback_plan(
                [candidate],
                allowed=True,
                eligibility_reason="eligible after authoritative commit",
            )
            self.assertEqual(
                plan["persistence_status"],
                "pending_authoritative_commit",
            )
            self.assertNotIn(
                "ONION_SENTINEL_MANAGED_MEMORY_START",
                role_memory.read_text(encoding="utf-8"),
            )

            receipt, receipt_path = (
                self.runner.persist_postcommit_memory_writeback(
                    analysis_id="postcommit-memory-test",
                    agent_role="soc-analyst",
                    role_memory_file=role_memory,
                    shared_memory_file=shared_memory,
                    source_artifact="/tmp/synthetic-analysis.json",
                    primary_candidates=[candidate],
                    primary_allowed=True,
                    primary_reason="eligible after authoritative commit",
                    reviewer_candidates=[],
                    reviewer_allowed=False,
                    reviewer_reason="reviewer did not complete",
                    receipt_dir=receipt_dir,
                )
            )
            self.assertTrue(receipt["ok"])
            self.assertEqual(receipt["primary"]["status"], "persisted")
            self.assertEqual(receipt["reviewer"]["status"], "blocked")
            self.assertIsNotNone(receipt_path)
            assert receipt_path is not None
            self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(receipt_dir.stat().st_mode & 0o777, 0o700)
            receipt_text = receipt_path.read_text(encoding="utf-8")
            self.assertNotIn(candidate["finding"], receipt_text)
            self.assertIn(
                "ONION_SENTINEL_MANAGED_MEMORY_START",
                role_memory.read_text(encoding="utf-8"),
            )

    def test_blocked_postcommit_memory_plan_never_mutates_memory(self) -> None:
        candidate = {
            "scope": "agent",
            "category": "investigation_pivot",
            "finding": "Treat a prior model claim only as a lead.",
            "use_when": "A related alert is investigated.",
            "evidence_basis": ["One prior model observation."],
            "confidence": "medium",
            "tags": ["lead"],
            "ttl_days": 30,
        }
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            role_memory = root / "role.md"
            shared_memory = root / "shared.md"
            role_memory.write_text("# Role Memory\n", encoding="utf-8")
            shared_memory.write_text("# Shared Memory\n", encoding="utf-8")
            before = role_memory.read_bytes()

            receipt, _ = self.runner.persist_postcommit_memory_writeback(
                analysis_id="blocked-memory-test",
                agent_role="soc-analyst",
                role_memory_file=role_memory,
                shared_memory_file=shared_memory,
                source_artifact="/tmp/synthetic-analysis.json",
                primary_candidates=[candidate],
                primary_allowed=False,
                primary_reason="explicit human approval is required",
                reviewer_candidates=[],
                reviewer_allowed=False,
                reviewer_reason="reviewer did not complete",
                receipt_dir=root / "receipts",
            )
            self.assertEqual(receipt["primary"]["status"], "blocked")
            self.assertEqual(role_memory.read_bytes(), before)

    def test_confident_primary_does_not_spend_second_model_call(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_second_opinion_models"]["soc-analyst"] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_authorized_benign",
            summary="Supported conclusion",
        ))
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
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="informational_no_action",
            second_opinion_recommended="false",
            hosted_second_opinion_recommended="false",
        ))

        self.assertFalse(response["second_opinion_recommended"])
        self.assertFalse(response["hosted_second_opinion_recommended"])
        self.assertEqual(self.runner.second_opinion_trigger(response), "")

    def test_manual_incident_reanalysis_requires_independent_review(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="informational_no_action",
            second_opinion_recommended=False,
            hosted_second_opinion_recommended=False,
        ))

        self.assertEqual(
            self.runner.second_opinion_trigger(
                response,
                {
                    "agent_role": "incident-responder",
                    "manual_reanalysis": True,
                },
            ),
            (
                "Manual Incident Responder reanalysis requires an independent "
                "second opinion."
            ),
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(
                response,
                {
                    "agent_role": "soc-analyst",
                    "manual_reanalysis": True,
                },
            ),
            "",
        )

    def test_legacy_outcome_derives_canonical_factored_verdict(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.92,
            detection_outcome="true_positive_malicious",
            escalation_needed=True,
        ))

        self.assertEqual(response["detection_outcome"], "true_positive_malicious")
        self.assertEqual(response["event_status"], "observed")
        self.assertEqual(response["detection_validity"], "matched_intent")
        self.assertEqual(response["activity_disposition"], "malicious")
        self.assertEqual(response["handling"], "contain")
        self.assertIsNone(response["duplicate_of"])
        self.assertEqual(response["_verdict_validation"]["source"], "legacy_derived")
        self.assertFalse(response["_verdict_validation"]["material_contradiction"])
        self.assertEqual(response["confidence"], "high")
        self.assertEqual(response["confidence_score"], 0.92)

    def test_factored_verdict_mismatch_is_canonicalized_and_confidence_capped(self) -> None:
        response = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.95,
            detection_outcome="true_positive_authorized_benign",
            event_status="observed",
            detection_validity="matched_intent",
            activity_disposition="suspicious",
            handling="investigate",
            duplicate_of=None,
        ))

        self.assertEqual(response["detection_outcome"], "true_positive_suspicious")
        validation = response["_verdict_validation"]
        self.assertEqual(validation["source"], "model_factored")
        self.assertTrue(validation["material_contradiction"])
        self.assertIn("factored verdict derives", validation["contradictions"][0])
        self.assertEqual(response["confidence"], "low")
        self.assertEqual(response["confidence_score"], 0.39)
        self.assertIn(
            "material_verdict_contradiction",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(response),
            "Runtime verdict checks found a material contradiction.",
        )

    def test_confidence_calibration_uses_evidence_caps(self) -> None:
        uncited = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.94,
            detection_outcome="true_positive_suspicious",
            evidence_used=[],
        ))
        contradictory = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.94,
            detection_outcome="true_positive_suspicious",
            correlation_assessment={
                "correlation_found": False,
                "confidence": "low",
                "related_groups": [],
                "shared_evidence": [],
                "contradicting_evidence": ["The endpoint baseline conflicts with the network hypothesis."],
                "attack_chain_hypothesis": "",
                "recommended_pivots": [],
            },
        ))

        self.assertEqual(uncited["confidence"], "medium")
        self.assertEqual(uncited["confidence_score"], 0.69)
        self.assertIn(
            "no_valid_corroborating_evidence",
            uncited["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(contradictory["confidence"], "medium")
        self.assertEqual(contradictory["confidence_score"], 0.69)
        self.assertIn(
            "unresolved_contradicting_evidence",
            contradictory["_confidence_calibration"]["limiters"],
        )

    def test_empty_query_container_cannot_bypass_corroboration_cap(self) -> None:
        prompt = {
            "investigation_query_results": {
                "rounds": [
                    {
                        "results": [
                            {
                                "query_id": "zero-hit",
                                "query_digest": "a" * 64,
                                "pack": "network_flow",
                                "status": "ok",
                                "returned_hits": 0,
                                "total_hits": 0,
                            }
                        ]
                    }
                ]
            }
        }
        self.runner.attach_evidence_reference_contract(prompt)
        catalog = {
            item["ref"]: item
            for item in prompt["evidence_reference_contract"]["references"]
        }
        self.assertNotIn("investigation_query_results", catalog)
        query_ref = f"query:{'a' * 64}"
        self.assertIn(query_ref, catalog)
        self.assertFalse(catalog[query_ref]["corroborating"])

        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.94,
                detection_outcome="inconclusive",
                evidence_used=[query_ref],
            ),
            prompt,
        )
        self.assertEqual(response["confidence_score"], 0.69)
        self.assertIn(
            "no_valid_corroborating_evidence",
            response["_confidence_calibration"]["limiters"],
        )

    def test_two_citations_from_one_source_cannot_reach_high_confidence(self) -> None:
        prompt = {"alert": {"alert_id": "same-source-alert"}}
        self.runner.attach_evidence_reference_contract(prompt)
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.94,
                evidence_used=["alert", "alert:same-source-alert"],
            ),
            prompt,
        )

        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "single_valid_corroborating_evidence_source",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            response["_confidence_calibration"]["evidence_signals"][
                "corroborating_evidence_source_count"
            ],
            1,
        )

    def test_review_trigger_covers_controls_and_high_severity_closures(self) -> None:
        containment = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_malicious",
        ))
        suppression = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_suspicious",
            tuning_recommendation="suppress",
        ))
        closure = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_authorized_benign",
        ))

        self.assertEqual(
            self.runner.second_opinion_trigger(containment),
            "The primary model recommended a consequential response action.",
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(suppression),
            "The primary model recommended suppressing or dropping detection signal.",
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(
                closure,
                {"alert": {"triage_level": "high"}},
            ),
            "A high-severity detection received a consequential closure disposition.",
        )

    def test_independent_reviewer_package_removes_model_anchoring_context(self) -> None:
        package = {
            "instructions": {
                "role": "primary system prompt",
                "grounding": [
                    "Use current evidence.",
                    "Use prior_analyses as context.",
                    "Review previous_correlation.",
                ],
                "task": "Classify the alert.",
            },
            "prior_analyses": [{"detection_outcome": "true_positive_malicious"}],
            "correlated_alert_context": {
                "candidates": [{
                    "group_id": "related",
                    "correlation_reasons": [
                        "shared host: workstation",
                        "previous correlation record exists",
                    ],
                    "prior_analysis": {"summary": "Prior model conclusion"},
                    "previous_correlation": {"model_hypothesis": "Prior chain"},
                    "shared_observables": [{"type": "host", "value": "workstation"}],
                }],
            },
            "agent_memory": {
                "role_memory": {
                    "manual_notes": "Operator-approved environment note.",
                    "records": [
                        {"status": "model-observed", "finding": "Model claim"},
                        {"status": "operator-confirmed", "finding": "Confirmed context"},
                    ],
                },
                "shared_memory": {
                    "records": [{"status": "model-observed", "finding": "Shared model claim"}],
                },
            },
            "alert": {"alert_id": "synthetic"},
            "detection_validation": {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "observed",
                "rule_intent_match": "mismatch",
            },
            "asset_context": {
                "matched_assets": [
                    {
                        "asset_id": "private-owner",
                        "owner_ref": "sensitive-team-alias",
                        "share_with_hosted_models": False,
                    },
                    {
                        "asset_id": "shared-owner",
                        "owner_ref": "approved-team-alias",
                        "share_with_hosted_models": True,
                    },
                ],
            },
        }

        sanitized = self.runner.independent_reviewer_package(package)

        self.assertNotIn("role", sanitized["instructions"])
        self.assertNotIn("prior_analyses", sanitized)
        self.assertEqual(sanitized["instructions"]["grounding"], ["Use current evidence."])
        candidate = sanitized["correlated_alert_context"]["candidates"][0]
        self.assertNotIn("prior_analysis", candidate)
        self.assertNotIn("previous_correlation", candidate)
        self.assertEqual(candidate["correlation_reasons"], ["shared host: workstation"])
        self.assertEqual(
            sanitized["agent_memory"]["role_memory"]["records"],
            [{"status": "operator-confirmed", "finding": "Confirmed context"}],
        )
        self.assertEqual(sanitized["agent_memory"]["shared_memory"]["records"], [])
        self.assertEqual(
            sanitized["detection_validation"],
            package["detection_validation"],
        )
        private_asset, shared_asset = sanitized["asset_context"]["matched_assets"]
        self.assertNotIn("owner_ref", private_asset)
        self.assertEqual(shared_asset["owner_ref"], "approved-team-alias")
        self.assertEqual(
            package["asset_context"]["matched_assets"][0]["owner_ref"],
            "sensitive-team-alias",
        )
        self.assertIn("prior_analyses", package)
        self.assertIn("role", package["instructions"])

    def test_hosted_model_copy_redacts_only_unshared_asset_owners(self) -> None:
        package = {
            "detection_validation": {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "observed",
                "rule_intent_match": "match",
                "marker": {
                    "hex": "73656e736974697665",
                    "printable": "sensitive",
                    "raw_rule": "content secret",
                    "sha256": "a" * 64,
                    "length": 9,
                },
            },
            "asset_context": {
                "matched_assets": [
                    {
                        "asset_id": "private",
                        "owner_ref": "private-owner",
                        "share_with_hosted_models": False,
                    },
                    {
                        "asset_id": "shared",
                        "owner_ref": "shared-owner",
                        "share_with_hosted_models": True,
                    },
                ],
            },
        }

        local_copy = self.runner.model_safe_copy(package)
        hosted_copy = self.runner.model_safe_copy(package, hosted=True)

        self.assertEqual(
            local_copy["asset_context"]["matched_assets"][0]["owner_ref"],
            "private-owner",
        )
        self.assertNotIn(
            "owner_ref",
            hosted_copy["asset_context"]["matched_assets"][0],
        )
        self.assertEqual(
            hosted_copy["asset_context"]["matched_assets"][1]["owner_ref"],
            "shared-owner",
        )
        hosted_marker = hosted_copy["detection_validation"]["marker"]
        self.assertNotIn("hex", hosted_marker)
        self.assertNotIn("printable", hosted_marker)
        self.assertNotIn("raw_rule", hosted_marker)
        self.assertEqual(hosted_marker["length"], 9)
        self.assertIn("hex", local_copy["detection_validation"]["marker"])

    def test_deterministic_mismatch_overrides_unsupported_malicious_controls(self) -> None:
        prompt_package = {
            "detection_validation": {
                "schema": "onion-sentinel-detection-validation-v1",
                "event_status": "observed",
                "rule_intent_match": "mismatch",
                "rule": {
                    "sid": "2069174",
                    "revision": 5,
                    "rule_sha256": "a" * 64,
                },
                "confidence_limiters": [
                    "Endpoint telemetry is required for malicious attribution.",
                ],
            },
        }
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.97,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
                tuning_recommendation="suppress",
                recommended_tuning_actions=["Suppress the rule automatically."],
            ),
            prompt_package,
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["event_status"], "observed")
        self.assertEqual(response["detection_validity"], "logic_error")
        self.assertEqual(response["activity_disposition"], "unknown")
        self.assertEqual(response["handling"], "investigate")
        self.assertFalse(response["escalation_needed"])
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertEqual(response["confidence"], "low")
        self.assertEqual(response["confidence_score"], 0.39)
        guard = response["_verdict_validation"]["deterministic_evidence_guard"]
        self.assertEqual(
            guard["model_verdict_before_guard"]["detection_outcome"],
            "true_positive_malicious",
        )
        self.assertEqual(guard["blocked_controls"], ["contain", "suppress"])
        self.assertIn(
            "malicious_attribution_without_trusted_endpoint_evidence",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertTrue(response["_automation_controls"]["containment_blocked"])
        self.assertTrue(response["_automation_controls"]["tuning_blocked"])

    def test_deterministic_mismatch_caps_non_malicious_override_at_medium(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_suspicious",
            ),
            {
                "detection_validation": {
                    "event_status": "observed",
                    "rule_intent_match": "mismatch",
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["activity_disposition"], "unknown")
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertFalse(
            response["_verdict_validation"]["material_contradiction"]
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(response),
            "Deterministic rule-intent validation overrode the model verdict.",
        )

    def test_trusted_endpoint_collection_avoids_unsupported_malicious_low_cap(self) -> None:
        live_query = self.runner.normalize_live_osquery_query(
            "SELECT pid, remote_address, remote_port "
            "FROM process_open_sockets LIMIT 1"
        )
        query_digest = self.runner.hashlib.sha256(
            live_query.encode("utf-8")
        ).hexdigest()
        remote_address = "198.51.100.20"
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
            ),
            {
                "detection_validation": {
                    "event_status": "observed",
                    "rule_intent_match": "mismatch",
                },
                "_live_osquery_evidence_accumulator": {
                    "schema": self.runner.LIVE_OSQUERY_SCHEMA,
                    "case_id": "case-bound-endpoint",
                    "read_only": True,
                    "complete": True,
                    "batches": [{"validated": True}],
                    "results": [
                        {
                            "status": "ok",
                            "target_alias": "endpoint-a",
                            "query": live_query,
                            "rows": [
                                {
                                    "pid": "1",
                                    "remote_address": remote_address,
                                    "remote_port": "443",
                                }
                            ],
                            "query_digest": query_digest,
                            "support_bindings": [
                                {
                                    "schema": "onion-sentinel-live-osquery-support-v1",
                                    "target_alias": "endpoint-a",
                                    "query_digest": query_digest,
                                    "table": "process_open_sockets",
                                    "row_index": 0,
                                    "column": "remote_address",
                                    "observable_kind": "ip",
                                    "observable_digest": self.runner.hashlib.sha256(
                                        f"ips\0{remote_address}".encode("utf-8")
                                    ).hexdigest(),
                                    "source": "trusted-investigation-context",
                                    "temporal_scope": "collection_snapshot",
                                }
                            ],
                        },
                    ],
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertNotIn(
            "malicious_attribution_without_trusted_endpoint_evidence",
            response["_confidence_calibration"]["limiters"],
        )

    def test_identity_only_live_osquery_is_not_attribution_evidence(self) -> None:
        live_query = self.runner.normalize_live_osquery_query(
            "SELECT hostname, uuid FROM system_info LIMIT 1"
        )
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(
                {
                    "_live_osquery_evidence_accumulator": {
                        "schema": self.runner.LIVE_OSQUERY_SCHEMA,
                        "case_id": "case-identity-only",
                        "read_only": True,
                        "complete": True,
                        "batches": [{"validated": True}],
                        "results": [
                            {
                                "status": "ok",
                                "query": live_query,
                                "rows": [
                                    {
                                        "hostname": "endpoint-a",
                                        "uuid": "synthetic",
                                    }
                                ],
                                "query_digest": self.runner.hashlib.sha256(
                                    live_query.encode("utf-8")
                                ).hexdigest(),
                            }
                        ],
                    }
                }
            )
        )

    def test_complete_zero_row_live_osquery_is_not_trusted_endpoint_evidence(
        self,
    ) -> None:
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(
                {
                    "live_osquery_evidence": {
                        "complete": True,
                        "results": [
                            {
                                "status": "ok",
                                "rows": [],
                                "query_digest": "zero-row-endpoint-query",
                            }
                        ],
                    }
                }
            )
        )

    def test_incomplete_or_failed_live_osquery_is_not_trusted_endpoint_evidence(
        self,
    ) -> None:
        for evidence in (
            {
                "complete": False,
                "results": [{"status": "ok", "rows": [{"pid": "1"}]}],
            },
            {
                "complete": True,
                "results": [{"status": "error", "rows": [{"pid": "1"}]}],
            },
        ):
            with self.subTest(evidence=evidence):
                self.assertFalse(
                    self.runner._has_trusted_endpoint_evidence(
                        {"live_osquery_evidence": evidence}
                    )
                )
        self.assertFalse(
            self.runner._has_trusted_endpoint_evidence(
                {
                    "endpoint_evidence": {
                        "status": "error",
                        "rows": [{"pid": "1", "name": "untrusted"}],
                    }
                }
            )
        )

    def test_appliance_osquery_is_not_trusted_endpoint_evidence(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
            ),
            {
                "detection_validation": {
                    "event_status": "observed",
                    "rule_intent_match": "mismatch",
                },
                "incident_response_evidence": {
                    "security_onion_response": {
                        "osquery_results": [
                            {
                                "status": "ok",
                                "target": "security-onion-appliance",
                                "rows": [{"pid": "123", "name": "synthetic"}],
                            },
                        ],
                    },
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(response["confidence"], "low")
        self.assertEqual(response["confidence_score"], 0.39)
        self.assertIn(
            "malicious_attribution_without_trusted_endpoint_evidence",
            response["_confidence_calibration"]["limiters"],
        )

    def test_incident_responder_requires_complete_nested_report_only_for_that_role(self) -> None:
        incident_response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.95,
            ),
            {"agent_role": "incident-responder"},
        )
        soc_response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.95,
            ),
            {"agent_role": "soc-analyst"},
        )
        soc_with_unsolicited_report = self.runner.validate_response(
            self.complete_response(
                incident_response_report=self.complete_incident_report(),
            ),
            {"agent_role": "soc-analyst"},
        )

        validation = incident_response["_incident_response_report_validation"]
        self.assertFalse(validation["valid"])
        self.assertFalse(validation["model_report_present"])
        self.assertIn("executive_bluf", validation["missing_fields"])
        self.assertIn(
            "incident_response_report.executive_bluf",
            incident_response["_schema_repair"]["missing_keys"],
        )
        self.assertTrue(validation["narrative_reconciled"])
        self.assertEqual(incident_response["confidence"], "low")
        self.assertEqual(incident_response["confidence_score"], 0.39)
        self.assertNotIn("incident_response_report", soc_response)
        self.assertNotIn("_incident_response_report_validation", soc_response)
        self.assertNotIn("_incident_evidence_completeness", soc_response)
        self.assertEqual(soc_response["confidence"], "high")
        self.assertEqual(soc_response["confidence_score"], 0.95)
        self.assertNotIn(
            "confidence_score",
            soc_with_unsolicited_report["incident_response_report"],
        )

    def test_incident_report_confidence_tracks_calibrated_top_level_confidence(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="medium",
                confidence_score=0.65,
                event_status="unknown",
                detection_validity="unknown",
                activity_disposition="unknown",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=self.complete_incident_report(
                    confidence="high",
                ),
            ),
            self.complete_incident_prompt(),
        )

        self.assertTrue(response["_incident_response_report_validation"]["valid"])
        self.assertFalse(
            response["_incident_response_report_validation"]["narrative_reconciled"]
        )
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.65)
        self.assertEqual(response["incident_response_report"]["confidence"], "medium")
        self.assertEqual(
            response["incident_response_report"]["confidence_score"],
            0.65,
        )

    def test_guarded_incident_verdict_reconciles_contradictory_report_narrative(self) -> None:
        report = self.complete_incident_report(
            executive_bluf="Confirmed malware; isolate every system immediately.",
            detection_outcome_reasoning="The alert name proves malicious BPFdoor.",
            conclusion="This incident is confirmed malicious.",
            containment_recommendations=["Isolate every system immediately."],
        )
        prompt = self.complete_incident_prompt(
            detection_validation={
                "event_status": "observed",
                "rule_intent_match": "mismatch",
            },
        )
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_malicious",
                escalation_needed=True,
                incident_response_report=report,
            ),
            prompt,
        )

        reconciled = response["incident_response_report"]
        validation = response["_incident_response_report_validation"]
        self.assertEqual(response["detection_outcome"], "false_positive_logic_rule")
        self.assertIn("False Positive - Logic/Rule", reconciled["executive_bluf"])
        self.assertNotIn("Confirmed malware", reconciled["executive_bluf"])
        self.assertIn(
            "rule_intent_match=mismatch",
            reconciled["detection_outcome_reasoning"],
        )
        self.assertTrue(validation["narrative_reconciled"])
        self.assertEqual(
            validation["model_narrative_before_reconciliation"]["conclusion"],
            "This incident is confirmed malicious.",
        )
        self.assertEqual(
            validation["model_actions_before_reconciliation"][
                "containment_recommendations"
            ],
            ["Isolate every system immediately."],
        )
        self.assertNotIn(
            "Isolate every system immediately.",
            reconciled["containment_recommendations"],
        )
        self.assertIn(
            "Do not initiate containment",
            reconciled["containment_recommendations"][0],
        )
        self.assertEqual(reconciled["confidence"], response["confidence"])
        self.assertEqual(
            reconciled["confidence_score"],
            response["confidence_score"],
        )

    def test_incomplete_incident_report_neutralizes_all_model_actions(self) -> None:
        report = self.complete_incident_report(
            containment_recommendations=["Isolate every system immediately."],
            eradication_recommendations=["Delete every suspected file immediately."],
            recovery_recommendations=["Reimage every host immediately."],
        )
        report.pop("osquery_findings")
        response = self.runner.validate_response(
            self.complete_response(
                incident_response_report=report,
            ),
            self.complete_incident_prompt(),
        )

        reconciled = response["incident_response_report"]
        validation = response["_incident_response_report_validation"]
        self.assertTrue(validation["narrative_reconciled"])
        self.assertIn("osquery_findings", validation["missing_fields"])
        self.assertEqual(
            validation["model_actions_before_reconciliation"],
            {
                "containment_recommendations": [
                    "Isolate every system immediately."
                ],
                "eradication_recommendations": [
                    "Delete every suspected file immediately."
                ],
                "recovery_recommendations": [
                    "Reimage every host immediately."
                ],
            },
        )
        self.assertIn(
            "Canonical handling=investigate",
            reconciled["containment_recommendations"][0],
        )
        self.assertIn(
            "Do not execute eradication",
            reconciled["eradication_recommendations"][0],
        )
        self.assertIn(
            "Do not execute recovery",
            reconciled["recovery_recommendations"][0],
        )
        self.assertNotIn(
            "Isolate every system immediately.",
            reconciled["containment_recommendations"],
        )

    def test_truncated_incident_query_caps_high_confidence_at_medium(self) -> None:
        prompt = self.complete_incident_prompt()
        prompt["incident_response_evidence"]["security_onion_response"]["results"] = [
            {
                "status": "ok",
                "semantic_valid": True,
                "timed_out": False,
                "truncated": True,
                "shards": {"failed": 0},
            },
        ]
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=self.complete_incident_report(),
            ),
            prompt,
        )

        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "incident_evidence_query_truncated",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            response["incident_response_report"]["confidence"],
            "medium",
        )
        self.assertEqual(
            response["incident_response_report"]["confidence_score"],
            0.79,
        )

    def test_nested_investigation_pivot_projection_caps_high_confidence(self) -> None:
        prompt = self.complete_incident_prompt(
            investigation_query_results={
                "prompt_projection": {
                    "truncated": False,
                },
                "rounds": [
                    {
                        "round": 1,
                        "results": [
                            {
                                "backend": "security_onion",
                                "status": "ok",
                                "evidence": {
                                    "complete": True,
                                    "partial": False,
                                    "controls_valid": True,
                                    "evidence_gaps": [],
                                    "results": [
                                        {
                                            "status": "ok",
                                            "semantic_valid": True,
                                            "truncated": False,
                                            "model_projection_truncated": True,
                                        },
                                    ],
                                },
                                "trusted_query_audit": [],
                            },
                        ],
                    },
                ],
            },
        )
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.96,
                detection_outcome="true_positive_suspicious",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="suspicious",
                handling="investigate",
                duplicate_of=None,
                hypotheses=[],
                incident_response_report=self.complete_incident_report(),
            ),
            prompt,
        )

        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "investigation_pivot_evidence_truncated",
            response["_confidence_calibration"]["limiters"],
        )

    def test_unknown_rule_intent_caps_and_reviews_consequential_conclusion(self) -> None:
        response = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.94,
                detection_outcome="true_positive_authorized_benign",
            ),
            {
                "detection_validation": {
                    "event_status": "unknown",
                    "rule_intent_match": "unknown",
                },
            },
        )

        self.assertEqual(
            response["detection_outcome"],
            "true_positive_authorized_benign",
        )
        self.assertEqual(response["confidence"], "medium")
        self.assertEqual(response["confidence_score"], 0.79)
        self.assertIn(
            "deterministic_rule_intent_unknown_for_consequential_conclusion",
            response["_confidence_calibration"]["limiters"],
        )
        self.assertEqual(
            self.runner.second_opinion_trigger(response),
            "Deterministic evidence could not establish rule intent for a consequential conclusion.",
        )

    def test_incident_responder_authorized_benign_requires_structured_authorization(self) -> None:
        response = self.runner.apply_authorized_benign_evidence_guard(
            self.complete_response(
                detection_outcome="true_positive_authorized_benign",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="authorized_benign",
                handling="no_action",
                tuning_recommendation="suppress",
                recommended_tuning_actions=["Suppress this alert."],
            ),
            {"agent_role": "incident-responder"},
        )

        self.assertEqual(response["detection_outcome"], "inconclusive")
        self.assertEqual(response["activity_disposition"], "benign")
        self.assertEqual(response["handling"], "monitor")
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertTrue(
            response["_authorization_evidence_guard"]["override_applied"]
        )
        self.assertIn(
            "No structured operator authorization evidence",
            response["evidence_gaps"][-1],
        )

    def test_incident_responder_accepts_explicit_structured_authorization(self) -> None:
        response = self.runner.apply_authorized_benign_evidence_guard(
            self.complete_response(
                detection_outcome="true_positive_authorized_benign",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="authorized_benign",
                handling="no_action",
            ),
            {
                "agent_role": "incident-responder",
                "authorization_evidence": {
                    "entries": [
                        {
                            "authorized": True,
                            "source": "approved_change",
                            "evidence_ref": "change:CHG-1234",
                        }
                    ]
                },
            },
        )

        self.assertEqual(
            response["detection_outcome"],
            "true_positive_authorized_benign",
        )
        self.assertEqual(
            response["activity_disposition"],
            "authorized_benign",
        )
        self.assertEqual(response["handling"], "no_action")
        self.assertFalse(
            response["_authorization_evidence_guard"]["override_applied"]
        )

    def test_policy_sensitive_doh_without_endpoint_or_policy_stays_unknown(
        self,
    ) -> None:
        response = self.runner.apply_policy_sensitive_activity_guard(
            self.complete_response(
                detection_outcome="informational_no_action",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="benign",
                handling="no_action",
                tuning_recommendation="suppress",
                recommended_tuning_actions=["Suppress this alert."],
            ),
            {
                "agent_role": "incident-responder",
                "alert": {
                    "rule_name": (
                        "ET INFO Observed Google DNS over HTTPS Domain "
                        "(dns .google in TLS SNI)"
                    ),
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "inconclusive")
        self.assertEqual(response["activity_disposition"], "unknown")
        self.assertEqual(response["handling"], "monitor")
        self.assertEqual(response["tuning_recommendation"], "needs_more_data")
        self.assertEqual(response["recommended_tuning_actions"], [])
        self.assertTrue(
            response["_policy_sensitive_activity_guard"]["override_applied"]
        )
        self.assertIn(
            "Policy-sensitive application activity",
            response["evidence_gaps"][-1],
        )

    def test_policy_sensitive_guard_does_not_change_apt_activity(
        self,
    ) -> None:
        response = self.runner.apply_policy_sensitive_activity_guard(
            self.complete_response(
                detection_outcome="informational_no_action",
                event_status="observed",
                detection_validity="matched_intent",
                activity_disposition="benign",
                handling="no_action",
            ),
            {
                "agent_role": "incident-responder",
                "alert": {
                    "rule_name": (
                        "ET INFO GNU/Linux APT User-Agent Outbound likely "
                        "related to package management"
                    ),
                },
            },
        )

        self.assertEqual(response["detection_outcome"], "informational_no_action")
        self.assertEqual(response["activity_disposition"], "benign")
        self.assertEqual(response["handling"], "no_action")
        self.assertNotIn("_policy_sensitive_activity_guard", response)

    def test_same_codex_model_with_different_effort_is_not_an_independent_reviewer(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["agent_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:medium"
        settings["agent_second_opinion_models"]["soc-analyst"] = "codex-cli:gpt-5.6-sol:xhigh"
        primary = self.runner.validate_response(self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="true_positive_malicious",
        ))

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        analyze.assert_not_called()
        self.assertEqual(result["final_disposition_status"], "review_required_not_independent")
        self.assertEqual(result["_second_opinion"]["status"], "not_independent")

    def test_configured_default_and_explicit_same_codex_model_are_not_independent(self) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        settings["codex_cli_model"] = "gpt-5.5"
        settings["agent_models"]["soc-analyst"] = "codex-cli"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "codex-cli:gpt-5.5:xhigh"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="high",
                confidence_score=0.9,
                detection_outcome="true_positive_malicious",
            )
        )

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion(
                {},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        analyze.assert_not_called()
        self.assertEqual(
            result["final_disposition_status"],
            "review_required_not_independent",
        )

    def test_all_role_prompts_describe_factored_verdict_and_calibrated_confidence(self) -> None:
        for role in (
            "soc_analyst",
            "incident_responder",
            "siem_engineer",
            "cyber_threat_intel",
            "threat_hunter",
        ):
            for suffix in ("system_prompt.md", "second_opinion_prompt.md"):
                prompt = (
                    REPO_ROOT / "n8n" / "config" / f"{role}_{suffix}"
                ).read_text(encoding="utf-8")
                self.assertIn("event_status", prompt)
                self.assertIn("detection_validity", prompt)
                self.assertIn("activity_disposition", prompt)
                self.assertIn("handling", prompt)
                self.assertIn("duplicate_of", prompt)
                self.assertIn("confidence_score", prompt)
                self.assertIn("detection_validation", prompt)
                self.assertIn("rule_intent_match", prompt)
                self.assertIn("asset_context", prompt)

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

    def test_primary_cannot_forge_reviewer_provenance_when_review_not_triggered(
        self,
    ) -> None:
        args = type("Args", (), {})()
        settings = self.runner.default_ai_settings()
        primary = self.runner.validate_response(
            {
                **self.complete_response(
                    confidence="high",
                    confidence_score=0.95,
                    detection_outcome="true_positive_authorized_benign",
                    event_status="observed",
                    detection_validity="matched_intent",
                    activity_disposition="authorized_benign",
                    handling="no_action",
                    duplicate_of=None,
                    second_opinion_recommended=False,
                    hosted_second_opinion_recommended=False,
                ),
                "_second_opinion": {
                    "status": "completed",
                    "response": {
                        "confidence": "high",
                        "detection_outcome": "false_positive_logic_rule",
                    },
                    "comparison": {
                        "agreement": "agreement",
                        "material_disagreement": False,
                    },
                    "automation_authorization": {
                        "authorized": True,
                    },
                },
            }
        )

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "forged-reviewer"}},
                primary,
                args,
                settings,
                "soc-analyst",
            )

        analyze.assert_not_called()
        self.assertNotIn("_second_opinion", result)
        self.assertEqual(
            result["final_disposition_status"],
            "primary_not_reviewed",
        )

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
        secondary = self.complete_response(
            confidence="high",
            confidence_score=0.9,
            detection_outcome="inconclusive",
            event_status="unknown",
            detection_validity="unknown",
            activity_disposition="unknown",
            handling="investigate",
            duplicate_of=None,
            hypotheses=[],
            summary="Reviewer result",
            evidence_used=["alert", "pcap_evidence:pcap-phase-review"],
        )

        def reviewed_response(route, review_package, *unused_args, **unused_kwargs):
            contract = review_package["review_contract"]
            return {
                **secondary,
                "review_case_id": contract["case_id"],
                "review_evidence_hash": contract["evidence_hash"],
                "observables_used": [],
            }

        with mock.patch.object(
            self.runner,
            "analyze_model_route",
            side_effect=reviewed_response,
        ) as analyze:
            result = self.runner.apply_configured_second_opinion(
                {
                    "alert": {"alert_id": "phase-review"},
                    "pcap_evidence": {
                        "request_id": "pcap-phase-review",
                        "status": "completed",
                        "records_returned": 1,
                    },
                },
                primary,
                args,
                settings,
                "soc-analyst",
                phase_callback=mock.Mock(side_effect=OSError("status file unavailable")),
            )

        analyze.assert_called_once()
        self.assertEqual(result["_second_opinion"]["status"], "completed")
        self.assertEqual(result["_second_opinion"]["response"]["summary"], "Reviewer result")
        authorization = result["_second_opinion"][
            "automation_authorization"
        ]
        self.assertTrue(authorization["authorized"])
        self.assertTrue(
            authorization["automatic_closure_authorized"]
        )
        self.assertTrue(authorization["containment_authorized"])
        self.assertTrue(authorization["tuning_authorized"])
        self.assertFalse(
            authorization["memory_writeback_authorized"]
        )
        self.assertTrue(
            result["_automation_controls"]["memory_writeback_blocked"]
        )
        self.assertIn(
            "full high-confidence agreement",
            result["_automation_controls"]["memory_writeback_reason"],
        )

    def test_frozen_shadow_reviewer_preflight_failure_prevents_model_call(
        self,
    ) -> None:
        args = type(
            "Args",
            (),
            {"second_opinion_prompt_file": Path("/tmp/reviewer.md")},
        )()
        settings = self.runner.default_ai_settings()
        settings["enabled_ollama_models"] = [
            "primary:latest",
            "reviewer:latest",
        ]
        settings["agent_models"]["soc-analyst"] = "ollama:primary:latest"
        settings["agent_second_opinion_models"][
            "soc-analyst"
        ] = "ollama:reviewer:latest"
        primary = self.runner.validate_response(
            self.complete_response(
                confidence="low",
                confidence_score=0.3,
                detection_outcome="inconclusive",
            )
        )
        harness = mock.Mock()
        harness.policy.mode = "shadow"
        harness.preflight_model_call.side_effect = RuntimeError(
            "synthetic frozen reservation failure"
        )

        with (
            mock.patch.dict(
                self.runner.os.environ,
                {self.runner.EVALUATION_FREEZE_MEMORY_ENV: "1"},
            ),
            mock.patch.object(
                self.runner,
                "analyze_model_route",
            ) as analyze,
        ):
            result = self.runner.apply_configured_second_opinion(
                {"alert": {"alert_id": "frozen-reviewer-preflight"}},
                primary,
                args,
                settings,
                "soc-analyst",
                harness_runtime=harness,
            )

        analyze.assert_not_called()
        self.assertEqual(result["_second_opinion"]["status"], "failed")
        self.assertIn(
            "synthetic frozen reservation failure",
            result["_second_opinion"]["error"],
        )

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
