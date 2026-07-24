#!/usr/bin/env python3
"""Contract tests for provider rosters and exact per-agent model routing."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
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
            [{"enabled": True, "model": "gpt-5.5", "reasoning_effort": "medium"}],
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

        with mock.patch.object(
            self.runner,
            "_ollama_request",
            return_value={"summary": "Independent review"},
        ) as request:
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

        with mock.patch.object(self.runner, "analyze_model_route", return_value=secondary) as analyze:
            result = self.runner.apply_configured_second_opinion({}, primary, args, settings, "soc-analyst")

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

        with mock.patch.object(self.runner, "analyze_model_route") as analyze:
            result = self.runner.apply_configured_second_opinion({}, primary, args, settings, "soc-analyst")

        self.assertIs(result, primary)
        self.assertNotIn("_second_opinion", result)
        analyze.assert_not_called()

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
