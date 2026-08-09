#!/usr/bin/env python3
"""Direct contracts for scheduler runner argv and child isolation."""
from __future__ import annotations

from pathlib import Path
import re
from types import SimpleNamespace
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from scheduler_runner_invocation import (  # noqa: E402
    CONTROLLED_RESULT_ENVIRONMENT,
    RunnerInvocationDefaults,
    RunnerInvocationSources,
    analysis_command,
    controlled_child_environment,
    invoke_analysis_runner,
)


class SchedulerRunnerInvocationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.defaults = RunnerInvocationDefaults(
            python_executable="/usr/bin/python3",
            runner_path=Path("/runtime/run-local-ai-analysis.py"),
            prompt_dir=Path("/runtime/prompts"),
            harness_policy=Path("/runtime/harness.json"),
            disagreement_prompt=Path("/runtime/disagreement.md"),
            live_osquery_config=Path("/runtime/osquery.json"),
            incident_evidence_config=Path("/runtime/evidence.json"),
            investigation_pivot_dir=Path("/runtime/pivots"),
            max_stdout_bytes=111,
            max_stderr_bytes=222,
            token_environment_key="ONION_SENTINEL_EVALUATION_TOKEN",
            token_pattern=re.compile(r"[a-f0-9]{64}"),
        )
        self.run_command = mock.Mock(return_value=object())
        self.environment = {"TMPDIR": "/runtime/tmp", "PRESERVED": "yes"}
        self.sources = RunnerInvocationSources(
            effective_prompt_limit=lambda _args, **_kwargs: 765432,
            role_prompt_file=lambda directory, role: directory / f"{role}.md",
            role_second_opinion_prompt_file=(
                lambda directory, role: directory / f"{role}-review.md"
            ),
            run_command=self.run_command,
            environment_snapshot=lambda: dict(self.environment),
            fallback_evaluation_token=lambda: "a" * 64,
        )
        self.args = SimpleNamespace(
            analysis_dir=Path("/runtime/output"),
            timeout=240,
            alert_store_url="http://127.0.0.1:18787",
            ai_settings_file=Path("/runtime/config/settings.json"),
            model="gpt-5.5",
        )

    @staticmethod
    def command_value(command: list[str], flag: str) -> str:
        return command[command.index(flag) + 1]

    def test_command_projects_defaults_role_model_and_attempt(self) -> None:
        command = analysis_command(
            self.defaults,
            self.sources,
            Path("/runtime/prompts/alert.json"),
            self.args,
            reanalysis_attempt_id="attempt-1",
            agent_role="incident-responder",
        )

        self.assertEqual(
            command[:2],
            ["/usr/bin/python3", str(self.defaults.runner_path)],
        )
        expected = {
            "--prompt-dir": self.defaults.prompt_dir,
            "--investigation-harness-policy": self.defaults.harness_policy,
            "--disagreement-adjudicator-prompt-file": (
                self.defaults.disagreement_prompt
            ),
            "--live-osquery-config": self.defaults.live_osquery_config,
            "--incident-evidence-config": self.defaults.incident_evidence_config,
            "--investigation-pivot-dir": self.defaults.investigation_pivot_dir,
            "--system-prompt-file": Path("/runtime/config/incident-responder.md"),
            "--second-opinion-prompt-file": Path(
                "/runtime/config/incident-responder-review.md"
            ),
        }
        for flag, path in expected.items():
            with self.subTest(flag=flag):
                self.assertEqual(self.command_value(command, flag), str(path))
        self.assertEqual(
            self.command_value(command, "--max-prompt-bytes"),
            "765432",
        )
        self.assertEqual(self.command_value(command, "--model"), "gpt-5.5")
        self.assertEqual(
            self.command_value(command, "--reanalysis-attempt-id"),
            "attempt-1",
        )

    def test_normal_invocation_inherits_environment_and_uses_watchdog(self) -> None:
        progress = mock.Mock()
        completed = invoke_analysis_runner(
            self.defaults,
            self.sources,
            Path("/runtime/prompts/alert.json"),
            self.args,
            progress_callback=progress,
        )

        self.assertIs(completed, self.run_command.return_value)
        options = self.run_command.call_args.kwargs
        self.assertIsNone(options["env"])
        self.assertEqual(options["timeout_seconds"], (240 * 5) + 300)
        self.assertEqual(options["max_stdout_bytes"], 111)
        self.assertEqual(options["max_stderr_bytes"], 222)
        self.assertIs(options["progress_callback"], progress)
        self.assertEqual(options["progress_interval_seconds"], 60)

    def test_controlled_environment_projects_every_frozen_field(self) -> None:
        identity = {
            field: (True if field == "reviewer_required" else f"value-{field}")
            for field in CONTROLLED_RESULT_ENVIRONMENT
        }
        environment = controlled_child_environment(
            self.defaults,
            self.sources,
            identity,
        )

        self.assertIsNotNone(environment)
        assert environment is not None
        self.assertEqual(environment["PRESERVED"], "yes")
        self.assertEqual(environment["TMPDIR"], "/runtime/tmp")
        self.assertEqual(
            environment["ONION_SENTINEL_EVALUATION_TOKEN"],
            "a" * 64,
        )
        for field, key in CONTROLLED_RESULT_ENVIRONMENT.items():
            expected = "1" if field == "reviewer_required" else f"value-{field}"
            with self.subTest(field=field):
                self.assertEqual(environment[key], expected)

    def test_live_token_precedes_fallback_and_false_reviewer_is_empty(self) -> None:
        self.environment["ONION_SENTINEL_EVALUATION_TOKEN"] = "b" * 64
        environment = controlled_child_environment(
            self.defaults,
            self.sources,
            {"reviewer_required": False},
        )

        assert environment is not None
        self.assertEqual(
            environment["ONION_SENTINEL_EVALUATION_TOKEN"],
            "b" * 64,
        )
        self.assertEqual(
            environment[CONTROLLED_RESULT_ENVIRONMENT["reviewer_required"]],
            "",
        )

    def test_whitespace_live_token_uses_valid_consumed_fallback(self) -> None:
        self.environment["ONION_SENTINEL_EVALUATION_TOKEN"] = "   "

        environment = controlled_child_environment(
            self.defaults,
            self.sources,
            {"job_id": 1},
        )

        assert environment is not None
        self.assertEqual(
            environment["ONION_SENTINEL_EVALUATION_TOKEN"],
            "a" * 64,
        )

    def test_invalid_fallback_token_is_not_injected(self) -> None:
        sources = RunnerInvocationSources(
            effective_prompt_limit=self.sources.effective_prompt_limit,
            role_prompt_file=self.sources.role_prompt_file,
            role_second_opinion_prompt_file=(
                self.sources.role_second_opinion_prompt_file
            ),
            run_command=self.run_command,
            environment_snapshot=lambda: dict(self.environment),
            fallback_evaluation_token=lambda: "invalid",
        )

        environment = controlled_child_environment(
            self.defaults,
            sources,
            {"job_id": 1},
        )

        assert environment is not None
        self.assertNotIn("ONION_SENTINEL_EVALUATION_TOKEN", environment)


if __name__ == "__main__":
    unittest.main()
