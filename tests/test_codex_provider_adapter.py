#!/usr/bin/env python3
"""Focused security contracts for the extracted Codex CLI adapter."""
from __future__ import annotations

import json
from pathlib import Path
import re
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.providers import cli_common, codex


class SyntheticProcessError(Exception):
    pass


class CodexProviderAdapterTests(unittest.TestCase):
    def args(self):
        return SimpleNamespace(timeout=15.0, max_response_bytes=4096)

    def chat(self, run_command, **overrides):
        values = {
            "prompt_package": {"alert": {"id": "synthetic"}},
            "args": self.args(),
            "settings": {"codex_cli_model": "gpt-5.6-sol"},
            "model": None,
            "reasoning_effort": "xhigh",
            "system_prompt_file": None,
            "independent_review": False,
            "resolve_executable": lambda _settings: "/opt/homebrew/bin/codex",
            "model_pattern": re.compile(r"^[A-Za-z0-9._-]+$"),
            "reasoning_efforts": frozenset({"medium", "xhigh"}),
            "prepare": lambda *_args, **_kwargs: (
                {"prompt_package": {}},
                '{"bounded":true}',
            ),
            "schema_builder": lambda value: value,
            "run_command": run_command,
            "sanitized_env": lambda _executable: {"PATH": "/usr/bin"},
            "process_error": SyntheticProcessError,
            "summarize": codex.summarize_failure,
            "read_bytes": lambda path, _maximum: path.read_bytes(),
            "extract_json": json.loads,
            "max_stderr_bytes": 1024,
            "controlled_tmpdir": None,
        }
        values.update(overrides)
        return codex.chat(**values)

    def test_fixed_argv_is_ephemeral_read_only_and_attests_model(self) -> None:
        observed = {}

        def run(command, **kwargs):
            observed["command"] = command
            observed["kwargs"] = kwargs
            output = Path(command[command.index("--output-last-message") + 1])
            output.write_text('{"summary":"bounded"}\n', encoding="utf-8")
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        result = self.chat(run)
        command = observed["command"]
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ignore-rules", command)
        self.assertIn("--ephemeral", command)
        self.assertEqual(command[command.index("--sandbox") + 1], "read-only")
        self.assertEqual(command[command.index("--model") + 1], "gpt-5.6-sol")
        self.assertIn('model_reasoning_effort="xhigh"', command)
        self.assertEqual(observed["kwargs"]["stdin_text"], '{"bounded":true}')
        self.assertEqual(result["_analysis_model"], "gpt-5.6-sol")
        self.assertEqual(result["_analysis_provider"], "codex-cli")

    def test_missing_executable_and_bounded_process_failure_are_classified(self) -> None:
        with self.assertRaisesRegex(SystemExit, "executable was not found"):
            self.chat(lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()))
        with self.assertRaisesRegex(SystemExit, "bounded failure"):
            self.chat(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    SyntheticProcessError("bounded failure")
                )
            )

    def test_nonzero_failure_never_echoes_prompt_transcript(self) -> None:
        def run(*_args, **_kwargs):
            return SimpleNamespace(
                returncode=1,
                stderr=(
                    "complete-secret-prompt-transcript\n"
                    "ERROR: provider rate limit exceeded\n"
                ),
                stdout="",
            )

        with self.assertRaises(SystemExit) as captured:
            self.chat(run)
        message = str(captured.exception)
        self.assertIn("provider rate or usage limit reached", message)
        self.assertNotIn("complete-secret", message)

    def test_missing_final_artifact_fails_closed(self) -> None:
        with self.assertRaisesRegex(SystemExit, "without a final response artifact"):
            self.chat(
                lambda *_args, **_kwargs: SimpleNamespace(
                    returncode=0,
                    stderr="",
                    stdout="",
                )
            )

    def test_model_and_effort_validation_precede_prompt_preparation(self) -> None:
        prepared: list[object] = []
        for overrides, message in (
            ({"model": "invalid model"}, "model name is invalid"),
            ({"reasoning_effort": "unsupported"}, "reasoning effort is invalid"),
        ):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(
                SystemExit, message
            ):
                self.chat(
                    lambda *_args, **_kwargs: None,
                    prepare=lambda *_args, **_kwargs: prepared.append(True),
                    **overrides,
                )
        self.assertEqual(prepared, [])

    def test_independent_review_writes_schema_before_process_invocation(self) -> None:
        trace: list[object] = []

        def schema_builder(template):
            trace.append(("schema", template))
            return {"strict": template}

        def run(command, **_kwargs):
            schema_path = Path(command[command.index("--output-schema") + 1])
            trace.append(("run", json.loads(schema_path.read_text(encoding="utf-8"))))
            final_path = Path(command[command.index("--output-last-message") + 1])
            final_path.write_text('{"summary":"reviewed"}', encoding="utf-8")
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        result = self.chat(
            run,
            independent_review=True,
            prepare=lambda *_args, **_kwargs: (
                {"prompt_package": {"response_schema": {"type": "object"}}},
                "{}",
            ),
            schema_builder=schema_builder,
        )
        self.assertEqual(trace, [
            ("schema", {"type": "object"}),
            ("run", {"strict": {"type": "object"}}),
        ])
        self.assertEqual(result["summary"], "reviewed")

    def test_final_artifact_is_read_before_temp_directory_cleanup_and_then_extracted(self) -> None:
        trace: list[object] = []
        final_path: list[Path] = []

        def run(command, **_kwargs):
            path = Path(command[command.index("--output-last-message") + 1])
            path.write_text('{"summary":"bounded"}', encoding="utf-8")
            final_path.append(path)
            trace.append("run")
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        def read(path: Path, maximum: int) -> bytes:
            trace.append(("read", path.is_file(), maximum))
            return path.read_bytes()

        def extract(value: str):
            trace.append(("extract", final_path[0].exists(), value))
            return json.loads(value)

        with tempfile.TemporaryDirectory() as controlled:
            result = self.chat(
                run,
                read_bytes=read,
                extract_json=extract,
                controlled_tmpdir=Path(controlled),
            )
            self.assertEqual(final_path[0].parent.parent, Path(controlled))
        self.assertEqual(trace, [
            "run",
            ("read", True, 4096),
            ("extract", False, '{"summary":"bounded"}'),
        ])
        self.assertEqual(result["_analysis_model_path"], "frontier-codex-cli")

    def test_invalid_utf8_propagates_before_json_extraction(self) -> None:
        extracted = mock.Mock()

        def run(command, **_kwargs):
            output = Path(command[command.index("--output-last-message") + 1])
            output.write_bytes(b"\xff")
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        with self.assertRaises(UnicodeDecodeError):
            self.chat(run, extract_json=extracted)
        extracted.assert_not_called()

    def test_sanitized_environment_does_not_inherit_provider_credentials(self) -> None:
        env = cli_common.sanitized_environment(
            "/opt/homebrew/bin/codex",
            environ={
                "HOME": "/synthetic/home",
                "LANG": "en_US.UTF-8",
                "OPENAI_API_KEY": "must-not-pass",
                "ANTHROPIC_API_KEY": "must-not-pass",
            },
            user_home=Path("/synthetic/home"),
        )
        self.assertEqual(env["HOME"], "/synthetic/home")
        self.assertEqual(env["LANG"], "en_US.UTF-8")
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("ANTHROPIC_API_KEY", env)
        self.assertEqual(env["NO_COLOR"], "1")


if __name__ == "__main__":
    unittest.main()
