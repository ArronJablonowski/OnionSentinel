#!/usr/bin/env python3
"""Focused security contracts for the extracted OpenClaw adapter."""
from __future__ import annotations

import json
from pathlib import Path
import re
from types import SimpleNamespace
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.providers import cli_common, openclaw


class SyntheticProcessError(Exception):
    pass


class OpenClawProviderAdapterTests(unittest.TestCase):
    MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$")

    def settings(self) -> dict[str, object]:
        return {
            "openclaw_enabled": True,
            "openclaw_model": "ollama/synthetic:latest",
            "openclaw_reasoning_effort": "high",
            "ollama_url": "http://127.0.0.1:11434",
        }

    def validate(self, model: str, settings: dict[str, object]) -> None:
        openclaw.validate_route(
            model,
            settings,
            model_pattern=self.MODEL_PATTERN,
            uses_ollama_runtime=lambda value: value.startswith("ollama/"),
            provider_prefix="ollama/",
            supported_urls=frozenset({"http://127.0.0.1:11434"}),
            default_url="http://127.0.0.1:11434",
        )

    def infer(self, run_command):
        return openclaw.infer_unlocked(
            {"alert": {"id": "synthetic"}},
            SimpleNamespace(timeout=15.0, max_response_bytes=4096),
            self.settings(),
            model="ollama/synthetic:latest",
            reasoning_effort="high",
            system_prompt_file=None,
            independent_review=False,
            validate=self.validate,
            resolve_executable=lambda _settings: "/usr/local/bin/openclaw",
            build_payload=lambda *_args, **_kwargs: {"bounded": True},
            atomic_write_json=lambda path, value: path.write_text(
                json.dumps(value), encoding="utf-8"
            ),
            run_command=run_command,
            sanitized_env=lambda executable, **kwargs: cli_common.sanitized_environment(
                executable,
                extra=kwargs.get("extra"),
                environ={"OPENAI_API_KEY": "must-not-pass"},
                user_home=Path("/synthetic/home"),
            ),
            process_error=SyntheticProcessError,
            summarize_failure=cli_common.summarize_harness_failure,
            extract_json=json.loads,
            max_prompt_bytes=4096,
            max_stderr_bytes=1024,
        )

    def test_fixed_argv_isolated_environment_and_identity_attestation(self) -> None:
        observed: dict[str, object] = {}

        def run(command, **kwargs):
            observed["command"] = command
            observed["env"] = kwargs["env"]
            observed["cwd"] = kwargs["cwd"]
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    "ok": True,
                    "provider": "ollama",
                    "model": "synthetic:latest",
                    "outputs": [{"text": '{"summary":"bounded"}'}],
                }),
                stderr="",
            )

        result = self.infer(run)
        command = observed["command"]
        environment = observed["env"]
        self.assertEqual(command[:5], [
            "/usr/local/bin/openclaw", "infer", "model", "run", "--local"
        ])
        self.assertEqual(command[command.index("--model") + 1], "ollama/synthetic:latest")
        self.assertEqual(command[command.index("--thinking") + 1], "high")
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["OPENCLAW_OFFLINE"], "1")
        self.assertEqual(environment["HTTP_PROXY"], "")
        self.assertFalse(Path(observed["cwd"]).exists())
        self.assertEqual(result["_analysis_model"], "ollama/synthetic:latest")
        self.assertEqual(result["_analysis_provider"], "ollama")

    def test_hosted_or_remote_routes_fail_before_execution(self) -> None:
        for model, settings in (
            ("openai/gpt-5.6-sol", self.settings()),
            (
                "ollama/synthetic:latest",
                {**self.settings(), "ollama_url": "http://192.0.2.10:11434"},
            ),
        ):
            with self.subTest(model=model), self.assertRaises(SystemExit):
                self.validate(model, settings)

    def test_missing_binary_bounded_failure_and_nonzero_exit_are_safe(self) -> None:
        with self.assertRaisesRegex(SystemExit, "executable was not found"):
            self.infer(lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError()))
        with self.assertRaisesRegex(SystemExit, "bounded failure"):
            self.infer(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    SyntheticProcessError("bounded failure")
                )
            )
        with self.assertRaises(SystemExit) as captured:
            self.infer(
                lambda *_args, **_kwargs: SimpleNamespace(
                    returncode=7,
                    stdout="",
                    stderr="secret evidence transcript",
                )
            )
        self.assertEqual(
            str(captured.exception),
            "OpenClaw analysis failed: OpenClaw exited with code 7",
        )

    def test_malformed_envelope_and_identity_mismatch_fail_closed(self) -> None:
        for stdout, expected in (
            ("not-json", "invalid JSON execution envelope"),
            (json.dumps({"ok": False}), "unsuccessful model invocation"),
            (
                json.dumps({
                    "ok": True,
                    "provider": "openai",
                    "model": "synthetic:latest",
                    "text": "{}",
                }),
                "different provider/model",
            ),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(SystemExit, expected):
                self.infer(
                    lambda *_args, **_kwargs: SimpleNamespace(
                        returncode=0, stdout=stdout, stderr=""
                    )
                )

    def test_observation_rejects_foreign_provider_for_expected_model(self) -> None:
        with self.assertRaisesRegex(SystemExit, "different provider/model"):
            openclaw.verified_observation(
                {
                    "provider": "openai",
                    "model": "ollama/gemma4:26b-mlx",
                },
                "ollama/gemma4:26b-mlx",
            )

    def test_locked_chat_always_unloads_after_failure(self) -> None:
        events: list[object] = []
        with tempfile.TemporaryDirectory() as name:
            lock_path = Path(name) / "ollama.lock"
            with self.assertRaisesRegex(SystemExit, "synthetic inference failure"):
                openclaw.locked_chat(
                    {},
                    SimpleNamespace(timeout=42),
                    self.settings(),
                    model="ollama/synthetic:latest",
                    reasoning_effort="high",
                    system_prompt_file=None,
                    independent_review=False,
                    boolean_setting=bool,
                    model_pattern=self.MODEL_PATTERN,
                    reasoning_efforts=frozenset({"high"}),
                    validate=self.validate,
                    lock_path=lock_path,
                    flock=lambda _handle, operation: events.append(operation),
                    lock_exclusive=1,
                    lock_unlock=2,
                    infer=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                        SystemExit("synthetic inference failure")
                    ),
                    unload=lambda settings, model, **kwargs: events.append(
                        (settings, model, kwargs["timeout"])
                    ),
                )
            self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(events[0], 1)
        self.assertEqual(events[1][1:], ("synthetic:latest", 42.0))
        self.assertEqual(events[2], 2)


if __name__ == "__main__":
    unittest.main()
