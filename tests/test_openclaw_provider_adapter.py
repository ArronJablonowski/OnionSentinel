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


class TrackingDict(dict):
    def __init__(self, *args, trace, label, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key, default=None):
        self.trace.append(("get", self.label, key))
        return super().get(key, default)

    def __getitem__(self, key):
        self.trace.append(("getitem", self.label, key))
        return super().__getitem__(key)


class TrackingString:
    def __init__(self, value, *, trace, label):
        self.value = value
        self.trace = trace
        self.label = label

    def __str__(self):
        self.trace.append(("str", self.label))
        return self.value


class OpenClawProviderAdapterTests(unittest.TestCase):
    MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,239}$")

    def test_output_text_preserves_list_access_coercion_and_join_order(self) -> None:
        trace: list[object] = []
        envelope = TrackingDict({
            "outputs": [
                "ignored",
                TrackingDict({"text": None}, trace=trace, label="none"),
                TrackingDict({"text": 7}, trace=trace, label="number"),
                TrackingDict({"text": ""}, trace=trace, label="empty"),
                TrackingDict({"text": "last"}, trace=trace, label="last"),
            ],
            "text": "fallback-must-not-be-read",
        }, trace=trace, label="envelope")

        self.assertEqual(openclaw.output_text(envelope), "7\nlast")
        self.assertEqual(trace, [
            ("get", "envelope", "outputs"),
            ("get", "none", "text"),
            ("get", "number", "text"), ("get", "number", "text"),
            ("get", "empty", "text"), ("get", "empty", "text"),
            ("get", "last", "text"), ("get", "last", "text"),
        ])

    def test_output_text_fallback_order_returns_original_unstripped_string(self) -> None:
        trace: list[object] = []
        original = "  bounded output  "
        envelope = TrackingDict({
            "outputs": [], "text": "   ", "output": original,
            "response": "not-read",
        }, trace=trace, label="envelope")
        observed = openclaw.output_text(envelope)
        self.assertIs(observed, original)
        self.assertEqual(trace, [
            ("get", "envelope", "outputs"),
            ("get", "envelope", "text"),
            ("getitem", "envelope", "text"),
            ("get", "envelope", "output"),
            ("getitem", "envelope", "output"),
            ("getitem", "envelope", "output"),
        ])

    def test_output_text_failure_preserves_exact_message_and_envelope(self) -> None:
        envelope = {"outputs": [{"text": None}], "text": "", "output": 7}
        snapshot = json.loads(json.dumps(envelope))
        with self.assertRaisesRegex(
            SystemExit, "OpenClaw completed without a text model output"
        ):
            openclaw.output_text(envelope)
        self.assertEqual(envelope, snapshot)

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

    def test_infer_preserves_ordered_ephemeral_execution_and_projection(self) -> None:
        events: list[object] = []
        observed: dict[str, object] = {}
        prompt_package = {"alert": {"id": "ordered"}}
        settings = self.settings()
        args = SimpleNamespace(timeout=17.5, max_response_bytes=8192)

        def validate(model, observed_settings):
            events.append(("validate", model, observed_settings is settings))

        def resolve(observed_settings):
            events.append(("resolve", observed_settings is settings))
            return "/synthetic/openclaw"

        def build(observed_package, observed_args, **kwargs):
            events.append((
                "build", observed_package is prompt_package,
                observed_args is args, kwargs,
            ))
            return {"z": 1, "a": "value"}

        def write_config(path, value):
            events.append(("write", value))
            path.write_text("{}", encoding="utf-8")
            observed["config"] = path

        def environment(executable, **kwargs):
            events.append(("environment", executable))
            observed["environment_extra"] = kwargs["extra"]
            return {"ISOLATED": "1"}

        def run(command, **kwargs):
            events.append(("run",))
            observed["command"] = command
            observed["run_kwargs"] = kwargs
            observed["config_mode"] = observed["config"].stat().st_mode & 0o777
            observed["directory_modes"] = {
                path: Path(value).stat().st_mode & 0o777
                for path, value in observed["environment_extra"].items()
                if path in {
                    "HOME", "OPENCLAW_STATE_DIR", "OPENCLAW_WORKSPACE_DIR",
                    "XDG_CONFIG_HOME", "TMPDIR",
                }
            }
            return SimpleNamespace(
                returncode=0,
                stdout=json.dumps({
                    "ok": True,
                    "provider": "ollama",
                    "model": "synthetic:latest",
                    "text": '{"summary":"ordered"}',
                }),
                stderr="",
            )

        def extract(value):
            events.append(("extract", value))
            return json.loads(value)

        result = openclaw.infer_unlocked(
            prompt_package, args, settings,
            model="ollama/synthetic:latest", reasoning_effort="medium",
            system_prompt_file=Path("/synthetic/system.md"),
            independent_review=True, validate=validate,
            resolve_executable=resolve, build_payload=build,
            atomic_write_json=write_config, run_command=run,
            sanitized_env=environment, process_error=SyntheticProcessError,
            summarize_failure=cli_common.summarize_harness_failure,
            extract_json=extract, max_prompt_bytes=4096, max_stderr_bytes=1024,
        )

        self.assertEqual([event[0] for event in events], [
            "validate", "resolve", "build", "write", "environment", "run",
            "extract",
        ])
        self.assertEqual(observed["command"], [
            "/synthetic/openclaw", "infer", "model", "run", "--local",
            "--model", "ollama/synthetic:latest", "--thinking", "medium",
            "--prompt", '{"z":1,"a":"value"}', "--json",
        ])
        self.assertEqual(observed["run_kwargs"]["timeout_seconds"], 17.5)
        self.assertEqual(observed["run_kwargs"]["max_stdout_bytes"], 8192)
        self.assertEqual(observed["run_kwargs"]["max_stderr_bytes"], 1024)
        self.assertEqual(observed["run_kwargs"]["env"], {"ISOLATED": "1"})
        self.assertEqual(observed["config_mode"], 0o600)
        self.assertEqual(set(observed["directory_modes"].values()), {0o700})
        self.assertFalse(observed["run_kwargs"]["cwd"].exists())
        self.assertFalse(observed["config"].exists())
        self.assertEqual(result, {
            "summary": "ordered",
            "_analysis_model": "ollama/synthetic:latest",
            "_analysis_model_path": "openclaw",
            "_analysis_provider": "ollama",
            "_analysis_harness": "openclaw",
        })
        self.assertEqual(prompt_package, {"alert": {"id": "ordered"}})
        self.assertEqual(settings, self.settings())

    def test_infer_prompt_limit_stops_before_ephemeral_execution(self) -> None:
        events: list[str] = []
        with self.assertRaisesRegex(SystemExit, "safe prompt argument limit"):
            openclaw.infer_unlocked(
                {}, SimpleNamespace(timeout=1, max_response_bytes=1), {},
                model="ollama/model", reasoning_effort="low",
                system_prompt_file=None, independent_review=False,
                validate=lambda *_args: events.append("validate"),
                resolve_executable=lambda *_args: events.append("resolve") or "openclaw",
                build_payload=lambda *_args, **_kwargs: events.append("build") or {"x": "é"},
                atomic_write_json=lambda *_args: events.append("write"),
                run_command=lambda *_args, **_kwargs: events.append("run"),
                sanitized_env=lambda *_args, **_kwargs: events.append("environment"),
                process_error=SyntheticProcessError,
                summarize_failure=cli_common.summarize_harness_failure,
                extract_json=json.loads, max_prompt_bytes=10, max_stderr_bytes=1,
            )
        self.assertEqual(events, ["validate", "resolve", "build"])

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

    def test_observation_preserves_access_coercion_and_accepted_spelling(self) -> None:
        trace: list[object] = []
        envelope = TrackingDict({
            "provider": TrackingString(" OLLAMA ", trace=trace, label="provider"),
            "model": TrackingString(
                " OllAmA/Gemma4:26B-MLX ", trace=trace, label="model"
            ),
        }, trace=trace, label="envelope")

        self.assertEqual(
            openclaw.verified_observation(
                envelope, "OlLaMa/gemma4:26b-mlx"
            ),
            ("ollama", "ollama/Gemma4:26B-MLX"),
        )
        self.assertEqual(trace, [
            ("get", "envelope", "provider"),
            ("str", "provider"),
            ("get", "envelope", "model"),
            ("str", "model"),
        ])

    def test_observation_missing_provenance_preserves_error_and_nonmutation(self) -> None:
        trace: list[object] = []
        envelope = TrackingDict({"provider": "", "model": " present "},
                                trace=trace, label="envelope")
        snapshot = dict(envelope)

        with self.assertRaisesRegex(
            SystemExit,
            "OpenClaw response omitted observed provider/model provenance",
        ):
            openclaw.verified_observation(envelope, "ollama/present")

        self.assertEqual(envelope, snapshot)
        self.assertEqual(trace, [
            ("get", "envelope", "provider"),
            ("get", "envelope", "model"),
        ])

    def test_observation_preserves_route_rejection_boundaries(self) -> None:
        cases = (
            ({"provider": "ollama", "model": "openai/model"}, "ollama/model"),
            ({"provider": "ollama", "model": "model"}, "openai/model"),
            ({"provider": "ollama", "model": "model"}, "ollama/"),
            ({"provider": "ollama", "model": "other"}, "ollama/model"),
        )
        for envelope, expected_model in cases:
            with self.subTest(
                envelope=envelope, expected_model=expected_model
            ), self.assertRaisesRegex(SystemExit, "different provider/model"):
                openclaw.verified_observation(envelope, expected_model)

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
