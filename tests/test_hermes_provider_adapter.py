#!/usr/bin/env python3
"""Focused security contracts for the extracted Hermes adapter."""
from __future__ import annotations

import fcntl
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.providers import cli_common, hermes


class ArtifactError(RuntimeError):
    pass


class ProcessError(RuntimeError):
    pass


class TrackingDict(dict):
    def __init__(self, *args, trace, label, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key, default=None):
        self.trace.append(("get", self.label, key))
        return super().get(key, default)


class TrackingUsage(dict):
    def __init__(self, *args, trace, **kwargs):
        super().__init__(*args, **kwargs)
        self.trace = trace

    def __getitem__(self, key):
        self.trace.append(("usage", key))
        return super().__getitem__(key)


def read_json(path: Path, **_kwargs):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactError("invalid artifact") from exc
    if not isinstance(value, dict):
        raise ArtifactError("invalid artifact")
    return value


class HermesProviderAdapterTests(unittest.TestCase):
    def chat_boundary(self, trace, **overrides):
        invoke_side_effect = overrides.pop("invoke_side_effect", None)
        response = {"summary": "bounded"}
        usage = TrackingUsage(
            {"model": "gpt-5.6-sol", "provider": "openai-codex"}, trace=trace
        )
        handle = SimpleNamespace(
            __enter__=lambda self: trace.append("enter") or self,
            __exit__=lambda self, *args: trace.append(("exit", args[0])) or False,
        )

        class Handle:
            def __enter__(self):
                trace.append("enter")
                return handle

            def __exit__(self, exc_type, _exc, _tb):
                trace.append(("exit", exc_type))
                return False

        values = {
            "prompt_package": {"alert": {"id": "synthetic"}},
            "args": SimpleNamespace(timeout=15.0, max_response_bytes=4096),
            "settings": {
                "hermes_agent_enabled": True,
                "hermes_agent_model": "gpt-5.6-sol",
                "hermes_agent_reasoning_effort": "medium",
            },
            "model": "gpt-5.6-sol",
            "reasoning_effort": "medium",
            "system_prompt_file": None,
            "independent_review": False,
            "boolean_setting": bool,
            "model_catalog": ("gpt-5.6-sol",),
            "required_effort": "medium",
            "resolve_executable": lambda _settings: trace.append("resolve") or "/bin/hermes",
            "build_payload": lambda *_args, **_kwargs: trace.append("payload") or {},
            "auth_file": Path("/private/tmp/synthetic-hermes-auth.json"),
            "load_dedicated_auth": lambda _path: trace.append("load") or {"auth": True},
            "write_dedicated_auth": lambda *_args: None,
            "atomic_write_json": lambda *_args: None,
            "run_command": lambda *_args, **_kwargs: None,
            "sanitized_env": lambda *_args, **_kwargs: {},
            "process_error": ProcessError,
            "artifact_error": ArtifactError,
            "summarize_failure": cli_common.summarize_harness_failure,
            "verify_usage": lambda *_args, **_kwargs: usage,
            "extract_json": json.loads,
            "max_prompt_bytes": 4096,
            "max_stderr_bytes": 1024,
            "flock": lambda _handle, operation: trace.append(("flock", operation)),
            "lock_exclusive": 1,
            "lock_unlock": 2,
        }
        values.update(overrides)
        with mock.patch.object(hermes, "_open_auth_lock", return_value=Handle()), \
                mock.patch.object(
                    hermes,
                    "_invoke_isolated",
                    side_effect=invoke_side_effect or (
                        lambda *_args, **_kwargs: (
                            trace.append("invoke"), (response, usage)
                        )[-1]
                    ),
                ):
            result = hermes.chat(**values)
        return result, response

    def test_chat_preserves_lock_transaction_and_usage_projection_order(self) -> None:
        trace: list[object] = []
        result, response = self.chat_boundary(trace)
        self.assertIs(result, response)
        self.assertEqual(trace, [
            "resolve", "payload", "enter", ("flock", 1), "load", "invoke",
            ("flock", 2), ("exit", None),
            ("usage", "model"), ("usage", "provider"),
        ])
        self.assertEqual(result["_analysis_model_path"], "hermes-agent")
        self.assertEqual(result["_analysis_harness"], "hermes-agent")

    def test_chat_unlocks_and_closes_when_invocation_fails(self) -> None:
        trace: list[object] = []
        failure = ProcessError("synthetic invocation failure")
        with self.assertRaises(ProcessError) as raised:
            self.chat_boundary(trace, invoke_side_effect=failure)
        self.assertIs(raised.exception, failure)
        self.assertIn(("flock", 2), trace)
        self.assertEqual(trace[-1], ("exit", ProcessError))

    def test_chat_auth_unavailable_preserves_path_message_cause_and_unlock(self) -> None:
        trace: list[object] = []
        failure = ArtifactError("credential detail must remain chained")
        with self.assertRaisesRegex(
            SystemExit,
            r"dedicated authentication is unavailable at /private/tmp/"
            r"synthetic-hermes-auth.json",
        ) as raised:
            self.chat_boundary(
                trace,
                load_dedicated_auth=lambda _path: (_ for _ in ()).throw(failure),
            )
        self.assertIs(raised.exception.__cause__, failure)
        self.assertIn(("flock", 2), trace)
        self.assertEqual(trace[-1], ("exit", SystemExit))

    def invoke_isolated(self, run_command, trace, **overrides):
        values = {
            "serialized": '{"bounded":true}',
            "args": SimpleNamespace(timeout=15.0, max_response_bytes=4096),
            "model": "gpt-5.6-sol",
            "executable": "/usr/local/bin/hermes",
            "dedicated_auth": {"providers": {"openai-codex": {"token": "redacted"}}},
            "atomic_write_json": lambda path, value: (
                trace.append(("atomic", path.name)),
                path.write_text(json.dumps(value), encoding="utf-8"),
            )[-1],
            "run_command": run_command,
            "sanitized_env": lambda _executable, **kwargs: {
                "HOME": kwargs["extra"]["HOME"]
            },
            "load_dedicated_auth": lambda path: (
                trace.append(("load", path.name)),
                {"providers": {"openai-codex": {"token": "rotated"}}},
            )[-1],
            "write_dedicated_auth": lambda path, value: trace.append(
                ("write", path.name, value["providers"]["openai-codex"]["token"])
            ),
            "auth_file": Path("/private/tmp/synthetic-hermes-auth.json"),
            "process_error": ProcessError,
            "artifact_error": ArtifactError,
            "summarize_failure": cli_common.summarize_harness_failure,
            "verify_usage": lambda path, **kwargs: (
                trace.append(("verify", path.name, kwargs["expected_model"])),
                {"attested": True},
            )[-1],
            "extract_json": lambda value: (
                trace.append(("extract", value)), json.loads(value)
            )[-1],
            "max_stderr_bytes": 1024,
        }
        values.update(overrides)
        return hermes._invoke_isolated(**values)

    def test_isolated_invocation_persists_rotation_before_process_error(self) -> None:
        trace: list[object] = []

        def run(*_args, **_kwargs):
            trace.append("run")
            raise ProcessError("bounded process failure")

        with self.assertRaisesRegex(
            SystemExit, "Hermes Agent analysis failed: bounded process failure"
        ) as raised:
            self.invoke_isolated(run, trace)
        self.assertIsInstance(raised.exception.__cause__, ProcessError)
        self.assertEqual(
            trace[1:],
            ["run", ("load", "auth.json"),
             ("write", "synthetic-hermes-auth.json", "rotated")],
        )

    def test_rotation_failure_precedes_the_original_invocation_error(self) -> None:
        trace: list[object] = []

        def fail_write(_path, _value):
            trace.append("write-failed")
            raise ArtifactError("synthetic rotation failure")

        with self.assertRaisesRegex(
            SystemExit, "credential rotation could not be persisted"
        ) as raised:
            self.invoke_isolated(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    FileNotFoundError("missing")
                ),
                trace,
                write_dedicated_auth=fail_write,
            )
        self.assertIsInstance(raised.exception.__cause__, ArtifactError)
        self.assertEqual(trace[-2:], [("load", "auth.json"), "write-failed"])

    def test_success_verifies_usage_before_extracting_and_cleans_temp_root(self) -> None:
        trace: list[object] = []
        work_dirs: list[Path] = []

        def run(command, **kwargs):
            trace.append("run")
            work_dirs.append(Path(kwargs["cwd"]))
            self.assertIn("--safe-mode", command)
            self.assertEqual(kwargs["timeout_seconds"], 15.0)
            self.assertEqual(kwargs["max_stdout_bytes"], 4096)
            self.assertEqual(kwargs["max_stderr_bytes"], 1024)
            return SimpleNamespace(returncode=0, stdout='{"summary":"ok"}', stderr="")

        response, usage = self.invoke_isolated(run, trace)
        self.assertEqual(response, {"summary": "ok"})
        self.assertEqual(usage, {"attested": True})
        self.assertEqual(trace[-2:], [
            ("verify", "usage.json", "gpt-5.6-sol"),
            ("extract", '{"summary":"ok"}'),
        ])
        self.assertFalse(work_dirs[0].exists())

    def test_unexpected_exception_is_reraised_after_rotation(self) -> None:
        trace: list[object] = []
        failure = KeyboardInterrupt("synthetic interrupt")
        with self.assertRaises(KeyboardInterrupt) as raised:
            self.invoke_isolated(
                lambda *_args, **_kwargs: (_ for _ in ()).throw(failure), trace
            )
        self.assertIs(raised.exception, failure)
        self.assertEqual(trace[-1], ("write", "synthetic-hermes-auth.json", "rotated"))

    def test_provider_credentials_preserve_access_order_identity_and_empty_admission(self) -> None:
        trace: list[object] = []
        provider_state = {"access_token": "dedicated"}
        pool_entries = [{"provider": "openai-codex", "access_token": "pool"}]
        raw = TrackingDict(
            {
                "providers": TrackingDict(
                    {"openai-codex": provider_state}, trace=trace, label="providers"
                ),
                "credential_pool": TrackingDict(
                    {"openai-codex": pool_entries}, trace=trace, label="pool"
                ),
            },
            trace=trace,
            label="raw",
        )

        observed_provider, observed_pool = hermes._provider_credentials(
            raw, ArtifactError
        )

        self.assertIs(observed_provider, provider_state)
        self.assertIs(observed_pool, pool_entries)
        self.assertEqual(trace, [
            ("get", "raw", "providers"),
            ("get", "providers", "openai-codex"),
            ("get", "raw", "credential_pool"),
            ("get", "pool", "openai-codex"),
        ])
        self.assertEqual(
            hermes._provider_credentials(
                {"providers": {"openai-codex": {}},
                 "credential_pool": {"openai-codex": []}},
                ArtifactError,
            ),
            (None, None),
        )

    def test_provider_credentials_reject_malformed_or_foreign_pool_entries(self) -> None:
        invalid_entries = [
            None,
            {"provider": "foreign", "access_token": "must-not-appear"},
        ]
        for entry in invalid_entries:
            with self.subTest(entry_type=type(entry).__name__):
                with self.assertRaisesRegex(
                    ArtifactError,
                    "dedicated Hermes openai-codex credential pool is invalid",
                ) as raised:
                    hermes._provider_credentials(
                        {"credential_pool": {"openai-codex": [entry]}},
                        ArtifactError,
                    )
            self.assertNotIn("must-not-appear", str(raised.exception))

    def test_provider_credentials_accept_absent_none_and_exact_provider_markers(self) -> None:
        entries = [
            {"id": "absent"},
            {"provider": None, "id": "none"},
            {"provider": "openai-codex", "id": "exact"},
            {"provider": " openai-codex ", "id": "trimmed"},
        ]
        _, observed = hermes._provider_credentials(
            {"credential_pool": {"openai-codex": entries}}, ArtifactError
        )
        self.assertIs(observed, entries)

    def test_auth_filter_never_copies_foreign_providers(self) -> None:
        filtered = hermes.filtered_auth_store(
            {
                "version": 2,
                "active_provider": "nous",
                "providers": {
                    "openai-codex": {"tokens": {"access_token": "codex"}},
                    "nous": {"access_token": "must-not-copy"},
                },
                "credential_pool": {
                    "openai-codex": [{"id": "codex", "access_token": "pool"}],
                    "nous": [{"id": "nous", "access_token": "must-not-copy"}],
                },
            },
            error_type=ArtifactError,
        )
        self.assertEqual(set(filtered["providers"]), {"openai-codex"})
        self.assertEqual(set(filtered["credential_pool"]), {"openai-codex"})
        self.assertEqual(filtered["active_provider"], "openai-codex")

    def test_atomic_auth_write_is_owner_only_and_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "private" / "auth.json"
            hermes.write_auth(
                path,
                {
                    "providers": {
                        "openai-codex": {"access_token": "dedicated"},
                        "foreign": {"access_token": "must-not-persist"},
                    },
                },
                error_type=ArtifactError,
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                set(json.loads(path.read_text(encoding="utf-8"))["providers"]),
                {"openai-codex"},
            )
            self.assertFalse(any(path.parent.glob(f".{path.name}.*.tmp")))

    def test_usage_attestation_fails_closed_on_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "usage.json"
            path.write_text(
                json.dumps({
                    "completed": True,
                    "failed": False,
                    "provider": "openai-codex",
                    "model": "gpt-5.6-terra",
                }),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SystemExit, "different provider/model"):
                hermes.verified_usage(
                    path,
                    expected_model="gpt-5.6-sol",
                    read_json=read_json,
                    error_type=ArtifactError,
                    max_bytes=4096,
                )

    def test_chat_is_tool_empty_ephemeral_and_persists_rotation(self) -> None:
        observed: dict[str, object] = {}
        with tempfile.TemporaryDirectory() as name:
            auth_file = Path(name) / "private" / "auth.json"
            hermes.write_auth(
                auth_file,
                {"providers": {"openai-codex": {"access_token": "initial"}}},
                error_type=ArtifactError,
            )

            def load_auth(path):
                return hermes.load_auth(
                    path,
                    read_json=read_json,
                    error_type=ArtifactError,
                    max_bytes=4096,
                )

            def write_auth(path, value):
                hermes.write_auth(path, value, error_type=ArtifactError)

            def verify_usage(path, *, expected_model):
                return hermes.verified_usage(
                    path,
                    expected_model=expected_model,
                    read_json=read_json,
                    error_type=ArtifactError,
                    max_bytes=4096,
                )

            def run(command, **kwargs):
                observed["command"] = command
                observed["env"] = kwargs["env"]
                observed["cwd"] = kwargs["cwd"]
                isolated_auth = Path(kwargs["env"]["HERMES_HOME"]) / "auth.json"
                rotated = json.loads(isolated_auth.read_text(encoding="utf-8"))
                rotated["providers"]["openai-codex"]["access_token"] = "rotated"
                rotated["providers"]["foreign"] = {"access_token": "exclude"}
                isolated_auth.write_text(json.dumps(rotated), encoding="utf-8")
                usage = Path(command[command.index("--usage-file") + 1])
                usage.write_text(
                    json.dumps({
                        "completed": True,
                        "failed": False,
                        "provider": "openai-codex",
                        "model": "gpt-5.6-sol",
                    }),
                    encoding="utf-8",
                )
                return SimpleNamespace(
                    returncode=0,
                    stdout='{"summary":"bounded"}',
                    stderr="",
                )

            response = hermes.chat(
                {"alert": {"id": "synthetic"}},
                SimpleNamespace(timeout=15.0, max_response_bytes=4096),
                {
                    "hermes_agent_enabled": True,
                    "hermes_agent_model": "gpt-5.6-sol",
                    "hermes_agent_reasoning_effort": "medium",
                },
                model="gpt-5.6-sol",
                reasoning_effort="medium",
                system_prompt_file=None,
                independent_review=False,
                boolean_setting=bool,
                model_catalog=("gpt-5.6-sol",),
                required_effort="medium",
                resolve_executable=lambda _settings: "/usr/local/bin/hermes",
                build_payload=lambda *_args, **_kwargs: {"bounded": True},
                auth_file=auth_file,
                load_dedicated_auth=load_auth,
                write_dedicated_auth=write_auth,
                atomic_write_json=lambda path, value: path.write_text(
                    json.dumps(value), encoding="utf-8"
                ),
                run_command=run,
                sanitized_env=lambda executable, **kwargs: cli_common.sanitized_environment(
                    executable,
                    extra=kwargs.get("extra"),
                    environ={"OPENAI_API_KEY": "must-not-pass"},
                    user_home=Path("/synthetic/home"),
                ),
                process_error=ProcessError,
                artifact_error=ArtifactError,
                summarize_failure=cli_common.summarize_harness_failure,
                verify_usage=verify_usage,
                extract_json=json.loads,
                max_prompt_bytes=4096,
                max_stderr_bytes=1024,
                flock=fcntl.flock,
                lock_exclusive=fcntl.LOCK_EX,
                lock_unlock=fcntl.LOCK_UN,
            )

            persisted = json.loads(auth_file.read_text(encoding="utf-8"))
            self.assertEqual(set(persisted["providers"]), {"openai-codex"})
            self.assertEqual(
                persisted["providers"]["openai-codex"]["access_token"],
                "rotated",
            )
        command = observed["command"]
        environment = observed["env"]
        self.assertIn("--oneshot", command)
        self.assertEqual(command[command.index("--provider") + 1], "openai-codex")
        self.assertEqual(command[command.index("--toolsets") + 1], "context_engine")
        self.assertIn("--safe-mode", command)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertEqual(environment["PYTHON_DOTENV_DISABLED"], "1")
        self.assertFalse(Path(observed["cwd"]).exists())
        self.assertEqual(response["_analysis_model"], "gpt-5.6-sol")
        self.assertEqual(response["_analysis_provider"], "openai-codex")


if __name__ == "__main__":
    unittest.main()
