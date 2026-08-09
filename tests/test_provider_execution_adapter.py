#!/usr/bin/env python3
"""Characterization tests for concrete provider execution binding."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.providers import execution_adapter


class ProviderExecutionAdapterTests(unittest.TestCase):
    def test_ollama_request_uses_live_bounded_transport_ports(self) -> None:
        provider = mock.Mock()
        provider.request.return_value = {"ok": True}
        urlopen = mock.Mock(name="urlopen")
        request = mock.Mock(name="request_factory")
        bindings = {
            "_ollama_provider": lambda: provider,
            "load_system_prompt": mock.Mock(name="load_prompt"),
            "read_bounded_json": mock.Mock(name="read_json"),
            "extract_json_object": mock.Mock(name="extract_json"),
            "urllib": SimpleNamespace(
                request=SimpleNamespace(urlopen=urlopen, Request=request),
                error=SimpleNamespace(URLError=OSError),
            ),
            "BoundedHttpError": RuntimeError,
            "FALLBACK_OLLAMA_MODEL": "fallback-model",
            "DEFAULT_OLLAMA_URL": "http://127.0.0.1:11434",
        }
        package, args, settings = {}, object(), {}
        self.assertEqual(
            execution_adapter.ollama_request(
                bindings, package, args, settings, "analysis"
            ),
            {"ok": True},
        )
        call = provider.request.call_args
        self.assertEqual(call.args, (package, args, settings, "analysis"))
        self.assertIs(call.kwargs["urlopen"], urlopen)
        self.assertIs(call.kwargs["request_factory"], request)
        self.assertEqual(
            call.kwargs["transport_errors"], (OSError, RuntimeError)
        )
        self.assertEqual(call.kwargs["fallback_model"], "fallback-model")

    def test_codex_chat_preserves_limits_identity_and_controlled_tmpdir(self) -> None:
        provider = mock.Mock()
        provider.chat.return_value = {"_analysis_provider": "codex-cli"}
        controlled_tmpdir = Path("/evaluation/tmp")
        named_ports = {
            name: mock.Mock(name=name)
            for name in (
                "resolve_codex_cli", "prepare_codex_cli_transport",
                "response_output_json_schema", "run_bounded_command",
                "sanitized_cli_harness_env", "summarize_codex_cli_failure",
                "read_bytes_bounded", "extract_json_object",
            )
        }
        bindings = {
            "_codex_provider": lambda: provider,
            **named_ports,
            "CODEX_CLI_MODEL_PATTERN": object(),
            "CODEX_CLI_REASONING_EFFORTS": frozenset({"high", "xhigh"}),
            "BoundedProcessError": RuntimeError,
            "DEFAULT_CLOUD_MAX_STDERR_BYTES": 262144,
            "_CONTROLLED_EVALUATION_TMPDIR": controlled_tmpdir,
        }
        result = execution_adapter.codex_chat(
            bindings, {}, object(), {}, model="gpt-5.6-sol",
            reasoning_effort="xhigh", independent_review=True,
        )
        self.assertEqual(result["_analysis_provider"], "codex-cli")
        kwargs = provider.chat.call_args.kwargs
        self.assertIs(kwargs["run_command"], named_ports["run_bounded_command"])
        self.assertIs(kwargs["prepare"], named_ports["prepare_codex_cli_transport"])
        self.assertIs(kwargs["controlled_tmpdir"], controlled_tmpdir)
        self.assertTrue(kwargs["independent_review"])
        self.assertEqual(kwargs["max_stderr_bytes"], 262144)

    def test_hermes_executable_and_private_auth_ports_remain_exact(self) -> None:
        provider = mock.Mock()
        provider.chat.side_effect = lambda *_args, **kwargs: kwargs
        resolver = mock.Mock(return_value="/approved/hermes")
        bindings = {
            "_hermes_provider": lambda: provider,
            "boolean_setting": mock.Mock(),
            "CODEX_CLI_MODEL_CATALOG": ("gpt-5.6-sol",),
            "HERMES_AGENT_REASONING_EFFORT": "medium",
            "resolve_cli_harness": resolver,
            "cli_analysis_payload": mock.Mock(),
            "DEFAULT_HERMES_AUTH_FILE": Path("/private/auth.json"),
            "_load_dedicated_hermes_auth": mock.Mock(),
            "_write_dedicated_hermes_auth": mock.Mock(),
            "atomic_write_json": mock.Mock(),
            "run_bounded_command": mock.Mock(),
            "sanitized_cli_harness_env": mock.Mock(),
            "BoundedProcessError": RuntimeError,
            "RuntimeArtifactError": ValueError,
            "summarize_cli_harness_failure": mock.Mock(),
            "_verified_hermes_usage": mock.Mock(),
            "extract_json_object": mock.Mock(),
            "HERMES_MAX_PROMPT_ARGUMENT_BYTES": 1024,
            "DEFAULT_CLOUD_MAX_STDERR_BYTES": 2048,
            "fcntl": SimpleNamespace(flock=mock.Mock(), LOCK_EX=2, LOCK_UN=8),
        }
        ports = execution_adapter.hermes_chat(
            bindings, {}, object(), {}, model="gpt-5.6-sol",
            reasoning_effort="medium",
        )
        self.assertEqual(ports["resolve_executable"]({}), "/approved/hermes")
        resolver.assert_called_once_with(
            {}, setting_key="hermes_agent_path", basename="hermes",
            label="Hermes Agent",
        )
        self.assertIs(
            ports["load_dedicated_auth"],
            bindings["_load_dedicated_hermes_auth"],
        )
        self.assertEqual(ports["auth_file"], Path("/private/auth.json"))

    def test_dispatch_resolves_every_adapter_from_current_bindings(self) -> None:
        registry = mock.Mock()
        registry.dispatch.side_effect = lambda *_args, **kwargs: kwargs
        names = (
            "enabled_agent_model_routes", "canonical_model_route",
            "model_route_is_hosted", "synchronize_hosted_investigation_contract",
            "parse_codex_cli_route", "parse_cli_harness_route", "cloud_cli_chat",
            "hermes_agent_chat", "openclaw_infer_chat",
            "_ollama_chat_for_model", "attest_model_route_response",
        )
        bindings = {name: mock.Mock(name=name) for name in names}
        bindings["_provider_registry"] = lambda: registry
        ports = execution_adapter.dispatch(
            bindings, "codex-cli:gpt-5.6-sol:xhigh", {}, object(), {},
            independent_review=True,
        )
        self.assertIs(ports["codex_adapter"], bindings["cloud_cli_chat"])
        self.assertIs(ports["hermes_adapter"], bindings["hermes_agent_chat"])
        self.assertIs(ports["openclaw_adapter"], bindings["openclaw_infer_chat"])
        self.assertIs(ports["ollama_adapter"], bindings["_ollama_chat_for_model"])
        self.assertIs(ports["attest"], bindings["attest_model_route_response"])
        self.assertTrue(ports["independent_review"])


if __name__ == "__main__":
    unittest.main()
