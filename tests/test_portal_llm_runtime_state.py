#!/usr/bin/env python3
"""Contracts for live LLM runtime provenance presentation."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_llm_runtime_state import (  # noqa: E402
    _execution_fields,
    llm_runtime_model_state,
)


class _TracingRecord(dict):
    def __init__(self, values: dict) -> None:
        super().__init__(values)
        self.trace = []

    def __contains__(self, key: object) -> bool:
        self.trace.append(("contains", key))
        return super().__contains__(key)

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", key, default))
        return super().get(key, default)


class LlmRuntimeStateTests(unittest.TestCase):
    def test_execution_fields_preserve_presence_branch_access_order_and_normalization(self) -> None:
        active = _TracingRecord({
            "active_phase": None,
            "active_model_route": " Route ",
            "active_model": 7,
            "active_provider": " CoDeX-CLI ",
            "active_model_path": " FRONTIER ",
            "model": "legacy must not be read",
        })
        legacy = _TracingRecord({
            "model_route": " Legacy-Route ",
            "model": None,
            "mode": " OLLAMA ",
            "model_path": " LOCAL ",
            "active_model": "active must not be read",
        })

        self.assertEqual(
            _execution_fields(active),
            ("primary_analysis", "Route", "7", "codex-cli", "frontier"),
        )
        self.assertEqual(
            active.trace,
            [
                ("contains", "active_phase"),
                ("get", "active_phase", None),
                ("get", "active_model_route", None),
                ("get", "active_model", None),
                ("get", "active_provider", None),
                ("get", "active_model_path", None),
            ],
        )
        self.assertEqual(
            _execution_fields(legacy),
            ("primary_analysis", "Legacy-Route", "", "ollama", "local"),
        )
        self.assertEqual(
            legacy.trace,
            [
                ("contains", "active_phase"),
                ("get", "model_route", None),
                ("get", "model", None),
                ("get", "mode", None),
                ("get", "model_path", None),
            ],
        )
    def test_non_running_or_malformed_records_are_idle(self) -> None:
        for record in (None, [], {}, {"status": "success"}):
            with self.subTest(record=record):
                self.assertEqual(llm_runtime_model_state(record), {"running": False})

    def test_exact_routes_project_provider_model_and_effort(self) -> None:
        cases = (
            ("codex-cli:gpt-5.6-sol:xhigh", "Codex CLI", "gpt-5.6-sol", "xhigh"),
            ("hermes-agent:hermes-4:high", "Hermes Agent", "hermes-4", "high"),
            ("openclaw:claude-sonnet:medium", "OpenClaw", "claude-sonnet", "medium"),
            ("ollama:gemma4:31b", "Ollama", "gemma4:31b", ""),
        )
        for route, provider, model, effort in cases:
            with self.subTest(route=route):
                result = llm_runtime_model_state({
                    "status": "running",
                    "active_phase": "primary_analysis",
                    "active_model_route": route,
                })
                self.assertEqual(result["provider"], provider)
                self.assertEqual(result["model"], model)
                suffix = f" ({effort})" if effort else ""
                self.assertEqual(result["label"], f"{provider} · {model}{suffix}")

    def test_provider_metadata_recovers_a_route_free_model(self) -> None:
        result = llm_runtime_model_state({
            "status": "running",
            "active_phase": "second_opinion",
            "active_model": "gpt-5.6-sol",
            "active_model_path": "frontier-codex-cli",
        })
        self.assertEqual(result["provider"], "Codex CLI")
        self.assertEqual(result["phase_label"], "Second-opinion review")
        self.assertEqual(result["label"], "Codex CLI · gpt-5.6-sol")

    def test_model_free_preparing_and_finalizing_never_claim_a_provider(self) -> None:
        for phase, label in (
            ("preparing", "Preparing analysis"),
            ("post_processing", "Finalizing analysis"),
        ):
            with self.subTest(phase=phase):
                result = llm_runtime_model_state({
                    "status": "running",
                    "active_phase": phase,
                    "active_provider": "codex-cli",
                })
                self.assertEqual(result["provider"], "")
                self.assertEqual(result["label"], "No model running")
                self.assertEqual(result["detail"], f"{label} · No model running")

    def test_legacy_running_record_preserves_rolling_deploy_fallback(self) -> None:
        result = llm_runtime_model_state({
            "status": "running",
            "mode": "codex-cli",
            "model": "gpt-5.5",
            "model_path": "frontier-codex-cli",
            "model_route": "codex-cli:gpt-5.5:medium",
        })
        self.assertEqual(result["phase"], "primary_analysis")
        self.assertEqual(result["phase_label"], "Analyzing")
        self.assertEqual(result["label"], "Codex CLI · gpt-5.5 (medium)")

    def test_unknown_running_model_is_explicit(self) -> None:
        result = llm_runtime_model_state({
            "status": "running", "active_phase": "live_follow_up",
        })
        self.assertEqual(result["label"], "Unknown model")
        self.assertEqual(result["phase_label"], "Live-evidence follow-up")


if __name__ == "__main__":
    unittest.main()
