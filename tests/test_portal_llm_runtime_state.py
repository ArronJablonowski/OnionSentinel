#!/usr/bin/env python3
"""Contracts for live LLM runtime provenance presentation."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_llm_runtime_state import llm_runtime_model_state  # noqa: E402


class LlmRuntimeStateTests(unittest.TestCase):
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
