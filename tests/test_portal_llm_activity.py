"""Behavior contracts for pure LLM activity and provenance projection."""
from __future__ import annotations

import sys
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_llm_activity import (  # noqa: E402
    compose_current_llm_analysis,
    decorate_llm_analysis_record,
    llm_agent_execution_state,
    merge_live_llm_activity,
)


def running_record(
    log_id: str, role: str, route: str, phase: str = "primary_analysis"
) -> dict:
    provider, model, effort = route.split(":", 2)
    return {
        "log_id": log_id,
        "status": "running",
        "agent_role": role,
        "active_phase": phase,
        "active_provider": provider,
        "active_model": model,
        "active_model_route": route,
        "active_model_path": "frontier-codex-cli",
        "effort": effort,
    }


class LlmActivityTests(unittest.TestCase):
    def test_agent_identity_normalizes_roles_and_bounds_unknown_values(self) -> None:
        incident = llm_agent_execution_state({"agent_role": "Incident_Responder"})
        unknown = llm_agent_execution_state("invalid")

        self.assertEqual(incident["agent_role"], "incident-responder")
        self.assertEqual(incident["agent_label"], "Incident Responder")
        self.assertEqual(incident["job_type"], "incident_response_analysis")
        self.assertEqual(unknown["agent_role"], "unknown")
        self.assertEqual(unknown["job_label"], "Unknown analysis job")

    def test_live_decoration_uses_observed_runtime_and_idle_fallback(self) -> None:
        live = decorate_llm_analysis_record(
            running_record(
                "one", "soc-analyst", "codex-cli:gpt-5.6-sol:xhigh"
            ),
            live=True,
        )
        idle = decorate_llm_analysis_record({"status": "success"}, live=True)

        self.assertEqual(live["agent_label"], "SOC Analyst")
        self.assertEqual(live["runtime_model_label"], "Codex CLI · gpt-5.6-sol (xhigh)")
        self.assertEqual(live["phase_label"], "Analyzing")
        self.assertEqual(idle["runtime_model_label"], "No model running")
        self.assertEqual(idle["phase_label"], "Idle")

    def test_historical_decoration_never_claims_unobserved_assigned_model(self) -> None:
        record = decorate_llm_analysis_record(
            {
                "status": "failure",
                "assigned_model": "gpt-5.6-sol",
                "assigned_model_route": "codex-cli:gpt-5.6-sol:xhigh",
                "model": "",
                "model_route": "",
            },
            live=False,
        )

        self.assertEqual(record["runtime_model_label"], "No model started")
        self.assertEqual(record["phase_label"], "Completed run")

    def test_live_decoration_preserves_copy_defaults_runtime_trace_and_order(self) -> None:
        source = {
            "raw": "audit",
            "agent_role": "SOC_Analyst",
            "agent_label": None,
        }
        snapshots = []

        def runtime_state(record):
            snapshots.append((id(record), dict(record)))
            return {"running": "yes", "label": "", "phase_label": ""}

        with mock.patch(
            "portal_llm_activity.llm_runtime_model_state",
            side_effect=runtime_state,
        ):
            decorated = decorate_llm_analysis_record(source, live=True)

        self.assertEqual(source, {
            "raw": "audit", "agent_role": "SOC_Analyst", "agent_label": None,
        })
        self.assertNotEqual(id(decorated), id(source))
        self.assertEqual(snapshots, [
            (
                id(decorated),
                {
                    "raw": "audit",
                    "agent_role": "SOC_Analyst",
                    "agent_label": None,
                    "job_type": "ai_analysis",
                    "job_label": "SOC alert triage",
                },
            )
        ])
        self.assertEqual(decorated["agent_label"], None)
        self.assertEqual(decorated["runtime_model_label"], "Unknown model")
        self.assertEqual(decorated["phase_label"], "Analysis")
        self.assertEqual(tuple(decorated)[-2:], ("runtime_model_label", "phase_label"))

    def test_historical_decoration_uses_synthetic_copy_but_raw_observation(self) -> None:
        source = {
            "status": "failure",
            "active_phase": "primary_analysis",
            "model": " ",
            "model_route": " codex-cli:model:high ",
        }
        runtime_inputs = []

        def runtime_state(record):
            runtime_inputs.append((id(record), dict(record)))
            return {"running": True, "label": ""}

        with mock.patch(
            "portal_llm_activity.llm_runtime_model_state",
            side_effect=runtime_state,
        ):
            decorated = decorate_llm_analysis_record(source, live=False)

        self.assertEqual(source["status"], "failure")
        self.assertEqual(source["active_phase"], "primary_analysis")
        self.assertEqual(runtime_inputs[0][1]["status"], "running")
        self.assertNotIn("active_phase", runtime_inputs[0][1])
        self.assertNotEqual(runtime_inputs[0][0], id(decorated))
        self.assertEqual(decorated["status"], "failure")
        self.assertEqual(decorated["active_phase"], "primary_analysis")
        self.assertEqual(decorated["runtime_model_label"], "Unknown model")
        self.assertEqual(decorated["phase_label"], "Completed run")

    def test_historical_decoration_ignores_runtime_label_without_raw_model(self) -> None:
        with mock.patch(
            "portal_llm_activity.llm_runtime_model_state",
            return_value={"running": True, "label": "Assigned only"},
        ):
            decorated = decorate_llm_analysis_record(
                {"model": "", "model_route": ""}, live=False,
            )

        self.assertEqual(decorated["runtime_model_label"], "No model started")

    def test_current_analysis_projects_idle_and_reconciles_stale_record(self) -> None:
        idle = compose_current_llm_analysis(4, [], {}, lambda _prompt: False)
        stale = compose_current_llm_analysis(
            2,
            [],
            {
                "status": "running",
                "prompt_package": "/tmp/prompt.json",
                "model_route": "codex-cli:gpt-5.5:medium",
            },
            lambda _prompt: False,
        )

        self.assertEqual(idle["status"], "idle")
        self.assertEqual(idle["queue_size"], 4)
        self.assertEqual(stale["status"], "idle")
        self.assertTrue(stale["stale_running_record"])
        self.assertEqual(stale["runtime_model_label"], "No model running")

    def test_current_analysis_aggregates_concurrent_agents_and_models(self) -> None:
        runs = [
            running_record("one", "soc-analyst", "codex-cli:gpt-5.6-sol:high"),
            {
                **running_record(
                    "two",
                    "incident-responder",
                    "ollama:gemma4:31b",
                    "second_opinion",
                ),
                "active_model_path": "ollama",
            },
        ]

        current = compose_current_llm_analysis(3, runs, {}, lambda _prompt: True)

        self.assertEqual(current["active_count"], 2)
        self.assertEqual(current["active_phase"], "concurrent")
        self.assertEqual(current["phase_label"], "Concurrent analyses")
        self.assertIn("SOC Analyst", current["agent_label"])
        self.assertIn("Incident Responder", current["agent_label"])
        self.assertIn("Codex CLI · gpt-5.6-sol (high)", current["active_model"])
        self.assertIn("Ollama · gemma4:31b", current["active_model"])

    def test_live_merge_preserves_queue_counts_and_raises_analyzing_floor(self) -> None:
        current = compose_current_llm_analysis(
            5,
            [running_record("one", "soc-analyst", "codex-cli:gpt-5.5:medium")],
            {},
            lambda _prompt: True,
        )
        merged = merge_live_llm_activity(
            {"counts": {"queued": 5, "analyzing": "bad"}}, current
        )

        self.assertTrue(merged["active"])
        self.assertEqual(merged["counts"], {"queued": 5, "analyzing": 1})
        self.assertEqual(merged["provider"], "Codex CLI")
        self.assertEqual(merged["phase"], "primary_analysis")

    def test_live_merge_ignores_nonrunning_and_malformed_active_entries(self) -> None:
        static = {"active": False, "counts": {"queued": 1}}
        merged = merge_live_llm_activity(
            static,
            {"active_runs": [None, {"status": "success"}, "bad"]},
        )

        self.assertEqual(merged, static)
        self.assertIsNot(merged, static)


if __name__ == "__main__":
    unittest.main()
