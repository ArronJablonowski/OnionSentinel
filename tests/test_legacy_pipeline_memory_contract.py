#!/usr/bin/env python3
"""Runtime ordering contract for frozen memory-context attestation."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import unittest

from n8n.onion_sentinel import legacy_pipeline


class _StartupAdapter:
    def __init__(self, prompt: dict) -> None:
        self.prompt = prompt

    def load_and_attest(self, *_args) -> SimpleNamespace:
        return SimpleNamespace(
            prompt_path=Path("/synthetic/prompt.json"),
            prompt_package=self.prompt,
            settings={"enabled": True},
            agent_role="soc-analyst",
            live_osquery_config={},
            enrichment_config={},
        )


class _Adapters:
    def __init__(self) -> None:
        self.prepared_prompt = None

    def prepare_runtime(self, _bindings, _module, _context, **kwargs):
        self.prepared_prompt = kwargs["prompt_package"]
        return SimpleNamespace(
            harness=None,
            running_record={},
            monitor_started=True,
            observe=lambda call: call(),
            update_phase=lambda *_args: None,
        )


class LegacyPipelineMemoryContractTests(unittest.TestCase):
    def test_frozen_memory_contract_is_attached_before_harness_preparation(self):
        prompt = {"agent_role": "soc-analyst"}
        events: list[tuple[str, bool]] = []

        def attach(value, *, evaluation_frozen):
            events.append(("attach", evaluation_frozen))
            value["memory_context_contract"] = {
                "evaluation_frozen": evaluation_frozen,
            }

        startup_adapter = _StartupAdapter(prompt)
        bindings = {
            "flush_analysis_index_queue": lambda *_args, **_kwargs: (0, 0, 0),
            "_startup_runtime_adapter": lambda: startup_adapter,
            "attach_agent_memory_context_contract": attach,
        }
        state = SimpleNamespace(
            controlled=True,
            memory_frozen=True,
            args=SimpleNamespace(alert_store_url="http://127.0.0.1:9"),
            context=object(),
            controlled_identity={"evaluation": True},
            prompt_path=None,
            prompt_package={},
            settings={},
            run_id="run-memory-contract",
            started_at="2026-08-14T00:00:00Z",
            active_record_path=Path("/synthetic/active.json"),
            resource_monitor=object(),
            prepared=None,
            harness=None,
            running_record={},
            monitor_started=False,
            observe_harness=None,
        )
        adapters = _Adapters()

        legacy_pipeline._load_and_prepare(bindings, adapters, state)

        self.assertEqual(events, [("attach", True)])
        self.assertIs(adapters.prepared_prompt, prompt)
        self.assertTrue(
            adapters.prepared_prompt["memory_context_contract"][
                "evaluation_frozen"
            ]
        )


if __name__ == "__main__":
    unittest.main()
