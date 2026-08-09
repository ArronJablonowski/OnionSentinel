#!/usr/bin/env python3
"""Characterization tests for reporting runtime binding."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
if str(N8N_ROOT) not in sys.path:
    sys.path.insert(0, str(N8N_ROOT))

from onion_sentinel.analysis.reporting import runtime_adapter


class ReportingRuntimeAdapterTests(unittest.TestCase):
    def test_log_record_projects_exact_resource_high_water_marks(self) -> None:
        module = SimpleNamespace(
            Resources=lambda **values: SimpleNamespace(**values),
            Inputs=lambda **values: SimpleNamespace(**values),
            Policy=lambda: object(),
            build=lambda inputs, *, policy, dependencies: {
                "inputs": inputs, "policy": policy, "dependencies": dependencies
            },
        )
        dependencies = object()
        monitor = SimpleNamespace(
            max_gpu_celsius=70.0, max_gpu_percent=50.0,
            max_cpu_celsius=65.0, max_soc_celsius=62.0,
            max_memory_percent=44.0, max_power_watts=80.0,
            max_cpu_percent=35.0, note="bounded sample",
        )
        result = runtime_adapter.build_log_record(
            {
                "_reporting_run_log": lambda: module,
                "_reporting_run_log_dependencies": lambda: dependencies,
            },
            run_id="run-1", status="success", started_at="start",
            finished_at="finish", runtime_seconds=1.5, prompt_path=Path("p"),
            prompt_package={}, settings={}, response={}, json_path=Path("j"),
            markdown_path=Path("m"), resource_monitor=monitor,
        )
        self.assertEqual(result["inputs"].resources.gpu_celsius, 70.0)
        self.assertEqual(result["inputs"].resources.power_watts, 80.0)
        self.assertEqual(result["inputs"].resources.note, "bounded sample")
        self.assertIs(result["dependencies"], dependencies)

    def test_phase_record_is_copy_on_write_and_attests_live_route(self) -> None:
        current = {"log_id": "one", "stable": "preserved"}
        result = runtime_adapter.phase_record(
            {
                "project_now": lambda: "2026-08-09T12:00:00Z",
                "model_route_metadata": lambda _settings, _route: (
                    "codex-cli:gpt-5.6-sol:xhigh", "gpt-5.6-sol",
                    "frontier-codex-cli", "codex-cli",
                ),
            },
            current, {}, phase="independent_review",
            model_route="codex-cli:gpt-5.6-sol:xhigh",
            trigger_reason="low confidence",
        )
        self.assertEqual(current, {"log_id": "one", "stable": "preserved"})
        self.assertEqual(result["active_phase"], "independent_review")
        self.assertEqual(result["active_model"], "gpt-5.6-sol")
        self.assertEqual(result["active_provider"], "codex-cli")
        self.assertEqual(result["second_opinion_trigger"], "low confidence")

    def test_phase_publication_is_atomic_and_notification_is_best_effort(self) -> None:
        target = Path("/runtime/active.json")
        updated = {"log_id": "one", "active_phase": "analysis"}
        atomic_write = mock.Mock()
        result = runtime_adapter.publish_phase(
            {
                "current_analysis_phase_record": mock.Mock(return_value=updated),
                "active_analysis_record_path": mock.Mock(
                    side_effect=AssertionError("explicit path must win")
                ),
                "atomic_write_json": atomic_write,
            },
            {}, {}, phase="analysis", active_record_path=target,
        )
        self.assertIs(result, updated)
        atomic_write.assert_called_once_with(target, updated)

        def fail(*_args):
            raise RuntimeError("telemetry is supplemental")

        runtime_adapter.notify_phase(fail, "analysis")
        runtime_adapter.notify_phase(None, "analysis")

    def test_missing_live_osquery_config_projects_explicit_disabled_capability(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as name:
            missing = Path(name) / "missing.json"
            workflow = mock.Mock()
            workflow.prepare_capability.side_effect = (
                lambda package, role, config, **kwargs: {
                    "package": package, "role": role, "config": config,
                    **kwargs,
                }
            )
            policy, dependencies = object(), object()
            bindings = {
                "load_live_osquery_config": mock.Mock(
                    side_effect=AssertionError("missing config must not load")
                ),
                "_query_live_workflow": lambda: workflow,
                "_query_live_workflow_policy": lambda: policy,
                "_query_live_workflow_dependencies": lambda: dependencies,
            }
            result = runtime_adapter.prepare_live_osquery(
                bindings, {"case": "one"}, "incident-responder", missing
            )
            self.assertEqual(result["config"], {
                "enabled": False,
                "allowed_target_aliases": [],
                "allowed_agent_roles": ["incident-responder"],
            })
            self.assertIs(result["policy"], policy)
            self.assertIs(result["dependencies"], dependencies)
            self.assertIsNone(runtime_adapter.prepare_live_osquery(
                bindings, {}, "untrusted-role", missing
            ))


if __name__ == "__main__":
    unittest.main()
