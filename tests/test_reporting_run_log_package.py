"""Direct contracts for pure analysis run-log projection."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
N8N_ROOT = ROOT / "n8n"
sys.path.insert(0, str(N8N_ROOT))
from onion_sentinel.analysis.reporting import run_log  # noqa: E402


DEPENDENCIES = run_log.Dependencies(
    enabled_routes=lambda settings: settings.get("enabled_routes", []),
    canonical_route=lambda value, routes: str(value or "default-route"),
    assigned_metadata=lambda settings, role: (
        "assigned-model", "frontier-codex-cli", "codex-cli"
    ),
)
RESOURCES = run_log.Resources(
    gpu_celsius=55.5,
    gpu_percent=60.0,
    cpu_celsius=50.0,
    soc_celsius=52.0,
    memory_percent=70.0,
    power_watts=30.0,
    cpu_percent=40.0,
    note="sampled",
)


def inputs(**overrides) -> run_log.Inputs:
    values = {
        "run_id": "run-1",
        "status": "running",
        "started_at": "start",
        "finished_at": None,
        "runtime_seconds": None,
        "prompt_path": Path("/tmp/prompt.json"),
        "prompt_package": {
            "agent_role": "soc-analyst",
            "alert": {"alert_id": "alert-1"},
        },
        "settings": {
            "agent_models": {"soc-analyst": "codex-cli:model:high"},
        },
        "response": None,
        "json_path": None,
        "markdown_path": None,
        "resources": RESOURCES,
    }
    values.update(overrides)
    return run_log.Inputs(**values)


class RunLogPackageTests(unittest.TestCase):
    def test_running_record_separates_assignment_from_observation(self) -> None:
        record = run_log.build(
            inputs(), policy=run_log.Policy(), dependencies=DEPENDENCIES,
        )
        self.assertEqual(record["assigned_model"], "assigned-model")
        self.assertEqual(record["assigned_model_path"], "frontier-codex-cli")
        self.assertEqual(record["assigned_model_route"], "codex-cli:model:high")
        self.assertEqual(record["model"], "")
        self.assertEqual(record["model_path"], "")
        self.assertEqual(record["model_route"], "")
        self.assertFalse(record["model_started"])
        self.assertEqual(record["active_phase"], "preparing")
        self.assertEqual(record["active_phase_started_at"], "start")
        self.assertEqual(record["active_model"], "")

    def test_success_record_projects_observed_model_resources_and_paths(self) -> None:
        record = run_log.build(
            inputs(
                status="success",
                finished_at="finish",
                runtime_seconds=1.23456,
                response={
                    "_analysis_model": "gpt-5.6-sol",
                    "_analysis_model_path": "frontier-codex-cli",
                    "_analysis_provider": "codex-cli",
                    "_analysis_harness": "onion-sentinel",
                    "_analysis_input_mode": "structured",
                },
                json_path=Path("/tmp/result.json"),
                markdown_path=Path("/tmp/result.md"),
            ),
            policy=run_log.Policy(),
            dependencies=DEPENDENCIES,
        )
        self.assertTrue(record["success"])
        self.assertEqual(record["runtime_seconds"], 1.235)
        self.assertEqual(record["mode"], "codex-cli")
        self.assertEqual(record["model"], "gpt-5.6-sol")
        self.assertEqual(record["model_route"], "codex-cli:model:high")
        self.assertTrue(record["model_started"])
        self.assertEqual(record["analysis_json"], "/tmp/result.json")
        self.assertEqual(record["analysis_markdown"], "/tmp/result.md")
        self.assertEqual(record["gpu_temperature_celsius_max"], 55.5)
        self.assertEqual(record["memory_used_percent_max"], 70.0)
        self.assertEqual(record["pcap_total_size_bytes"], 0)
        self.assertGreater(record["alert_context_size_bytes"], 0)
        self.assertEqual(record["alert"]["primary_alert_id"], "alert-1")

    def test_alert_projection_caps_timeline_and_repairs_count(self) -> None:
        summary = run_log.alert_summary({
            "alert": {
                "alert_id": "primary",
                "rule_name": "Rule",
                "seen_count": "invalid",
            },
            "grouped_alert_context": {
                "timeline": [
                    {"alert_id": f"alert-{number}"} for number in range(30)
                ],
            },
        })
        self.assertEqual(summary["primary_alert_id"], "primary")
        self.assertEqual(summary["alert_ids"][0], "primary")
        self.assertEqual(len(summary["alert_ids"]), 26)
        self.assertEqual(summary["alert_ids_truncated"], 4)
        self.assertEqual(summary["alert_count"], 1)

    def test_pcap_size_deduplicates_per_request_and_identity(self) -> None:
        package = {"pcap_evidence": {"parsed_evidence": [
            {
                "request_id": "request-a",
                "pcap_files": [
                    {"sha256": "same", "size_bytes": 100},
                    {"sha256": "same", "size_bytes": 100},
                    {"name": "negative", "size_bytes": -20},
                    {"name": "invalid", "size_bytes": "not-a-size"},
                ],
            },
            {
                "request_id": "request-b",
                "pcap_files": [{"sha256": "same", "size_bytes": 50}],
            },
        ]}}
        self.assertEqual(run_log.pcap_size_bytes(package), 150)

    def test_context_size_matches_canonical_projection(self) -> None:
        package = {
            "alert": {"id": "a"},
            "grouped_alert_context": {"count": 2},
            "ignored": "not projected",
        }
        baseline = run_log.alert_context_size_bytes(package)
        package["ignored"] = "x" * 1000
        self.assertEqual(run_log.alert_context_size_bytes(package), baseline)

    def test_failure_uses_only_recognized_observed_active_phase(self) -> None:
        observation = {
            "active_phase": "second_opinion",
            "active_model": "reviewer",
            "active_model_path": "ollama",
            "active_model_route": "ollama:reviewer",
        }
        record = run_log.build(
            inputs(
                status="failure",
                runtime_observation=observation,
                error="failed",
            ),
            policy=run_log.Policy(),
            dependencies=DEPENDENCIES,
        )
        self.assertEqual(record["model"], "reviewer")
        self.assertEqual(record["model_path"], "ollama")
        self.assertEqual(record["model_route"], "ollama:reviewer")
        self.assertEqual(record["mode"], "ollama")
        self.assertEqual(record["error"], "failed")
        ignored = run_log.build(
            inputs(
                status="failure",
                runtime_observation={**observation, "active_phase": "preparing"},
            ),
            policy=run_log.Policy(),
            dependencies=DEPENDENCIES,
        )
        self.assertEqual(ignored["model"], "")
        self.assertFalse(ignored["model_started"])

    def test_projection_has_no_io_primitives(self) -> None:
        source = (
            N8N_ROOT / "onion_sentinel" / "analysis" / "reporting"
            / "run_log.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            ".write_text(", ".write_bytes(", "urlopen(", "subprocess.",
            "sqlite3.", "open(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
