"""Characterization for provider and supervision readiness phases."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "check-onion-sentinel-readiness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("readiness_phases", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


readiness = load_module()


def completed(returncode: int = 0, stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], returncode, stdout, "")


class ProviderReadinessCharacterization(unittest.TestCase):
    def test_public_surface_and_target_signatures_are_exact(self) -> None:
        names = sorted(name for name in dir(readiness) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (37, "e5085d6e6684f7398212fe40c42382cfdc3bce4d12e3156b801945c037b63945"),
        )
        self.assertEqual(
            str(inspect.signature(readiness.check_credentials)),
            "(stack: 'Path') -> 'dict[str, Any]'",
        )
        self.assertEqual(
            str(inspect.signature(readiness.check_providers)),
            "(stack: 'Path') -> 'dict[str, Any]'",
        )
        self.assertEqual(
            str(inspect.signature(readiness.check_supervision)),
            "(stack: 'Path') -> 'dict[str, Any]'",
        )

    def test_configured_routes_are_sorted_and_deduplicated(self) -> None:
        settings = {
            "agent_models": {"b": "openclaw:model", "a": "codex-cli:model"},
            "agent_second_opinion_models": {"a": "codex-cli:model"},
            "agent_adjudicator_models": {"a": "hermes-agent:model"},
        }
        self.assertEqual(
            readiness.configured_routes(settings),
            ["codex-cli:model", "hermes-agent:model", "openclaw:model"],
        )

    def test_all_supported_provider_rules_and_result_are_exact(self) -> None:
        settings = {
            "agent_models": {
                "a": "codex-cli:one",
                "b": "ollama:two",
                "c": "hermes-agent:three",
                "d": "openclaw:four",
            },
            "agent_second_opinion_models": {},
            "agent_adjudicator_models": {},
            "codex_cli_path": "codex-test",
            "ollama_url": "http://127.0.0.1:11434/api",
            "hermes_agent_path": "/opt/readiness/hermes",
            "openclaw_path": "/opt/readiness/openclaw",
        }
        with mock.patch.object(readiness, "read_json", return_value=settings), mock.patch.object(
            readiness.shutil,
            "which",
            return_value="/usr/local/bin/codex-test",
        ) as which, mock.patch.object(
            readiness.os.path,
            "isfile",
            return_value=True,
        ) as isfile, mock.patch.object(
            readiness.os,
            "access",
            return_value=True,
        ) as access, mock.patch.object(
            readiness.time,
            "monotonic",
            side_effect=[10.0, 10.125],
        ):
            value = readiness.check_providers(Path("/synthetic-stack"))

        self.assertEqual(
            value,
            {
                "component": "providers",
                "state": "ready",
                "reason_code": "assigned_executables_available",
                "duration_ms": 125,
                "assigned_route_count": 4,
            },
        )
        which.assert_called_once_with("codex-test")
        self.assertEqual(
            [call.args[0] for call in isfile.call_args_list],
            [
                "/usr/local/bin/codex-test",
                "/opt/readiness/hermes",
                "/opt/readiness/openclaw",
            ],
        )
        self.assertEqual(
            [call.args for call in access.call_args_list],
            [
                ("/usr/local/bin/codex-test", os.X_OK),
                ("/opt/readiness/hermes", os.X_OK),
                ("/opt/readiness/openclaw", os.X_OK),
            ],
        )

    def provider_failure(self, settings: dict[str, object]) -> dict[str, object]:
        with mock.patch.object(readiness, "read_json", return_value=settings), mock.patch.object(
            readiness.time,
            "monotonic",
            side_effect=[20.0, 20.001],
        ):
            return readiness.check_providers(Path("/synthetic-stack"))

    def test_provider_failure_reason_codes_are_exact(self) -> None:
        cases = (
            ({"agent_models": {}}, "no_assigned_routes"),
            ({"agent_models": {"a": "unknown:model"}}, "unsupported_assigned_provider"),
            (
                {"agent_models": {"a": "ollama:model"}, "ollama_url": "ssh://host"},
                "ollama_endpoint_invalid",
            ),
            (
                {"agent_models": {"a": "ollama:model"}, "ollama_url": "http://u:p@host"},
                "ollama_endpoint_invalid",
            ),
            (
                {"agent_models": {"a": "ollama:model"}, "ollama_url": "http://host?q=1"},
                "ollama_endpoint_invalid",
            ),
        )
        for settings, reason in cases:
            with self.subTest(reason=reason, settings=settings):
                self.assertEqual(self.provider_failure(settings)["reason_code"], reason)

    def test_missing_executable_names_the_provider_without_a_path(self) -> None:
        settings = {
            "agent_models": {"a": "hermes-agent:model"},
            "hermes_agent_path": "",
        }
        self.assertEqual(
            self.provider_failure(settings),
            {
                "component": "providers",
                "state": "failed",
                "reason_code": "hermes-agent_executable_unavailable",
                "duration_ms": 1,
            },
        )


class SupervisionReadinessCharacterization(unittest.TestCase):
    def stack(self, root: str) -> Path:
        stack = Path(root) / "stack"
        (stack / "logs").mkdir(parents=True)
        return stack

    def test_registered_jobs_and_single_workers_use_exact_bounded_commands(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            stack = self.stack(root)
            with mock.patch.object(
                readiness.subprocess,
                "run",
                side_effect=[completed()] * 6 + [completed(stdout="41\n"), completed()],
            ) as run, mock.patch.object(
                readiness.os,
                "getuid",
                return_value=502,
            ), mock.patch.object(
                readiness.time,
                "monotonic",
                side_effect=[30.0, 30.01],
            ):
                value = readiness.check_supervision(stack)

        self.assertEqual(
            value,
            {
                "component": "supervision",
                "state": "ready",
                "reason_code": "jobs_registered_no_duplicates",
                "duration_ms": 10,
            },
        )
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["/bin/launchctl", "print", "gui/502/com.arron.onion-sentinel.web"],
                ["/bin/launchctl", "print", "gui/502/com.arron.soc.alert-store"],
                ["/bin/launchctl", "print", "gui/502/com.arron.soc.ai-analysis"],
                ["/bin/launchctl", "print", "gui/502/com.arron.soc.ai-analysis-cli"],
                ["/bin/launchctl", "print", "gui/502/com.arron.n8n.ensure-stack"],
                ["/bin/launchctl", "print", "gui/502/com.arron.n8n.monitor-stack"],
                ["/usr/bin/pgrep", "-f", "auto-run-ai-analysis.py --provider-lane ollama"],
                ["/usr/bin/pgrep", "-f", "auto-run-ai-analysis.py --provider-lane cli"],
            ],
        )
        for call in run.call_args_list:
            self.assertEqual(
                call.kwargs,
                {"capture_output": True, "check": False, "text": True, "timeout": 2},
            )

    def write_budget(self, stack: Path, value: object) -> None:
        path = stack / "logs" / "onion-sentinel-web-restart-budget.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        os.chmod(path, 0o600)

    def test_restart_budget_invalid_and_active_fail_before_process_checks(self) -> None:
        cases = (
            ({"window_seconds": "invalid"}, "restart_budget_invalid"),
            (
                {"quarantined": True, "updated_at": 950.0, "window_seconds": 100},
                "web_restart_quarantined",
            ),
        )
        for budget, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as root:
                stack = self.stack(root)
                self.write_budget(stack, budget)
                with mock.patch.object(readiness.time, "time", return_value=1000.0), mock.patch.object(
                    readiness.subprocess,
                    "run",
                ) as run:
                    value = readiness.check_supervision(stack)
                self.assertEqual(value["reason_code"], reason)
                run.assert_not_called()

    def test_expired_quarantine_continues_to_process_checks(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            stack = self.stack(root)
            self.write_budget(
                stack,
                {"quarantined": True, "updated_at": 800.0, "window_seconds": 100},
            )
            with mock.patch.object(readiness.time, "time", return_value=1000.0), mock.patch.object(
                readiness.subprocess,
                "run",
                side_effect=[completed()] * 8,
            ) as run:
                value = readiness.check_supervision(stack)
        self.assertEqual(value["state"], "ready")
        self.assertEqual(run.call_count, 8)

    def test_launchd_failure_and_exception_reason_codes_are_exact(self) -> None:
        cases = (
            ([completed(returncode=3)], "required_job_unregistered"),
            ([OSError("private")], "launchd_check_failed"),
        )
        for side_effect, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as root:
                stack = self.stack(root)
                with mock.patch.object(
                    readiness.subprocess,
                    "run",
                    side_effect=side_effect,
                ):
                    value = readiness.check_supervision(stack)
                self.assertEqual(value["reason_code"], reason)

    def test_each_worker_lane_duplicate_and_error_reason_is_exact(self) -> None:
        cases = (
            ([completed()] * 6 + [completed(stdout="41\n42\n")], "duplicate_ollama_workers"),
            (
                [completed()] * 6 + [completed(), completed(stdout="41\n42\n")],
                "duplicate_cli_workers",
            ),
            ([completed()] * 6 + [OSError("private")], "worker_check_failed"),
        )
        for side_effect, reason in cases:
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as root:
                stack = self.stack(root)
                with mock.patch.object(
                    readiness.subprocess,
                    "run",
                    side_effect=side_effect,
                ):
                    value = readiness.check_supervision(stack)
                self.assertEqual(value["reason_code"], reason)


if __name__ == "__main__":
    unittest.main()
