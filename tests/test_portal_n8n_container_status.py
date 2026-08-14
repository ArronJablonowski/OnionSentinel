#!/usr/bin/env python3
"""Contracts for bounded n8n Docker and healthz status."""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_n8n_container_status import (  # noqa: E402
    N8nContainerStatusSources,
    _inspect_container,
    compose_n8n_container_status,
)


@dataclass
class Process:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


class Runner:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((command, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def inspect_payload(state="running", restart="unless-stopped") -> str:
    return json.dumps([{
        "State": {"Status": state, "StartedAt": "2026-08-07T10:00:00Z"},
        "HostConfig": {"RestartPolicy": {"Name": restart}},
        "Config": {"Env": ["SECRET=must-not-project"]},
    }])


class N8nContainerStatusTests(unittest.TestCase):
    def sources(self, runner: Runner) -> N8nContainerStatusSources:
        return N8nContainerStatusSources(
            docker_bin="/docker", container_name="n8n", health_url="http://healthz",
            environment={"PATH": "/bin"}, pipe=-1, run=runner,
            now=lambda: dt.datetime(2026, 8, 7, 12, 0, tzinfo=dt.timezone.utc),
            format_timestamp=lambda _value: "checked",
        )

    def compose(self, runner: Runner):
        return compose_n8n_container_status(self.sources(runner))

    def test_inspect_boundary_preserves_runner_contract_and_success_shapes(self) -> None:
        base = {"id": "n8n", "checked_at": "timestamp"}
        for output, expected in (
            ('[{"State":{"Status":"running"}}]', {"State": {"Status": "running"}}),
            ("[]", {}),
            ('{"State":{}}', {}),
            ("null", {}),
        ):
            with self.subTest(output=output):
                runner = Runner(Process(stdout=output))

                result = _inspect_container(
                    self.sources(runner), base, "checked-label",
                )

                self.assertEqual(result, (expected, None))
                self.assertEqual(runner.calls, [
                    (
                        ["/docker", "inspect", "n8n"],
                        {
                            "text": True,
                            "stdout": -1,
                            "stderr": -1,
                            "timeout": 5,
                            "check": False,
                            "env": {"PATH": "/bin"},
                        },
                    )
                ])

    def test_inspect_failure_reason_precedence_and_missing_classification(self) -> None:
        base = {"id": "n8n", "checked_at": "timestamp"}
        cases = (
            (Process(1, stdout="ignored", stderr="first\nNo Such Container: n8n"), "Missing", "No Such Container: n8n"),
            (Process(1, stdout="daemon offline", stderr=""), "Docker unavailable", "daemon offline"),
            (Process(1, stdout="\n", stderr="\n"), "Docker unavailable", "docker inspect failed"),
        )
        for process, value, reason in cases:
            with self.subTest(value=value, reason=reason):
                container, failure = _inspect_container(
                    self.sources(Runner(process)), base, "checked-label",
                )

                self.assertEqual(container, {})
                self.assertEqual(failure["value"], value)
                self.assertEqual(
                    failure["detail"],
                    f"WARNING: n8n status unavailable: {reason} · healthz not checked "
                    "· checked checked-label",
                )

    def test_inspect_exception_is_bounded_docker_unavailable(self) -> None:
        result = self.compose(Runner(RuntimeError("socket unavailable")))
        self.assertEqual(result["value"], "Docker unavailable")
        self.assertIn("socket unavailable", result["detail"])

    def test_missing_container_is_distinguished(self) -> None:
        result = self.compose(Runner(Process(1, stderr="Error: No such object: n8n")))
        self.assertEqual(result["value"], "Missing")
        self.assertIn("healthz not checked", result["detail"])

    def test_invalid_inspect_json_is_unknown(self) -> None:
        result = self.compose(Runner(Process(stdout="not-json")))
        self.assertEqual(result["value"], "Unknown")
        self.assertEqual(result["level"], "alert")

    def test_stopped_container_does_not_probe_healthz(self) -> None:
        runner = Runner(Process(stdout=inspect_payload(state="exited")))
        result = self.compose(runner)
        self.assertEqual(result["value"], "exited")
        self.assertEqual(result["healthz"], "not checked")
        self.assertEqual(len(runner.calls), 1)

    def test_healthy_container_requires_healthz_and_restart_policy(self) -> None:
        runner = Runner(
            Process(stdout=inspect_payload()),
            Process(stdout='{"status":"ok"}'),
        )
        result = self.compose(runner)
        self.assertTrue(result["running"])
        self.assertEqual(result["value"], "Healthy")
        self.assertEqual(result["healthz"], "ok")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_unhealthy_response_and_policy_drift_are_warnings(self) -> None:
        unhealthy = self.compose(Runner(
            Process(stdout=inspect_payload()), Process(stdout='{"status":"degraded"}'),
        ))
        policy = self.compose(Runner(
            Process(stdout=inspect_payload(restart="always")),
            Process(stdout='{"status":"ok"}'),
        ))
        self.assertEqual(unhealthy["value"], "Health warning")
        self.assertEqual(policy["value"], "Policy warning")
        self.assertFalse(unhealthy["running"])
        self.assertFalse(policy["running"])


if __name__ == "__main__":
    unittest.main()
