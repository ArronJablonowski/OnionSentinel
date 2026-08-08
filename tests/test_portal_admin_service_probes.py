"""Behavior contracts for Administration process and daemon probes."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_service_probes import (  # noqa: E402
    AdminServiceProbeSources,
    ServiceCommandOutcome,
    codex_app_status,
    codex_cli_status,
    docker_status,
    macs_fan_control_status,
    matching_process_lines,
)


class AdminServiceProbeTests(unittest.TestCase):
    def sources(
        self,
        lines: list[str] | Exception | None = None,
        docker: ServiceCommandOutcome | Exception | None = None,
    ) -> AdminServiceProbeSources:
        def process_lines() -> list[str]:
            if isinstance(lines, Exception):
                raise lines
            return list(lines or [])

        def docker_info() -> ServiceCommandOutcome:
            if isinstance(docker, Exception):
                raise docker
            return docker or ServiceCommandOutcome(1)

        return AdminServiceProbeSources(process_lines, docker_info)

    def test_matching_process_lines_applies_include_and_exclude_rules(self) -> None:
        lines = [" 1 target worker", "2 target grep", "3 other"]
        self.assertEqual(
            matching_process_lines(lines, ["target"], ["grep"]),
            ["1 target worker"],
        )

    def test_fan_and_codex_app_probes_report_running_missing_and_errors(self) -> None:
        fan = macs_fan_control_status(
            self.sources(["10 /Applications/Macs Fan Control.app/Contents/MacOS/Macs Fan Control"])
        )
        codex = codex_app_status(
            self.sources(["11 /Applications/Codex.app/Contents/MacOS/Codex"])
        )
        missing = codex_app_status(self.sources([]))
        failed = macs_fan_control_status(self.sources(RuntimeError("ps failed")))
        self.assertTrue(fan[0])
        self.assertTrue(codex[0])
        self.assertFalse(missing[0])
        self.assertIn("not currently running", missing[1])
        self.assertIn("ps failed", failed[1])

    def test_codex_cli_excludes_desktop_helpers_and_bounds_preview(self) -> None:
        sources = self.sources(
            [
                "1 /Applications/Codex.app/Contents/MacOS/Codex",
                "2 /Users/test/.local/bin/codex exec task-a",
                "3 codex resume task-b",
                "4 openai_codex worker",
                "5 /opt/bin/codex --help",
            ]
        )
        result = codex_cli_status(sources)
        self.assertTrue(result[0])
        self.assertNotIn("Applications/Codex.app", result[1])
        self.assertIn("+1 more", result[1])
        self.assertEqual(
            codex_cli_status(self.sources([])),
            (False, "Codex CLI is not currently running."),
        )

    def test_docker_daemon_version_is_authoritative(self) -> None:
        result = docker_status(
            self.sources(
                ["com.docker.backend"],
                ServiceCommandOutcome(0, stdout="28.1.0\n"),
            )
        )
        self.assertEqual(
            result, (True, "Docker daemon is running. Server version: 28.1.0.")
        )

    def test_docker_desktop_fallback_and_helper_only_warning(self) -> None:
        desktop = docker_status(
            self.sources(
                ["22 com.docker.backend"],
                ServiceCommandOutcome(1, stderr="daemon unavailable"),
            )
        )
        helper = docker_status(
            self.sources(
                ["23 com.docker.vmnetd"],
                ServiceCommandOutcome(1, stderr="cannot connect"),
            )
        )
        self.assertTrue(desktop[0])
        self.assertIn("docker info did not return", desktop[1])
        self.assertFalse(helper[0])
        self.assertIn("cannot connect", helper[1])
        self.assertIn("Docker helper is present", helper[1])

    def test_docker_probe_errors_are_explicit(self) -> None:
        result = docker_status(self.sources(docker=RuntimeError("docker missing")))
        self.assertFalse(result[0])
        self.assertIn("Unable to verify Docker state: docker missing", result[1])
        result = docker_status(
            self.sources(docker=ServiceCommandOutcome(None, error="launch failed"))
        )
        self.assertIn("launch failed", result[1])


if __name__ == "__main__":
    unittest.main()
