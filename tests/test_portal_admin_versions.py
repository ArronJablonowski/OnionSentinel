"""Behavior contracts for bounded Administration version discovery."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_versions import (  # noqa: E402
    AdminVersionSources,
    compose_admin_action_version_info,
)


class CommandSource:
    def __init__(self, responses: dict[tuple[str, ...], tuple[int | None, str]]) -> None:
        self.responses = responses
        self.calls: list[tuple[tuple[str, ...], int]] = []

    def __call__(self, command: list[str], timeout: int) -> tuple[int | None, str]:
        key = tuple(command)
        self.calls.append((key, timeout))
        return self.responses.get(key, (1, "missing test response"))


class AdminVersionTests(unittest.TestCase):
    def sources(
        self,
        responses: dict[tuple[str, ...], tuple[int | None, str]] | None = None,
        macos_status: dict | None = None,
    ) -> tuple[AdminVersionSources, CommandSource]:
        command = CommandSource(responses or {})
        return (
            AdminVersionSources(
                run_command=command,
                read_macos_update_status=lambda: macos_status or {},
                hermes_bin="/test/hermes",
                hermes_project=Path("/test/hermes-agent"),
            ),
            command,
        )

    def test_macos_reports_build_and_cached_update(self) -> None:
        sources, command = self.sources(
            {("/usr/bin/sw_vers",): (0, "ProductVersion: 26.1\nBuildVersion: 25B1")},
            {
                "updates": ["macOS Redwood 26.2"],
                "count": 1,
                "checked_at": "2026-08-07T20:00:00Z",
            },
        )

        result = compose_admin_action_version_info("macos-update", sources)

        self.assertEqual(result["current"], "macOS 26.1 (25B1)")
        self.assertEqual(result["latest"], "macOS Redwood 26.2")
        self.assertIn("1 cached macOS update", result["detail"])
        self.assertEqual(command.calls, [(('/usr/bin/sw_vers',), 6)])

    def test_macos_distinguishes_current_from_unknown(self) -> None:
        sources, _command = self.sources(
            {("/usr/bin/sw_vers",): (0, "ProductVersion: 26.1")},
            {"updates": [], "count": 0, "checked_at": "now"},
        )
        self.assertEqual(
            compose_admin_action_version_info("macos-update", sources)["latest"],
            "Current",
        )
        sources, _command = self.sources(
            {("/usr/bin/sw_vers",): (1, "")},
            {"updates": "invalid", "count": -1, "status": "failed"},
        )
        result = compose_admin_action_version_info("macos-update", sources)
        self.assertEqual(result["current"], "macOS Unknown")
        self.assertEqual(result["latest"], "Unknown")
        self.assertIn("failed", result["detail"])

    def test_brew_normalizes_formula_and_cask_versions(self) -> None:
        payload = (
            'prefix noise {"formulae":[{"name":"jq","installed_versions":["1.7"],'
            '"current_version":"1.8"}],"casks":[{"token":"firefox",'
            '"installed_version":"153","latest_version":"154"}]}'
        )
        sources, command = self.sources(
            {
                ("/opt/homebrew/bin/brew", "--version"): (0, "Homebrew 5.0\nmore"),
                ("/opt/homebrew/bin/brew", "outdated", "--json=v2"): (0, payload),
            }
        )

        result = compose_admin_action_version_info("brew-update", sources)

        self.assertEqual(result["current"], "Homebrew 5.0")
        self.assertIn("jq 1.8", result["latest"])
        self.assertIn("firefox 154", result["latest"])
        self.assertIn("jq: 1.7 → 1.8", result["detail"])
        self.assertEqual(command.calls[-1][1], 25)

    def test_brew_failure_is_unknown_and_bounded(self) -> None:
        sources, _command = self.sources(
            {
                ("/opt/homebrew/bin/brew", "--version"): (0, "Homebrew 5.0"),
                ("/opt/homebrew/bin/brew", "outdated", "--json=v2"): (2, "x" * 400),
            }
        )

        result = compose_admin_action_version_info("brew-update", sources)

        self.assertEqual(result["latest"], "Unknown")
        self.assertLessEqual(len(result["detail"]), 260)

    def test_hermes_reports_remote_version_when_commits_differ(self) -> None:
        project = "/test/hermes-agent"
        sources, command = self.sources(
            {
                ("/test/hermes", "--version"): (0, "Hermes Agent v1.2.3"),
                ("/usr/bin/git", "-C", project, "rev-parse", "--short", "HEAD"): (0, "abc123"),
                ("/usr/bin/git", "-C", project, "rev-parse", "--short", "origin/main"): (0, "def456"),
                ("/usr/bin/git", "-C", project, "log", "origin/main", "-1", "--pretty=%s"): (0, "Security update"),
                ("/usr/bin/git", "-C", project, "show", "origin/main:hermes_cli/__init__.py"): (
                    0,
                    "__version__ = '1.3.0'\n__release_date__ = '2026-08-07'",
                ),
            }
        )

        result = compose_admin_action_version_info("hermes-update", sources)

        self.assertIn("v1.2.3 · abc123", result["current"])
        self.assertIn("v1.3.0 (2026-08-07) · def456", result["latest"])
        self.assertIn("Security update", result["detail"])
        self.assertEqual(len(command.calls), 5)

    def test_hermes_cli_update_hint_survives_missing_git_metadata(self) -> None:
        sources, _command = self.sources(
            {("/test/hermes", "--version"): (0, "Hermes Agent v1.2.3\nUpdate available")}
        )

        result = compose_admin_action_version_info("hermes-update", sources)

        self.assertEqual(result["latest"], "Available")
        self.assertIn("Update available", result["detail"])

    def test_unsupported_action_does_not_run_commands(self) -> None:
        sources, command = self.sources()

        result = compose_admin_action_version_info("reboot", sources)

        self.assertEqual(result["current"], "Not applicable")
        self.assertEqual(command.calls, [])


if __name__ == "__main__":
    unittest.main()
