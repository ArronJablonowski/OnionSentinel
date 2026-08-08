"""Behavior contracts for Administration update-availability policy."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_availability import (  # noqa: E402
    AdminAvailabilitySources,
    AdminCommandOutcome,
    compose_admin_action_availability,
)


class CommandSource:
    def __init__(self, outcome: AdminCommandOutcome | None = None) -> None:
        self.outcome = outcome or AdminCommandOutcome(0)
        self.calls: list[tuple[tuple[str, ...], int, bool]] = []

    def __call__(
        self, command: list[str], timeout: int, combine_stderr: bool
    ) -> AdminCommandOutcome:
        self.calls.append((tuple(command), timeout, combine_stderr))
        return self.outcome


class AdminAvailabilityTests(unittest.TestCase):
    def sources(
        self,
        status: dict | None = None,
        outcome: AdminCommandOutcome | None = None,
    ) -> tuple[AdminAvailabilitySources, CommandSource]:
        command = CommandSource(outcome)
        return (
            AdminAvailabilitySources(
                read_macos_update_status=lambda: status or {},
                run_command=command,
                hermes_bin="/test/hermes",
            ),
            command,
        )

    def test_reboot_and_skip_paths_do_not_execute_expensive_sources(self) -> None:
        sources, command = self.sources()

        reboot = compose_admin_action_availability("reboot", False, sources)
        skipped = compose_admin_action_availability("brew-update", True, sources)

        self.assertTrue(reboot[0])
        self.assertIn("typed confirmation", reboot[1])
        self.assertTrue(skipped[0])
        self.assertIn("skipped", skipped[1])
        self.assertEqual(command.calls, [])

    def test_macos_reports_available_current_and_unknown_cache_states(self) -> None:
        sources, command = self.sources({"count": "2", "checked_at": "now"})
        self.assertEqual(
            compose_admin_action_availability("macos-update", False, sources),
            (True, "2 macOS update(s) available. Last checked now."),
        )
        sources, _ = self.sources({"count": 0, "checked_at": "then"})
        self.assertEqual(
            compose_admin_action_availability("macos-update", False, sources),
            (False, "No macOS updates available. Last checked then."),
        )
        sources, _ = self.sources({"count": "invalid"})
        result = compose_admin_action_availability("macos-update", False, sources)
        self.assertFalse(result[0])
        self.assertIn("unknown", result[1])
        self.assertEqual(command.calls, [])

    def test_brew_lists_a_bounded_preview_and_count(self) -> None:
        outcome = AdminCommandOutcome(
            0, stdout="one\ntwo\nthree\nfour\nfive\nsix\n"
        )
        sources, command = self.sources(outcome=outcome)

        result = compose_admin_action_availability("brew-update", False, sources)

        self.assertEqual(
            result,
            (
                True,
                "6 Homebrew package(s) outdated: one, two, three, four, five and 1 more.",
            ),
        )
        self.assertEqual(
            command.calls,
            [(('/opt/homebrew/bin/brew', 'outdated', '--quiet'), 20, False)],
        )

    def test_brew_distinguishes_current_failure_and_execution_error(self) -> None:
        sources, _ = self.sources(outcome=AdminCommandOutcome(0))
        self.assertEqual(
            compose_admin_action_availability("brew-update", False, sources),
            (False, "No Homebrew updates available."),
        )
        sources, _ = self.sources(outcome=AdminCommandOutcome(2, stderr="bad state"))
        self.assertEqual(
            compose_admin_action_availability("brew-update", False, sources),
            (False, "Could not determine Homebrew update availability: bad state."),
        )
        sources, _ = self.sources(
            outcome=AdminCommandOutcome(None, error="executable missing")
        )
        self.assertEqual(
            compose_admin_action_availability("brew-update", False, sources),
            (
                False,
                "Could not determine Homebrew update availability: executable missing",
            ),
        )

    def test_hermes_recognizes_positive_and_negative_update_phrases(self) -> None:
        for output, expected in (
            ("Update available", True),
            ("Local checkout is 1 commit behind", True),
            ("Already up to date", False),
            ("No update required", False),
        ):
            with self.subTest(output=output):
                sources, command = self.sources(
                    outcome=AdminCommandOutcome(0, stdout=output)
                )
                result = compose_admin_action_availability(
                    "hermes-update", False, sources
                )
                self.assertEqual(result[0], expected)
                self.assertEqual(
                    command.calls,
                    [(('/test/hermes', 'update', '--check'), 45, True)],
                )

    def test_hermes_unknown_output_is_bounded_and_failure_is_explicit(self) -> None:
        sources, _ = self.sources(
            outcome=AdminCommandOutcome(0, stdout="x" * 400)
        )
        result = compose_admin_action_availability("hermes-update", False, sources)
        self.assertFalse(result[0])
        self.assertLessEqual(len(result[1]), 290)
        sources, _ = self.sources(outcome=AdminCommandOutcome(3, stdout="failed"))
        self.assertEqual(
            compose_admin_action_availability("hermes-update", False, sources),
            (
                False,
                "Could not determine Hermes Agent update availability: failed.",
            ),
        )

    def test_unknown_action_remains_available_without_process_execution(self) -> None:
        sources, command = self.sources()

        result = compose_admin_action_availability("custom", False, sources)

        self.assertTrue(result[0])
        self.assertIn("No update availability rule", result[1])
        self.assertEqual(command.calls, [])


if __name__ == "__main__":
    unittest.main()
