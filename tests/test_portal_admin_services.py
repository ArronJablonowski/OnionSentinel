"""Behavior contracts for Administration service cards and startup policy."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_services import (  # noqa: E402
    AdminServiceStartSources,
    compose_admin_service_statuses,
    start_admin_service,
)


class AdminServicesTests(unittest.TestCase):
    def test_composition_projects_stable_cards_and_preserves_n8n_record(self) -> None:
        labels = {"one": "Service One", "two": "Service Two"}
        n8n = {"id": "n8n", "label": "n8n", "running": False, "level": "alert"}
        result = compose_admin_service_statuses(
            labels,
            {
                "one": lambda: (True, "healthy"),
                "two": lambda: (False, "stopped"),
            },
            lambda: n8n,
        )
        self.assertEqual(result["one"]["value"], "Running")
        self.assertEqual(result["one"]["level"], "ok")
        self.assertEqual(result["two"]["value"], "Not running")
        self.assertEqual(result["two"]["level"], "warn")
        self.assertIs(result["n8n"], n8n)

    def sources(self, snapshots, spawn=None):
        calls = []
        iterator = iter(snapshots)

        def statuses():
            calls.append("status")
            return next(iterator)

        source = AdminServiceStartSources(
            labels={"codex": "Codex app"},
            start_commands={"codex": ["open", "-a", "Codex"]},
            statuses=statuses,
            spawn=spawn or (lambda command: calls.append(tuple(command))),
        )
        return source, calls

    def test_unknown_service_is_rejected_without_probe_or_spawn(self) -> None:
        source, calls = self.sources([])
        self.assertEqual(
            start_admin_service("missing", source),
            (False, "Unknown service.", None),
        )
        self.assertEqual(calls, [])

    def test_running_service_is_idempotent(self) -> None:
        card = {"id": "codex", "running": True}
        source, calls = self.sources([{"codex": card}])
        result = start_admin_service("codex", source)
        self.assertEqual(result, (True, "Codex app is already running.", card))
        self.assertEqual(calls, ["status"])

    def test_start_uses_allowlisted_command_and_reprobes(self) -> None:
        initial = {"id": "codex", "running": False}
        latest = {"id": "codex", "running": True}
        source, calls = self.sources([{"codex": initial}, {"codex": latest}])
        result = start_admin_service("codex", source)
        self.assertTrue(result[0])
        self.assertIn("Started Codex app", result[1])
        self.assertIs(result[2], latest)
        self.assertEqual(calls, ["status", ("open", "-a", "Codex"), "status"])

    def test_spawn_failure_reprobes_and_returns_observed_card(self) -> None:
        card = {"id": "codex", "running": False}

        def fail(_command):
            raise RuntimeError("launch failed")

        source, calls = self.sources(
            [{"codex": card}, {"codex": card}], spawn=fail
        )
        result = start_admin_service("codex", source)
        self.assertFalse(result[0])
        self.assertIn("Unable to start Codex app: launch failed", result[1])
        self.assertIs(result[2], card)
        self.assertEqual(calls, ["status", "status"])


if __name__ == "__main__":
    unittest.main()
