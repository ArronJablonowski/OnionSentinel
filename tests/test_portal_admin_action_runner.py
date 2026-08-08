"""Behavior contracts for validated Administration action launching."""
from __future__ import annotations

import shlex
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_action_runner import (  # noqa: E402
    AdminActionRunnerSources,
    build_admin_wrapped_command,
    start_admin_action,
)


class AdminActionRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.actions = {
            "update": {
                "label": "Update packages",
                "summary": "Apply trusted updates",
                "command": ["/test/update", "arg with space", "safe;literal"],
            },
            "reboot": {
                "label": "Reboot system",
                "summary": "Restart",
                "command": ["sudo", "shutdown", "-r", "now"],
                "requires_confirmation": "REBOOT",
            },
        }
        self.running = None
        self.current_status = {"state": "idle", "pid": None}
        self.live_pids: set[int] = set()
        self.available = (True, "Available")
        self.claimed = (True, "Lock acquired.")
        self.claim_calls = []
        self.released = []
        self.lock_updates = []
        self.status_writes = []
        self.spawn_calls = []
        self.spawn_error: Exception | None = None

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def sources(self) -> AdminActionRunnerSources:
        def spawn(command: str, log) -> int:
            self.spawn_calls.append(command)
            log.write(b"spawn adapter called\n")
            if self.spawn_error:
                raise self.spawn_error
            return 4242

        return AdminActionRunnerSources(
            actions=self.actions,
            state_dir=self.state_dir,
            lock_file=self.state_dir / ".lock",
            macos_update_checker=Path("/test/check_macos_updates.py"),
            now_iso=lambda: "2026-08-07T21:00:00Z",
            running_action=lambda: self.running,
            read_status=lambda _action_id: dict(self.current_status),
            process_running=lambda pid: pid in self.live_pids,
            check_available=lambda _action_id: self.available,
            claim_lock=lambda action_id, label, started: (
                self.claim_calls.append((action_id, label, started)) or self.claimed
            ),
            release_lock=self.released.append,
            update_lock_pid=lambda action_id, pid: self.lock_updates.append(
                (action_id, pid)
            ),
            write_status=lambda action_id, status: self.status_writes.append(
                (action_id, dict(status))
            ),
            status_path=lambda action_id: self.state_dir / f"{action_id}.json",
            log_path=lambda action_id: self.state_dir / f"{action_id}.log",
            quote=shlex.quote,
            spawn=spawn,
        )

    def test_unknown_and_confirmation_failure_are_side_effect_free(self) -> None:
        unknown = start_admin_action("missing", "", self.sources())
        denied = start_admin_action("reboot", "wrong", self.sources())
        self.assertEqual(unknown, (False, "Unknown admin action."))
        self.assertIn("Type 'REBOOT'", denied[1])
        self.assertEqual(self.claim_calls, [])
        self.assertEqual(self.status_writes, [])
        self.assertEqual(self.spawn_calls, [])

    def test_global_and_same_action_running_guards_precede_availability(self) -> None:
        self.running = {"label": "Other update", "pid": 88}
        result = start_admin_action("update", "", self.sources())
        self.assertFalse(result[0])
        self.assertIn("Other update is still running as PID 88", result[1])
        self.running = None
        self.current_status = {"state": "running", "pid": 89}
        self.live_pids.add(89)
        result = start_admin_action("update", "", self.sources())
        self.assertEqual(result, (False, "Update packages is already running."))
        self.assertEqual(self.claim_calls, [])

    def test_unavailable_and_lock_failure_do_not_write_or_spawn(self) -> None:
        self.available = (False, "No updates available.")
        self.assertEqual(
            start_admin_action("update", "", self.sources()),
            (False, "No updates available."),
        )
        self.available = (True, "Available")
        self.claimed = (False, "Lock busy")
        self.assertEqual(
            start_admin_action("update", "", self.sources()),
            (False, "Lock busy"),
        )
        self.assertEqual(self.status_writes, [])
        self.assertEqual(self.spawn_calls, [])

    def test_success_journals_launch_and_pid_in_order(self) -> None:
        result = start_admin_action("update", "", self.sources())

        self.assertEqual(result, (True, "Started Update packages."))
        self.assertEqual(
            self.claim_calls,
            [("update", "Update packages", "2026-08-07T21:00:00Z")],
        )
        self.assertEqual(len(self.status_writes), 2)
        first = self.status_writes[0][1]
        final = self.status_writes[1][1]
        self.assertEqual(first["state"], "running")
        self.assertIsNone(first["pid"])
        self.assertEqual(final["pid"], 4242)
        self.assertEqual(final["message"], "Started Update packages as PID 4242.")
        self.assertEqual(self.lock_updates, [("update", 4242)])
        wrapper = self.spawn_calls[0]
        self.assertIn("'arg with space'", wrapper)
        self.assertIn("'safe;literal'", wrapper)
        self.assertIn("check_macos_updates.py", wrapper)
        self.assertIn("update.json", wrapper)
        log = (self.state_dir / "update.log").read_text()
        self.assertIn("START Update packages", log)
        self.assertIn("Command: /test/update arg with space safe;literal", log)
        self.assertIn("spawn adapter called", log)

    def test_spawn_failure_releases_lock_and_persists_failure(self) -> None:
        self.spawn_error = RuntimeError("launch failed")

        result = start_admin_action("update", "", self.sources())

        self.assertEqual(
            result, (False, "Failed to start Update packages: launch failed")
        )
        self.assertEqual(self.released, ["update"])
        self.assertEqual(len(self.status_writes), 2)
        failed = self.status_writes[-1][1]
        self.assertEqual(failed["state"], "failed")
        self.assertIsNone(failed["returncode"])
        self.assertIn("launch failed", failed["message"])
        self.assertEqual(self.lock_updates, [])

    def test_wrapper_updates_status_releases_only_owned_lock_and_preserves_exit(self) -> None:
        wrapper = build_admin_wrapped_command(
            "macos-update",
            "macOS update",
            ["/usr/sbin/softwareupdate", "--install", "--all"],
            Path("/state/macos-update.json"),
            Path("/state/.lock"),
            Path("/checker.py"),
            shlex.quote,
        )
        tokens = shlex.split(wrapper)
        completion = tokens[tokens.index("-c") + 1]
        self.assertIn("rc=$?", wrapper)
        self.assertIn("'state':'ok' if rc == 0 else 'failed'", completion)
        self.assertIn("aid == 'macos-update'", completion)
        self.assertIn("l.get('id') == aid", completion)
        self.assertTrue(wrapper.endswith('"$rc"; exit $rc'))


if __name__ == "__main__":
    unittest.main()
