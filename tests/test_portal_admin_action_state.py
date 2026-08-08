"""Behavior contracts for Administration action state and lock ownership."""
from __future__ import annotations

import datetime as dt
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_admin_action_state import (  # noqa: E402
    AdminActionStateSources,
    action_log_path,
    action_status_path,
    claim_action_lock,
    latest_action_outcome,
    read_action_lock,
    read_action_status,
    release_action_lock,
    running_action,
    update_action_lock_pid,
    write_action_status,
)


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class AdminActionStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.live_pids: set[int] = set()
        self.actions = {
            "update": {
                "label": "Update packages",
                "summary": "Apply updates",
                "command": ["update", "--safe"],
            },
            "reboot": {
                "label": "Reboot",
                "summary": "Restart host",
                "command": ["sudo", "shutdown", "-r", "now"],
            },
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def sources(self) -> AdminActionStateSources:
        return AdminActionStateSources(
            state_dir=self.state_dir,
            lock_file=self.state_dir / ".lock",
            actions=self.actions,
            process_running=lambda pid: pid in self.live_pids,
            now_iso=lambda: "2026-08-07T20:00:00Z",
            parse_timestamp=parse_timestamp,
            format_timestamp=lambda value: value.isoformat(),
        )

    def test_paths_and_idle_defaults_are_stable(self) -> None:
        sources = self.sources()
        status = read_action_status("update", sources)
        self.assertEqual(action_status_path("update", sources), self.state_dir / "update.json")
        self.assertEqual(action_log_path("update", sources), self.state_dir / "update.log")
        self.assertEqual(status["state"], "idle")
        self.assertEqual(status["command"], "update --safe")
        self.assertEqual(status["message"], "Not run yet.")

    def test_write_updates_timestamp_and_stale_running_process_becomes_unknown(self) -> None:
        sources = self.sources()
        status = {"state": "running", "pid": 41, "message": "working"}
        write_action_status("update", status, sources)
        self.assertEqual(status["updated_at"], "2026-08-07T20:00:00Z")

        loaded = read_action_status("update", sources)

        self.assertEqual(loaded["state"], "unknown")
        self.assertIn("no longer visible", loaded["message"])

    def test_running_process_remains_running_and_malformed_status_is_error(self) -> None:
        sources = self.sources()
        self.live_pids.add(42)
        write_action_status("update", {"state": "running", "pid": 42}, sources)
        self.assertEqual(read_action_status("update", sources)["state"], "running")
        action_status_path("update", sources).write_text("not-json")
        result = read_action_status("update", sources)
        self.assertEqual(result["state"], "error")
        self.assertIn("Could not read status", result["message"])

    def test_reboot_audit_migrates_missing_or_stale_command(self) -> None:
        sources = self.sources()
        for document in (
            {"state": "ok", "started_at": "2026-08-07T10:00:00Z"},
            {
                "state": "ok",
                "started_at": "2026-08-07T10:00:00Z",
                "command": "old reboot command",
            },
        ):
            with self.subTest(document=document):
                self.state_dir.mkdir(exist_ok=True)
                action_status_path("reboot", sources).write_text(json.dumps(document))
                result = read_action_status("reboot", sources)
                self.assertEqual(result["command"], "sudo shutdown -r now")
                self.assertIn("audit history", result["message"])

    def test_latest_outcome_uses_finish_update_start_priority_and_newest_action(self) -> None:
        sources = self.sources()
        write_action_status(
            "update",
            {
                "state": "failed",
                "finished_at": "2026-08-07T12:00:00Z",
                "updated_at": "2026-08-07T20:00:00Z",
                "message": "failed",
                "returncode": 1,
            },
            sources,
        )
        write_action_status(
            "reboot",
            {
                "state": "ok",
                "started_at": "2026-08-07T13:00:00Z",
                "command": "sudo shutdown -r now",
                "message": "done",
                "returncode": 0,
            },
            sources,
        )

        result = latest_action_outcome(sources)

        self.assertEqual(result["id"], "reboot")
        self.assertEqual(result["state"], "ok")
        self.assertEqual(result["when"], "2026-08-07T20:00:00+00:00")

    def test_live_lock_wins_and_stale_lock_is_reconciled(self) -> None:
        sources = self.sources()
        self.state_dir.mkdir()
        sources.lock_file.write_text(
            json.dumps({"id": "update", "label": "Update packages", "pid": 50})
        )
        self.live_pids.add(50)
        self.assertEqual(running_action(sources)["pid"], 50)
        self.live_pids.clear()
        self.assertIsNone(running_action(sources))
        self.assertFalse(sources.lock_file.exists())

    def test_running_status_is_used_when_no_lock_exists(self) -> None:
        sources = self.sources()
        self.live_pids.add(61)
        write_action_status(
            "update",
            {
                "state": "running",
                "pid": 61,
                "started_at": "now",
                "label": "Live update",
            },
            sources,
        )
        result = running_action(sources)
        self.assertEqual(result["id"], "update")
        self.assertEqual(result["label"], "Live update")

    def test_claim_update_and_release_enforce_lock_owner(self) -> None:
        sources = self.sources()
        claimed = claim_action_lock("update", "Update packages", "now", sources)
        self.assertEqual(claimed, (True, "Lock acquired."))
        self.assertEqual(read_action_lock(sources)["pid"], None)
        update_action_lock_pid("other", 90, sources)
        self.assertIsNone(read_action_lock(sources)["pid"])
        update_action_lock_pid("update", 90, sources)
        self.assertEqual(read_action_lock(sources)["pid"], 90)
        release_action_lock("other", sources)
        self.assertTrue(sources.lock_file.exists())
        release_action_lock("update", sources)
        self.assertFalse(sources.lock_file.exists())

    def test_claim_rejects_existing_live_owner(self) -> None:
        sources = self.sources()
        self.state_dir.mkdir()
        sources.lock_file.write_text(
            json.dumps({"id": "update", "label": "Active update", "pid": 99})
        )
        self.live_pids.add(99)
        result = claim_action_lock("reboot", "Reboot", "now", sources)
        self.assertFalse(result[0])
        self.assertIn("Active update is still running as PID 99", result[1])


if __name__ == "__main__":
    unittest.main()
