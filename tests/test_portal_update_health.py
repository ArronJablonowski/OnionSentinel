"""Behavior contracts for update source checks and precedence policy."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_update_health import (  # noqa: E402
    UpdateCommandOutcome,
    UpdateHealthSources,
    compose_brew_update_source_metric,
    compose_hermes_update_source_metric,
    compose_latest_running_update_action,
    compose_latest_update_action_failure,
    compose_macos_update_metric,
    compose_prioritized_updates_metric,
    read_macos_update_status,
)


class UpdateHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.status_file = Path(self.temp.name) / "macos.json"
        self.statuses = {}
        self.running_pids = set()
        self.brew = UpdateCommandOutcome(0)
        self.hermes = UpdateCommandOutcome(0, "up to date")
        self.brew_calls = 0
        self.hermes_calls = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def sources(self) -> UpdateHealthSources:
        def brew_check():
            self.brew_calls += 1
            if isinstance(self.brew, Exception):
                raise self.brew
            return self.brew

        def hermes_check():
            self.hermes_calls += 1
            if isinstance(self.hermes, Exception):
                raise self.hermes
            return self.hermes

        return UpdateHealthSources(
            macos_status_file=self.status_file,
            run_brew_check=brew_check,
            run_hermes_check=hermes_check,
            read_action_status=lambda action_id: self.statuses.get(action_id, {}),
            process_running=lambda pid: pid in self.running_pids,
            action_labels={
                "macos-update": "macOS software updates",
                "brew-update": "Homebrew update + upgrade",
                "hermes-update": "Hermes Agent update",
            },
            parse_timestamp=lambda value: dt.datetime.fromisoformat(
                str(value).replace("Z", "+00:00")
            ),
            format_timestamp=lambda value: value.isoformat(),
        )

    def write_macos(self, **overrides) -> None:
        payload = {
            "status": "Current",
            "checked_at": "2026-08-07T00:00:00Z",
            "count": 0,
            "updates": [],
        }
        payload.update(overrides)
        self.status_file.write_text(json.dumps(payload))

    def test_macos_status_loader_and_metric_bound_invalid_data(self) -> None:
        loaded = read_macos_update_status(self.status_file)
        self.assertEqual(loaded["status"], "Not checked")
        self.assertEqual(compose_macos_update_metric(self.status_file)[2], -1)

        self.status_file.write_text("[]")
        self.assertEqual(read_macos_update_status(self.status_file), {})

        self.write_macos(
            status="Updates available",
            count="bad",
            updates=["one", "two", "three", "four", "five", "six"],
            error="partial result",
        )
        status, detail, count = compose_macos_update_metric(self.status_file)
        self.assertEqual(status, "Updates available")
        self.assertEqual(count, -1)
        self.assertIn("one; two; three; four; five", detail)
        self.assertNotIn("six", detail)
        self.assertIn("Error: partial result", detail)

    def test_brew_metric_handles_updates_current_failure_and_exception(self) -> None:
        packages = "\n".join(f"package-{index}" for index in range(10))
        count, detail, items = compose_brew_update_source_metric(
            lambda: UpdateCommandOutcome(0, packages)
        )
        self.assertEqual(count, 10)
        self.assertEqual(len(items), 10)
        self.assertIn("and 2 more", detail)
        self.assertEqual(
            compose_brew_update_source_metric(lambda: UpdateCommandOutcome(0)),
            (0, "No Homebrew updates available.", []),
        )
        self.assertIn(
            "permission denied",
            compose_brew_update_source_metric(
                lambda: UpdateCommandOutcome(1, stderr="permission denied")
            )[1],
        )

        def fail():
            raise TimeoutError("timed out")

        self.assertEqual(compose_brew_update_source_metric(fail)[0], -1)

    def test_hermes_metric_classifies_available_current_and_failed_checks(self) -> None:
        available = compose_hermes_update_source_metric(
            lambda: UpdateCommandOutcome(1, "Update available\nmore detail")
        )
        self.assertTrue(available[0])
        self.assertIn("Update available", available[1])
        self.assertEqual(
            compose_hermes_update_source_metric(
                lambda: UpdateCommandOutcome(0, "unrecognized success")
            ),
            (False, "No Hermes Agent update available."),
        )
        failed = compose_hermes_update_source_metric(
            lambda: UpdateCommandOutcome(2, "check failed")
        )
        self.assertFalse(failed[0])
        self.assertIn("check failed", failed[1])

    def test_running_action_requires_live_pid_and_formats_known_provider(self) -> None:
        self.statuses["brew-update"] = {
            "state": "running",
            "pid": 42,
            "started_at": "2026-08-07T01:02:03+00:00",
        }
        self.assertIsNone(compose_latest_running_update_action(self.sources()))
        self.running_pids.add(42)

        result = compose_latest_running_update_action(self.sources())

        self.assertEqual(result[0], "brew running")
        self.assertIn("PID 42", result[1])
        expected = dt.datetime(
            2026, 8, 7, 1, 2, 3, tzinfo=dt.timezone.utc
        ).astimezone().isoformat()
        self.assertIn(expected, result[1])

    def test_running_action_preserves_order_process_failure_and_first_live_short_circuit(self) -> None:
        trace = []
        statuses = {
            "macos-update": {"state": "running", "pid": 1},
            "brew-update": {"state": "idle", "pid": 2},
            "hermes-update": {
                "state": "running",
                "pid": 3,
                "label": "Hermes Agent update",
                "updated_at": "2026-08-07T03:00:00+00:00",
            },
        }

        def read_status(action_id):
            trace.append(("read", action_id))
            return statuses[action_id]

        def process_running(pid):
            trace.append(("process", pid))
            if pid == 1:
                raise PermissionError("process unavailable")
            return pid == 3

        def parse_timestamp(value):
            trace.append(("parse", value))
            return dt.datetime.fromisoformat(value)

        def format_timestamp(value):
            trace.append(("format", value))
            return "formatted-time"

        sources = UpdateHealthSources(
            macos_status_file=self.status_file,
            run_brew_check=lambda: self.brew,
            run_hermes_check=lambda: self.hermes,
            read_action_status=read_status,
            process_running=process_running,
            action_labels={},
            parse_timestamp=parse_timestamp,
            format_timestamp=format_timestamp,
        )

        result = compose_latest_running_update_action(sources)

        self.assertEqual(result[0], "Hermes running")
        self.assertIn("PID 3; started at formatted-time", result[1])
        self.assertEqual(trace, [
            ("read", "macos-update"),
            ("process", 1),
            ("read", "brew-update"),
            ("read", "hermes-update"),
            ("process", 3),
            ("parse", "2026-08-07T03:00:00+00:00"),
            ("format", dt.datetime(
                2026, 8, 7, 3, 0, tzinfo=dt.timezone.utc
            ).astimezone()),
        ])

    def test_running_action_preserves_unknown_pid_label_and_timestamp_fallbacks(self) -> None:
        self.statuses["macos-update"] = {
            "state": "running",
            "pid": 0,
            "label": "",
            "started_at": "",
            "updated_at": "invalid",
        }
        sources = self.sources()
        sources = UpdateHealthSources(
            **{
                **sources.__dict__,
                "process_running": lambda _pid: True,
                "action_labels": {},
            }
        )

        result = compose_latest_running_update_action(sources)

        self.assertEqual(result[0], "Update running")
        self.assertIn("macos-update is currently running as PID unknown", result[1])
        self.assertIn("started at unknown time", result[1])

    def test_running_action_propagates_format_and_base_exception_boundaries(self) -> None:
        self.statuses["macos-update"] = {
            "state": "running",
            "pid": 7,
            "started_at": "2026-08-07T01:02:03+00:00",
        }
        self.running_pids.add(7)
        sources = self.sources()
        format_failure = UpdateHealthSources(
            **{
                **sources.__dict__,
                "format_timestamp": lambda _value: (_ for _ in ()).throw(
                    RuntimeError("format owner failed")
                ),
            }
        )
        with self.assertRaisesRegex(RuntimeError, "format owner failed"):
            compose_latest_running_update_action(format_failure)

        process_failure = UpdateHealthSources(
            **{
                **sources.__dict__,
                "process_running": lambda _pid: (_ for _ in ()).throw(
                    KeyboardInterrupt("process owner stopped")
                ),
            }
        )
        with self.assertRaisesRegex(KeyboardInterrupt, "process owner stopped"):
            compose_latest_running_update_action(process_failure)

    def test_failure_action_selects_newest_and_handles_invalid_timestamp(self) -> None:
        self.statuses.update(
            {
                "macos-update": {
                    "state": "failed",
                    "finished_at": "invalid",
                    "message": "old failure",
                },
                "hermes-update": {
                    "state": "error",
                    "finished_at": "2026-08-07T02:00:00+00:00",
                    "message": "new failure",
                },
            }
        )

        result = compose_latest_update_action_failure(self.sources())

        self.assertEqual(result[0], "Hermes failed")
        self.assertIn("new failure", result[1])

    def test_precedence_short_circuits_running_then_failure(self) -> None:
        self.write_macos(count=5)
        self.statuses["macos-update"] = {"state": "running", "pid": 7}
        self.running_pids.add(7)
        result = compose_prioritized_updates_metric(self.sources())
        self.assertEqual(result, (
            "⏳ macOS running",
            "macOS software updates is currently running as PID 7; started at unknown time. The Updates metric will refresh availability after the action completes.",
            2,
            "running",
        ))
        self.assertEqual((self.brew_calls, self.hermes_calls), (0, 0))

        self.running_pids.clear()
        self.statuses["macos-update"] = {
            "state": "failed",
            "message": "install failed",
        }
        result = compose_prioritized_updates_metric(self.sources())
        self.assertEqual(result[0], "⚠ macOS failed")
        self.assertEqual(result[3], "failed")
        self.assertEqual((self.brew_calls, self.hermes_calls), (0, 0))

    def test_source_precedence_covers_macos_brew_hermes_unknown_and_current(self) -> None:
        self.write_macos(count=2)
        self.assertEqual(compose_prioritized_updates_metric(self.sources())[3], "macos")
        self.assertEqual((self.brew_calls, self.hermes_calls), (0, 0))

        self.write_macos(count=0)
        self.brew = UpdateCommandOutcome(0, "alpha\nbeta\n")
        self.assertEqual(compose_prioritized_updates_metric(self.sources())[3], "brew")
        self.assertEqual(self.hermes_calls, 0)

        self.brew = UpdateCommandOutcome(0)
        self.hermes = UpdateCommandOutcome(1, "commits behind upstream")
        self.assertEqual(compose_prioritized_updates_metric(self.sources())[3], "hermes")

        self.hermes = UpdateCommandOutcome(0, "up to date")
        self.assertEqual(compose_prioritized_updates_metric(self.sources())[3], "none")

        self.status_file.unlink()
        self.assertEqual(compose_prioritized_updates_metric(self.sources())[3], "unknown")


if __name__ == "__main__":
    unittest.main()
