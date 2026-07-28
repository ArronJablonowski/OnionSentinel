#!/usr/bin/env python3
"""Lifecycle tests for the bounded macOS resource sampler."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
RUNNER_PATH = BIN_DIR / "run-local-ai-analysis.py"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
SPEC = importlib.util.spec_from_file_location(
    "run_local_ai_analysis_resource_monitor_tests",
    RUNNER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


EMPTY_SAMPLE = (
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    "synthetic sample",
)


class SystemResourceMonitorTests(unittest.TestCase):
    def assert_process_gone(self, pid: int) -> None:
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            probe = subprocess.run(
                ["/bin/ps", "-o", "state=", "-p", str(pid)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            state = probe.stdout.strip()
            if probe.returncode != 0 or not state or state.upper().startswith("Z"):
                return
            time.sleep(0.05)
        self.fail(f"resource sampler process {pid} survived cancellation")

    @staticmethod
    def wait_for_pid(path: Path) -> int:
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                value = ""
            if value:
                return int(value)
            time.sleep(0.02)
        raise AssertionError("synthetic mactop PID was not published")

    def test_mactop_sample_cancellation_terminates_and_reaps_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp_name:
            pid_path = Path(temp_name) / "mactop.pid"
            program = (
                "import os,pathlib,time;"
                f"pathlib.Path({str(pid_path)!r}).write_text(str(os.getpid()));"
                "time.sleep(30)"
            )
            command = shlex.join([sys.executable, "-c", program])
            cancelled = threading.Event()
            result: list[tuple[object, ...]] = []
            worker = threading.Thread(
                target=lambda: result.append(
                    RUNNER.read_mactop_system_sample(
                        cancel_event=cancelled,
                    )
                )
            )
            with mock.patch.dict(
                os.environ,
                {"SOC_MACTOP_COMMAND": command},
            ):
                worker.start()
                pid = self.wait_for_pid(pid_path)
                cancelled.set()
                worker.join(timeout=6)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(result), 1)
            self.assertIn("cancelled", str(result[0][-1]))
            self.assert_process_gone(pid)

    def test_monitor_stop_cancels_sample_and_joins_non_daemon_thread(self) -> None:
        entered = threading.Event()
        calls = 0

        def sample(*, cancel_event=None):
            nonlocal calls
            calls += 1
            if calls == 1:
                return EMPTY_SAMPLE
            entered.set()
            assert cancel_event is not None
            cancel_event.wait(timeout=5)
            return (*EMPTY_SAMPLE[:-1], "synthetic sample cancelled")

        monitor = RUNNER.SystemResourceMonitor(interval_seconds=0.01)
        with (
            mock.patch.object(
                RUNNER,
                "read_mactop_system_sample",
                side_effect=sample,
            ),
            mock.patch.object(
                RUNNER,
                "read_gpu_temperature_celsius",
                return_value=(1.0, "synthetic fallback"),
            ),
        ):
            monitor.start()
            thread = monitor._thread
            self.assertIsNotNone(thread)
            assert thread is not None
            self.assertFalse(thread.daemon)
            self.assertTrue(entered.wait(timeout=2))
            monitor.stop()
        self.assertFalse(thread.is_alive())
        self.assertIsNone(monitor._thread)

    def test_stop_refuses_to_silently_accept_a_live_monitor_thread(self) -> None:
        class StuckThread:
            def __init__(self) -> None:
                self.join_timeout = None

            def join(self, timeout=None) -> None:
                self.join_timeout = timeout

            def is_alive(self) -> bool:
                return True

        monitor = RUNNER.SystemResourceMonitor()
        stuck = StuckThread()
        monitor._thread = stuck
        with self.assertRaisesRegex(
            RuntimeError,
            "did not terminate after cancellation",
        ):
            monitor.stop()
        self.assertEqual(stuck.join_timeout, 12)


if __name__ == "__main__":
    unittest.main()
