from __future__ import annotations

import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
RELAY_DIR = ROOT / "relay" / "app"
for path in (BIN_DIR, DASHBOARD_DIR, RELAY_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from bounded_http import BoundedHttpError, read_bounded_body, read_bounded_json  # noqa: E402
from bounded_process import BoundedProcessError, run_bounded_command, run_bounded_command_to_file  # noqa: E402
from jsonl_log import JsonlLogIndex  # noqa: E402
from process_io import (  # noqa: E402
    BoundedProcessError as RelayBoundedProcessError,
    run_bounded_command as run_relay_bounded_command,
)


class FakeResponse(io.BytesIO):
    def __init__(self, body: bytes, content_length: str | None = None) -> None:
        super().__init__(body)
        self.headers = {} if content_length is None else {"Content-Length": content_length}


class BoundedHttpTests(unittest.TestCase):
    def test_rejects_declared_and_streamed_overflow(self) -> None:
        with self.assertRaisesRegex(BoundedHttpError, "exceeded"):
            read_bounded_body(FakeResponse(b"{}", "100"), max_bytes=10)
        with self.assertRaisesRegex(BoundedHttpError, "exceeded"):
            read_bounded_body(FakeResponse(b"x" * 11), max_bytes=10)

    def test_rejects_truncation_and_non_object_json(self) -> None:
        with self.assertRaisesRegex(BoundedHttpError, "ended before"):
            read_bounded_body(FakeResponse(b"{}", "3"), max_bytes=10)
        with self.assertRaisesRegex(BoundedHttpError, "must be an object"):
            read_bounded_json(FakeResponse(b"[]"), max_bytes=10)

    def test_accepts_bounded_json_object(self) -> None:
        value = read_bounded_json(FakeResponse(b'{"ok":true}', "11"), max_bytes=32)
        self.assertEqual(value, {"ok": True})


class BoundedProcessTests(unittest.TestCase):
    def test_captures_bounded_output(self) -> None:
        result = run_bounded_command(
            [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
            stdin_text="hello",
            timeout_seconds=5,
            max_stdout_bytes=100,
            max_stderr_bytes=100,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "HELLO")

    def test_kills_output_overflow_and_timeout(self) -> None:
        with self.assertRaisesRegex(BoundedProcessError, "stdout exceeded"):
            run_bounded_command(
                [sys.executable, "-c", "print('x' * 10000)"],
                stdin_text="",
                timeout_seconds=5,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
            )
        started = time.monotonic()
        with self.assertRaisesRegex(BoundedProcessError, "timed out"):
            run_bounded_command(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                stdin_text="",
                timeout_seconds=0.1,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
            )
        self.assertLess(time.monotonic() - started, 2)

    def test_relay_control_command_rejects_stdout_overflow(self) -> None:
        with self.assertRaisesRegex(RelayBoundedProcessError, "stdout exceeded"):
            run_relay_bounded_command(
                [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
                timeout_seconds=5,
                max_stdout_bytes=128,
                max_stderr_bytes=128,
            )

    def test_relay_control_command_accepts_bounded_input_and_output(self) -> None:
        result = run_relay_bounded_command(
            [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
            input_bytes=b"bounded relay control",
            timeout_seconds=5,
            max_stdout_bytes=128,
            max_stderr_bytes=128,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"bounded relay control")

    def test_streams_large_stdout_to_file_without_buffering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "capture.bin"
            result = run_bounded_command_to_file(
                [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1048576)"],
                destination,
                timeout_seconds=5,
                max_stdout_bytes=1048576,
                max_stderr_bytes=100,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(destination.stat().st_size, 1048576)
            self.assertEqual(result.stdout, "")

    def test_file_stream_overflow_removes_partial_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "capture.bin"
            with self.assertRaisesRegex(BoundedProcessError, "file limit"):
                run_bounded_command_to_file(
                    [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 1024)"],
                    destination,
                    timeout_seconds=5,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                )
            self.assertFalse(destination.exists())

    def test_progress_callback_failure_terminates_child(self) -> None:
        started = time.monotonic()

        def lose_lease() -> None:
            raise RuntimeError("lease lost")

        with self.assertRaisesRegex(RuntimeError, "lease lost"):
            run_bounded_command(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout_seconds=10,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
                progress_callback=lose_lease,
                progress_interval_seconds=0.05,
            )
        self.assertLess(time.monotonic() - started, 2)


class JsonlLogIndexTests(unittest.TestCase):
    def test_incremental_count_and_reverse_pagination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runs.jsonl"
            path.write_text('\n'.join(json.dumps({"id": value}) for value in range(5)) + "\n", encoding="utf-8")
            index = JsonlLogIndex(path, block_bytes=1024)

            total, page, rows = index.page(page=1, limit=2)
            self.assertEqual((total, page), (5, 1))
            self.assertEqual([row["id"] for row in rows], [4, 3])

            with path.open("a", encoding="utf-8") as handle:
                handle.write("not-json\n")
                handle.write(json.dumps({"id": 5}) + "\n")
            total, page, rows = index.page(page=2, limit=2)
            self.assertEqual((total, page), (6, 2))
            self.assertEqual([row["id"] for row in rows], [3, 2])

    def test_incomplete_tail_is_not_published_until_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runs.jsonl"
            path.write_bytes(b'{"id":1}\n{"id":')
            index = JsonlLogIndex(path)
            self.assertEqual(index.page(page=1, limit=10)[0], 1)
            with path.open("ab") as handle:
                handle.write(b"2}\n")
            total, _, rows = index.page(page=1, limit=10)
            self.assertEqual(total, 2)
            self.assertEqual([row["id"] for row in rows], [2, 1])


class InstallerDependencyTests(unittest.TestCase):
    def test_installer_copies_refactored_runtime_dependencies(self) -> None:
        installer = (ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh").read_text(encoding="utf-8")
        for filename in (
            "bounded_http.py",
            "bounded_process.py",
            "http_json_client.js",
            "http_runtime.py",
            "http_runtime.js",
            "jsonl_log.py",
            "atomic_io.py",
            "dashboard_pcap_request_index.py",
        ):
            self.assertIn(filename, installer)

    def test_pi_installer_copies_bounded_process_helper(self) -> None:
        installer = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(encoding="utf-8")
        self.assertIn('relay/app/process_io.py" /opt/so-alert-relay/app/process_io.py', installer)


if __name__ == "__main__":
    unittest.main()
