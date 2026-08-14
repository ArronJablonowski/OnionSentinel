from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
RELAY_DIR = ROOT / "relay" / "app"
for path in (BIN_DIR, DASHBOARD_DIR, RELAY_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from bounded_http import BoundedHttpError, read_bounded_body, read_bounded_json  # noqa: E402
import bounded_process as bounded_process_module  # noqa: E402
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
    @staticmethod
    def _read_pid(path: Path) -> int:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                value = path.read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                value = ""
            if value:
                return int(value)
            time.sleep(0.02)
        raise AssertionError(f"child PID was not written to {path}")

    def assertProcessGone(self, pid: int) -> None:  # noqa: N802
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = subprocess.run(
                ["ps", "-o", "state=", "-p", str(pid)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            state = result.stdout.strip()
            if result.returncode != 0 or not state or state.upper().startswith("Z"):
                return
            time.sleep(0.05)
        self.fail(f"process {pid} survived bounded cleanup")

    @staticmethod
    def _detached_child_script(pid_path: Path, *, child_sleep: float, parent_sleep: float) -> str:
        return textwrap.dedent(
            f"""
            import os
            import pathlib
            import subprocess
            import sys
            import time

            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep({child_sleep!r})"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            pathlib.Path({str(pid_path)!r}).write_text(str(child.pid), encoding="utf-8")
            time.sleep({parent_sleep!r})
            os._exit(0)
            """
        )

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

    def test_repeated_fast_exit_commands_remain_supported(self) -> None:
        for _ in range(20):
            result = run_bounded_command(
                ["/usr/bin/true"],
                timeout_seconds=5,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
            )
            self.assertEqual(result.returncode, 0)

    def test_snapshot_failure_fails_closed_and_kills_direct_child(self) -> None:
        started = time.monotonic()
        with mock.patch.object(
            bounded_process_module,
            "_read_process_snapshot",
            side_effect=bounded_process_module._ProcessSnapshotError("forced snapshot failure"),
        ):
            with self.assertRaisesRegex(BoundedProcessError, "forced snapshot failure") as caught:
                run_bounded_command(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    timeout_seconds=10,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                )
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn(
            "forced snapshot failure",
            getattr(caught.exception, "bounded_process_cleanup", ""),
        )

    def test_post_spawn_initialization_failure_kills_both_variants(
        self,
    ) -> None:
        real_popen = subprocess.Popen
        for file_variant in (False, True):
            with self.subTest(file_variant=file_variant):
                spawned: list[subprocess.Popen] = []

                def capture_popen(*args: object, **kwargs: object):
                    process = real_popen(*args, **kwargs)
                    spawned.append(process)
                    return process

                with (
                    tempfile.TemporaryDirectory() as tmp,
                    mock.patch.object(
                        bounded_process_module.subprocess,
                        "Popen",
                        side_effect=capture_popen,
                    ),
                    mock.patch.object(
                        bounded_process_module.selectors,
                        "DefaultSelector",
                        side_effect=RuntimeError("forced selector failure"),
                    ),
                ):
                    destination = Path(tmp) / "capture.bin"
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "forced selector failure",
                    ):
                        if file_variant:
                            run_bounded_command_to_file(
                                [
                                    sys.executable,
                                    "-c",
                                    "import time; time.sleep(30)",
                                ],
                                destination,
                                timeout_seconds=10,
                                max_stdout_bytes=100,
                                max_stderr_bytes=100,
                            )
                        else:
                            run_bounded_command(
                                [
                                    sys.executable,
                                    "-c",
                                    "import time; time.sleep(30)",
                                ],
                                timeout_seconds=10,
                                max_stdout_bytes=100,
                                max_stderr_bytes=100,
                            )
                    self.assertEqual(len(spawned), 1)
                    self.assertProcessGone(spawned[0].pid)
                    self.assertIsNotNone(spawned[0].stdout)
                    self.assertIsNotNone(spawned[0].stderr)
                    self.assertTrue(spawned[0].stdout.closed)
                    self.assertTrue(spawned[0].stderr.closed)
                    self.assertFalse(destination.exists())

    def test_steady_state_tracking_backs_off_from_startup_frequency(self) -> None:
        identity = bounded_process_module._ProcessIdentity(
            pid=424242,
            pgid=424242,
            uid=os.getuid(),
            start_time="Mon Jul 27 10:00:00 2026",
            command_hash="a" * 64,
        )
        record = bounded_process_module._ProcessRecord(
            identity=identity,
            ppid=1,
            state="S",
        )
        tracker = bounded_process_module._DescendantTracker(identity.pid)
        tracker._created_at -= bounded_process_module._PROCESS_STARTUP_TRACK_SECONDS + 1
        with mock.patch.object(
            bounded_process_module,
            "_read_process_snapshot",
            return_value={identity.pid: record},
        ) as snapshot:
            tracker.observe(force=True)
            for _ in range(20):
                tracker.observe()
        self.assertEqual(snapshot.call_count, 1)

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

    def test_file_variant_preserves_nonzero_exit_and_bounded_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "capture.bin"
            result = run_bounded_command_to_file(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.write('body'); sys.stderr.write('detail'); sys.exit(7)",
                ],
                destination,
                timeout_seconds=5,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
            )
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "detail")
            self.assertEqual(destination.read_text(encoding="utf-8"), "body")

    def test_invalid_limits_fail_before_launch_for_both_variants(self) -> None:
        cases = (
            {"timeout_seconds": 0, "max_stdout_bytes": 1, "max_stderr_bytes": 1},
            {"timeout_seconds": 1, "max_stdout_bytes": 0, "max_stderr_bytes": 1},
            {"timeout_seconds": 1, "max_stdout_bytes": 1, "max_stderr_bytes": 0},
        )
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp) / "capture.bin"
            for options in cases:
                with self.subTest(options=options), mock.patch.object(
                    bounded_process_module.subprocess,
                    "Popen",
                ) as popen:
                    with self.assertRaises(ValueError):
                        run_bounded_command(["ignored"], **options)
                    with self.assertRaises(ValueError):
                        run_bounded_command_to_file(
                            ["ignored"],
                            destination,
                            **options,
                        )
                    popen.assert_not_called()
                    self.assertFalse(destination.exists())

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

    def test_spoofed_containment_marker_is_replaced_without_losing_env(
        self,
    ) -> None:
        fake_token = "0" * 64
        original_fd = os.environ.get(
            bounded_process_module._CONTAINMENT_FD_ENV
        )
        original_token = os.environ.get(
            bounded_process_module._CONTAINMENT_TOKEN_ENV
        )
        environment = {
            **os.environ,
            bounded_process_module._CONTAINMENT_FD_ENV: "999999",
            bounded_process_module._CONTAINMENT_TOKEN_ENV: fake_token,
            "ONION_SENTINEL_TEST_ENV": "preserved",
        }
        result = run_bounded_command(
            [
                sys.executable,
                "-c",
                textwrap.dedent(
                    f"""
                    import os
                    print(os.environ["ONION_SENTINEL_TEST_ENV"])
                    print(
                        os.environ[{bounded_process_module._CONTAINMENT_TOKEN_ENV!r}]
                        != {fake_token!r}
                    )
                    """
                ),
            ],
            timeout_seconds=5,
            max_stdout_bytes=100,
            max_stderr_bytes=100,
            env=environment,
        )
        self.assertEqual(
            result.stdout.splitlines(),
            ["preserved", "True"],
        )
        self.assertEqual(
            os.environ.get(bounded_process_module._CONTAINMENT_FD_ENV),
            original_fd,
        )
        self.assertEqual(
            os.environ.get(bounded_process_module._CONTAINMENT_TOKEN_ENV),
            original_token,
        )

    def test_outer_callback_kills_nested_bounded_runner_and_inner_command(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested_pid_path = root / "nested-runner.pid"
            inner_pid_path = root / "inner-command.pid"
            nested_topology_path = root / "nested-runner.json"
            inner_topology_path = root / "inner-command.json"
            nested_script = textwrap.dedent(
                f"""
                import json
                import os
                import pathlib
                import sys

                sys.path.insert(0, {str(BIN_DIR)!r})
                from bounded_process import run_bounded_command

                pathlib.Path({str(nested_pid_path)!r}).write_text(
                    str(os.getpid()),
                    encoding="utf-8",
                )
                pathlib.Path({str(nested_topology_path)!r}).write_text(
                    json.dumps({{
                        "pid": os.getpid(),
                        "pgid": os.getpgrp(),
                        "sid": os.getsid(0),
                    }}),
                    encoding="utf-8",
                )
                inner_script = (
                    "import json, os, pathlib, time; "
                    f"pathlib.Path({str(inner_pid_path)!r}).write_text("
                    "str(os.getpid()), encoding='utf-8'); "
                    f"pathlib.Path({str(inner_topology_path)!r}).write_text("
                    "json.dumps({{"
                    "'pid': os.getpid(), "
                    "'pgid': os.getpgrp(), "
                    "'sid': os.getsid(0), "
                    "'env': os.environ.get('ONION_SENTINEL_NESTED_ENV'),"
                    "}}), encoding='utf-8'); "
                    "time.sleep(30)"
                )
                run_bounded_command(
                    [sys.executable, "-c", inner_script],
                    timeout_seconds=30,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                    env={{**os.environ, "ONION_SENTINEL_NESTED_ENV": "preserved"}},
                )
                """
            )

            def lose_lease() -> None:
                self._read_pid(nested_pid_path)
                self._read_pid(inner_pid_path)
                raise RuntimeError("outer controlled lease lost")

            with self.assertRaisesRegex(
                RuntimeError,
                "outer controlled lease lost",
            ):
                run_bounded_command(
                    [sys.executable, "-c", nested_script],
                    timeout_seconds=10,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                    progress_callback=lose_lease,
                    progress_interval_seconds=0.4,
                )
            self.assertProcessGone(self._read_pid(nested_pid_path))
            self.assertProcessGone(self._read_pid(inner_pid_path))
            nested_topology = json.loads(
                nested_topology_path.read_text(encoding="utf-8")
            )
            inner_topology = json.loads(
                inner_topology_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                nested_topology,
                {
                    "pid": nested_topology["pid"],
                    "pgid": nested_topology["pid"],
                    "sid": nested_topology["pid"],
                },
            )
            self.assertEqual(inner_topology["pgid"], nested_topology["pid"])
            self.assertEqual(inner_topology["sid"], nested_topology["pid"])
            self.assertEqual(inner_topology["env"], "preserved")

    def test_callback_failure_kills_detached_grandchild_and_preserves_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pid_path = Path(tmp) / "grandchild.pid"
            script = self._detached_child_script(pid_path, child_sleep=30, parent_sleep=30)

            def lose_lease() -> None:
                raise RuntimeError("authoritative lease loss")

            with self.assertRaisesRegex(RuntimeError, "authoritative lease loss"):
                run_bounded_command(
                    [sys.executable, "-c", script],
                    timeout_seconds=10,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                    progress_callback=lose_lease,
                    progress_interval_seconds=0.4,
                )
            self.assertProcessGone(self._read_pid(pid_path))

    def test_cleanup_failure_does_not_replace_callback_exception(self) -> None:
        original_cleanup = bounded_process_module._terminate_process_tree

        def cleanup_then_fail(*args: object, **kwargs: object) -> object:
            original_cleanup(*args, **kwargs)
            raise RuntimeError("secondary cleanup diagnostic")

        def lose_lease() -> None:
            raise RuntimeError("authoritative lease loss")

        with mock.patch.object(
            bounded_process_module,
            "_terminate_process_tree",
            side_effect=cleanup_then_fail,
        ):
            with self.assertRaisesRegex(RuntimeError, "authoritative lease loss") as caught:
                run_bounded_command(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    timeout_seconds=10,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                    progress_callback=lose_lease,
                    progress_interval_seconds=0.1,
                )
        self.assertIn(
            "secondary cleanup diagnostic",
            getattr(caught.exception, "bounded_process_cleanup", ""),
        )

    def test_normal_exit_kills_and_reports_detached_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pid_path = Path(tmp) / "grandchild.pid"
            script = self._detached_child_script(pid_path, child_sleep=30, parent_sleep=0.5)
            with self.assertRaisesRegex(BoundedProcessError, "surviving descendants"):
                run_bounded_command(
                    [sys.executable, "-c", script],
                    timeout_seconds=5,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                )
            self.assertProcessGone(self._read_pid(pid_path))

    def test_natural_detached_descendant_exit_within_grace_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pid_path = Path(tmp) / "grandchild.pid"
            script = self._detached_child_script(pid_path, child_sleep=0.8, parent_sleep=0.5)
            result = run_bounded_command(
                [sys.executable, "-c", script],
                timeout_seconds=5,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
            )
            self.assertEqual(result.returncode, 0)
            self.assertProcessGone(self._read_pid(pid_path))

    def test_file_variant_kills_and_reports_detached_descendant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_path = root / "grandchild.pid"
            destination = root / "capture.bin"
            script = self._detached_child_script(pid_path, child_sleep=30, parent_sleep=0.5)
            with self.assertRaisesRegex(BoundedProcessError, "surviving descendants"):
                run_bounded_command_to_file(
                    [sys.executable, "-c", script],
                    destination,
                    timeout_seconds=5,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                )
            self.assertFalse(destination.exists())
            self.assertProcessGone(self._read_pid(pid_path))

    def test_file_variant_allows_natural_descendant_exit_within_grace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_path = root / "grandchild.pid"
            destination = root / "capture.bin"
            script = self._detached_child_script(pid_path, child_sleep=0.8, parent_sleep=0.5)
            result = run_bounded_command_to_file(
                [sys.executable, "-c", script],
                destination,
                timeout_seconds=5,
                max_stdout_bytes=100,
                max_stderr_bytes=100,
            )
            self.assertEqual(result.returncode, 0)
            self.assertTrue(destination.exists())
            self.assertProcessGone(self._read_pid(pid_path))

    def test_file_variant_timeout_kills_detached_grandchild(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pid_path = root / "grandchild.pid"
            destination = root / "capture.bin"
            script = self._detached_child_script(pid_path, child_sleep=30, parent_sleep=30)
            with self.assertRaisesRegex(BoundedProcessError, "timed out"):
                run_bounded_command_to_file(
                    [sys.executable, "-c", script],
                    destination,
                    timeout_seconds=0.6,
                    max_stdout_bytes=100,
                    max_stderr_bytes=100,
                )
            self.assertFalse(destination.exists())
            self.assertProcessGone(self._read_pid(pid_path))

    def test_process_identity_mismatch_and_zombie_are_not_signal_targets(self) -> None:
        identity = bounded_process_module._ProcessIdentity(
            pid=424242,
            pgid=424242,
            uid=os.getuid(),
            start_time="Mon Jul 27 10:00:00 2026",
            command_hash="a" * 64,
        )
        mismatched = bounded_process_module._ProcessIdentity(
            pid=identity.pid,
            pgid=identity.pgid,
            uid=identity.uid,
            start_time=identity.start_time,
            command_hash="b" * 64,
        )
        tracker = bounded_process_module._DescendantTracker(identity.pid)
        tracker.root_identity = identity
        tracker._remember(identity, depth=0)
        live_mismatch = bounded_process_module._ProcessRecord(
            identity=mismatched,
            ppid=1,
            state="S",
        )
        self.assertEqual(
            tracker.verified_records({identity.pid: live_mismatch}, include_root=True),
            [],
        )
        zombie = bounded_process_module._ProcessRecord(
            identity=identity,
            ppid=1,
            state="Z",
        )
        self.assertEqual(
            tracker.verified_records({identity.pid: zombie}, include_root=True),
            [],
        )

    def test_process_snapshot_parser_accepts_bsd_and_gnu_layouts(self) -> None:
        records = bounded_process_module._parse_ps_snapshot(
            "  101     1   101   501 Ss   Mon Jul 27 10:00:00 2026     /bin/sleep 5\n"
            "  202   101   202  1000 S    Tue Jul  7 09:08:07 2026 python -c worker\n"
        )
        self.assertEqual(set(records), {101, 202})
        self.assertEqual(records[101].identity.pgid, 101)
        self.assertEqual(records[202].ppid, 101)
        self.assertEqual(records[202].identity.start_time, "Tue Jul 7 09:08:07 2026")
        self.assertNotEqual(
            records[101].identity.command_hash,
            records[202].identity.command_hash,
        )


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
            "bounded_process_policy.py",
            "bounded_process_observation.py",
            "bounded_process_io.py",
            "bounded_process_termination.py",
            "bounded_process_runtime.py",
            "http_json_client.js",
            "http_runtime.py",
            "http_runtime.js",
            "jsonl_log.py",
            "atomic_io.py",
            "dashboard_pcap_request_index.py",
        ):
            self.assertIn(filename, installer)

    def test_bounded_process_facade_imports_from_a_flat_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            deployed_bin = Path(tmp) / "bin"
            deployed_bin.mkdir()
            for module in (
                "bounded_process.py",
                "bounded_process_policy.py",
                "bounded_process_observation.py",
                "bounded_process_io.py",
                "bounded_process_termination.py",
                "bounded_process_runtime.py",
            ):
                shutil.copy2(BIN_DIR / module, deployed_bin / module)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-c",
                    (
                        "import sys; "
                        f"sys.path.insert(0, {str(deployed_bin)!r}); "
                        "import bounded_process; "
                        "result = bounded_process.run_bounded_command("
                        "['/usr/bin/true'], timeout_seconds=5, "
                        "max_stdout_bytes=100, max_stderr_bytes=100); "
                        "assert result.returncode == 0"
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr or completed.stdout,
            )

    def test_production_python_imports_software_inventory_migration_chain(self) -> None:
        production_python = Path("/usr/bin/python3")
        if not production_python.is_file():
            self.skipTest("production system Python is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            deployed_bin = Path(tmp) / "bin"
            deployed_bin.mkdir()
            for source in BIN_DIR.glob("*.py"):
                shutil.copy2(source, deployed_bin / source.name)
            collector = deployed_bin / "collect-software-inventory.py"
            completed = subprocess.run(
                [
                    str(production_python),
                    "-I",
                    "-c",
                    (
                        "import importlib.util, sys; "
                        "root = sys.argv[1]; "
                        "sys.path.insert(0, root); "
                        "path = root + '/collect-software-inventory.py'; "
                        "spec = importlib.util.spec_from_file_location("
                        "'_onion_sentinel_software_inventory_collector', path); "
                        "module = importlib.util.module_from_spec(spec); "
                        "spec.loader.exec_module(module)"
                    ),
                    str(deployed_bin),
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr or completed.stdout,
            )

    def test_installer_validation_only_checks_system_python_before_shutdown(self) -> None:
        installer = BIN_DIR / "install-macstudio-stack.zsh"
        source = installer.read_text(encoding="utf-8")
        validation_call = "prepare_alert_store_stage\nvalidate_production_python_sources"
        self.assertIn(validation_call, source)
        self.assertLess(
            source.index(validation_call),
            source.index("trap keep_critical_agents_down_on_failure EXIT"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            completed = subprocess.run(
                ["/bin/zsh", str(installer)],
                env={
                    **os.environ,
                    "STACK_DIR": str(Path(tmp) / "runtime"),
                    "ONION_SENTINEL_RELEASE_ID": "arr-133-validation-only",
                    "ONION_SENTINEL_VALIDATE_ONLY": "1",
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr or completed.stdout,
            )
            self.assertIn(
                "Mac Studio installer preflight validation passed.",
                completed.stdout,
            )

    def test_installer_rejects_unknown_argument_before_staging(self) -> None:
        installer = BIN_DIR / "install-macstudio-stack.zsh"
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            completed = subprocess.run(
                ["/bin/zsh", str(installer), "--not-an-installer-option"],
                env={
                    **os.environ,
                    "STACK_DIR": str(runtime),
                    "ONION_SENTINEL_RELEASE_ID": "arr-70-unknown-argument",
                    "ONION_SENTINEL_VALIDATE_ONLY": "1",
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn(
                "Unknown installer argument: --not-an-installer-option",
                completed.stderr,
            )
            self.assertFalse(runtime.exists())

    def test_installer_explicit_validation_option_is_preflight_only(self) -> None:
        installer = BIN_DIR / "install-macstudio-stack.zsh"
        source = installer.read_text(encoding="utf-8")
        argument_parser = 'parse_installer_arguments "$@"'
        release_validation = (
            '/usr/bin/python3 "$REPO_DIR/n8n/bin/set-runtime-release-id.py"'
        )
        staging = "prepare_alert_store_stage\nvalidate_production_python_sources"
        self.assertLess(source.index(argument_parser), source.index(release_validation))
        self.assertLess(source.index(argument_parser), source.index(staging))
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            completed = subprocess.run(
                ["/bin/zsh", str(installer), "--validate-only"],
                env={
                    **os.environ,
                    "STACK_DIR": str(runtime),
                    "ONION_SENTINEL_RELEASE_ID": "arr-70-explicit-validation",
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=60,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr or completed.stdout,
            )
            self.assertIn(
                "Mac Studio installer preflight validation passed.",
                completed.stdout,
            )
            self.assertFalse((runtime / ".env").exists())

    def test_installer_help_and_invalid_validation_environment_are_safe(self) -> None:
        installer = BIN_DIR / "install-macstudio-stack.zsh"
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Path(tmp) / "runtime"
            environment = {
                **os.environ,
                "STACK_DIR": str(runtime),
            }
            environment.pop("ONION_SENTINEL_RELEASE_ID", None)
            help_result = subprocess.run(
                ["/bin/zsh", str(installer), "--help"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(help_result.returncode, 0)
            self.assertIn("[--validate-only]", help_result.stdout)
            self.assertFalse(runtime.exists())

            invalid_result = subprocess.run(
                ["/bin/zsh", str(installer)],
                env={
                    **environment,
                    "ONION_SENTINEL_VALIDATE_ONLY": "invalid",
                },
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(invalid_result.returncode, 2)
            self.assertIn(
                "ONION_SENTINEL_VALIDATE_ONLY must be 0 or 1.",
                invalid_result.stderr,
            )
            self.assertFalse(runtime.exists())

    def test_pi_installer_copies_bounded_process_helper(self) -> None:
        installer = (ROOT / "relay" / "bin" / "install-pi-relay.sh").read_text(encoding="utf-8")
        self.assertIn('relay/app/process_io.py" /opt/so-alert-relay/app/process_io.py', installer)


if __name__ == "__main__":
    unittest.main()
