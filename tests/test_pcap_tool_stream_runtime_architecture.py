from __future__ import annotations

import copy
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_runtime():
    spec = importlib.util.spec_from_file_location(
        "pcap_tool_stream_runtime_architecture",
        BIN / "pcap_tool_runtime.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeStream:
    def __init__(self, name: str, descriptor: int, trace: list[object]) -> None:
        self.name = name
        self.descriptor = descriptor
        self.trace = trace

    def fileno(self) -> int:
        return self.descriptor

    def close(self) -> None:
        self.trace.append(["stream_close", self.name])


class FakeProcess:
    def __init__(
        self,
        trace: list[object],
        *,
        returncode: int = 0,
        poll_result: int | None = None,
        wait_errors: list[BaseException | None] | None = None,
    ) -> None:
        self.trace = trace
        self.pid = 4242
        self.stdout = FakeStream("stdout", 10, trace)
        self.stderr = FakeStream("stderr", 11, trace)
        self.returncode = returncode
        self.poll_result = poll_result
        self.wait_errors = list(wait_errors or [])

    def poll(self) -> int | None:
        self.trace.append(["poll"])
        return self.poll_result

    def wait(self, timeout: float) -> int:
        self.trace.append(["wait", timeout])
        if self.wait_errors:
            error = self.wait_errors.pop(0)
            if error is not None:
                raise error
        return self.returncode

    def kill(self) -> None:
        self.trace.append(["process_kill"])


class FakeSelector:
    def __init__(
        self,
        trace: list[object],
        *,
        empty_first: bool = False,
    ) -> None:
        self.trace = trace
        self.empty_first = empty_first
        self.select_count = 0
        self.mapping: dict[int, object] = {}

    def register(self, stream: FakeStream, event: int, data: str) -> None:
        self.trace.append(["register", stream.name, event, data])
        self.mapping[stream.fileno()] = SimpleNamespace(
            fileobj=stream,
            data=data,
        )

    def get_map(self) -> dict[int, object]:
        return self.mapping

    def select(self, timeout: float) -> list[tuple[object, int]]:
        self.trace.append(["select", timeout])
        self.select_count += 1
        if self.empty_first and self.select_count == 1:
            return []
        return [
            (key, 1)
            for key in list(self.mapping.values())
        ]

    def unregister(self, stream: FakeStream) -> None:
        self.trace.append(["unregister", stream.name])
        self.mapping.pop(stream.fileno())

    def close(self) -> None:
        self.trace.append(["selector_close"])


class PcapToolStreamRuntimeArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runtime = load_runtime()

    def execute(
        self,
        *,
        stdout: list[bytes],
        stderr: list[bytes],
        timeout_seconds: float = 5,
        max_stderr_bytes: int = 1024,
        max_stream_bytes: int = 1024,
        max_line_bytes: int = 1024,
        time_values: list[float] | None = None,
        returncode: int = 0,
        poll_result: int | None = None,
        empty_first: bool = False,
        killpg_error: BaseException | None = None,
        wait_errors: list[BaseException | None] | None = None,
        callback_error: BaseException | None = None,
    ) -> dict[str, object]:
        trace: list[object] = []
        output_lines: list[str] = []
        process = FakeProcess(
            trace,
            returncode=returncode,
            poll_result=poll_result,
            wait_errors=wait_errors,
        )
        selector = FakeSelector(trace, empty_first=empty_first)
        chunks = {10: list(stdout), 11: list(stderr)}
        popen_calls: list[object] = []

        def popen(command, **kwargs):
            popen_calls.append([list(command), kwargs])
            trace.append(["popen"])
            return process

        def read(descriptor: int, size: int) -> bytes:
            trace.append(["read", descriptor, size])
            queue = chunks[descriptor]
            return queue.pop(0) if queue else b""

        def killpg(pid: int, signal_number: int) -> None:
            trace.append(["killpg", pid, signal_number])
            if killpg_error is not None:
                raise killpg_error

        def on_line(value: str) -> None:
            trace.append(["line", value])
            output_lines.append(value)
            if callback_error is not None:
                raise callback_error

        values = iter(time_values or [100, 100.5, 101, 101.5, 102, 102.5])
        command = ("tshark", "-r", "synthetic.pcap")
        command_before = copy.deepcopy(command)
        with (
            mock.patch.object(
                self.runtime,
                "isolated_command",
                side_effect=lambda value: ["isolated", *value],
            ),
            mock.patch.object(
                self.runtime,
                "parser_environment",
                return_value={"PATH": "/synthetic"},
            ),
            mock.patch.object(
                self.runtime.subprocess,
                "Popen",
                side_effect=popen,
            ),
            mock.patch.object(
                self.runtime.selectors,
                "DefaultSelector",
                return_value=selector,
            ),
            mock.patch.object(self.runtime.os, "read", side_effect=read),
            mock.patch.object(self.runtime.os, "killpg", side_effect=killpg),
            mock.patch.object(
                self.runtime.time,
                "monotonic",
                side_effect=lambda: next(values),
            ),
            mock.patch.object(
                self.runtime.shutil,
                "which",
                return_value="/usr/bin/sandbox-exec",
            ),
            mock.patch.object(
                self.runtime,
                "sys_platform_is_macos",
                return_value=True,
            ),
        ):
            try:
                result = self.runtime.stream_isolated_lines(
                    command,
                    on_line,
                    cwd=Path("synthetic-work"),
                    timeout_seconds=timeout_seconds,
                    max_stderr_bytes=max_stderr_bytes,
                    max_stream_bytes=max_stream_bytes,
                    max_line_bytes=max_line_bytes,
                )
                outcome: dict[str, object] = {"result": result}
            except BaseException as error:
                outcome = {"error": error}
        outcome.update({
            "trace": trace,
            "lines": output_lines,
            "popen_calls": popen_calls,
            "command_before": command_before,
            "command_after": command,
        })
        return outcome

    def test_success_preserves_exact_wiring_framing_and_result(self) -> None:
        outcome = self.execute(
            stdout=[b"one\nsplit", b"-two\nbad-\xff"],
            stderr=[b"warn", b"ing"],
            returncode=7,
        )

        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["command_before"], outcome["command_after"])
        self.assertEqual(outcome["lines"], ["one", "split-two", "bad-�"])
        self.assertEqual(outcome["result"], {
            "ok": False,
            "returncode": 7,
            "stderr": "warning",
            "command": ["tshark", "-r", "synthetic.pcap"],
            "line_count": 3,
            "stream_bytes": 19,
            "isolation": {
                "network_disabled": True,
                "stripped_environment": True,
                "cpu_seconds": self.runtime.PARSER_CPU_SECONDS,
                "memory_bytes": self.runtime.PARSER_MEMORY_BYTES,
                "file_bytes": self.runtime.PARSER_FILE_BYTES,
            },
        })
        command, kwargs = outcome["popen_calls"][0]
        self.assertEqual(
            command,
            ["isolated", "tshark", "-r", "synthetic.pcap"],
        )
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"], subprocess.PIPE)
        self.assertIs(kwargs["stderr"], subprocess.PIPE)
        self.assertEqual(kwargs["cwd"], "synthetic-work")
        self.assertEqual(kwargs["env"], {"PATH": "/synthetic"})
        self.assertIs(kwargs["preexec_fn"], self.runtime.parser_resource_limits)
        self.assertIs(kwargs["start_new_session"], True)
        trace = outcome["trace"]
        self.assertEqual(trace[1:3], [
            ["register", "stdout", self.runtime.selectors.EVENT_READ, "stdout"],
            ["register", "stderr", self.runtime.selectors.EVENT_READ, "stderr"],
        ])
        self.assertEqual(trace[-4:], [
            ["wait", 3],
            ["selector_close"],
            ["stream_close", "stdout"],
            ["stream_close", "stderr"],
        ])

    def test_empty_select_after_exit_forces_final_pipe_drain(self) -> None:
        outcome = self.execute(
            stdout=[b"final\n"],
            stderr=[],
            empty_first=True,
            poll_result=0,
        )

        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["lines"], ["final"])
        self.assertIn(["poll"], outcome["trace"])
        self.assertEqual(outcome["result"]["line_count"], 1)

    def test_exact_byte_and_line_limits_are_inclusive(self) -> None:
        outcome = self.execute(
            stdout=[b"four"],
            stderr=[b"ok"],
            max_stderr_bytes=2,
            max_stream_bytes=4,
            max_line_bytes=4,
        )

        self.assertNotIn("error", outcome)
        self.assertEqual(outcome["lines"], ["four"])
        self.assertEqual(outcome["result"]["stream_bytes"], 4)

    def test_each_stream_limit_preserves_exact_error_and_cleanup(self) -> None:
        cases = (
            (
                {"stdout": [], "stderr": [b"abc"], "max_stderr_bytes": 2},
                "command stderr exceeded the 2-byte limit",
            ),
            (
                {"stdout": [b"abcd"], "stderr": [], "max_stream_bytes": 3},
                "command stream exceeded the 3-byte limit",
            ),
            (
                {"stdout": [b"abcd"], "stderr": [], "max_line_bytes": 3},
                "command line exceeded the 3-byte limit",
            ),
            (
                {"stdout": [b"abcd\n"], "stderr": [], "max_line_bytes": 3},
                "command line exceeded the 3-byte limit",
            ),
        )
        for arguments, message in cases:
            with self.subTest(message=message):
                outcome = self.execute(**arguments)
                error = outcome["error"]
                self.assertIsInstance(error, self.runtime.BoundedProcessError)
                self.assertEqual(str(error), message)
                self.assertIsNone(error.__cause__)
                self.assertIn(
                    ["killpg", 4242, self.runtime.signal.SIGKILL],
                    outcome["trace"],
                )
                self.assertEqual(outcome["trace"][-3:], [
                    ["selector_close"],
                    ["stream_close", "stdout"],
                    ["stream_close", "stderr"],
                ])

    def test_timeout_preserves_exact_error_and_process_group_kill(self) -> None:
        outcome = self.execute(
            stdout=[],
            stderr=[],
            timeout_seconds=1,
            time_values=[10, 11],
        )

        error = outcome["error"]
        self.assertIsInstance(error, self.runtime.BoundedProcessError)
        self.assertEqual(str(error), "command timed out after 1 seconds")
        self.assertNotIn("select", [event[0] for event in outcome["trace"]])
        self.assertIn(
            ["killpg", 4242, self.runtime.signal.SIGKILL],
            outcome["trace"],
        )
        self.assertIn(["wait", 5], outcome["trace"])

    def test_callback_error_preserves_kill_fallback_wait_and_cleanup(self) -> None:
        callback_error = RuntimeError("synthetic callback failure")
        wait_timeout = subprocess.TimeoutExpired("synthetic", 5)
        outcome = self.execute(
            stdout=[b"line\n"],
            stderr=[],
            callback_error=callback_error,
            killpg_error=PermissionError("synthetic permission failure"),
            wait_errors=[wait_timeout],
        )

        self.assertIs(outcome["error"], callback_error)
        self.assertIsNone(outcome["error"].__cause__)
        trace = outcome["trace"]
        killpg_index = trace.index([
            "killpg", 4242, self.runtime.signal.SIGKILL,
        ])
        self.assertEqual(trace[killpg_index:killpg_index + 4], [
            ["killpg", 4242, self.runtime.signal.SIGKILL],
            ["process_kill"],
            ["wait", 5],
            ["process_kill"],
        ])
        self.assertEqual(trace[-3:], [
            ["selector_close"],
            ["stream_close", "stdout"],
            ["stream_close", "stderr"],
        ])


if __name__ == "__main__":
    unittest.main()
