"""Behavior contracts for bounded active LLM status storage."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_llm_active_store import (  # noqa: E402
    ActiveLlmSources,
    active_llm_record_paths,
    llm_analysis_process_active,
    llm_queue_size,
    read_active_llm_analyses,
    read_bounded_llm_record,
)


class _CommandSequence(list[str]):
    def __init__(self, commands: list[str]) -> None:
        super().__init__(commands)
        self.visited: list[str] = []

    def __iter__(self):
        for command in super().__iter__():
            self.visited.append(command)
            yield command


class ActiveLlmStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_record(self, name: str, payload: object, mtime: int) -> Path:
        path = self.directory / name
        path.write_text(json.dumps(payload))
        os.utime(path, ns=(mtime, mtime))
        return path

    def test_queue_size_is_nonnegative_and_bounds_malformed_shapes(self) -> None:
        self.assertEqual(llm_queue_size({"ai": {"counts": {"queued": "7"}}}), 7)
        self.assertEqual(llm_queue_size({"ai": {"counts": {"queued": -3}}}), 0)
        self.assertEqual(llm_queue_size({"ai": {"counts": []}}), 0)
        self.assertEqual(llm_queue_size(None), 0)

    def test_bounded_reader_rejects_oversize_invalid_and_nonobject_json(self) -> None:
        valid = self.directory / "valid.json"
        valid.write_text('{"status":"running"}')
        oversized = self.directory / "oversized.json"
        oversized.write_text("x" * 20)
        invalid = self.directory / "invalid.json"
        invalid.write_bytes(b"\xff")
        array = self.directory / "array.json"
        array.write_text("[]")

        self.assertEqual(read_bounded_llm_record(valid, 100)["status"], "running")
        self.assertEqual(read_bounded_llm_record(oversized, 10), {})
        self.assertEqual(read_bounded_llm_record(invalid, 10), {})
        self.assertEqual(read_bounded_llm_record(array, 10), {})
        self.assertEqual(read_bounded_llm_record(self.directory / "missing", 10), {})

    def test_path_discovery_is_newest_first_bounded_and_rejects_symlinks(self) -> None:
        oldest = self.write_record("old.json", {}, 10)
        middle = self.write_record("middle.json", {}, 20)
        newest = self.write_record("new.json", {}, 30)
        (self.directory / "ignore.txt").write_text("{}")
        (self.directory / "link.json").symlink_to(oldest)

        paths = active_llm_record_paths(self.directory, 2)

        self.assertEqual(paths, [newest, middle])
        self.assertEqual(active_llm_record_paths(self.directory / "missing", 2), [])

    def test_process_matching_prefers_exact_runner_pid(self) -> None:
        commands = [
            "101 python run-local-ai-analysis.py /tmp/a.json",
            "202 unrelated /tmp/b.json",
        ]
        self.assertTrue(llm_analysis_process_active("/tmp/other.json", commands, 101))
        self.assertFalse(llm_analysis_process_active("/tmp/a.json", commands, 202))
        self.assertTrue(llm_analysis_process_active("/tmp/a.json", commands))
        self.assertTrue(llm_analysis_process_active("", commands))
        self.assertFalse(llm_analysis_process_active("", ["1 unrelated"]))

    def test_process_matching_identity_matrix_is_exact(self) -> None:
        commands = [
            "  7   python /opt/run-local-ai-analysis.py /tmp/prompt.json  ",
            "07 python /opt/run-local-ai-analysis.py /tmp/other.json",
            "7",
            "8 python /tmp/not-run-local-ai-analysis.py /tmp/prompt.json",
            "9 python /opt/run-local-ai-analysis.py /tmp/prompt.json.backup",
        ]
        for prompt, runner_pid, expected in (
            ("/tmp/missing.json", " 7 ", True),
            ("/tmp/prompt.json", 8, True),
            ("/tmp/prompt.json", "07", True),
            ("/tmp/prompt.json", -7, True),
            ("/tmp/prompt.json", 0, True),
            ("/tmp/prompt.json", 7.0, True),
            ("/tmp/prompt.json", True, True),
            ("/tmp/absent.json", None, False),
            ("", None, True),
        ):
            with self.subTest(prompt=prompt, runner_pid=runner_pid):
                self.assertIs(
                    llm_analysis_process_active(prompt, commands, runner_pid),
                    expected,
                )

    def test_process_matching_short_circuits_at_first_accepted_command(self) -> None:
        pid_commands = _CommandSequence([
            "1 unrelated",
            "22 python run-local-ai-analysis.py",
            "22 later run-local-ai-analysis.py",
        ])
        prompt_commands = _CommandSequence([
            "1 run-local-ai-analysis.py /tmp/other.json",
            "2 run-local-ai-analysis.py /tmp/target.json",
            "3 run-local-ai-analysis.py /tmp/target.json",
        ])

        self.assertTrue(llm_analysis_process_active("/ignored", pid_commands, 22))
        self.assertEqual(pid_commands.visited, pid_commands[:2])
        self.assertTrue(
            llm_analysis_process_active("/tmp/target.json", prompt_commands)
        )
        self.assertEqual(prompt_commands.visited, prompt_commands[:2])

    def test_active_reader_uses_one_snapshot_filters_and_orders_runs(self) -> None:
        self.write_record(
            "later.json",
            {
                "status": "running",
                "runner_pid": 202,
                "started_at": "2026-08-07T02:00:00Z",
                "log_id": "later",
            },
            30,
        )
        self.write_record(
            "earlier.json",
            {
                "status": "running",
                "runner_pid": 101,
                "started_at": "2026-08-07T01:00:00Z",
                "log_id": "earlier",
            },
            20,
        )
        self.write_record(
            "stale.json",
            {"status": "running", "runner_pid": 303, "log_id": "stale"},
            10,
        )
        self.write_record("complete.json", {"status": "success"}, 5)
        calls = []

        def commands() -> list[str]:
            calls.append(True)
            return [
                "101 python run-local-ai-analysis.py",
                "202 python run-local-ai-analysis.py",
            ]

        records = read_active_llm_analyses(
            ActiveLlmSources(self.directory, 1024, 10, commands)
        )

        self.assertEqual([record["log_id"] for record in records], ["earlier", "later"])
        self.assertEqual(len(calls), 1)

    def test_no_running_records_skips_process_snapshot(self) -> None:
        self.write_record("complete.json", {"status": "success"}, 5)

        def commands() -> list[str]:
            raise AssertionError("process snapshot should not run")

        records = read_active_llm_analyses(
            ActiveLlmSources(self.directory, 1024, 10, commands)
        )
        self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
