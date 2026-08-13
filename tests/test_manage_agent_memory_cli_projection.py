"""Characterize the role-aware agent-memory compatibility CLI."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/manage-agent-memory.py"
BIN = MODULE_PATH.parent


def load_module(name: str = "manage_agent_memory_cli_projection"):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("manage-agent-memory CLI cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(BIN))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(BIN))
    return module


memory_cli = load_module()


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class TrackingMapping(dict):
    def __init__(self, values):
        super().__init__(values)
        self.trace: list[tuple[str, object]] = []

    def get(self, key, default=None):
        self.trace.append((key, default))
        return super().get(key, default)


class Recorder:
    def __init__(self):
        self.calls: list[tuple[str, tuple, dict]] = []

    def function(self, name, result=None):
        def invoke(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return result

        return invoke


class ManageAgentMemoryCliProjectionTests(unittest.TestCase):
    def test_decomposed_cli_owners_stay_within_quality_bounds(self):
        self.assertLessEqual(len(MODULE_PATH.read_text(encoding="utf-8").splitlines()), 250)
        for name in (
            "_add_quarantine_parser",
            "build_parser",
            "_writeback",
            "_quarantine",
            "dispatch",
            "main",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def invoke(self, argv, *, loaded=None, quarantine=None):
        recorder = Recorder()
        stdout = io.StringIO()
        stderr = io.StringIO()
        role_path = Path("/synthetic/role.md")
        patches = (
            mock.patch.object(sys, "argv", ["manage-agent-memory.py", *argv]),
            mock.patch.object(
                memory_cli,
                "role_memory_file",
                side_effect=recorder.function("role_file", role_path),
            ),
            mock.patch.object(
                memory_cli,
                "load_json",
                side_effect=recorder.function("load_json", loaded),
            ),
            mock.patch.object(
                memory_cli,
                "build_agent_memory_context",
                side_effect=recorder.function("query", {"mode": "query"}),
            ),
            mock.patch.object(
                memory_cli,
                "build_agent_execution_context",
                side_effect=recorder.function("prepare", {"mode": "prepare"}),
            ),
            mock.patch.object(
                memory_cli,
                "persist_memory_candidates",
                side_effect=recorder.function("writeback", {"mode": "writeback"}),
            ),
            mock.patch.object(
                memory_cli,
                "quarantine_bpfdoor_code_zero_memory",
                side_effect=quarantine
                or recorder.function(
                    "quarantine", {"matched": 0, "applied": 0}
                ),
            ),
        )
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = memory_cli.main()
        return result, json.loads(stdout.getvalue()), stderr.getvalue(), recorder

    def test_query_dispatch_preserves_paths_evidence_bounds_and_output(self):
        evidence = {"source": "synthetic"}
        result, output, stderr, recorder = self.invoke(
            [
                "--agent", "soc-analyst",
                "--memory-dir", "/synthetic/memory",
                "--config-dir", "/synthetic/config",
                "query",
                "--evidence-json", "/synthetic/evidence.json",
                "--memory-bytes", "321",
            ],
            loaded=evidence,
        )
        self.assertEqual(result, 0)
        self.assertEqual(output, {"mode": "query"})
        self.assertEqual(stderr, "")
        self.assertEqual(
            recorder.calls,
            [
                (
                    "role_file",
                    (Path("/synthetic/memory"), "soc-analyst"),
                    {},
                ),
                ("load_json", (Path("/synthetic/evidence.json"),), {}),
                (
                    "query",
                    (),
                    {
                        "agent_role": "soc-analyst",
                        "role_memory_file": Path("/synthetic/role.md"),
                        "shared_memory_file": Path(
                            "/synthetic/memory/shared-agent-memory.md"
                        ),
                        "evidence": evidence,
                        "limit_bytes": 321,
                    },
                ),
            ],
        )

    def test_prepare_dispatch_preserves_config_memory_and_default_bound(self):
        evidence = {"source": "synthetic"}
        result, output, stderr, recorder = self.invoke(
            [
                "--agent", "incident-responder",
                "--memory-dir", "/synthetic/memory",
                "--config-dir", "/synthetic/config",
                "prepare",
                "--evidence-json", "/synthetic/evidence.json",
            ],
            loaded=evidence,
        )
        self.assertEqual((result, output, stderr), (0, {"mode": "prepare"}, ""))
        self.assertEqual(recorder.calls[0][0], "role_file")
        self.assertEqual(recorder.calls[1][0], "load_json")
        self.assertEqual(
            recorder.calls[2],
            (
                "prepare",
                (),
                {
                    "agent_role": "incident-responder",
                    "config_dir": Path("/synthetic/config"),
                    "memory_dir": Path("/synthetic/memory"),
                    "evidence": evidence,
                    "limit_bytes": 8000,
                },
            ),
        )

    def test_writeback_envelope_access_candidates_and_provenance_are_exact(self):
        response = TrackingMapping({"memory_candidates": [{"id": "candidate"}]})
        payload = TrackingMapping({"response": response})
        result, output, stderr, recorder = self.invoke(
            [
                "--agent", "soc-analyst",
                "--memory-dir", "/synthetic/memory",
                "writeback",
                "--response-json", "/synthetic/response.json",
                "--analysis-id", "analysis-268",
            ],
            loaded=payload,
        )
        self.assertEqual((result, output, stderr), (0, {"mode": "writeback"}, ""))
        self.assertEqual(
            payload.trace,
            [("response", None), ("response", None)],
        )
        self.assertEqual(response.trace, [("memory_candidates", [])])
        self.assertEqual(
            recorder.calls[-1],
            (
                "writeback",
                (),
                {
                    "agent_role": "soc-analyst",
                    "role_memory_file": Path("/synthetic/role.md"),
                    "shared_memory_file": Path(
                        "/synthetic/memory/shared-agent-memory.md"
                    ),
                    "candidates": [{"id": "candidate"}],
                    "analysis_id": "analysis-268",
                    "source_artifact": "/synthetic/response.json",
                },
            ),
        )

    def test_quarantine_scope_order_apply_gate_records_and_totals_are_exact(self):
        recorder = Recorder()
        outcomes = iter(
            (
                {"path": "role", "matched": 2, "applied": 1},
                {"path": "shared", "matched": "3", "applied": None},
            )
        )

        def quarantine(*args, **kwargs):
            recorder.calls.append(("quarantine", args, kwargs))
            return next(outcomes)

        result, output, stderr, base_recorder = self.invoke(
            [
                "--agent", "soc-analyst",
                "--memory-dir", "/synthetic/memory",
                "quarantine-bpfdoor-code-zero",
                "--scope", "both",
                "--apply",
                "--record-id", "record-a",
                "--record-id", "record-b",
            ],
            quarantine=quarantine,
        )
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            output,
            {
                "dry_run": False,
                "matched": 5,
                "applied": 1,
                "files": [
                    {"path": "role", "matched": 2, "applied": 1},
                    {"path": "shared", "matched": "3", "applied": None},
                ],
            },
        )
        self.assertEqual(base_recorder.calls[0][0], "role_file")
        self.assertEqual(
            recorder.calls,
            [
                (
                    "quarantine",
                    (Path("/synthetic/role.md"),),
                    {"apply": True, "record_ids": ["record-a", "record-b"]},
                ),
                (
                    "quarantine",
                    (Path("/synthetic/memory/shared-agent-memory.md"),),
                    {"apply": True, "record_ids": ["record-a", "record-b"]},
                ),
            ],
        )

    def test_parser_failures_preserve_exit_two_and_do_not_call_ports(self):
        cases = (
            (["--agent", "soc-analyst"], "the following arguments are required: command"),
            (["--agent", "invalid", "query"], "invalid choice: 'invalid'"),
            (
                ["--agent", "soc-analyst", "query"],
                "the following arguments are required: --evidence-json",
            ),
        )
        for argv, message in cases:
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch.object(
                    sys, "argv", ["manage-agent-memory.py", *argv]
                ), mock.patch.object(
                    memory_cli, "role_memory_file"
                ) as role_file, contextlib.redirect_stdout(
                    stdout
                ), contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as raised:
                        memory_cli.main()
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertIn("usage:", stderr.getvalue())
                self.assertIn(message, stderr.getvalue())
                role_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
