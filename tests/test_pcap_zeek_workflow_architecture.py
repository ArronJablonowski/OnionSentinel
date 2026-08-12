from __future__ import annotations

import ast
import copy
import importlib.machinery
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/pcap_processor_zeek.py"
WORKFLOW = ROOT / "n8n/bin/pcap_zeek_workflow.py"
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_zeek():
    loader = importlib.machinery.SourceFileLoader(
        "pcap_zeek_workflow_architecture", str(SCRIPT)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def function_metrics(name: str, path: Path = SCRIPT) -> tuple[int, int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )

    class Complexity(ast.NodeVisitor):
        def __init__(self):
            self.value = 1

        def visit_FunctionDef(self, node):
            return

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If
        visit_While = visit_If

        def visit_Try(self, node):
            self.value += len(node.handlers)
            self.generic_visit(node)

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_IfExp(self, node):
            self.value += 1
            self.generic_visit(node)

        def visit_ListComp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_ListComp
        visit_GeneratorExp = visit_ListComp
        visit_DictComp = visit_ListComp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class FakeCounter:
    instances = []

    def __init__(self, capacity):
        self.capacity = capacity
        self.key = len(self.instances)
        self.instances.append(self)

    def most_common(self, fields, limit):
        return [{
            "counter": self.key,
            "fields": list(fields),
            "limit": limit,
        }]


class FakeCoverage:
    instances = []

    def __init__(self):
        self.key = len(self.instances)
        self.instances.append(self)
        self.total_records = 0
        self.first_timestamp = None
        self.last_timestamp = None
        self.malformed_records = 0

    def as_dict(self):
        return {
            "key": self.key,
            "total_records": self.total_records,
            "malformed_records": self.malformed_records,
        }


class FakeReservoir:
    instances = []

    def __init__(self, limit):
        self.limit = limit
        self.key = len(self.instances)
        self.instances.append(self)
        self.values = []

    def add(self, value):
        self.values.append(value)

    def records(self):
        return copy.deepcopy(self.values)


class PcapZeekWorkflowArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.zeek = load_zeek()

    def setUp(self) -> None:
        FakeCounter.instances = []
        FakeCoverage.instances = []
        FakeReservoir.instances = []

    def test_facade_and_workflow_meet_quality_and_installer_contracts(self) -> None:
        lines, complexity = function_metrics("run_zeek")
        self.assertLessEqual(lines, 50)
        self.assertLessEqual(complexity, 5)
        for name in (
            "_initial_state",
            "_aggregate_capture_logs",
            "_run_capture",
            "_coverage_projection",
            "_sampling_projection",
            "_summary_projection",
            "_query_index_projection",
            "_final_projection",
            "run_zeek",
        ):
            lines, complexity = function_metrics(name, WORKFLOW)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(WORKFLOW.read_text().splitlines()), 600)
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        workflow_copy = (
            'cp "$REPO_DIR/n8n/bin/pcap_zeek_workflow.py" '
            '"$STACK_DIR/bin/pcap_zeek_workflow.py"'
        )
        facade_copy = (
            'cp "$REPO_DIR/n8n/bin/pcap_processor_zeek.py" '
            '"$STACK_DIR/bin/pcap_processor_zeek.py"'
        )
        self.assertEqual(installer.count(workflow_copy), 1)
        self.assertLess(installer.index(workflow_copy), installer.index(facade_copy))

    def test_missing_executable_returns_exact_bounded_reason(self) -> None:
        captures = [Path("synthetic.pcap")]
        before = copy.deepcopy(captures)
        with mock.patch.object(self.zeek, "tool_path", return_value=None) as tool:
            result = self.zeek.run_zeek(captures, Path("unused"))

        self.assertEqual(captures, before)
        tool.assert_called_once_with("ZEEK_BIN", "zeek")
        self.assertEqual(result, {
            "available": False,
            "reason": "zeek executable not found on PATH or ZEEK_BIN",
        })

    def test_execution_aggregation_projection_and_cleanup_are_exact(self) -> None:
        trace = []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work_dir = root / "work"
            captures = [root / "alpha one.pcap", root / "beta.pcap"]
            for capture in captures:
                capture.write_bytes(b"synthetic")
            before = copy.deepcopy(captures)

            def run_command(command, cwd, timeout):
                trace.append([
                    "command",
                    command,
                    cwd.name,
                    timeout,
                ])
                (cwd / "conn.log").write_text("{}\n")
                (cwd / "ssl.log").write_text("{}\n")
                (cwd / "tls.log").write_text("{}\n")
                if cwd.name.startswith("0001"):
                    (cwd / "dns.log").write_text("{}\n")
                return {
                    "ok": cwd.name.startswith("0000"),
                    "returncode": 0 if cwd.name.startswith("0000") else 1,
                    "stderr": "" if cwd.name.startswith("0000") else "failed",
                    "command": command,
                    "ignored": "not projected",
                }

            def aggregate(path, fields, counter, coverage, sample, log_type):
                trace.append([
                    "aggregate",
                    path.name,
                    list(fields),
                    counter.key,
                    coverage.key,
                    sample.key,
                    log_type,
                ])
                coverage.total_records += coverage.key + 1
                coverage.first_timestamp = 100.0 + coverage.key
                coverage.last_timestamp = 200.0 + coverage.key
                coverage.malformed_records += coverage.key
                sample.add({"log_type": log_type, "capture": path.parent.name})

            real_rmtree = self.zeek.shutil.rmtree

            def rmtree(path, ignore_errors):
                trace.append(["rmtree", Path(path).name, ignore_errors])
                return real_rmtree(path, ignore_errors=ignore_errors)

            with (
                mock.patch.object(self.zeek, "tool_path", return_value="/tools/zeek"),
                mock.patch.object(
                    self.zeek,
                    "safe_filename",
                    side_effect=lambda value: str(value).replace(" ", "-"),
                ),
                mock.patch.object(self.zeek, "run_command", side_effect=run_command),
                mock.patch.object(
                    self.zeek,
                    "aggregate_zeek_log",
                    side_effect=aggregate,
                ),
                mock.patch.object(self.zeek, "BoundedTopCounter", FakeCounter),
                mock.patch.object(self.zeek, "CoverageTracker", FakeCoverage),
                mock.patch.object(
                    self.zeek,
                    "DeterministicReservoir",
                    FakeReservoir,
                ),
                mock.patch.object(self.zeek.shutil, "rmtree", side_effect=rmtree),
            ):
                result = self.zeek.run_zeek(captures, work_dir)

            self.assertEqual(captures, before)
            self.assertTrue(result["available"])
            self.assertEqual(
                [item["returncode"] for item in result["commands"]],
                [0, 1],
            )
            self.assertTrue(
                all("ignored" not in item for item in result["commands"])
            )
            self.assertEqual(result["coverage"]["pcap_files_total"], 2)
            self.assertEqual(result["coverage"]["pcap_files_processed"], 1)
            self.assertEqual(result["coverage"]["records_aggregated"], 10)
            self.assertEqual(result["coverage"]["first_timestamp_epoch"], 100.0)
            self.assertEqual(result["coverage"]["last_timestamp_epoch"], 202.0)
            self.assertFalse(result["coverage"]["complete"])
            self.assertEqual(
                result["sampling"]["invalid_json_lines"],
                {
                    "conn": 0,
                    "dns": 1,
                    "tls": 4,
                    "http": 0,
                    "files": 0,
                    "notice": 0,
                    "weird": 0,
                },
            )
            self.assertEqual(len(result["_local_query_index"]["connections"]), 2)
            self.assertEqual(len(result["_local_query_index"]["dns"]), 1)
            self.assertEqual(len(result["_local_query_index"]["tls"]), 2)
            aggregate_paths = [
                item[1]
                for item in trace
                if item[0] == "aggregate"
            ]
            self.assertEqual(
                aggregate_paths,
                ["conn.log", "ssl.log", "conn.log", "dns.log", "ssl.log"],
            )
            self.assertNotIn("tls.log", aggregate_paths)
            command_events = [item for item in trace if item[0] == "command"]
            self.assertEqual(command_events[0][2], "0000-alpha-one")
            self.assertEqual(command_events[1][2], "0001-beta")
            self.assertEqual(
                command_events[0][1],
                [
                    "/tools/zeek",
                    "-C",
                    "LogAscii::use_json=T",
                    "-r",
                    str(captures[0]),
                ],
            )
            self.assertEqual(
                [item[1:] for item in trace if item[0] == "rmtree"],
                [
                    ["0000-alpha-one", True],
                    ["0001-beta", True],
                ],
            )
            self.assertFalse((work_dir / "zeek" / "0000-alpha-one").exists())
            self.assertFalse((work_dir / "zeek" / "0001-beta").exists())

    def test_command_failure_still_removes_capture_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "capture.pcap"
            capture.write_bytes(b"synthetic")
            capture_dir = root / "work" / "zeek" / "0000-capture"
            with (
                mock.patch.object(self.zeek, "tool_path", return_value="/tools/zeek"),
                mock.patch.object(
                    self.zeek,
                    "run_command",
                    side_effect=RuntimeError("synthetic Zeek launch failure"),
                ),
                self.assertRaisesRegex(
                    RuntimeError, "synthetic Zeek launch failure"
                ),
            ):
                self.zeek.run_zeek([capture], root / "work")

            self.assertFalse(capture_dir.exists())


if __name__ == "__main__":
    unittest.main()
