from __future__ import annotations

import argparse
import ast
import copy
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/pcap_processor_workflow.py"
PHASES = ROOT / "n8n/bin/pcap_processor_workflow_phases.py"
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_workflow():
    loader = importlib.machinery.SourceFileLoader(
        "pcap_process_one_architecture", str(SCRIPT)
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


class FixedTemporaryDirectory:
    def __init__(self, path: Path, trace: list, prefix: str):
        self.path = path
        self.trace = trace
        self.trace.append(["temporary_init", prefix])

    def __enter__(self):
        self.path.mkdir(parents=True, exist_ok=True)
        self.trace.append(["temporary_enter", self.path.name])
        return str(self.path)

    def __exit__(self, error_type, _error, _traceback):
        self.trace.append([
            "temporary_exit",
            error_type.__name__ if error_type else None,
        ])
        return False


class PcapProcessOneArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_workflow()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_process_one_and_phases_meet_quality_and_installer_contracts(self) -> None:
        lines, complexity = function_metrics("process_one")
        self.assertLessEqual(lines, 50)
        self.assertLessEqual(complexity, 5)
        for name in (
            "_request_identity",
            "_detection_inputs",
            "_pcap_metadata",
            "_detection_context",
            "_tool_paths",
            "_coverage",
            "_evidence_security",
            "_analysis_document",
            "_analyze_artifacts",
            "_verified_publication",
            "_cleanup_artifacts",
            "process_one",
        ):
            lines, complexity = function_metrics(name, PHASES)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(PHASES.read_text().splitlines()), 600)
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        phases_copy = (
            'cp "$REPO_DIR/n8n/bin/pcap_processor_workflow_phases.py" '
            '"$STACK_DIR/bin/pcap_processor_workflow_phases.py"'
        )
        workflow_copy = (
            'cp "$REPO_DIR/n8n/bin/pcap_processor_workflow.py" '
            '"$STACK_DIR/bin/pcap_processor_workflow.py"'
        )
        self.assertEqual(installer.count(phases_copy), 1)
        self.assertLess(installer.index(phases_copy), installer.index(workflow_copy))

    def test_success_path_preserves_call_order_schema_publication_and_cleanup(self) -> None:
        trace = []
        work_dir = self.root / "controlled-work"
        capture = work_dir / "capture.pcap"
        missing = work_dir / "missing.pcap"
        out_dir = self.root / "out"
        args = argparse.Namespace(
            db=self.root / "alerts.sqlite3",
            detection_playbooks=self.root / "playbooks.json",
            ai_settings=self.root / "settings.json",
            out_dir=out_dir,
            artifact_dir=self.root / "artifacts",
            retain_artifact=False,
        )
        request = {
            "request_id": "unsafe/request",
            "alert_id": "alert-1",
            "group_id": "group-1",
        }
        request_before = copy.deepcopy(request)
        rule_context = {
            "sid": "1001",
            "revision": "7",
            "name": "Synthetic rule",
            "ruleset": "local",
            "parsed_rule": {"rule_sha256": "a" * 64},
            "playbook_policy": {
                "status": "matched",
                "fail_closed": False,
                "evidence_gap": "bounded gap",
                "registry_version": "2026.1",
            },
        }
        playbook = {"id": "pb-1", "version": 3, "status": "active"}
        zeek = {"available": True, "coverage": {"complete": True, "records": 2}}
        tshark = {
            "available": True,
            "coverage": {"complete": True, "records": 3},
            "samples": [],
        }

        def materialize(received, received_args, received_work, direct):
            trace.append([
                "materialize",
                received["request_id"],
                received_args is args,
                received_work.name,
                direct,
            ])
            capture.write_bytes(b"synthetic-pcap")
            return [capture, missing], "copied-artifact"

        def atomic_write(path, content):
            trace.append(["atomic_write", path.name, content[:12]])
            path.write_text(content, encoding="utf-8")

        def call(name, value):
            def side_effect(*items):
                trace.append([name, *[str(item) for item in items]])
                return copy.deepcopy(value)

            return side_effect

        with (
            mock.patch.object(
                self.workflow.tempfile,
                "TemporaryDirectory",
                side_effect=lambda prefix: FixedTemporaryDirectory(
                    work_dir, trace, prefix
                ),
            ),
            mock.patch.object(
                self.workflow,
                "safe_filename",
                side_effect=call("safe_filename", "safe-request"),
            ),
            mock.patch.object(
                self.workflow,
                "signature_context_for_request",
                side_effect=call("signature_context", (rule_context, playbook)),
            ),
            mock.patch.object(
                self.workflow,
                "detection_marker_specs",
                side_effect=call("markers", ["marker"]),
            ),
            mock.patch.object(
                self.workflow,
                "materialize_pcap_files",
                side_effect=materialize,
            ),
            mock.patch.object(
                self.workflow,
                "sha256_file",
                side_effect=call("sha256", "b" * 64),
            ),
            mock.patch.object(
                self.workflow,
                "run_zeek",
                side_effect=call("run_zeek", zeek),
            ),
            mock.patch.object(
                self.workflow,
                "configured_maxmind_db_paths",
                side_effect=call("maxmind_paths", {"city": self.root / "city.mmdb"}),
            ),
            mock.patch.object(
                self.workflow,
                "icmp_evidence_scope",
                side_effect=call("icmp_scope", {"mode": "bounded"}),
            ),
            mock.patch.object(
                self.workflow,
                "run_tshark",
                side_effect=call("run_tshark", tshark),
            ),
            mock.patch.object(
                self.workflow,
                "project_now",
                side_effect=call("project_now", "2026-01-02  03:04:05-07:00"),
            ),
            mock.patch.object(
                self.workflow,
                "tool_path",
                side_effect=lambda env, executable: trace.append(
                    ["tool_path", env, executable]
                ) or f"/tools/{executable}",
            ),
            mock.patch.object(
                self.workflow,
                "analysis_json_path",
                side_effect=lambda directory, identity: trace.append(
                    ["analysis_json_path", directory.name, identity]
                ) or directory / f"{identity}-pcap-analysis.json",
            ),
            mock.patch.object(
                self.workflow,
                "atomic_write_text",
                side_effect=atomic_write,
            ),
            mock.patch.object(
                self.workflow,
                "build_markdown",
                side_effect=lambda analysis: trace.append(
                    ["build_markdown", analysis["artifact_state"]]
                ) or "SYNTHETIC MARKDOWN\n",
            ),
            mock.patch.object(
                self.workflow,
                "analysis_completed",
                side_effect=call("analysis_completed", True),
            ),
            mock.patch.object(
                self.workflow,
                "delete_request_artifacts",
                side_effect=call(
                    "delete_request_artifacts",
                    {"deleted": True, "bytes": 14, "files": 1},
                ),
            ),
            mock.patch.object(self.workflow.sys, "platform", "darwin"),
            mock.patch.object(self.workflow.shutil, "which", return_value="/usr/bin/sandbox-exec"),
        ):
            result = self.workflow.process_one(request, args)

        self.assertEqual(request, request_before)
        self.assertEqual(result["analysis_type"], "soc-pcap-analysis")
        self.assertEqual(result["artifact_state"], "copied-artifact")
        self.assertEqual(result["pcap_files"], [{
            "path": str(capture),
            "name": "capture.pcap",
            "size_bytes": 14,
            "sha256": "b" * 64,
        }])
        self.assertEqual(result["detection_context"]["policy_status"], "matched")
        self.assertEqual(result["detection_context"]["evidence_gaps"], ["bounded gap"])
        self.assertEqual(result["detection_context"]["playbook"], playbook)
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["source_bytes"], 14)
        self.assertEqual(
            result["evidence_security"]["parser_network_access"],
            "denied-by-sandbox-exec",
        )
        self.assertEqual(
            result["raw_artifact_cleanup"],
            {"deleted": True, "bytes": 14, "files": 1},
        )
        self.assertEqual(result["_json_path"], str(out_dir / "safe-request-pcap-analysis.json"))
        self.assertEqual(result["_markdown_path"], str(out_dir / "safe-request-pcap-analysis.md"))
        persisted = json.loads(Path(result["_json_path"]).read_text())
        self.assertEqual(persisted["raw_artifact_cleanup"], result["raw_artifact_cleanup"])
        self.assertNotIn("_json_path", persisted)
        self.assertEqual(Path(result["_markdown_path"]).read_text(), "SYNTHETIC MARKDOWN\n")
        self.assertEqual(
            [item[0] for item in trace],
            [
                "safe_filename", "signature_context", "markers",
                "temporary_init", "temporary_enter", "materialize", "sha256",
                "run_zeek", "maxmind_paths", "icmp_scope", "run_tshark",
                "project_now", "tool_path", "tool_path", "tool_path",
                "temporary_exit", "analysis_json_path", "atomic_write",
                "build_markdown", "atomic_write", "analysis_completed",
                "delete_request_artifacts", "atomic_write",
            ],
        )

    def test_empty_markdown_fails_before_cleanup_or_metadata_rewrite(self) -> None:
        trace = []
        work_dir = self.root / "work"
        args = types.SimpleNamespace(
            out_dir=self.root / "out",
            artifact_dir=self.root / "artifacts",
            retain_artifact=False,
        )
        request = {"request_id": "request-1"}

        def atomic_write(path, content):
            trace.append(["write", path.name])
            path.write_text(content, encoding="utf-8")

        with (
            mock.patch.object(
                self.workflow.tempfile,
                "TemporaryDirectory",
                side_effect=lambda prefix: FixedTemporaryDirectory(
                    work_dir, trace, prefix
                ),
            ),
            mock.patch.object(
                self.workflow,
                "signature_context_for_request",
                return_value=({}, None),
            ),
            mock.patch.object(
                self.workflow,
                "materialize_pcap_files",
                return_value=([], "missing"),
            ),
            mock.patch.object(self.workflow, "project_now", return_value="now"),
            mock.patch.object(self.workflow, "tool_path", return_value=None),
            mock.patch.object(
                self.workflow,
                "analysis_json_path",
                side_effect=lambda directory, identity: directory / f"{identity}.json",
            ),
            mock.patch.object(self.workflow, "atomic_write_text", side_effect=atomic_write),
            mock.patch.object(self.workflow, "build_markdown", return_value="  \n"),
            mock.patch.object(
                self.workflow,
                "delete_request_artifacts",
            ) as delete,
            self.assertRaisesRegex(
                RuntimeError, "PCAP Markdown analysis output is empty"
            ),
        ):
            self.workflow.process_one(request, args)

        delete.assert_not_called()
        self.assertEqual([item[0] for item in trace].count("write"), 2)

    def test_direct_pcap_never_invokes_raw_artifact_cleanup(self) -> None:
        direct = self.root / "direct.pcap"
        direct.write_bytes(b"direct")
        args = types.SimpleNamespace(
            out_dir=self.root / "out",
            artifact_dir=self.root / "artifacts",
            retain_artifact=False,
        )
        request = {"request_id": "direct"}
        with (
            mock.patch.object(
                self.workflow,
                "signature_context_for_request",
                return_value=({}, None),
            ),
            mock.patch.object(
                self.workflow,
                "materialize_pcap_files",
                return_value=([direct], "direct"),
            ),
            mock.patch.object(self.workflow, "sha256_file", return_value="c" * 64),
            mock.patch.object(
                self.workflow,
                "run_zeek",
                return_value={"available": True, "coverage": {"complete": True}},
            ),
            mock.patch.object(
                self.workflow,
                "run_tshark",
                return_value={"available": True, "coverage": {"complete": True}},
            ),
            mock.patch.object(self.workflow, "configured_maxmind_db_paths", return_value={}),
            mock.patch.object(self.workflow, "project_now", return_value="now"),
            mock.patch.object(self.workflow, "tool_path", return_value=None),
            mock.patch.object(
                self.workflow,
                "delete_request_artifacts",
            ) as delete,
        ):
            result = self.workflow.process_one(request, args, direct)

        delete.assert_not_called()
        self.assertEqual(
            result["raw_artifact_cleanup"],
            {"deleted": False, "bytes": 0, "files": 0},
        )


if __name__ == "__main__":
    unittest.main()
