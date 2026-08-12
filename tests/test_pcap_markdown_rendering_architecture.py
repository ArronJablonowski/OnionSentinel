from __future__ import annotations

import ast
import copy
import hashlib
import importlib.machinery
import importlib.util
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/pcap_processor_workflow.py"
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_workflow():
    loader = importlib.machinery.SourceFileLoader(
        "pcap_markdown_rendering_architecture", str(SCRIPT)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
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


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def available_analysis() -> dict:
    return {
        "generated_at": "2026-01-02  03:04:05-07:00",
        "artifact_state": "ready",
        "pcap_files": [{"name": "one.pcap"}, {"name": "two.pcap"}],
        "request": {
            "request_id": "req-2",
            "alert_id": "alert-2",
            "group_id": "group-2",
        },
        "zeek": {
            "available": True,
            "record_counts": {"weird": 2, "conn": 3},
            "coverage": {
                "pcap_files_processed": 2,
                "pcap_files_total": 2,
                "records_aggregated": 5,
                "complete": True,
            },
            "top_connections": [{"z": 2, "a": 1}],
            "dns_queries": [],
            "tls_sni": ["b", "a"],
            "http_hosts": None,
            "files": [1],
            "notices": [2],
            "weird": [3],
        },
        "tshark": {
            "available": True,
            "coverage": {
                "pcap_files_processed": 2,
                "pcap_files_total": 2,
                "decoded_records": 9,
                "total_records": 10,
                "decode_percent": 90.0,
                "total_bytes": 1234,
                "first_timestamp_epoch": "1.5",
                "last_timestamp_epoch": "2.5",
                "complete": False,
            },
            "sampling": {
                "packets_sampled": 2,
                "packets_seen": 10,
                "strategy": "reservoir",
            },
            "protocol_counts": [{"protocol": "tcp", "count": 2}],
            "top_conversations": [{"b": 2, "a": 1}],
            "icmp_size_review": {"large": []},
            "dns_activity": {"queries": ["x"]},
            "http_user_agents": {"agents": ["ua"]},
            "tls_versions": {"TLSv1.3": 2},
            "geoip": {"available": True, "records": [{"ip": "8.8.8.8"}]},
            "samples": [
                {
                    "pcap": "/private/evidence/first.pcap",
                    "protocol_hierarchy": "  frame: 2  ",
                    "conversations": "",
                },
                {
                    "pcap": "second.pcap",
                    "protocol_hierarchy": "",
                    "conversations": "  tcp  ",
                },
                {
                    "pcap": "third.pcap",
                    "protocol_hierarchy": "SHOULD NOT RENDER",
                    "conversations": "x",
                },
            ],
        },
    }


class PcapMarkdownRenderingArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = load_workflow()

    def test_facade_retains_pre_extraction_quality_ceiling(self) -> None:
        lines, complexity = function_metrics("build_markdown")
        self.assertLessEqual(lines, 124)
        self.assertLessEqual(complexity, 18)

    def test_minimal_projection_is_byte_exact_and_nonmutating(self) -> None:
        analysis = {}
        before = copy.deepcopy(analysis)
        result = self.workflow.build_markdown(analysis)

        self.assertEqual(analysis, before)
        self.assertEqual(
            digest(result),
            "5b0da81999497afed80ffc3b5eacf3feefeb1002be7c59085674ed1d5ceb24b0",
        )
        self.assertTrue(result.startswith("---\ntype: soc-pcap-analysis\n"))
        self.assertTrue(result.endswith("directory yet.\n"))

    def test_unavailable_tools_projection_is_byte_exact(self) -> None:
        analysis = {
            "generated_at": "2026-01-02  03:04:05-07:00",
            "artifact_state": "missing",
            "pcap_files": [],
            "request": {
                "request_id": "req-1",
                "alert_id": "alert-1",
                "group_id": "group-1",
            },
            "zeek": {"available": False, "reason": "zeek missing"},
            "tshark": {"available": False, "reason": "tshark missing"},
        }
        before = copy.deepcopy(analysis)
        result = self.workflow.build_markdown(analysis)

        self.assertEqual(analysis, before)
        self.assertEqual(
            digest(result),
            "a74f325fe838efbbfe9e4b85aee376bd17f4dd38c57d144a69c5fcaef3bc5067",
        )
        self.assertIn("- Zeek unavailable: zeek missing", result)
        self.assertIn("- TShark unavailable: tshark missing", result)

    def test_available_projection_preserves_json_samples_and_policy_bytes(self) -> None:
        analysis = available_analysis()
        before = copy.deepcopy(analysis)
        result = self.workflow.build_markdown(analysis)

        self.assertEqual(analysis, before)
        self.assertEqual(
            digest(result),
            "67542a18ee269a6d1294c3a0994258e7fdc33a48c0a0cf3adada7ffb28c92c84",
        )
        self.assertIn('- Record counts: `{"conn": 3, "weird": 2}`', result)
        self.assertIn("### first.pcap", result)
        self.assertIn("### second.pcap", result)
        self.assertNotIn("third.pcap", result)
        self.assertIn("frame: 2", result)
        self.assertIn("```text\nn/a\n```", result)
        self.assertIn("### Offline GeoIP", result)
        self.assertIn("Geolocation is approximate context, not proof", result)

    def test_malformed_shapes_preserve_exact_exception_contract(self) -> None:
        cases = [
            (None, AttributeError, "'NoneType' object has no attribute 'get'"),
            ({"request": []}, AttributeError, "'list' object has no attribute 'get'"),
            ({"zeek": []}, AttributeError, "'list' object has no attribute 'get'"),
            (
                {"tshark": {"available": True, "samples": None}},
                TypeError,
                "'NoneType' object is not subscriptable",
            ),
            (
                {"tshark": {"available": True, "samples": ["bad"]}},
                AttributeError,
                "'str' object has no attribute 'get'",
            ),
        ]
        for analysis, error_type, message in cases:
            with self.subTest(analysis=analysis):
                before = copy.deepcopy(analysis)
                with self.assertRaisesRegex(error_type, re.escape(message)):
                    self.workflow.build_markdown(analysis)
                self.assertEqual(analysis, before)


if __name__ == "__main__":
    unittest.main()
