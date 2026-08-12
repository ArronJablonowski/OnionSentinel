from __future__ import annotations

import ast
import copy
import importlib.util
import inspect
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPORTER_PATH = ROOT / "n8n/bin/export-adjudicated-analysis-replays.py"


def load_exporter():
    spec = importlib.util.spec_from_file_location(
        "adjudicated_replay_evidence_catalog_architecture", EXPORTER_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse(EXPORTER_PATH.read_text(encoding="utf-8"))
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


class TrackingDict(dict):
    def __init__(self, values):
        super().__init__(values)
        self.trace = []

    def __contains__(self, key):
        self.trace.append(["contains", key])
        return super().__contains__(key)

    def __getitem__(self, key):
        self.trace.append(["getitem", key])
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.trace.append(["get", key])
        return super().get(key, default)


class BadText:
    def __str__(self):
        raise RuntimeError("synthetic string conversion failure")


class AdjudicatedReplayEvidenceCatalogArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.exporter = load_exporter()

    def test_signature_current_debt_and_replay_case_callback_are_exact(self) -> None:
        signature = inspect.signature(
            self.exporter.evidence_reference_catalog
        )
        self.assertEqual(list(signature.parameters), ["prompt_package"])
        self.assertEqual(str(signature.return_annotation), "list[str]")
        for name in (
            "_add_evidence_reference",
            "_add_alert_group_references",
            "_add_enrichment_pcap_references",
            "_add_validation_asset_references",
            "_add_prior_related_references",
            "_add_correlation_references",
            "_add_incident_references",
            "evidence_reference_catalog",
        ):
            lines, complexity = function_metrics(name)
            self.assertLessEqual(lines, 50)
            self.assertLessEqual(complexity, 10)
        source = EXPORTER_PATH.read_text(encoding="utf-8")
        self.assertEqual(source.count("evidence_reference_catalog(prompt_package)"), 1)
        self.assertLessEqual(len(source.splitlines()), 800)

    def test_every_supported_section_and_nested_reference_is_exact(self) -> None:
        package = {
            "alert": {"alert_id": " A  1 "},
            "grouped_alert_context": {
                "timeline": [
                    {"alert_id": "G2"},
                    {"alert_id": "G1"},
                    None,
                ]
            },
            "public_enrichment": {
                "records": [
                    {
                        "source": " src ",
                        "indicator_type": " ip ",
                        "indicator": " 192.0.2.1 ",
                    },
                    {"source": "", "indicator_type": "dns", "indicator": "x"},
                ]
            },
            "pcap_evidence": {"parsed_evidence": [{"request_id": "P1"}, None]},
            "detection_validation": {
                "rule": {"sid": "100", "revision": "2"},
                "playbook": {"id": "PB"},
            },
            "asset_context": {"matched_assets": [{"asset_id": "AS1"}, None]},
            "prior_analyses": [{"analysis_id": "PR1"}, None],
            "related_alerts": [{"alert_id": "R1"}, None],
            "correlated_alert_context": {
                "candidates": [{"group_id": "C1"}, None]
            },
            "incident_response_evidence": {
                "security_onion_response": {
                    "results": [{"pack": "zeek", "window_index": 0}, None],
                    "osquery_results": [{"pack": "processes"}, None],
                }
            },
            "analyst_state": {},
            "agent_memory": None,
        }
        before = copy.deepcopy(package)
        self.assertEqual(
            self.exporter.evidence_reference_catalog(package),
            [
                "alert",
                "alert:A 1",
                "analyst_state",
                "asset_context",
                "asset_context:AS1",
                "correlated_alert_context",
                "correlated_alert_context:C1",
                "detection_validation",
                "detection_validation:100:2",
                "detection_validation:playbook:PB",
                "grouped_alert_context",
                "grouped_alert_context:G1",
                "grouped_alert_context:G2",
                "incident_response_evidence",
                "incident_response_evidence:osquery:processes",
                "incident_response_evidence:zeek:0",
                "pcap_evidence",
                "pcap_evidence:P1",
                "prior_analyses",
                "prior_analyses:PR1",
                "public_enrichment",
                "public_enrichment:src:ip:192.0.2.1",
                "related_alerts",
                "related_alerts:R1",
            ],
        )
        self.assertEqual(package, before)

    def test_wrong_nested_shapes_keep_only_present_top_level_sections(self) -> None:
        package = {
            "alert": [],
            "grouped_alert_context": "wrong",
            "public_enrichment": {"records": "wrong"},
            "pcap_evidence": {"parsed_evidence": {}},
            "detection_validation": {"rule": [], "playbook": "wrong"},
            "asset_context": {"matched_assets": {}},
            "prior_analyses": {},
            "related_alerts": "wrong",
            "correlated_alert_context": {"candidates": "wrong"},
            "incident_response_evidence": {"security_onion_response": []},
        }
        self.assertEqual(
            self.exporter.evidence_reference_catalog(package),
            sorted(package),
        )

    def test_cleaning_deduplication_truncation_sort_then_cap_are_exact(self) -> None:
        original_length = self.exporter.MAX_EVIDENCE_REF_LENGTH
        original_count = self.exporter.MAX_EVIDENCE_REFS
        self.exporter.MAX_EVIDENCE_REF_LENGTH = 12
        self.exporter.MAX_EVIDENCE_REFS = 4
        try:
            package = {
                "alert": {"alert_id": "  same   value  with suffix "},
                "related_alerts": [
                    {"alert_id": "same value with suffix"},
                    {"alert_id": "z-last"},
                    {"alert_id": ""},
                ],
                "agent_memory": {},
                "public_enrichment": {
                    "records": [
                        {"source": "x", "indicator_type": None, "indicator": "y"}
                    ]
                },
            }
            result = self.exporter.evidence_reference_catalog(package)
        finally:
            self.exporter.MAX_EVIDENCE_REF_LENGTH = original_length
            self.exporter.MAX_EVIDENCE_REFS = original_count
        self.assertEqual(
            result,
            ["agent_memory", "alert", "alert:same v", "public_enric"],
        )

    def test_top_level_access_order_is_exact(self) -> None:
        package = TrackingDict({"alert": {"alert_id": "fixture"}})
        self.assertEqual(
            self.exporter.evidence_reference_catalog(package),
            ["alert", "alert:fixture"],
        )
        section_trace = []
        for key in self.exporter.EVIDENCE_SECTION_KEYS:
            section_trace.append(["contains", key])
            if key == "alert":
                section_trace.append(["getitem", key])
        self.assertEqual(package.trace[: len(section_trace)], section_trace)
        self.assertEqual(
            package.trace[len(section_trace) :],
            [
                ["get", "alert"],
                ["get", "grouped_alert_context"],
                ["get", "public_enrichment"],
                ["get", "pcap_evidence"],
                ["get", "detection_validation"],
                ["get", "asset_context"],
                ["get", "prior_analyses"],
                ["get", "related_alerts"],
                ["get", "correlated_alert_context"],
                ["get", "incident_response_evidence"],
            ],
        )

    def test_string_conversion_failure_propagates_without_cause_or_mutation(self) -> None:
        value = BadText()
        package = {"alert": {"alert_id": value}}
        with self.assertRaisesRegex(
            RuntimeError, "synthetic string conversion failure"
        ) as raised:
            self.exporter.evidence_reference_catalog(package)
        self.assertIsNone(raised.exception.__cause__)
        self.assertIs(package["alert"]["alert_id"], value)


if __name__ == "__main__":
    unittest.main()
