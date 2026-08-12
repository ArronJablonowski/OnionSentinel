"""Characterize deployed and playbook marker normalization semantics."""

from __future__ import annotations

import ast
import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
SCRIPT = BIN / "detection_validation_packet_markers.py"
sys.path.insert(0, str(BIN))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "detection_validation_packet_markers_characterized",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


MARKERS = load_module()


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

        def visit_comprehension(self, node):
            self.value += 1 + len(node.ifs)
            self.generic_visit(node)

    complexity = Complexity()
    for statement in target.body:
        complexity.visit(statement)
    return target.end_lineno - target.lineno + 1, complexity.value


class DetectionValidationMarkerSpecsTests(unittest.TestCase):
    def test_changed_owner_architecture_is_bounded(self):
        names = (
            "_deployed_content_items",
            "_marker_modifiers",
            "_deployed_marker_spec",
            "_deployed_marker_specs",
            "_playbook_marker_items",
            "_playbook_marker_applies",
            "_playbook_marker_spec",
            "_playbook_marker_specs",
        )
        for name in names:
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(SCRIPT.read_text().splitlines()), 600)

    def test_deployed_requires_a_parsed_rule_object_and_contents_list(self):
        for context in (
            {},
            {"parsed_rule": None},
            {"parsed_rule": []},
            {"parsed_rule": {"contents": None}},
            {"parsed_rule": {"contents": {"hex": "41"}}},
        ):
            with self.subTest(context=context):
                self.assertEqual(MARKERS._deployed_marker_specs(context), [])

    def test_deployed_filters_invalid_entries_and_numbers_only_accepted_items(self):
        context = {
            "parsed_rule": {
                "contents": [
                    None,
                    "41",
                    {},
                    {"id": "empty", "hex": ""},
                    {"id": "zero", "hex": 0},
                    {"hex": "41"},
                    {"hex": "42"},
                ]
            }
        }

        self.assertEqual(
            MARKERS._deployed_marker_specs(context),
            [
                {
                    "id": "deployed-content-1",
                    "hex": "41",
                    "modifiers": {},
                    "buffer": "",
                    "negated": False,
                    "source": "deployed_rule",
                },
                {
                    "id": "deployed-content-2",
                    "hex": "42",
                    "modifiers": {},
                    "buffer": "",
                    "negated": False,
                    "source": "deployed_rule",
                },
            ],
        )

    def test_deployed_projects_exact_fields_bounds_and_boolean_coercion(self):
        modifiers = {"nocase": "yes", 7: ["retained"]}
        context = {
            "parsed_rule": {
                "contents": [
                    {
                        "id": "i" * 120,
                        "hex": "a" * 600,
                        "modifiers": modifiers,
                        "buffer": "b" * 100,
                        "negated": "false",
                        "ignored": "value",
                    },
                    {
                        "id": 17,
                        "hex": True,
                        "modifiers": ["not", "a", "mapping"],
                        "buffer": 53,
                        "negated": 0,
                    },
                ]
            }
        }
        before = copy.deepcopy(context)

        result = MARKERS._deployed_marker_specs(context)

        self.assertEqual(
            result,
            [
                {
                    "id": "i" * 100,
                    "hex": "a" * 512,
                    "modifiers": modifiers,
                    "buffer": "b" * 80,
                    "negated": True,
                    "source": "deployed_rule",
                },
                {
                    "id": "17",
                    "hex": "True",
                    "modifiers": {},
                    "buffer": "53",
                    "negated": False,
                    "source": "deployed_rule",
                },
            ],
        )
        self.assertIsNot(result[0]["modifiers"], modifiers)
        self.assertEqual(context, before)

    def test_playbook_requires_an_object_and_marker_list(self):
        context = {"sid": "1"}
        for playbook in (
            None,
            [],
            {},
            {"marker_predicates": None},
            {"marker_predicates": {"hex": "41"}},
        ):
            with self.subTest(playbook=playbook):
                self.assertEqual(
                    MARKERS._playbook_marker_specs(context, playbook, start=3),
                    [],
                )

    def test_playbook_filters_shape_hex_and_sid_scope_before_numbering(self):
        playbook = {
            "marker_predicates": [
                None,
                "41",
                {},
                {"id": "empty", "hex": ""},
                {"id": "other", "hex": "40", "applies_to_sids": ["2"]},
                {"hex": "41", "applies_to_sids": [1, "3"]},
                {"hex": "42", "applies_to_sids": ("2",)},
            ]
        }

        self.assertEqual(
            MARKERS._playbook_marker_specs({"sid": 1}, playbook, start=4),
            [
                {
                    "id": "playbook-marker-5",
                    "hex": "41",
                    "expected_offset": None,
                    "modifiers": {},
                    "negated": False,
                    "source": "playbook",
                },
                {
                    "id": "playbook-marker-6",
                    "hex": "42",
                    "expected_offset": None,
                    "modifiers": {},
                    "negated": False,
                    "source": "playbook",
                },
            ],
        )

    def test_playbook_projects_exact_fields_bounds_and_offset_identity(self):
        offset = {"unexpected": [1, 2]}
        playbook = {
            "marker_predicates": [
                {
                    "id": "p" * 120,
                    "hex": "B" * 600,
                    "expected_offset": offset,
                    "applies_to_sids": [None, "7", 7],
                    "buffer": "ignored",
                    "negated": True,
                }
            ]
        }
        before = copy.deepcopy(playbook)

        result = MARKERS._playbook_marker_specs({"sid": "7"}, playbook, start=8)

        self.assertEqual(
            result,
            [
                {
                    "id": "p" * 100,
                    "hex": "B" * 512,
                    "expected_offset": offset,
                    "modifiers": {},
                    "negated": False,
                    "source": "playbook",
                }
            ],
        )
        self.assertIs(result[0]["expected_offset"], offset)
        self.assertEqual(playbook, before)

    def test_public_marker_specs_orders_deduplicates_and_preserves_case(self):
        context = {
            "sid": "7",
            "parsed_rule": {
                "contents": [
                    {"id": "same", "hex": "Aa"},
                    {"id": "deployed-only", "hex": "41"},
                ]
            },
        }
        playbook = {
            "marker_predicates": [
                {"id": "same", "hex": "aA"},
                {"id": "same", "hex": "AB"},
                {"id": "playbook-only", "hex": "42"},
            ]
        }

        result = MARKERS.marker_specs(context, playbook)

        self.assertEqual(
            [(item["id"], item["hex"], item["source"]) for item in result],
            [
                ("same", "Aa", "deployed_rule"),
                ("deployed-only", "41", "deployed_rule"),
                ("same", "AB", "playbook"),
                ("playbook-only", "42", "playbook"),
            ],
        )

    def test_public_marker_limit_applies_after_deduplication(self):
        duplicate = {"id": "same", "hex": "AA"}
        contents = [duplicate, duplicate.copy()]
        contents.extend(
            {"id": f"deployed-{index}", "hex": f"{index + 1:02x}"}
            for index in range(MARKERS.MAX_MARKERS + 2)
        )
        playbook = {
            "marker_predicates": [
                {"id": f"playbook-{index}", "hex": f"{index + 80:02x}"}
                for index in range(3)
            ]
        }

        result = MARKERS.marker_specs(
            {"sid": "1", "parsed_rule": {"contents": contents}},
            playbook,
        )

        self.assertEqual(len(result), MARKERS.MAX_MARKERS)
        self.assertEqual(result[0]["id"], "same")
        self.assertEqual(
            [item["id"] for item in result[1:]],
            [f"deployed-{index}" for index in range(MARKERS.MAX_MARKERS - 1)],
        )
        self.assertNotIn("playbook", {item["source"] for item in result})


if __name__ == "__main__":
    unittest.main()
