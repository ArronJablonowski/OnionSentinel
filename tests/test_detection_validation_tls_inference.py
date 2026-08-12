from __future__ import annotations

import ast
import copy
import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
SCRIPT = BIN / "detection_validation_packet_buffers.py"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_module():
    spec = importlib.util.spec_from_file_location(
        "detection_validation_tls_inference_under_test",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
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

        def visit_If(self, node):
            self.value += 1
            self.generic_visit(node)

        visit_For = visit_If

        def visit_BoolOp(self, node):
            self.value += max(0, len(node.values) - 1)
            self.generic_visit(node)

        def visit_GeneratorExp(self, node):
            self.value += sum(
                1 + len(generator.ifs) for generator in node.generators
            )
            self.generic_visit(node)

        visit_SetComp = visit_GeneratorExp

    visitor = Complexity()
    for child in target.body:
        visitor.visit(child)
    return target.end_lineno - target.lineno + 1, visitor.value


class DetectionValidationTlsInferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_tls_projection_helpers_meet_quality_boundaries(self):
        for name in (
            "_candidate_tls_names",
            "_tls_marker_names",
            "_matching_tls_names",
            "_inferred_tls_name",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)
        self.assertLessEqual(len(SCRIPT.read_text().splitlines()), 250)

    def test_exact_and_subdomain_matches_are_case_and_dot_normalized(self):
        cases = (
            (
                "TLS API.Example.COM and unrelated.invalid",
                [({"buffer": " TLS.SNI "}, b".example.com")],
                "api.example.com",
            ),
            (
                "Exact.Example.COM. repeated exact.example.com",
                [({"buffer": "tls.sni"}, b"EXACT.EXAMPLE.COM.")],
                "",
            ),
            (
                "prefix.example.com",
                [({"buffer": "tls.sni"}, b"prefix.example.com")],
                "prefix.example.com",
            ),
        )
        for decoded, markers, expected in cases:
            with self.subTest(decoded=decoded):
                before = copy.deepcopy(markers)
                self.assertEqual(
                    self.module._inferred_tls_name(decoded, markers),
                    expected,
                )
                self.assertEqual(markers, before)

    def test_zero_or_ambiguous_matches_fail_closed(self):
        cases = (
            ("a.example.com b.example.com", b"example.com"),
            ("unrelated.invalid", b"example.com"),
            ("example.com", b""),
            ("example.com", b"."),
        )
        for decoded, marker in cases:
            with self.subTest(decoded=decoded, marker=marker):
                self.assertEqual(
                    self.module._inferred_tls_name(
                        decoded,
                        [({"buffer": "tls.sni"}, marker)],
                    ),
                    "",
                )
        self.assertEqual(self.module._inferred_tls_name("example.com", None), "")
        self.assertEqual(self.module._inferred_tls_name("example.com", []), "")

    def test_only_tls_sni_marker_specs_participate(self):
        markers = [
            ({"buffer": "http.host"}, b"example.com"),
            ({"buffer": ""}, b"example.com"),
            ({}, b"example.com"),
            ({"buffer": "tls.sni"}, b"allowed.example.com"),
        ]
        before = copy.deepcopy(markers)
        self.assertEqual(
            self.module._inferred_tls_name(
                "example.com allowed.example.com",
                markers,
            ),
            "allowed.example.com",
        )
        self.assertEqual(markers, before)

    def test_domain_regex_boundaries_and_length_admission_are_exact(self):
        oversized = ".".join(("a" * 63,) * 4) + ".com"
        decoded = " ".join(
            (
                "-bad.example.com",
                "bad-.example.com",
                "one_label",
                "insidegood.example.comsuffix",
                oversized,
                "good.example.com",
            )
        )
        self.assertEqual(
            self.module._inferred_tls_name(
                decoded,
                [({"buffer": "tls.sni"}, b"good.example.com")],
            ),
            "good.example.com",
        )
        self.assertEqual(
            self.module._inferred_tls_name(
                oversized,
                [({"buffer": "tls.sni"}, b"com")],
            ),
            "",
        )

    def test_marker_bytes_use_latin1_lower_and_leading_dot_rules(self):
        self.assertEqual(
            self.module._inferred_tls_name(
                "service.example.com",
                [({"buffer": "tls.sni"}, b".EXAMPLE.COM")],
            ),
            "service.example.com",
        )
        self.assertEqual(
            self.module._inferred_tls_name(
                "service.example.com\u00ff",
                [({"buffer": "tls.sni"}, b".EXAMPLE.COM\xff")],
            ),
            "",
        )

    def test_malformed_marker_inputs_preserve_exact_failures(self):
        cases = (
            ([(None, b"example.com")], AttributeError),
            ([({"buffer": "tls.sni"}, "example.com")], AttributeError),
            ([({"buffer": "tls.sni"}, None)], AttributeError),
        )
        for markers, error_type in cases:
            with self.subTest(markers=markers):
                before = copy.deepcopy(markers)
                with self.assertRaises(error_type):
                    self.module._inferred_tls_name("example.com", markers)
                self.assertEqual(markers, before)


if __name__ == "__main__":
    unittest.main()
