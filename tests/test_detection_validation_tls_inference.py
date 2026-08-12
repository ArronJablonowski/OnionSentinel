from __future__ import annotations

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


class DetectionValidationTlsInferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

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
