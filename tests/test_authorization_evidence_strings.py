"""Characterization for canonical authorization string-list admission."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import authorization_evidence


class AuthorizationEvidenceStringsTests(unittest.TestCase):
    @staticmethod
    def invoke(value, *, maximum=3, required=False, validator=None):
        return authorization_evidence._strings(
            {"field": value},
            "field",
            maximum=maximum,
            required=required,
            validator=validator or (lambda _text: True),
        )

    def test_container_limit_and_required_boundaries_are_exact(self) -> None:
        for value in (None, "alpha", ("alpha",), {"alpha"}, {"x": 1}):
            with self.subTest(value=value):
                self.assertIsNone(self.invoke(value))
        self.assertEqual(self.invoke([]), [])
        self.assertIsNone(self.invoke([], required=True))
        self.assertEqual(self.invoke(["a", "b", "c"], maximum=3), ["a", "b", "c"])
        self.assertIsNone(self.invoke(["a", "b", "c", "d"], maximum=3))
        self.assertIsNone(
            authorization_evidence._strings(
                {},
                "field",
                maximum=3,
                required=False,
                validator=lambda _text: True,
            )
        )

    def test_only_exact_lowercase_nonempty_strings_are_admitted(self) -> None:
        self.assertEqual(self.invoke(["alpha", "beta"]), ["alpha", "beta"])
        for item in (
            "",
            " ",
            "Alpha",
            " alpha",
            "alpha ",
            1,
            True,
            None,
            b"alpha",
        ):
            with self.subTest(item=item):
                self.assertIsNone(self.invoke([item]))

    def test_validator_receives_canonical_text_and_stops_on_rejection(self) -> None:
        calls = []

        def validator(text):
            calls.append(text)
            return text != "blocked"

        self.assertIsNone(
            self.invoke(
                ["alpha", "blocked", "unreached"],
                validator=validator,
            )
        )
        self.assertEqual(calls, ["alpha", "blocked"])

    def test_noncanonical_items_short_circuit_before_validator(self) -> None:
        calls = []
        self.assertIsNone(
            self.invoke(
                ["Alpha"],
                validator=lambda text: calls.append(text) or True,
            )
        )
        self.assertEqual(calls, [])

    def test_duplicate_is_validated_again_then_rejected(self) -> None:
        calls = []
        self.assertIsNone(
            self.invoke(
                ["alpha", "alpha"],
                validator=lambda text: calls.append(text) or True,
            )
        )
        self.assertEqual(calls, ["alpha", "alpha"])

    def test_validator_exceptions_still_propagate(self) -> None:
        def fail(_text):
            raise RuntimeError("validator defect")

        with self.assertRaisesRegex(RuntimeError, "validator defect"):
            self.invoke(["alpha"], validator=fail)

    def test_canonical_coverage_remains_fail_closed_for_string_fields(self) -> None:
        coverage = {
            "source_ips": ["192.0.2.10"],
            "destination_ips": [],
            "rule_ids": ["rule-1"],
            "source_ports": [],
            "destination_ports": [443],
            "destination_port_ranges": [],
            "transport_protocols": ["tcp"],
            "authorization_start": "2026-08-13T00:00:00Z",
            "authorization_end": "2026-08-13T01:00:00Z",
        }
        self.assertEqual(
            authorization_evidence.canonical_coverage(coverage),
            coverage,
        )
        for key, value in (
            ("source_ips", ["192.0.2.10", "192.0.2.10"]),
            ("source_ips", ["192.0.2.999"]),
            ("rule_ids", ["Rule-1"]),
            ("rule_ids", []),
            ("transport_protocols", ["TCP"]),
        ):
            with self.subTest(key=key, value=value):
                tampered = {**coverage, key: value}
                self.assertIsNone(
                    authorization_evidence.canonical_coverage(tampered)
                )


if __name__ == "__main__":
    unittest.main()
