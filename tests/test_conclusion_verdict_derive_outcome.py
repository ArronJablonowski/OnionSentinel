"""Characterization for factored-to-compatibility outcome derivation."""
from __future__ import annotations

import sys
import unittest
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import verdict


def factors(**overrides):
    value = {
        "duplicate_of": None,
        "detection_validity": "matched_intent",
        "event_status": "observed",
        "activity_disposition": "suspicious",
        "handling": "investigate",
    }
    value.update(overrides)
    return value


class TracedGetMapping(Mapping):
    def __init__(self, value):
        self.value = value
        self.calls = []

    def get(self, key, default=None):
        self.calls.append((key, default))
        return self.value.get(key, default)

    def __getitem__(self, key):
        return self.value[key]

    def __iter__(self):
        return iter(self.value)

    def __len__(self):
        return len(self.value)


class ConclusionVerdictDeriveOutcomeTests(unittest.TestCase):
    def test_duplicate_identifier_has_absolute_precedence(self) -> None:
        for duplicate in ("group-1", " group-1 ", 1, True, ["group-1"]):
            with self.subTest(duplicate=duplicate):
                self.assertEqual(
                    verdict.derive_outcome(
                        factors(
                            duplicate_of=duplicate,
                            detection_validity="parser_error",
                            event_status="not_observed",
                        )
                    ),
                    "duplicate",
                )
        for duplicate in (None, "", " ", 0, False, [], {}):
            with self.subTest(duplicate=duplicate):
                self.assertNotEqual(
                    verdict.derive_outcome(factors(duplicate_of=duplicate)),
                    "duplicate",
                )

    def test_detection_error_mappings_precede_event_observation(self) -> None:
        expected = {
            "parser_error": "false_positive_data_parser",
            "logic_error": "false_positive_logic_rule",
            "intel_error": "false_positive_bad_intel_ioc",
        }
        for validity, outcome in expected.items():
            for status in ("observed", "not_observed", "unknown"):
                with self.subTest(validity=validity, status=status):
                    self.assertEqual(
                        verdict.derive_outcome(
                            factors(
                                detection_validity=validity,
                                event_status=status,
                            )
                        ),
                        outcome,
                    )

    def test_nonobserved_events_are_inconclusive_before_direct_mapping(self) -> None:
        for status in ("not_observed", "unknown", "Observed", " observed ", ""):
            with self.subTest(status=status):
                self.assertEqual(
                    verdict.derive_outcome(
                        factors(
                            event_status=status,
                            activity_disposition="malicious",
                        )
                    ),
                    "inconclusive",
                )

    def test_direct_and_informational_tables_are_exact(self) -> None:
        cases = (
            ("matched_intent", "malicious", "contain", "true_positive_malicious"),
            ("matched_intent", "suspicious", "investigate", "true_positive_suspicious"),
            ("matched_intent", "authorized_benign", "no_action", "true_positive_authorized_benign"),
            ("not_applicable", "malicious", "escalate", "false_negative"),
            ("matched_intent", "benign", "no_action", "informational_no_action"),
            ("not_applicable", "benign", "no_action", "informational_no_action"),
            ("not_applicable", "authorized_benign", "no_action", "informational_no_action"),
        )
        for validity, disposition, handling, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    verdict.derive_outcome(
                        factors(
                            detection_validity=validity,
                            activity_disposition=disposition,
                            handling=handling,
                        )
                    ),
                    expected,
                )
        self.assertEqual(
            verdict.derive_outcome(
                factors(
                    detection_validity="matched_intent",
                    activity_disposition="benign",
                    handling="monitor",
                )
            ),
            "inconclusive",
        )

    def test_defaults_string_coercion_and_whitespace_are_exact(self) -> None:
        self.assertEqual(verdict.derive_outcome({}), "inconclusive")
        self.assertEqual(
            verdict.derive_outcome(
                {
                    "event_status": "observed",
                    "detection_validity": "matched_intent",
                    "activity_disposition": "suspicious",
                }
            ),
            "true_positive_suspicious",
        )
        self.assertEqual(
            verdict.derive_outcome(factors(duplicate_of="   ")),
            "true_positive_suspicious",
        )
        self.assertEqual(
            verdict.derive_outcome(factors(detection_validity=None)),
            "inconclusive",
        )
        self.assertEqual(
            verdict.derive_outcome(factors(event_status=None)),
            "inconclusive",
        )

    def test_mapping_get_order_and_defaults_are_exact(self) -> None:
        mapping = TracedGetMapping(factors(duplicate_of="group-1"))
        self.assertEqual(verdict.derive_outcome(mapping), "duplicate")
        self.assertEqual(
            mapping.calls,
            [
                ("duplicate_of", None),
                ("detection_validity", None),
                ("event_status", None),
                ("activity_disposition", None),
                ("handling", None),
            ],
        )

    def test_unhashable_coerced_values_and_input_mutation_are_exact(self) -> None:
        value = factors(detection_validity=["parser_error"])
        before = dict(value)
        self.assertEqual(verdict.derive_outcome(value), "inconclusive")
        self.assertEqual(value, before)
        for key in ("event_status", "activity_disposition"):
            with self.subTest(key=key):
                candidate = factors(**{key: ["value"]})
                self.assertEqual(
                    verdict.derive_outcome(candidate),
                    "inconclusive",
                )
        self.assertEqual(
            verdict.derive_outcome(factors(handling=["value"])),
            "true_positive_suspicious",
        )


if __name__ == "__main__":
    unittest.main()
