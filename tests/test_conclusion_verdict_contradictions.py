"""Characterization for deterministic factored-verdict contradictions."""
from __future__ import annotations

import sys
import unittest
from collections.abc import Mapping
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import verdict


MESSAGES = (
    "an unobserved event cannot be a validated detection-intent match",
    "malicious activity cannot use monitor/no_action handling",
    "benign or authorized activity cannot use contain handling",
    "a duplicate record cannot independently authorize containment or escalation",
    "a duplicate outcome must identify the canonical alert or group in duplicate_of",
)


def factors(**overrides):
    value = {
        "event_status": "observed",
        "detection_validity": "matched_intent",
        "activity_disposition": "suspicious",
        "handling": "investigate",
        "duplicate_of": None,
    }
    value.update(overrides)
    return value


class TracedMapping(Mapping):
    def __init__(self, value):
        self.value = value
        self.calls = []

    def __getitem__(self, key):
        self.calls.append(key)
        return self.value[key]

    def __iter__(self):
        return iter(self.value)

    def __len__(self):
        return len(self.value)


class ConclusionVerdictContradictionsTests(unittest.TestCase):
    def test_each_rule_has_exact_condition_and_message(self) -> None:
        cases = (
            (
                factors(event_status="not_observed"),
                "true_positive_suspicious",
                [MESSAGES[0]],
            ),
            (
                factors(activity_disposition="malicious", handling="monitor"),
                "true_positive_malicious",
                [MESSAGES[1]],
            ),
            (
                factors(activity_disposition="malicious", handling="no_action"),
                "true_positive_malicious",
                [MESSAGES[1]],
            ),
            (
                factors(activity_disposition="authorized_benign", handling="contain"),
                "true_positive_authorized_benign",
                [MESSAGES[2]],
            ),
            (
                factors(activity_disposition="benign", handling="contain"),
                "informational_no_action",
                [MESSAGES[2]],
            ),
            (
                factors(duplicate_of="group-1", handling="contain"),
                "duplicate",
                [MESSAGES[3]],
            ),
            (
                factors(duplicate_of="group-1", handling="escalate"),
                "duplicate",
                [MESSAGES[3]],
            ),
            (factors(), "duplicate", [MESSAGES[4]]),
        )
        for value, canonical, expected in cases:
            with self.subTest(canonical=canonical, value=value):
                self.assertEqual(
                    verdict._contradictions(value, canonical),
                    expected,
                )

    def test_near_misses_remain_noncontradictory(self) -> None:
        cases = (
            factors(event_status="unknown"),
            factors(event_status="not_observed", detection_validity="unknown"),
            factors(activity_disposition="malicious", handling="investigate"),
            factors(activity_disposition="benign", handling="no_action"),
            factors(duplicate_of="group-1", handling="no_action"),
        )
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(
                    verdict._contradictions(value, "inconclusive"),
                    [],
                )
        self.assertEqual(
            verdict._contradictions(factors(duplicate_of="group-1"), "duplicate"),
            [],
        )

    def test_multiple_messages_keep_policy_order(self) -> None:
        self.assertEqual(
            verdict._contradictions(
                factors(
                    event_status="not_observed",
                    activity_disposition="malicious",
                    handling="no_action",
                ),
                "duplicate",
            ),
            [MESSAGES[0], MESSAGES[1], MESSAGES[4]],
        )
        self.assertEqual(
            verdict._contradictions(
                factors(
                    activity_disposition="authorized_benign",
                    handling="contain",
                    duplicate_of="group-1",
                ),
                "duplicate",
            ),
            [MESSAGES[2], MESSAGES[3]],
        )

    def test_truthiness_of_duplicate_identifier_is_preserved(self) -> None:
        for duplicate in (None, "", 0, False, [], {}):
            with self.subTest(duplicate=duplicate):
                self.assertEqual(
                    verdict._contradictions(
                        factors(duplicate_of=duplicate),
                        "duplicate",
                    ),
                    [MESSAGES[4]],
                )
        for duplicate in ("group-1", 1, True, ["group-1"]):
            with self.subTest(duplicate=duplicate):
                self.assertEqual(
                    verdict._contradictions(
                        factors(duplicate_of=duplicate),
                        "duplicate",
                    ),
                    [],
                )

    def test_key_access_order_and_short_circuiting_are_exact(self) -> None:
        value = TracedMapping(factors())
        self.assertEqual(verdict._contradictions(value, "duplicate"), [MESSAGES[4]])
        self.assertEqual(
            value.calls,
            [
                "event_status",
                "activity_disposition",
                "activity_disposition",
                "duplicate_of",
                "duplicate_of",
            ],
        )
        duplicate = TracedMapping(factors(duplicate_of="group-1", handling="contain"))
        verdict._contradictions(duplicate, "duplicate")
        self.assertEqual(
            duplicate.calls,
            [
                "event_status",
                "activity_disposition",
                "activity_disposition",
                "duplicate_of",
                "handling",
                "duplicate_of",
            ],
        )

    def test_missing_keys_and_input_mutation_contract_are_exact(self) -> None:
        for missing in ("event_status", "activity_disposition", "duplicate_of"):
            value = factors()
            del value[missing]
            with self.subTest(missing=missing):
                with self.assertRaises(KeyError):
                    verdict._contradictions(value, "duplicate")
        for unused in ("detection_validity", "handling"):
            value = factors()
            del value[unused]
            with self.subTest(short_circuited=unused):
                self.assertEqual(
                    verdict._contradictions(value, "duplicate"),
                    [MESSAGES[4]],
                )
        value = factors(activity_disposition="malicious", handling="monitor")
        before = dict(value)
        verdict._contradictions(value, "inconclusive")
        self.assertEqual(value, before)


if __name__ == "__main__":
    unittest.main()
