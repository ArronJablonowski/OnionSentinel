"""Characterize the full factored-verdict normalization boundary."""
from __future__ import annotations

import unittest

from n8n.onion_sentinel.analysis.conclusions import verdict
from tests.test_conclusion_verdict_package import (
    DISPOSITIONS,
    EVENTS,
    HANDLING,
    KEYS,
    OUTCOMES,
    VALIDITY,
)


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace

    def __contains__(self, key: object) -> bool:
        self.trace.append(("contains", key))
        return super().__contains__(key)

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", key, default))
        return super().get(key, default)

    def update(self, *args: object, **kwargs: object) -> None:
        value = args[0] if args else kwargs
        self.trace.append(("update", tuple(value.items())))
        return super().update(*args, **kwargs)

    def __setitem__(self, key: object, value: object) -> None:
        self.trace.append(("set", key, value))
        return super().__setitem__(key, value)


def normalize(response: dict, callback) -> dict:
    return verdict.normalize(
        response,
        outcome_values=OUTCOMES,
        event_status_values=EVENTS,
        validity_values=VALIDITY,
        disposition_values=DISPOSITIONS,
        handling_values=HANDLING,
        factored_keys=KEYS,
        boolean_setting=callback,
    )


class VerdictNormalizeBoundaryTests(unittest.TestCase):
    def test_access_callback_and_mutation_order_are_exact(self) -> None:
        trace: list[object] = []
        response = TrackingDict(
            {
                "detection_outcome": "inconclusive",
                "escalation_needed": "yes",
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "suspicious",
                "handling": "escalate",
                "duplicate_of": None,
            },
            trace=trace,
        )

        def boolean(value: object) -> bool:
            trace.append(("boolean", value))
            return True

        result = normalize(response, boolean)

        self.assertIs(result, response)
        audit = result["_verdict_validation"]
        self.assertEqual(result["detection_outcome"], "true_positive_suspicious")
        self.assertEqual(audit["source"], "model_factored")
        self.assertEqual(audit["warnings"], [
            "factored verdict derives true_positive_suspicious, but model supplied inconclusive"
        ])
        self.assertEqual(trace[:3], [
            ("get", "detection_outcome", None),
            ("get", "escalation_needed", None),
            ("boolean", "yes"),
        ])
        update_index = next(i for i, item in enumerate(trace) if item[0] == "update")
        self.assertEqual(trace[update_index + 1][0:2], ("set", "detection_outcome"))
        self.assertEqual(trace[update_index + 2][0:2], ("set", "_verdict_validation"))

    def test_invalid_raw_and_partial_mismatch_projection_are_exact(self) -> None:
        response = normalize(
            {
                "detection_outcome": "invented",
                "event_status": "observed",
                "handling": "contain",
                "duplicate_of": [],
            },
            bool,
        )
        audit = response["_verdict_validation"]
        self.assertEqual(response["detection_outcome"], "inconclusive")
        self.assertEqual(audit["source"], "hybrid")
        self.assertEqual(audit["invalid_fields"], {
            "detection_outcome": "invented",
            "duplicate_of": [],
        })
        self.assertTrue(audit["material_contradiction"])
        self.assertEqual(audit["warnings"], [])
        self.assertEqual(audit["contradictions"], [])

    def test_boolean_callback_exception_precedes_supplied_field_reads(self) -> None:
        trace: list[object] = []
        response = TrackingDict(
            {"detection_outcome": "inconclusive", "event_status": "observed"},
            trace=trace,
        )

        def explode(_value: object) -> bool:
            raise LookupError("boolean setting failed")

        with self.assertRaisesRegex(LookupError, "boolean setting failed"):
            normalize(response, explode)
        self.assertNotIn(("contains", "event_status"), trace)
        self.assertEqual(dict(response), {
            "detection_outcome": "inconclusive",
            "event_status": "observed",
        })

    def test_complete_matching_factors_have_no_warning_or_contradiction(self) -> None:
        response = normalize(
            {
                "detection_outcome": "true_positive_malicious",
                "event_status": "observed",
                "detection_validity": "matched_intent",
                "activity_disposition": "malicious",
                "handling": "contain",
                "duplicate_of": None,
            },
            bool,
        )
        audit = response["_verdict_validation"]
        self.assertEqual(audit["source"], "model_factored")
        self.assertEqual(audit["contradictions"], [])
        self.assertEqual(audit["warnings"], [])
        self.assertFalse(audit["material_contradiction"])


if __name__ == "__main__":
    unittest.main()
