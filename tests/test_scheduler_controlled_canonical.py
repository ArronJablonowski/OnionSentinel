from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_acceptance import (  # noqa: E402
    controlled_accepted_fields_match,
    controlled_expected_accepted_fields,
)
from scheduler_controlled_canonical import (  # noqa: E402
    controlled_normalize_timestamp,
    controlled_storage_canonical_digest,
    controlled_storage_canonical_json,
)
from scheduler_javascript_compat import (  # noqa: E402
    javascript_json_number,
    javascript_object_key_order,
    javascript_safe_string,
    javascript_string_value,
    javascript_trim,
    javascript_truthy,
)


class SchedulerJavascriptCompatibilityTests(unittest.TestCase):
    def test_trim_uses_ecmascript_whitespace_set(self) -> None:
        self.assertEqual(javascript_trim("\ufeff\u00a0 value \u3000"), "value")
        self.assertEqual(javascript_trim("\u001cvalue\u0085"), "\u001cvalue\u0085")

    def test_string_value_and_truthiness_match_json_javascript_values(self) -> None:
        self.assertEqual(javascript_string_value(None), "")
        self.assertEqual(javascript_string_value([1, None, True]), "1,,true")
        self.assertEqual(javascript_string_value({"key": "value"}), "[object Object]")
        self.assertEqual(javascript_string_value(math.nan), "NaN")
        self.assertFalse(javascript_truthy(math.nan))
        self.assertFalse(javascript_truthy(-0.0))
        self.assertTrue(javascript_truthy([]))

    def test_safe_string_collapses_whitespace_and_matches_utf16_slice(self) -> None:
        self.assertEqual(javascript_safe_string("  a\t\nb  ", 20), "a b")
        self.assertEqual(javascript_safe_string("abc😀tail", 4), "abc\ufffd")
        self.assertEqual(javascript_safe_string("abc😀tail", 5), "abc😀")

    def test_json_number_thresholds_and_nonfinite_values(self) -> None:
        cases = {
            -0.0: "0",
            0.000001: "0.000001",
            0.0000001: "1e-7",
            1e20: "100000000000000000000",
            1e21: "1e+21",
            math.inf: "null",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(javascript_json_number(value), expected)

    def test_object_keys_put_array_indexes_before_utf16_sorted_keys(self) -> None:
        value = {"10": 1, "2": 2, "01": 3, "é": 4, "a": 5}
        self.assertEqual(
            javascript_object_key_order(value),
            ["2", "10", "01", "a", "é"],
        )


class SchedulerControlledCanonicalTests(unittest.TestCase):
    def test_timestamp_normalization_matches_alert_store_shape(self) -> None:
        normalized = controlled_normalize_timestamp(
            "2026-07-24T18:30:45.987654Z"
        )
        self.assertIsInstance(normalized, str)
        self.assertRegex(
            normalized or "",
            r"^2026-07-(?:24|25)  \d{2}:\d{2}:45\.987[+-]\d{2}:\d{2}$",
        )
        overflow = controlled_normalize_timestamp("2024-02-30T00:00:00Z")
        self.assertIsInstance(overflow, str)
        self.assertNotIn("T", overflow or "")
        self.assertRegex(overflow or "", r"^2024-0[23]-\d{2}  ")
        self.assertIsNone(controlled_normalize_timestamp(""))

    def test_canonical_json_normalizes_nested_timestamps_and_key_order(self) -> None:
        value = {
            "z": "2026-07-24T18:30:45Z",
            "10": "ten",
            "2": "two",
            "unicode": "Café 🧅",
            "nonfinite": math.nan,
        }
        canonical = controlled_storage_canonical_json(value)
        self.assertTrue(canonical.startswith('{"2":"two","10":"ten"'))
        self.assertIn('"nonfinite":null', canonical)
        self.assertIn('"unicode":"Café 🧅"', canonical)
        self.assertRegex(
            canonical,
            r'"z":"2026-07-(?:24|25)  \d{2}:\d{2}:45[+-]\d{2}:\d{2}"',
        )
        self.assertEqual(len(controlled_storage_canonical_digest(value)), 64)

    def test_canonical_json_rejects_non_json_objects(self) -> None:
        with self.assertRaisesRegex(TypeError, "non-JSON"):
            controlled_storage_canonical_json({"bad": object()})


class SchedulerControlledAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = {
            "generated_at": "2026-07-24T18:30:45Z",
            "model": "primary-model",
            "model_path": "/model/path",
            "artifact_path": "/artifact/path",
            "evidence_hash": "ABCD",
        }
        self.response = {
            "_analysis_model": "fallback-model",
            "_analysis_model_path": "/fallback/path",
            "detection_outcome": "true_positive_suspicious",
            "bluf": "  concise\n finding ",
            "summary": "summary",
            "confidence": "HIGH",
        }

    def test_projection_prefers_truthy_payload_model_and_bounds_fields(self) -> None:
        projected = controlled_expected_accepted_fields(
            self.payload, self.response
        )
        self.assertEqual(projected["model"], "primary-model")
        self.assertEqual(projected["model_path"], "/model/path")
        self.assertEqual(projected["bluf"], "concise finding")
        self.assertEqual(projected["confidence"], "high")
        self.assertEqual(projected["evidence_hash"], "abcd")

    def test_projection_falls_back_to_response_model(self) -> None:
        self.payload["model"] = ""
        self.payload["model_path"] = None
        projected = controlled_expected_accepted_fields(
            self.payload, self.response
        )
        self.assertEqual(projected["model"], "fallback-model")
        self.assertEqual(projected["model_path"], "/fallback/path")

    def test_acceptance_match_normalizes_timestamp_and_case_fields(self) -> None:
        expected = controlled_expected_accepted_fields(
            self.payload, self.response
        )
        accepted = dict(expected)
        accepted["generated_at"] = "2026-07-24  12:30:45-06:00"
        accepted["confidence"] = "HIGH"
        accepted["evidence_hash"] = "ABCD"
        self.assertTrue(controlled_accepted_fields_match(accepted, expected))
        accepted["summary"] = "different"
        self.assertFalse(controlled_accepted_fields_match(accepted, expected))

    def test_dynamic_generated_at_cannot_produce_terminal_proof(self) -> None:
        self.payload.pop("generated_at")
        expected = controlled_expected_accepted_fields(
            self.payload, self.response
        )
        self.assertIsNone(expected["generated_at"])
        self.assertFalse(controlled_accepted_fields_match({}, expected))


if __name__ == "__main__":
    unittest.main()
