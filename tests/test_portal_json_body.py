import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_json_body as bodies  # noqa: E402


class PortalJsonBodyTests(unittest.TestCase):
    def test_valid_object_and_array_preserve_json_value(self) -> None:
        object_body = bodies.parse_json_body('{"enabled": true}')
        array_body = bodies.parse_json_body('[1, 2]')
        self.assertTrue(object_body.valid)
        self.assertTrue(object_body.is_object)
        self.assertEqual(object_body.value, {"enabled": True})
        self.assertTrue(array_body.valid)
        self.assertFalse(array_body.is_object)
        self.assertEqual(array_body.value, [1, 2])

    def test_malformed_json_is_distinct_from_valid_null(self) -> None:
        malformed = bodies.parse_json_body('{')
        null_body = bodies.parse_json_body('null')
        self.assertFalse(malformed.valid)
        self.assertIsNone(malformed.value)
        self.assertEqual(malformed.value_or({"fallback": True}), {"fallback": True})
        self.assertTrue(null_body.valid)
        self.assertIsNone(null_body.value)
        self.assertIsNone(null_body.value_or({"fallback": True}))

    def test_empty_object_mode_matches_legacy_lenient_parser(self) -> None:
        strict_empty = bodies.parse_json_body('')
        lenient_empty = bodies.parse_json_body('', empty_object=True)
        self.assertFalse(strict_empty.valid)
        self.assertTrue(lenient_empty.valid)
        self.assertEqual(lenient_empty.value, {})

    def test_lenient_mode_only_falls_back_for_malformed_json(self) -> None:
        malformed = bodies.parse_json_body('not-json', empty_object=True)
        valid_scalar = bodies.parse_json_body('42', empty_object=True)
        self.assertEqual(malformed.value_or({}), {})
        self.assertEqual(valid_scalar.value_or({}), 42)


if __name__ == "__main__":
    unittest.main()
