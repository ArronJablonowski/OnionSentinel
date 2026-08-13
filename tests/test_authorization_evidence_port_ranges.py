"""Characterization for canonical authorization destination-port ranges."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.conclusions import authorization_evidence


class AuthorizationEvidencePortRangesTests(unittest.TestCase):
    @staticmethod
    def invoke(value):
        return authorization_evidence._port_ranges(
            {"destination_port_ranges": value}
        )

    def test_container_and_twenty_range_limit_are_exact(self) -> None:
        for value in (None, "1-2", ((1, 2),), {"range": [1, 2]}):
            with self.subTest(value=value):
                self.assertIsNone(self.invoke(value))
        self.assertEqual(self.invoke([]), [])
        twenty = [[index, index] for index in range(1, 21)]
        self.assertEqual(self.invoke(twenty), twenty)
        self.assertIsNone(self.invoke(twenty + [[21, 21]]))
        self.assertIsNone(authorization_evidence._port_ranges({}))

    def test_each_range_must_be_an_exact_two_item_list(self) -> None:
        for item in (
            None,
            "1-2",
            (1, 2),
            [1],
            [1, 2, 3],
            {"lower": 1, "upper": 2},
        ):
            with self.subTest(item=item):
                self.assertIsNone(self.invoke([item]))

    def test_integer_and_boolean_admission_is_exact(self) -> None:
        self.assertEqual(self.invoke([[1, 65535]]), [[1, 65535]])
        for item in (
            [True, 2],
            [1, False],
            [1.0, 2],
            [1, 2.0],
            ["1", 2],
            [1, "2"],
        ):
            with self.subTest(item=item):
                self.assertIsNone(self.invoke([item]))

    def test_bounds_and_order_are_fail_closed(self) -> None:
        for item in (
            [0, 1],
            [-1, 1],
            [1, 0],
            [65536, 65536],
            [1, 65536],
            [2, 1],
        ):
            with self.subTest(item=item):
                self.assertIsNone(self.invoke([item]))
        self.assertEqual(self.invoke([[1, 1], [443, 443], [8000, 9000]]), [[1, 1], [443, 443], [8000, 9000]])

    def test_duplicate_rejection_and_order_preservation_are_exact(self) -> None:
        self.assertIsNone(self.invoke([[1, 2], [1, 2]]))
        self.assertEqual(
            self.invoke([[8000, 9000], [1, 2], [443, 443]]),
            [[8000, 9000], [1, 2], [443, 443]],
        )

    def test_result_copies_each_range_without_mutating_input(self) -> None:
        first = [1, 2]
        second = [443, 443]
        source = [first, second]
        result = self.invoke(source)
        self.assertEqual(result, source)
        self.assertIsNot(result, source)
        self.assertIsNot(result[0], first)
        self.assertIsNot(result[1], second)
        self.assertEqual(source, [[1, 2], [443, 443]])


if __name__ == "__main__":
    unittest.main()
