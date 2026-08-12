from __future__ import annotations

import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_query as query


class SoftwareInventoryQueryFilterArchitectureTests(unittest.TestCase):
    def test_public_signature_defaults_types_and_key_order_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(query.parse_filters)),
            "(query: 'dict[str, list[str]] | None') -> 'dict[str, object]'",
        )
        expected = {
            "limit": 100,
            "offset": 0,
            "search": "",
            "tier": "all",
            "confidence": "all",
            "freshness": "all",
            "platform": "all",
            "window": "30d",
            "sort": "last_seen",
            "direction": "desc",
        }
        self.assertEqual(query.parse_filters(None), expected)
        self.assertEqual(query.parse_filters({}), expected)
        self.assertEqual(list(query.parse_filters(None)), list(expected))
        self.assertTrue(callable(query._one))

    def test_all_valid_values_preserve_exact_normalization(self) -> None:
        result = query.parse_filters(
            {
                "limit": [" 250 "],
                "offset": ["50000"],
                "search": ["  FiRe Fox  "],
                "tier": [" INSTALLED "],
                "confidence": [" HIGH "],
                "freshness": [" CURRENT "],
                "platform": ["  MacOS  "],
                "window": [" 24H "],
                "sort": [" PRODUCT "],
                "direction": [" ASC "],
            }
        )
        self.assertEqual(
            result,
            {
                "limit": 250,
                "offset": 50000,
                "search": "FiRe Fox",
                "tier": "installed",
                "confidence": "high",
                "freshness": "current",
                "platform": "MacOS",
                "window": "24h",
                "sort": "product",
                "direction": "asc",
            },
        )

    def test_unknown_and_repeated_parameter_precedence_is_exact(self) -> None:
        cases = (
            (
                {"zeta": ["x"], "alpha": ["x"], "limit": ["bad"]},
                "unsupported query parameter: alpha",
            ),
            (
                {"limit": ["1", "2"]},
                "limit and offset must be integers",
            ),
            (
                {"offset": ["1", "2"]},
                "limit and offset must be integers",
            ),
            ({"search": ["x", "y"]}, "search must appear once"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ) as caught:
                    query.parse_filters(value)
                if message == "limit and offset must be integers":
                    self.assertIsInstance(
                        caught.exception.__cause__,
                        query.InventoryQueryError,
                    )

    def test_integer_conversion_range_and_cause_are_exact(self) -> None:
        for value in ("bad", "1.5", ""):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError,
                    "^limit and offset must be integers$",
                ) as caught:
                    query.parse_filters({"limit": [value]})
                self.assertIsInstance(caught.exception.__cause__, ValueError)
        cases = (
            ({"limit": ["0"]}, "limit must be between 1 and 250"),
            ({"limit": ["251"]}, "limit must be between 1 and 250"),
            ({"offset": ["-1"]}, "offset must be between 0 and 50000"),
            ({"offset": ["50001"]}, "offset must be between 0 and 50000"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ) as caught:
                    query.parse_filters(value)
                self.assertIsNone(caught.exception.__cause__)

    def test_search_and_platform_boundaries_are_exact(self) -> None:
        self.assertEqual(
            query.parse_filters({"search": ["x" * 253]})["search"],
            "x" * 253,
        )
        self.assertEqual(
            query.parse_filters({"platform": ["P" * 160]})["platform"],
            "P" * 160,
        )
        cases = (
            ({"search": ["x" * 254]}, "search is invalid"),
            ({"search": ["safe\x1funsafe"]}, "search is invalid"),
            ({"platform": [" "]}, "platform is invalid"),
            ({"platform": ["P" * 161]}, "platform is invalid"),
            ({"platform": ["safe\x00unsafe"]}, "platform is invalid"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ):
                    query.parse_filters(value)

    def test_enum_error_order_and_messages_are_exact(self) -> None:
        cases = (
            ({"tier": ["bad"]}, "tier is unsupported"),
            ({"confidence": ["bad"]}, "confidence is unsupported"),
            ({"freshness": ["bad"]}, "freshness is unsupported"),
            ({"window": ["bad"]}, "window is unsupported"),
            ({"sort": ["bad"]}, "sort is unsupported"),
            ({"direction": ["bad"]}, "direction is unsupported"),
            (
                {"tier": ["bad"], "confidence": ["bad"]},
                "tier is unsupported",
            ),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ):
                    query.parse_filters(value)


if __name__ == "__main__":
    unittest.main()
