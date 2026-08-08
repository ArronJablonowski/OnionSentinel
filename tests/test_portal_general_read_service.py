#!/usr/bin/env python3
"""Contracts for general portal read dispatch."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_general_read_service import (  # noqa: E402
    GeneralReadCallbacks,
    dispatch_general_read,
)


class GeneralReadServiceTests(unittest.TestCase):
    def callbacks(self, calls: list[tuple[str, object]]) -> GeneralReadCallbacks:
        return GeneralReadCallbacks(
            home=lambda: calls.append(("home", None)) or b"home",
            health=lambda: calls.append(("health", None)) or {"ok": True},
            resource_favorites=lambda: calls.append(("favorites", None)) or ["one"],
            system_health_beacons=lambda query: calls.append(("beacons", query)) or {"items": []},
            asset_inventory=lambda query: calls.append(("assets", query)) or (206, {"assets": []}),
            dhcp_asset_discovery=lambda: calls.append(("dhcp", None)) or (503, {"ok": False}),
            software_inventory=lambda query: calls.append(("software", query)) or (200, {"software": []}),
            cti_program=lambda: calls.append(("cti", None)) or (200, {"sources": []}),
        )

    def dispatch(self, operation: str | None, query=None):
        calls: list[tuple[str, object]] = []
        result = dispatch_general_read(
            operation,
            query=query or {},
            callbacks=self.callbacks(calls),
        )
        return result, calls

    def test_unknown_operation_is_declined_without_callbacks(self) -> None:
        result, calls = self.dispatch("soc_alerts")
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_home_is_an_encoded_html_response(self) -> None:
        result, calls = self.dispatch("home")
        self.assertEqual(result.status, 200)
        self.assertEqual(result.payload, b"home")
        self.assertEqual(result.content_type, "text/html; charset=utf-8")
        self.assertTrue(result.encoded)
        self.assertEqual(calls, [("home", None)])

    def test_health_and_favorites_preserve_public_shapes(self) -> None:
        health, health_calls = self.dispatch("health")
        favorites, favorites_calls = self.dispatch("resource_favorites")
        self.assertEqual(health.payload, {"ok": True})
        self.assertEqual(favorites.payload, {"ok": True, "favorites": ["one"]})
        self.assertEqual(health_calls, [("health", None)])
        self.assertEqual(favorites_calls, [("favorites", None)])

    def test_query_reads_receive_the_original_query_once(self) -> None:
        query = {"limit": ["17"]}
        for operation, callback_name in (
            ("system_health_beacons", "beacons"),
            ("asset_inventory", "assets"),
            ("software_inventory", "software"),
        ):
            with self.subTest(operation=operation):
                result, calls = self.dispatch(operation, query)
                self.assertIsNotNone(result)
                self.assertEqual(calls, [(callback_name, query)])

    def test_callback_statuses_are_not_normalized(self) -> None:
        assets, _ = self.dispatch("asset_inventory")
        dhcp, _ = self.dispatch("dhcp_asset_discovery")
        self.assertEqual(assets.status, 206)
        self.assertEqual(dhcp.status, 503)

    def test_cti_read_uses_only_the_cti_callback(self) -> None:
        result, calls = self.dispatch("cti_program")
        self.assertEqual(result.payload, {"sources": []})
        self.assertEqual(calls, [("cti", None)])


if __name__ == "__main__":
    unittest.main()
