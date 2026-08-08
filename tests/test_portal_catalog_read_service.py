#!/usr/bin/env python3
"""Direct contracts for catalog index and metric dispatch."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_catalog_read_service import (  # noqa: E402
    CatalogReadCallbacks,
    dispatch_catalog_read,
)
from portal_catalog_routes import classify_catalog_route  # noqa: E402


@dataclass
class Report:
    rid: str = "report-1"
    title: str = "Report One"
    rel: str = "reports/one.html"
    category: str = "Reports"
    mtime: float = 123.0
    size: int = 456


def callbacks(calls: list[str]) -> CatalogReadCallbacks:
    return CatalogReadCallbacks(
        scan_reports=lambda: calls.append("scan") or [Report()],
        render_system_uptime=lambda: calls.append("metric") or b"metric",
        render_updates=lambda: b"updates",
        render_macos_updates=lambda: b"macos",
        render_hermes_backups=lambda: b"backups",
        render_local_disk=lambda: b"disk",
        render_portal_update=lambda reports: (
            calls.append(f"portal:{len(reports)}") or b"portal"
        ),
    )


class CatalogReadServiceTests(unittest.TestCase):
    def test_unknown_and_asset_routes_are_declined_without_callbacks(self) -> None:
        for path in ("/unknown", "/view/report-1/"):
            calls: list[str] = []
            result = dispatch_catalog_read(
                classify_catalog_route(path), callbacks(calls),
            )
            self.assertIsNone(result)
            self.assertEqual(calls, [])

    def test_catalog_index_scans_once_and_projects_public_fields(self) -> None:
        calls: list[str] = []
        result = dispatch_catalog_read(
            classify_catalog_route("/api/reports"), callbacks(calls),
        )
        self.assertEqual(calls, ["scan"])
        self.assertEqual(result.payload[0], {
            "id": "report-1", "title": "Report One",
            "path": "reports/one.html", "category": "Reports",
            "mtime": 123.0, "size": 456,
        })
        self.assertFalse(result.encoded)

    def test_ordinary_metric_does_not_scan_catalog(self) -> None:
        calls: list[str] = []
        result = dispatch_catalog_read(
            classify_catalog_route("/metrics/system-uptime"), callbacks(calls),
        )
        self.assertEqual(calls, ["metric"])
        self.assertEqual(result.payload, b"metric")
        self.assertTrue(result.encoded)

    def test_portal_update_scans_once_and_renders_snapshot(self) -> None:
        calls: list[str] = []
        result = dispatch_catalog_read(
            classify_catalog_route("/metrics/portal-update"), callbacks(calls),
        )
        self.assertEqual(calls, ["scan", "portal:1"])
        self.assertEqual(result.payload, b"portal")


if __name__ == "__main__":
    unittest.main()
