#!/usr/bin/env python3
"""Direct contracts for static and report catalog delivery."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_catalog_delivery import (  # noqa: E402
    CatalogDeliveryCallbacks,
    deliver_catalog_route,
)
from portal_catalog_routes import classify_catalog_route  # noqa: E402


@dataclass
class Report:
    rid: str
    path: Path


class CatalogDeliveryTests(unittest.TestCase):
    def deliver(self, path: str, root: Path, reports=None):
        calls: list[str] = []
        result = deliver_catalog_route(
            classify_catalog_route(path),
            forest_asset_root=root / "forest",
            qr_landing_source=root / "qr.pdf",
            callbacks=CatalogDeliveryCallbacks(
                lambda: calls.append("reports") or (reports or {}),
            ),
        )
        return result, calls

    def test_unknown_route_is_declined_without_catalog_scan(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result, calls = self.deliver("/unknown", Path(raw))
        self.assertIsNone(result)
        self.assertEqual(calls, [])

    def test_static_aliases_do_not_scan_reports_and_preserve_mime(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "forest").mkdir()
            (root / "forest" / "page.html").write_text("<h1>page</h1>")
            (root / "qr.pdf").write_bytes(b"pdf")
            forest, forest_calls = self.deliver(
                "/forest_room5_assets/page.html", root,
            )
            qr, qr_calls = self.deliver("/qr_landing_source.pdf", root)
        self.assertEqual(forest.content_type, "text/html; charset=utf-8")
        self.assertEqual(qr.content_type, "application/pdf")
        self.assertEqual(forest_calls + qr_calls, [])

    def test_forest_and_report_asset_traversal_are_forbidden(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report_path = root / "reports" / "index.html"
            report_path.parent.mkdir()
            report_path.write_text("index")
            forest, _ = self.deliver(
                "/forest_room5_assets/../secret.txt", root,
            )
            report, _ = self.deliver(
                "/view/report-1/../secret.txt", root,
                {"report-1": Report("report-1", report_path)},
            )
        self.assertEqual(forest.status, 403)
        self.assertEqual(report.status, 403)

    def test_missing_report_and_asset_have_distinct_not_found_messages(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            missing, _ = self.deliver("/view/missing/", root)
            report, _ = self.deliver(
                "/view/report-1/missing.png", root,
                {"report-1": Report("report-1", root / "index.html")},
            )
        self.assertEqual(missing.body, b"Report not found")
        self.assertEqual(report.body, b"Asset not found")

    def test_open_redirect_and_download_headers_preserve_report_identity(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report_path = root / "Report One.html"
            report_path.write_text("report")
            reports = {"report-1": Report("report-1", report_path)}
            opened, _ = self.deliver("/open/report-1/", root, reports)
            downloaded, _ = self.deliver("/download/report-1/", root, reports)
        self.assertEqual(opened.redirect, "/view/report-1/")
        self.assertEqual(downloaded.body, b"report")
        self.assertEqual(downloaded.content_type, "text/html")
        self.assertEqual(
            downloaded.headers["Content-Disposition"],
            "attachment; filename=Report%20One.html",
        )

    def test_download_read_failure_preserves_internal_error_contract(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            result, _ = self.deliver(
                "/download/report-1/", root,
                {"report-1": Report("report-1", root / "missing.html")},
            )
        self.assertEqual(result.status, 500)
        self.assertIn(b"No such file", result.body)


if __name__ == "__main__":
    unittest.main()
