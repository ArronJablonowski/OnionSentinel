import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import portal_catalog_routes as routes  # noqa: E402


def load_portal():
    path = DASHBOARD / "report_portal.py"
    spec = importlib.util.spec_from_file_location("catalog_route_portal", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PortalCatalogRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.portal = load_portal()

    def test_exact_catalog_and_metric_routes_are_explicit(self) -> None:
        for path, operation in routes.CATALOG_EXACT_OPERATIONS.items():
            with self.subTest(path=path):
                route = routes.classify_catalog_route(path)
                self.assertEqual(route.operation, operation)
        self.assertTrue(
            routes.classify_catalog_route("/api/reports").requires_catalog_scan
        )
        self.assertTrue(
            routes.classify_catalog_route(
                "/metrics/portal-update"
            ).requires_catalog_scan
        )
        self.assertFalse(
            routes.classify_catalog_route(
                "/metrics/system-uptime"
            ).requires_catalog_scan
        )

    def test_static_aliases_take_precedence_over_open_report(self) -> None:
        forest = routes.classify_catalog_route(
            "/open/forest_room5_assets/floor%20plan.png"
        )
        qr = routes.classify_catalog_route("/open/qr_landing_source.pdf")
        self.assertEqual(forest.operation, "forest_asset")
        self.assertEqual(forest.asset_path, "floor plan.png")
        self.assertEqual(qr.operation, "qr_landing_source")

    def test_view_open_and_download_targets_are_decoded_once(self) -> None:
        view = routes.classify_catalog_route(
            "/view/report%20id/assets/chart%201.png"
        )
        opened = routes.classify_catalog_route("/open/report%20id/")
        downloaded = routes.classify_catalog_route("/download/report%20id/")
        self.assertEqual(view.operation, "view_report")
        self.assertEqual(view.report_id, "report id")
        self.assertEqual(view.asset_path, "assets/chart 1.png")
        self.assertEqual(opened.operation, "open_report")
        self.assertEqual(opened.report_id, "report id")
        self.assertEqual(downloaded.operation, "download_report")
        self.assertEqual(downloaded.report_id, "report id")

    def test_unknown_route_has_no_catalog_work(self) -> None:
        route = routes.classify_catalog_route("/not-a-route")
        self.assertIsNone(route.operation)
        self.assertFalse(route.requires_catalog_scan)

    def handler(self, path):
        handler = self.portal.PortalHandler.__new__(self.portal.PortalHandler)
        handler.path = path
        handler._send = mock.Mock(return_value="sent")
        return handler

    def test_unknown_and_ordinary_metric_routes_do_not_scan_catalog(self) -> None:
        with mock.patch.object(self.portal, "scan_reports") as scan_reports:
            unknown = self.handler("/not-a-route")
            self.assertEqual(unknown.do_GET(), "sent")
            self.assertEqual(
                unknown._send.call_args.args[0],
                self.portal.HTTPStatus.NOT_FOUND,
            )

            metric = self.handler("/metrics/system-uptime")
            with mock.patch.object(
                self.portal,
                "render_system_uptime_detail",
                return_value=b"metric",
            ) as render_metric:
                self.assertEqual(metric.do_GET(), "sent")
            render_metric.assert_called_once_with()
            scan_reports.assert_not_called()

    def test_catalog_index_is_the_only_index_route_that_scans(self) -> None:
        handler = self.handler("/api/reports")
        with mock.patch.object(
            self.portal, "scan_reports", return_value=[]
        ) as scan_reports:
            self.assertEqual(handler.do_GET(), "sent")
        scan_reports.assert_called_once_with()
        status, body = handler._send.call_args.args[:2]
        self.assertEqual(status, self.portal.HTTPStatus.OK)
        self.assertEqual(json.loads(body), [])

    def test_forest_asset_traversal_remains_forbidden_without_scan(self) -> None:
        handler = self.handler("/forest_room5_assets/../secret.txt")
        with mock.patch.object(self.portal, "scan_reports") as scan_reports:
            self.assertEqual(handler.do_GET(), "sent")
        scan_reports.assert_not_called()
        self.assertEqual(
            handler._send.call_args.args[0],
            self.portal.HTTPStatus.FORBIDDEN,
        )


if __name__ == "__main__":
    unittest.main()
