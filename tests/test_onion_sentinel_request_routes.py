from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD_DIR))
routes = importlib.import_module("onion_sentinel_request_routes")


class DashboardGetDispatchTests(unittest.TestCase):
    def handler(self, path: str, *, authenticated: bool = False):
        events: list[tuple[object, ...]] = []
        handler = SimpleNamespace(
            path=path,
            dashboard_root=Path("/dashboard"),
            _admin_authenticated=lambda: authenticated,
            _redirect=lambda target: events.append(("redirect", target)) or "redirect",
            _send=lambda *args: events.append(("send", *args)) or "send",
            _serve_file=lambda target: events.append(("file", target)) or "file",
        )
        return handler, events

    def context(self, events: list[tuple[object, ...]], *, controlled: bool = False):
        portal_handler = SimpleNamespace(
            do_GET=lambda handler: events.append(("soc", handler.path)) or "soc"
        )
        return SimpleNamespace(
            CONTROLLED_EVALUATION_MODE=controlled,
            APPLICATION_LOG_API_PATH="/api/application-logs",
            application_log_route_identifier=lambda path: (
                "onion-sentinel-application"
                if path == "/api/application-logs/onion-sentinel-application"
                else None
            ),
            ac_hunter_review=SimpleNamespace(
                deep_review_response=lambda **kwargs: (
                    events.append(("deep-review", kwargs)) or (200, {"ok": True})
                )
            ),
            render_login=lambda: b"login",
            render_admin_status=lambda: b"admin",
            is_soc_get_api=lambda path: path in {
                "/api/ac-hunter/deep-review",
                "/api/soc-alerts",
            },
            runtime=SimpleNamespace(PortalHandler=portal_handler),
            resolve_dashboard_target=lambda _root, raw_path: (
                Path("/dashboard/index.html") if raw_path == "/" else None
            ),
        )

    def test_controlled_mode_allows_only_the_exact_raw_health_target(self) -> None:
        for path, expected in (
            ("/healthz", "health"),
            ("/healthz?probe=1", "forbidden"),
            ("/api/soc-alerts", "forbidden"),
        ):
            with self.subTest(path=path):
                handler, events = self.handler(path)
                context = self.context(events, controlled=True)
                with (
                    mock.patch.object(routes, "_health", return_value="health") as health,
                    mock.patch.object(routes, "_json_error", return_value="forbidden") as error,
                ):
                    self.assertEqual(routes.do_get(handler, context), expected)
                self.assertEqual(health.call_count, int(expected == "health"))
                self.assertEqual(error.call_count, int(expected == "forbidden"))

    def test_api_dispatch_precedence_and_arguments_are_exact(self) -> None:
        cases = (
            ("/api/application-logs?ignored=1", None, "logs"),
            (
                "/api/application-logs/onion-sentinel-application?member=1",
                "onion-sentinel-application",
                "logs",
            ),
            ("/api/ac-hunter/deep-review", None, "json"),
            ("/api/soc-alerts?limit=10", None, "soc"),
        )
        for path, expected_log_id, expected in cases:
            with self.subTest(path=path):
                handler, events = self.handler(path, authenticated=True)
                context = self.context(events)
                with (
                    mock.patch.object(routes, "_application_logs", return_value="logs") as logs,
                    mock.patch.object(routes, "_json_response", return_value="json") as response,
                ):
                    self.assertEqual(routes.do_get(handler, context), expected)
                if expected == "logs":
                    logs.assert_called_once()
                    self.assertEqual(logs.call_args.args[3], expected_log_id)
                    self.assertEqual(logs.call_args.args[2].query, path.partition("?")[2])
                else:
                    logs.assert_not_called()
                if expected == "json":
                    self.assertEqual(events, [("deep-review", {"force_refresh": False})])
                    response.assert_called_once_with(
                        handler, 200, {"ok": True}, indent=2
                    )

    def test_admin_static_and_not_found_dispatch_preserve_responses(self) -> None:
        cases = (
            ("/admin/login", True, [("redirect", "/admin")], "redirect"),
            ("/admin/login", False, [("send", 200, b"login")], "send"),
            ("/admin", False, [("redirect", "/admin/login")], "redirect"),
            ("/admin", True, [("send", 200, b"admin")], "send"),
            ("/", False, [("file", Path("/dashboard/index.html"))], "file"),
            (
                "/unknown",
                False,
                [("send", 404, b"Not found", "text/plain; charset=utf-8")],
                "send",
            ),
        )
        for path, authenticated, expected_events, expected in cases:
            with self.subTest(path=path, authenticated=authenticated):
                handler, events = self.handler(path, authenticated=authenticated)
                context = self.context(events)
                self.assertEqual(routes.do_get(handler, context), expected)
                self.assertEqual(events, expected_events)


if __name__ == "__main__":
    unittest.main()
