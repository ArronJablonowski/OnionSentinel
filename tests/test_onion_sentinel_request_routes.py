from __future__ import annotations

import importlib
import io
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
            is_application_log_get_api=lambda path: path.startswith(
                "/api/application-logs"
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

    def test_enforcement_admin_get_uses_the_versioned_session_boundary(self):
        handler, events = self.handler("/admin/login", authenticated=True)
        context = self.context(events)
        context.ACCESS_RUNTIME = SimpleNamespace(
            admin_authenticated=lambda _handler: False
        )
        self.assertEqual(routes.do_get(handler, context), "send")
        self.assertEqual(events, [("send", 200, b"login")])

        handler, events = self.handler("/admin", authenticated=True)
        context = self.context(events)
        context.ACCESS_RUNTIME = SimpleNamespace(
            admin_authenticated=lambda _handler: False
        )
        self.assertEqual(routes.do_get(handler, context), "redirect")
        self.assertEqual(events, [("redirect", "/admin/login")])

    def test_rbac_read_denies_evidence_before_api_or_static_dispatch(self):
        for path, expected, blocked_event in (
            ("/api/soc-alerts", "json", ("soc", "/api/soc-alerts")),
            ("/", "redirect", ("file", Path("/dashboard/index.html"))),
        ):
            with self.subTest(path=path):
                handler, events = self.handler(path)
                context = self.context(events)
                context.ACCESS_RUNTIME = SimpleNamespace(
                    read_authenticated=lambda _handler: False
                )
                with mock.patch.object(
                    routes, "_json_response", return_value="json"
                ) as response:
                    self.assertEqual(routes.do_get(handler, context), expected)
                self.assertNotIn(blocked_event, events)
                if path.startswith("/api/"):
                    response.assert_called_once_with(
                        handler,
                        401,
                        {
                            "ok": False,
                            "authentication_required": True,
                            "error": "Sign-in is required to view evidence.",
                        },
                    )
                else:
                    self.assertEqual(events, [("redirect", "/admin/login")])

        handler, events = self.handler("/unknown")
        context = self.context(events)
        context.ACCESS_RUNTIME = SimpleNamespace(
            read_authenticated=lambda _handler: False
        )
        self.assertEqual(routes.do_get(handler, context), "send")
        self.assertEqual(
            events,
            [("send", 404, b"Not found", "text/plain; charset=utf-8")],
        )

    def test_rbac_head_denies_known_evidence_without_changing_unknown_404(self):
        for path, expected in (("/api/soc-alerts", 401), ("/unknown", 404)):
            with self.subTest(path=path):
                events = []
                handler = SimpleNamespace(
                    path=path,
                    dashboard_root=Path("/dashboard"),
                    send_response=lambda status: events.append(("status", status)),
                    send_header=lambda key, value: events.append(
                        ("header", key, value)
                    ),
                    end_headers=lambda: events.append(("end",)),
                    _security_headers=lambda: {},
                )
                context = self.context(events)
                context.ACCESS_RUNTIME = SimpleNamespace(
                    read_authenticated=lambda _handler: False
                )
                routes.do_head(handler, context)
                self.assertEqual(events[0], ("status", expected))


class DedicatedAdminSessionBridgeTests(unittest.TestCase):
    @staticmethod
    def handler(form: bytes):
        events: list[tuple[object, ...]] = []
        handler = SimpleNamespace(
            headers={"Content-Length": str(len(form))},
            rfile=io.BytesIO(form),
            client_address=("127.0.0.1", 41414),
            _admin_session_id=lambda: (
                events.append(("legacy-session-id",)) or "legacy-session"
            ),
            _redirect=lambda *args: events.append(("redirect", *args)) or "redirect",
            _send=lambda *args: events.append(("send", *args)) or "send",
        )
        return handler, events

    @staticmethod
    def context(events: list[tuple[object, ...]]):
        runtime = SimpleNamespace(
            ensure_admin_token=lambda: (
                events.append(("validate-form-token",)) or "form-token"
            ),
            admin_password_configured=lambda: (
                events.append(("password-configured",)) or True
            ),
            verify_admin_password=lambda password: (
                events.append(("verify-password", password)) or True
            ),
            create_admin_session=lambda client: (
                events.append(("create-legacy", client)) or "legacy-session"
            ),
            destroy_admin_session=lambda session_id: events.append(
                ("destroy-legacy", session_id)
            ),
        )
        access_runtime = SimpleNamespace(
            password_configured=lambda: (
                events.append(("password-configured",)) or True
            ),
            verify_password=lambda password: (
                events.append(("verify-password", password)) or True
            ),
            create_session=lambda handler, session_id: (
                events.append(("create-target", session_id)) or "csrf-token"
            ),
            destroy_session=lambda session_id: events.append(
                ("destroy-target", session_id)
            ),
            login_cookie_headers=lambda session_id, csrf_token: (
                events.append(("login-cookies", session_id, csrf_token))
                or ["legacy-cookie", "csrf-cookie"]
            ),
            logout_cookie_headers=lambda: (
                events.append(("logout-cookies",))
                or ["expired-legacy-cookie", "expired-csrf-cookie"]
            ),
        )
        return SimpleNamespace(
            runtime=runtime,
            ACCESS_RUNTIME=access_runtime,
            render_login=lambda *args: b"login",
        )

    def test_login_dual_writes_after_legacy_authentication(self) -> None:
        handler, events = self.handler(b"token=form-token&password=secret")
        context = self.context(events)

        self.assertEqual(
            routes._admin_post(handler, context, "/admin/login"),
            "redirect",
        )
        self.assertEqual(
            events,
            [
                ("validate-form-token",),
                ("password-configured",),
                ("verify-password", "secret"),
                ("create-legacy", "127.0.0.1"),
                ("create-target", "legacy-session"),
                ("login-cookies", "legacy-session", "csrf-token"),
                (
                    "redirect",
                    "/admin",
                    {"Set-Cookie": ["legacy-cookie", "csrf-cookie"]},
                ),
            ],
        )

    def test_logout_revokes_legacy_and_target_before_expiring_cookies(self) -> None:
        handler, events = self.handler(b"token=form-token")
        context = self.context(events)

        self.assertEqual(
            routes._admin_post(handler, context, "/admin/logout"),
            "redirect",
        )
        self.assertEqual(
            events,
            [
                ("validate-form-token",),
                ("legacy-session-id",),
                ("destroy-legacy", "legacy-session"),
                ("destroy-target", "legacy-session"),
                ("logout-cookies",),
                (
                    "redirect",
                    "/admin/login",
                    {
                        "Set-Cookie": [
                            "expired-legacy-cookie",
                            "expired-csrf-cookie",
                        ]
                    },
                ),
            ],
        )

    def test_enforcement_login_rolls_back_legacy_session_when_target_creation_fails(self):
        handler, events = self.handler(b"token=form-token&password=secret")
        context = self.context(events)
        context.ACCESS_RUNTIME.session_required = True
        context.ACCESS_RUNTIME.create_session = lambda _handler, session_id: (
            events.append(("create-target-failed", session_id)) or None
        )

        self.assertEqual(
            routes._admin_post(handler, context, "/admin/login"),
            "send",
        )
        self.assertEqual(
            events[-3:],
            [
                ("create-target-failed", "legacy-session"),
                ("destroy-legacy", "legacy-session"),
                ("send", 503, b"login"),
            ],
        )

    def test_access_denial_has_stable_json_and_form_responses(self):
        handler, events = self.handler(b"")
        context = self.context(events)
        admission = SimpleNamespace(
            status=401,
            reason="unauthenticated",
            json_request=True,
        )
        with mock.patch.object(
            routes, "_json_response", return_value="json"
        ) as response:
            self.assertEqual(
                routes.send_access_denial(handler, context, admission),
                "json",
            )
        response.assert_called_once_with(
            handler,
            401,
            {
                "ok": False,
                "authentication_required": True,
                "error": "Administrator sign-in is required.",
                "reason": "unauthenticated",
            },
        )

        admission = SimpleNamespace(
            status=503,
            reason="audit_precommit_failed",
            json_request=False,
        )
        self.assertEqual(
            routes.send_access_denial(handler, context, admission),
            "send",
        )
        self.assertEqual(events[-1], ("send", 503, b"login"))


if __name__ == "__main__":
    unittest.main()
