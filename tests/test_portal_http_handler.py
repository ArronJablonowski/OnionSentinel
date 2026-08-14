"""Behavior contracts for the report-portal HTTP compatibility adapter."""
from __future__ import annotations

import importlib
import io
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

adapter = importlib.import_module("portal_http_handler")


class _Headers:
    def __init__(self, values: dict[str, object], trace: list[tuple[str, str]]) -> None:
        self.values = values
        self.trace = trace

    def get(self, name: str) -> object:
        self.trace.append(("header", name))
        return self.values.get(name)


class _RecordingBody(io.BytesIO):
    def __init__(self, value: bytes, trace: list[tuple[object, ...]]) -> None:
        super().__init__(value)
        self.trace = trace

    def read(self, size: int = -1) -> bytes:
        self.trace.append(("read", size))
        return super().read(size)


class _PostHarness:
    def __init__(
        self,
        *,
        intake: object,
        json_write: object = None,
        admin_form: object = None,
        body: bytes = b"payload",
        intake_auth: bool = False,
    ) -> None:
        self.trace: list[tuple[object, ...]] = []
        self.callback_args: tuple[object, ...] = ()
        self.intake = intake
        self.json_write = json_write
        self.admin_form = admin_form
        self.intake_auth = intake_auth
        self.handler = self._build_handler(body)
        self.runtime = self._build_runtime()

    def _build_handler(self, body: bytes) -> object:
        handler = SimpleNamespace(
            path="/submitted?mode=1",
            headers=_Headers({"Content-Length": "7"}, self.trace),
            rfile=_RecordingBody(body, self.trace),
            client_address=("192.0.2.44", 4312),
        )
        handler._admin_session_id = self._recording_value("session", "session-id")
        handler._admin_authenticated = self._recording_value("authenticated", True)
        handler._send = self._recording_call("send", "sent")
        handler._redirect = self._recording_call("redirect", "redirected")
        return handler

    def _recording_value(self, event: str, value: object):
        def callback():
            self.trace.append((event,))
            return value

        return callback

    def _recording_call(self, event: str, result: object):
        def callback(*args: object, **kwargs: object):
            self.trace.append((event, args, kwargs))
            return result

        return callback

    def _build_runtime(self) -> object:
        runtime = SimpleNamespace(
            CTI_PROGRAM_API_PATH="/cti-program",
            SOC_SETTINGS_PROMPT_API_PATHS=("/prompt-a", "/prompt-b"),
            ASSET_INVENTORY_ADMIN_WRITE_REQUIRED=True,
            cti_program=SimpleNamespace(MAX_FILE_BYTES=4096),
        )
        runtime.urlparse = self._urlparse
        runtime.classify_post_route = self._classify
        runtime.prepare_post_intake = self._prepare_intake
        runtime.portal_json_write_callbacks = self._json_callbacks
        runtime.dispatch_json_write = self._dispatch_json
        runtime.AdminFormCallbacks = self._admin_callbacks
        runtime.prepare_admin_form = self._prepare_admin
        runtime.json = SimpleNamespace(dumps=self._json_dumps)
        runtime.render_admin_dashboard = self._rendering("dashboard")
        runtime.render_admin_login = self._rendering("login")
        for name in self._admin_callback_names():
            setattr(runtime, name, self._recording_value(name, name))
        return runtime

    @staticmethod
    def _admin_callback_names() -> tuple[str, ...]:
        return (
            "ensure_admin_token", "admin_password_configured",
            "verify_admin_password", "create_admin_session",
            "admin_session_cookie_header", "destroy_admin_session",
            "expired_admin_session_cookie_header", "start_admin_action",
        )

    def _urlparse(self, value: str) -> object:
        self.trace.append(("urlparse", value))
        return SimpleNamespace(path="/submitted")

    def _classify(self, path: str, **kwargs: object) -> str:
        self.trace.append(("classify", path, kwargs))
        return "admin-route"

    def _prepare_intake(self, route: str, length: object, **kwargs: object) -> object:
        auth = kwargs.pop("admin_authenticated")
        self.trace.append(("intake", route, length, kwargs))
        if self.intake_auth:
            self.trace.append(("intake-auth-result", auth()))
        return self.intake

    def _json_callbacks(self, handler: object) -> str:
        self.trace.append(("json-callbacks", handler is self.handler))
        return "json-callback-bundle"

    def _dispatch_json(self, route: str, raw: str, **kwargs: object) -> object:
        self.trace.append(("dispatch-json", route, raw, kwargs))
        return self.json_write

    def _admin_callbacks(self, *args: object) -> str:
        self.callback_args = args
        self.trace.append(("admin-callbacks", len(args)))
        return "admin-callback-bundle"

    def _prepare_admin(self, route: str, raw: str, **kwargs: object) -> object:
        auth = kwargs.pop("admin_authenticated")
        self.trace.append(("prepare-admin", route, raw, kwargs))
        self.trace.append(("admin-auth-result", auth()))
        return self.admin_form

    def _json_dumps(self, payload: object, **kwargs: object) -> str:
        self.trace.append(("json-dumps", payload, kwargs))
        return "{\n  encoded\n}"

    def _rendering(self, view: str):
        def render(message: str, error: bool) -> bytes:
            self.trace.append(("render", view, message, error))
            return f"{view}:{message}:{error}".encode()

        return render


class PortalHttpHandlerTests(unittest.TestCase):
    def test_soc_review_write_authorization_matrix_and_trace_are_exact(self) -> None:
        cases = (
            ({}, False, ("Content-Type",), ()),
            ({"Content-Type": "text/plain"}, False, ("Content-Type",), ()),
            (
                {"Content-Type": " application/json", "X-Onion-Sentinel-Request": "dashboard"},
                False,
                ("Content-Type",),
                (),
            ),
            (
                {"Content-Type": "application/json", "X-Onion-Sentinel-Request": "Dashboard"},
                False,
                ("Content-Type", "X-Onion-Sentinel-Request"),
                (),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Sec-Fetch-Site": "cross-site",
                },
                False,
                ("Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site"),
                (),
            ),
            (
                {
                    "Content-Type": "Application/JSON; Charset=UTF-8",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Sec-Fetch-Site": " SAME-ORIGIN ",
                },
                True,
                ("Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site", "Origin"),
                (),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "   ",
                },
                True,
                ("Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site", "Origin"),
                (),
            ),
            (
                {
                    "Content-Type": "application/json-patch+json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "HTTPS://Portal.Example:8766",
                    "Host": " PORTAL.EXAMPLE:8766 ",
                },
                True,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("HTTPS://Portal.Example:8766",),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "ftp://portal.example",
                    "Host": "portal.example",
                },
                False,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("ftp://portal.example",),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "/relative",
                    "Host": "portal.example",
                },
                False,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("/relative",),
            ),
            (
                {
                    "Content-Type": "application/json",
                    "X-Onion-Sentinel-Request": "dashboard",
                    "Origin": "https://portal.example",
                    "Host": "other.example",
                },
                False,
                (
                    "Content-Type", "X-Onion-Sentinel-Request", "Sec-Fetch-Site",
                    "Origin", "Host",
                ),
                ("https://portal.example",),
            ),
        )
        for values, expected, expected_headers, expected_origins in cases:
            with self.subTest(values=values):
                trace: list[tuple[str, str]] = []

                def parse_origin(value: str):
                    trace.append(("urlparse", value))
                    return urlparse(value)

                handler = SimpleNamespace(headers=_Headers(values, trace))
                runtime = SimpleNamespace(urlparse=parse_origin)

                result = adapter._soc_review_write_authorized(handler, runtime)

                self.assertIs(result, expected)
                self.assertEqual(
                    tuple(value for kind, value in trace if kind == "header"),
                    expected_headers,
                )
                self.assertEqual(
                    tuple(value for kind, value in trace if kind == "urlparse"),
                    expected_origins,
                )

    def test_post_rejections_short_circuit_with_exact_rendering(self) -> None:
        cases = (
            ("dashboard", "dash rejected", 401, "dashboard:dash rejected:True"),
            ("login", "login rejected", 403, "login:login rejected:True"),
        )
        for view, message, status, rendered in cases:
            with self.subTest(view=view):
                intake = SimpleNamespace(
                    ready=False, view=view, message=message, status=status,
                )
                harness = _PostHarness(intake=intake)

                result = adapter._do_post(harness.handler, harness.runtime)

                self.assertEqual(result, "sent")
                self.assertEqual(harness.trace[-2], ("render", view, message, True))
                self.assertEqual(
                    harness.trace[-1],
                    ("send", (status, rendered.encode()), {}),
                )
                self.assertFalse(any(event[0] == "read" for event in harness.trace))
                self.assertFalse(any(event[0] == "dispatch-json" for event in harness.trace))

    def test_post_raw_rejection_preserves_body_and_content_type(self) -> None:
        intake = SimpleNamespace(
            ready=False,
            view=None,
            status=413,
            body=b"too large",
            content_type="text/plain; charset=utf-8",
        )
        harness = _PostHarness(intake=intake, intake_auth=True)

        result = adapter._do_post(harness.handler, harness.runtime)

        self.assertEqual(result, "sent")
        self.assertIn(("intake-auth-result", True), harness.trace)
        self.assertEqual(
            harness.trace[-1],
            ("send", (413, b"too large", "text/plain; charset=utf-8"), {}),
        )
        self.assertFalse(any(event[0] == "read" for event in harness.trace))

    def test_post_json_write_reads_and_serializes_exactly_once(self) -> None:
        intake = SimpleNamespace(ready=True, length=7)
        json_write = SimpleNamespace(status=202, payload={"saved": True})
        harness = _PostHarness(
            intake=intake, json_write=json_write, body=b"ab\xffrest-extra",
        )

        result = adapter._do_post(harness.handler, harness.runtime)

        self.assertEqual(result, "sent")
        self.assertIn(("read", 7), harness.trace)
        self.assertIn(("json-callbacks", True), harness.trace)
        self.assertIn(
            (
                "dispatch-json", "admin-route", "ab\ufffdrest",
                {
                    "asset_admin_required": True,
                    "callbacks": "json-callback-bundle",
                },
            ),
            harness.trace,
        )
        self.assertEqual(
            harness.trace[-2],
            ("json-dumps", {"saved": True}, {"indent": 2}),
        )
        self.assertEqual(
            harness.trace[-1],
            (
                "send",
                (202, b"{\n  encoded\n}", "application/json; charset=utf-8"),
                {},
            ),
        )
        self.assertFalse(any(event[0] == "prepare-admin" for event in harness.trace))

    def test_post_admin_redirect_preserves_callback_order_and_arguments(self) -> None:
        intake = SimpleNamespace(ready=True, length=7)
        admin_form = SimpleNamespace(
            redirect="/admin/jobs/7", headers={"Set-Cookie": "token"}, status=303,
        )
        harness = _PostHarness(intake=intake, admin_form=admin_form)

        result = adapter._do_post(harness.handler, harness.runtime)

        expected_callbacks = (
            harness.runtime.ensure_admin_token,
            harness.runtime.admin_password_configured,
            harness.runtime.verify_admin_password,
            harness.runtime.create_admin_session,
            harness.runtime.admin_session_cookie_header,
            harness.handler._admin_session_id,
            harness.runtime.destroy_admin_session,
            harness.runtime.expired_admin_session_cookie_header,
            harness.runtime.start_admin_action,
        )
        self.assertEqual(result, "redirected")
        self.assertEqual(harness.callback_args, expected_callbacks)
        self.assertIn(
            (
                "prepare-admin", "admin-route", "payload",
                {
                    "client_ip": "192.0.2.44",
                    "callbacks": "admin-callback-bundle",
                },
            ),
            harness.trace,
        )
        self.assertIn(("admin-auth-result", True), harness.trace)
        self.assertEqual(
            harness.trace[-1],
            (
                "redirect", ("/admin/jobs/7", {"Set-Cookie": "token"}),
                {"status": 303},
            ),
        )

    def test_post_admin_response_selects_dashboard_only_for_exact_view(self) -> None:
        cases = (("dashboard", "dashboard"), ("Dashboard", "login"), (None, "login"))
        for view, renderer in cases:
            with self.subTest(view=view):
                intake = SimpleNamespace(ready=True, length=7)
                admin_form = SimpleNamespace(
                    redirect=None, view=view, message="form result", error=False,
                    status=422,
                )
                harness = _PostHarness(intake=intake, admin_form=admin_form)

                result = adapter._do_post(harness.handler, harness.runtime)

                self.assertEqual(result, "sent")
                self.assertEqual(
                    harness.trace[-2],
                    ("render", renderer, "form result", False),
                )
                self.assertEqual(
                    harness.trace[-1],
                    (
                        "send",
                        (422, f"{renderer}:form result:False".encode()),
                        {},
                    ),
                )
                self.assertFalse(any(event[0] == "redirect" for event in harness.trace))


if __name__ == "__main__":
    unittest.main()
