import io
import unittest
from unittest import mock

from tests.test_portal_admin_session_store import load_portal


class FakeSseHandler:
    def __init__(self):
        self.status = None
        self.headers = []
        self.wfile = io.BytesIO()

    def send_response(self, status):
        self.status = status

    def send_header(self, name, value):
        self.headers.append((name, value))

    def end_headers(self):
        return None


class PortalSseStreamContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_stream_headers_event_projection_and_keepalive_are_exact(self):
        handler = FakeSseHandler()
        payload = {"time": "volatile", "revision": "same"}
        with (
            mock.patch.object(self.portal, "cached_soc_alert_events_snapshot", return_value=payload),
            mock.patch.object(self.portal.time, "sleep"),
            mock.patch.object(self.portal.time, "time", return_value=1234.9),
        ):
            self.portal.PortalHandler._send_soc_alert_events(handler)
        self.assertEqual(handler.status, 200)
        self.assertEqual(
            handler.headers,
            [
                ("Content-Type", "text/event-stream; charset=utf-8"),
                ("Cache-Control", "no-store"),
                ("Connection", "keep-alive"),
                ("X-Accel-Buffering", "no"),
                ("X-Content-Type-Options", "nosniff"),
            ],
        )
        body = handler.wfile.getvalue().decode("utf-8")
        self.assertEqual(body.count("event: soc-alerts"), 1)
        self.assertIn("id: 1234\n", body)
        self.assertIn('data: {"revision":"same","time":"volatile"}\n\n', body)
        self.assertEqual(body.count(": keepalive\n\n"), 59)

    def test_disconnect_is_a_clean_stream_exit(self):
        handler = FakeSseHandler()
        handler.wfile = mock.Mock()
        handler.wfile.write.side_effect = BrokenPipeError
        with (
            mock.patch.object(
                self.portal,
                "cached_soc_alert_events_snapshot",
                return_value={"revision": "one"},
            ),
            mock.patch.object(self.portal.time, "sleep"),
        ):
            self.assertIsNone(self.portal.PortalHandler._send_soc_alert_events(handler))


if __name__ == "__main__":
    unittest.main()
