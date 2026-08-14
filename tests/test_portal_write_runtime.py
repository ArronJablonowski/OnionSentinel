from __future__ import annotations

import json
import sys
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_write_runtime import alert_store_post_json  # noqa: E402


class BoundedResponseError(Exception):
    pass


class AlertStoreRequestError(Exception):
    def __init__(self, detail, status) -> None:
        super().__init__(detail)
        self.detail = detail
        self.status = status


class ResponseContext:
    def __init__(self, trace, response) -> None:
        self.trace = trace
        self.response = response

    def __enter__(self):
        self.trace.append(("enter", self.response))
        return self.response

    def __exit__(self, exc_type, exc, traceback):
        self.trace.append(("exit", exc_type, exc, traceback))
        return False


class PortalWriteRuntimeTests(unittest.TestCase):
    def runtime(
        self,
        *,
        result=None,
        token="evaluation-token",
        urlopen_error=None,
        error_result=None,
        error_read_error=None,
    ):
        trace = []
        response = object()
        requests = []

        def request(url, *, data, method, headers):
            trace.append(("request", url, data, method, headers))
            value = object()
            requests.append((value, headers))
            return value

        def urlopen(req, *, timeout):
            trace.append(("urlopen", req, timeout))
            if urlopen_error is not None:
                raise urlopen_error
            return ResponseContext(trace, response)

        def read_bounded_json(owner, *, max_bytes):
            trace.append(("read", owner, max_bytes))
            if isinstance(owner, urllib.error.HTTPError):
                if error_read_error is not None:
                    raise error_read_error
                return error_result
            return result

        runtime = SimpleNamespace(
            json=json,
            urllib_request=SimpleNamespace(Request=request, urlopen=urlopen),
            urllib_error=urllib.error,
            SOC_ALERT_STORE_EVALUATION_TOKEN=token,
            SOC_ALERT_STORE_API_URL="http://127.0.0.1:8787",
            SOC_ALERT_STORE_RESPONSE_MAX_BYTES=4096,
            read_bounded_json=read_bounded_json,
            BoundedResponseError=BoundedResponseError,
            AlertStoreRequestError=AlertStoreRequestError,
        )
        return runtime, trace, requests, response

    def test_alert_store_post_serializes_headers_reads_and_returns_exact_result(self) -> None:
        result = {"ok": True, "value": 7}
        runtime, trace, requests, response = self.runtime(result=result)

        returned = alert_store_post_json(
            runtime,
            "/path",
            {"snowman": "☃"},
            timeout=3.5,
        )

        encoded = json.dumps({"snowman": "☃"}).encode("utf-8")
        self.assertIs(returned, result)
        self.assertEqual(requests[0][1], {
            "Content-Type": "application/json",
            "Content-Length": str(len(encoded)),
            "X-Onion-Sentinel-Evaluation-Token": "evaluation-token",
        })
        self.assertEqual(trace, [
            (
                "request",
                "http://127.0.0.1:8787/path",
                encoded,
                "POST",
                requests[0][1],
            ),
            ("urlopen", requests[0][0], 3.5),
            ("enter", response),
            ("read", response, 4096),
            ("exit", None, None, None),
        ])

    def test_alert_store_post_omits_empty_evaluation_token(self) -> None:
        runtime, _, requests, _ = self.runtime(result={"ok": True}, token="")

        alert_store_post_json(runtime, "/path", {})

        self.assertNotIn("X-Onion-Sentinel-Evaluation-Token", requests[0][1])

    def test_alert_store_post_maps_http_error_payload_and_preserves_cause(self) -> None:
        error = urllib.error.HTTPError(
            "http://127.0.0.1:8787/path",
            422,
            "http reason",
            {},
            None,
        )
        runtime, trace, _, _ = self.runtime(
            urlopen_error=error,
            error_result={"reason": "bounded reason", "error": "secondary"},
        )

        with self.assertRaises(AlertStoreRequestError) as raised:
            alert_store_post_json(runtime, "/path", {})

        self.assertEqual(raised.exception.detail, "bounded reason")
        self.assertEqual(raised.exception.status, 422)
        self.assertIs(raised.exception.__cause__, error)
        self.assertEqual(trace[-1], ("read", error, 4096))

    def test_alert_store_post_uses_http_reason_only_for_bounded_read_failures(self) -> None:
        error = urllib.error.HTTPError("url", None, "http reason", {}, None)
        runtime, _, _, _ = self.runtime(
            urlopen_error=error,
            error_read_error=BoundedResponseError("too large"),
        )

        with self.assertRaises(AlertStoreRequestError) as raised:
            alert_store_post_json(runtime, "/path", {})

        self.assertEqual(raised.exception.detail, "http reason")
        self.assertEqual(raised.exception.status, 503)
        self.assertIs(raised.exception.__cause__, error)

    def test_alert_store_post_preserves_transport_and_result_error_boundaries(self) -> None:
        transport = urllib.error.URLError("offline")
        runtime, _, _, _ = self.runtime(urlopen_error=transport)
        with self.assertRaises(AlertStoreRequestError) as raised:
            alert_store_post_json(runtime, "/path", {})
        self.assertEqual(raised.exception.status, 503)
        self.assertIs(raised.exception.__cause__, transport)

        for result, expected in (
            ({"ok": False, "reason": "reason"}, "reason"),
            ({"ok": False, "error": "error"}, "error"),
            ({"ok": False}, "alert-store rejected request"),
        ):
            with self.subTest(result=result):
                runtime, _, _, _ = self.runtime(result=result)
                with self.assertRaises(AlertStoreRequestError) as rejected:
                    alert_store_post_json(runtime, "/path", {})
                self.assertEqual(rejected.exception.detail, expected)
                self.assertEqual(rejected.exception.status, 400)

        runtime, _, _, _ = self.runtime(result=[])
        with self.assertRaises(AttributeError):
            alert_store_post_json(runtime, "/path", {})


if __name__ == "__main__":
    unittest.main()
