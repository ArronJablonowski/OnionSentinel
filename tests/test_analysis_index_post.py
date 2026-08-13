"""Characterize the immutable analysis-index HTTP submission boundary."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.persistence import analysis_index  # noqa: E402


class SubmissionError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        retryable: bool,
        status_code: int | None = None,
        response_sha256: str = "",
    ) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
        self.response_sha256 = response_sha256


class TrackingBody(io.BytesIO):
    def __init__(self, body: bytes) -> None:
        super().__init__(body)
        self.read_sizes: list[int] = []
        self.closed_by_boundary = False

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        return super().read(size)

    def close(self) -> None:
        self.closed_by_boundary = True
        super().close()


class TrackingResponse(TrackingBody):
    def __enter__(self) -> "TrackingResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def post_kwargs() -> dict[str, object]:
    return {
        "timeout": 17,
        "max_response_bytes": 321,
        "submission_error": SubmissionError,
        "environment": {"MODE": "1", "TOKEN": "b" * 64},
        "evaluation_mode_env": "MODE",
        "evaluation_token_env": "TOKEN",
        "evaluation_token_header": "X-Controlled-Token",
        "evaluation_token_pattern": re.compile(r"[a-f0-9]{64}"),
        "fallback_evaluation_token": "c" * 64,
    }


class AnalysisIndexPostCharacterizationTests(unittest.TestCase):
    def test_success_preserves_exact_request_and_receipt_binding(self) -> None:
        payload = {
            "analysis_id": "Analysis-1",
            "response": {"summary": "compact", "items": [1, True, None]},
        }
        original = copy.deepcopy(payload)
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        response = TrackingResponse(b"response bytes are owned by the decoder")
        calls: list[tuple[object, ...]] = []

        def urlopen(request: object, *, timeout: int) -> TrackingResponse:
            calls.append(("urlopen", request, timeout))
            return response

        def read_json(stream: object, *, max_bytes: int) -> dict[str, object]:
            calls.append(("read", stream, max_bytes))
            return {"wire": "receipt"}

        expected = {"validated": True}
        with (
            mock.patch.object(analysis_index.urllib.request, "urlopen", urlopen),
            mock.patch.object(
                analysis_index,
                "_validate_receipt",
                return_value=expected,
            ) as validate,
        ):
            result = analysis_index.post(
                payload,
                "http://127.0.0.1:8787///",
                read_bounded_json=read_json,
                **post_kwargs(),
            )

        self.assertIs(result, expected)
        self.assertEqual(payload, original)
        self.assertEqual([item[0] for item in calls], ["urlopen", "read"])
        request = calls[0][1]
        self.assertEqual(request.full_url, "http://127.0.0.1:8787/analysis/result")
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.data, body)
        headers = {key.lower(): value for key, value in request.header_items()}
        self.assertEqual(
            headers,
            {
                "content-type": "application/json",
                "user-agent": "Onion-Sentinel-AI/1.0",
                "x-controlled-token": "b" * 64,
            },
        )
        self.assertEqual(calls[0][2], 17)
        self.assertIs(calls[1][1], response)
        self.assertEqual(calls[1][2], 321)
        self.assertTrue(response.closed_by_boundary)
        validate.assert_called_once_with(
            {"wire": "receipt"},
            payload,
            hashlib.sha256(body).hexdigest(),
            SubmissionError,
        )

    def test_http_error_reads_bounded_body_closes_and_classifies(self) -> None:
        cases = (
            (400, False),
            (408, True),
            (425, True),
            (429, True),
            (499, False),
            (500, True),
            (599, True),
        )
        for status_code, retryable in cases:
            with self.subTest(status_code=status_code):
                body = (f"failure-{status_code}-".encode("ascii") + b"x" * 400)
                stream = TrackingBody(body)
                error = urllib.error.HTTPError(
                    "http://127.0.0.1:8787/analysis/result",
                    status_code,
                    "failure",
                    {},
                    stream,
                )
                with (
                    mock.patch.object(
                        analysis_index.urllib.request,
                        "urlopen",
                        side_effect=error,
                    ),
                    self.assertRaises(SubmissionError) as raised,
                ):
                    analysis_index.post(
                        {"analysis_id": "analysis-1"},
                        "http://127.0.0.1:8787",
                        read_bounded_json=lambda *_args, **_kwargs: {},
                        **post_kwargs(),
                    )

                exc = raised.exception
                self.assertEqual(str(exc), f"analysis index HTTP {status_code}")
                self.assertEqual(exc.retryable, retryable)
                self.assertEqual(exc.status_code, status_code)
                self.assertEqual(stream.read_sizes, [322])
                self.assertEqual(
                    exc.response_sha256,
                    hashlib.sha256(body[:322]).hexdigest(),
                )
                self.assertTrue(stream.closed_by_boundary)
                self.assertIs(exc.__cause__, error)

    def test_transport_failures_are_retryable_and_preserve_cause(self) -> None:
        failures = (
            urllib.error.URLError("offline"),
            TimeoutError("late"),
            OSError("socket"),
        )
        for failure in failures:
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(
                    analysis_index.urllib.request,
                    "urlopen",
                    side_effect=failure,
                ),
                self.assertRaises(SubmissionError) as raised,
            ):
                analysis_index.post(
                    {"analysis_id": "analysis-1"},
                    "http://127.0.0.1:8787",
                    read_bounded_json=lambda *_args, **_kwargs: {},
                    **post_kwargs(),
                )

            exc = raised.exception
            self.assertEqual(str(exc), "analysis index transport failed")
            self.assertTrue(exc.retryable)
            self.assertIsNone(exc.status_code)
            self.assertEqual(exc.response_sha256, "")
            self.assertIs(exc.__cause__, failure)

    def test_unclassified_transport_exception_propagates_unchanged(self) -> None:
        failure = RuntimeError("programming defect")
        with mock.patch.object(
            analysis_index.urllib.request,
            "urlopen",
            side_effect=failure,
        ):
            with self.assertRaises(RuntimeError) as raised:
                analysis_index.post(
                    {"analysis_id": "analysis-1"},
                    "http://127.0.0.1:8787",
                    read_bounded_json=lambda *_args, **_kwargs: {},
                    **post_kwargs(),
                )
        self.assertIs(raised.exception, failure)


if __name__ == "__main__":
    unittest.main()
