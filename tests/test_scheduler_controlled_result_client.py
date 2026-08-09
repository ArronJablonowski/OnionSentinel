from __future__ import annotations

import hashlib
import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_result_client import (  # noqa: E402
    ControlledResultClientPolicy,
    ControlledResultClientSources,
    post_controlled_recovery_result,
)


class BoundedFailure(Exception):
    pass


class Response:
    def __init__(self, status: int, result: dict[str, object]) -> None:
        self.status = status
        self.result = result
        self.closed = False

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.closed = True


class SchedulerControlledResultClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = {
            "analysis_id": "analysis-1",
            "response": {"summary": "exact result"},
        }
        self.body = json.dumps(
            self.payload, separators=(",", ":")
        ).encode("utf-8")
        self.submission_digest = hashlib.sha256(self.body).hexdigest()
        self.receipt = {
            "ok": True,
            "analysis_id": "analysis-1",
            "submission_sha256": self.submission_digest,
            "stored_response_sha256": "a" * 64,
        }
        self.open_url = mock.Mock()
        self.read_json = mock.Mock(
            side_effect=lambda response, **_kwargs: response.result
        )
        self.sleep = mock.Mock()
        self.headers = mock.Mock(return_value={"X-Test": "token"})
        self.sources = ControlledResultClientSources(
            mutation_headers=self.headers,
            open_url=self.open_url,
            read_bounded_json=self.read_json,
            sleep=self.sleep,
            transport_errors=(
                urllib.error.URLError,
                TimeoutError,
                OSError,
                BoundedFailure,
            ),
        )
        self.policy = ControlledResultClientPolicy(
            indeterminate_marker="submission_indeterminate",
            max_response_bytes=4096,
        )

    def post(self, *, attempts: int = 3) -> dict[str, object]:
        return post_controlled_recovery_result(
            self.sources,
            self.policy,
            self.payload,
            "http://127.0.0.1:8765/",
            attempts=attempts,
        )

    def test_exact_receipt_returns_and_binds_request_bytes(self) -> None:
        response = Response(200, self.receipt)
        self.open_url.return_value = response

        self.assertEqual(self.post(), self.receipt)

        request = self.open_url.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8765/analysis/result")
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.data, self.body)
        self.assertEqual(request.get_header("X-test"), "token")
        self.assertEqual(self.open_url.call_args.kwargs["timeout"], 10)
        self.read_json.assert_called_once_with(response, max_bytes=4096)
        self.headers.assert_called_once_with(
            "Onion-Sentinel-AI-Recovery/1.0"
        )
        self.assertTrue(response.closed)

    def test_transport_failure_retries_same_bytes_then_succeeds(self) -> None:
        self.open_url.side_effect = [
            urllib.error.URLError("sensitive backend detail"),
            Response(200, self.receipt),
        ]

        self.assertEqual(self.post(), self.receipt)

        self.assertEqual(self.open_url.call_count, 2)
        requests = [call.args[0] for call in self.open_url.call_args_list]
        self.assertEqual(requests[0].data, requests[1].data)
        self.sleep.assert_called_once_with(0.05)

    def test_retryable_http_status_then_exact_receipt_succeeds(self) -> None:
        first = Response(429, {})
        self.open_url.side_effect = [first, Response(200, self.receipt)]
        self.assertEqual(self.post(), self.receipt)
        self.assertTrue(first.closed)
        self.sleep.assert_called_once_with(0.05)

    def test_http_409_is_immediately_indeterminate(self) -> None:
        error = urllib.error.HTTPError(
            "http://127.0.0.1:8765/analysis/result",
            409,
            "conflict",
            None,
            None,
        )
        self.open_url.side_effect = error
        with self.assertRaisesRegex(
            RuntimeError, "submission_indeterminate.*HTTP 409"
        ):
            self.post()
        self.assertEqual(self.open_url.call_count, 1)

    def test_nonretryable_client_error_fails_without_indeterminate_marker(
        self,
    ) -> None:
        self.open_url.return_value = Response(400, {})
        with self.assertRaisesRegex(RuntimeError, r"^analysis.*HTTP 400$"):
            self.post()
        self.assertEqual(self.open_url.call_count, 1)

    def test_inexact_receipt_exhausts_bounded_attempts(self) -> None:
        wrong = dict(self.receipt)
        wrong["submission_sha256"] = "b" * 64
        self.open_url.side_effect = [Response(200, wrong), Response(200, wrong)]
        with self.assertRaisesRegex(
            RuntimeError, "submission_indeterminate.*not exact"
        ):
            self.post(attempts=2)
        self.assertEqual(self.open_url.call_count, 2)

    def test_attempt_count_is_clamped_between_one_and_five(self) -> None:
        self.open_url.side_effect = urllib.error.URLError("offline")
        with self.assertRaisesRegex(RuntimeError, "submission_indeterminate"):
            self.post(attempts=99)
        self.assertEqual(self.open_url.call_count, 5)
        self.assertEqual(self.sleep.call_count, 4)

        self.open_url.reset_mock()
        self.sleep.reset_mock()
        with self.assertRaisesRegex(RuntimeError, "submission_indeterminate"):
            self.post(attempts=0)
        self.assertEqual(self.open_url.call_count, 1)
        self.sleep.assert_not_called()

    def test_bounded_receipt_failure_is_retried_without_error_detail(self) -> None:
        self.open_url.return_value = Response(200, {})
        self.read_json.side_effect = BoundedFailure("secret response detail")
        with self.assertRaisesRegex(
            RuntimeError, "submission_indeterminate.*BoundedFailure"
        ) as raised:
            self.post(attempts=1)
        self.assertNotIn("secret response detail", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
