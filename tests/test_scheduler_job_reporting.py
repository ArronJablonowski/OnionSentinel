from __future__ import annotations

import io
import json
import re
import sys
import unittest
import urllib.error
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))

from scheduler_job_reporting import (  # noqa: E402
    ClaimedAiLease,
    ControlledClaimRejected,
    SchedulerReportingSources,
    transition_ai_job_status,
)


PRIMARY = "codex-cli:gpt-5.5:high"
REVIEWER = "codex-cli:gpt-5.6-sol:xhigh"


class SchedulerJobReportingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.requests = []
        self.responses = []
        self.sleeps = []

        def request_factory(url, **kwargs):
            request = type("Request", (), {"url": url, **kwargs})()
            self.requests.append(request)
            return request

        def open_url(request, **kwargs):
            response = self.responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        self.sources = SchedulerReportingSources(
            request_factory=request_factory,
            open_url=open_url,
            read_json=lambda response, **kwargs: json.loads(response.read()),
            mutation_headers=lambda: {"X-Test": "yes"},
            sleep=self.sleeps.append,
            valid_stable_group_key=lambda value: bool(value) and "\0" not in str(value),
            model_route_pattern=re.compile(
                r"codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):"
                r"(?:low|medium|high|xhigh)"
            ),
            max_response_bytes=1024,
            exact_claim_attempts=3,
        )

    @staticmethod
    def response(payload: dict, status: int = 200):
        response = io.BytesIO(json.dumps(payload).encode())
        response.status = status
        return response

    def exact_fields(self) -> dict:
        return {
            "expected_job_id": 41,
            "expected_representative_alert_id": "alert-unit",
            "expected_dispatch_id": "a" * 64,
            "expected_stable_group_key": "v2|unit",
            "expected_assigned_route": PRIMARY,
            "expected_reviewer_route": REVIEWER,
            "reviewer_required": True,
        }

    def test_terminal_transition_projects_bounded_error_and_retryability(self) -> None:
        self.responses.append(self.response({"ok": True}))
        result = transition_ai_job_status(
            self.sources,
            "http://127.0.0.1:8787/",
            "group-unit",
            "failed",
            "x" * 1200,
            "lease-unit",
            retryable=False,
        )
        self.assertIs(result, True)
        payload = json.loads(self.requests[0].data)
        self.assertEqual(len(payload["error"]), 1000)
        self.assertIs(payload["retryable"], False)
        self.assertEqual(self.requests[0].url, "http://127.0.0.1:8787/jobs/status")

    def test_processing_returns_server_authoritative_lease_snapshot(self) -> None:
        self.responses.append(self.response({
            "ok": True,
            "lease_token": "lease-unit",
            "claim": {
                "job_id": 41,
                "job_type": "ai_analysis",
                "dedupe_key": "claimed-group",
                "payload": {"alert_id": "alert-unit"},
            },
        }))
        result = transition_ai_job_status(
            self.sources,
            "http://127.0.0.1:8787",
            "requested-group",
            "processing",
            **self.exact_fields(),
        )
        self.assertIsInstance(result, ClaimedAiLease)
        self.assertEqual(result, "lease-unit")
        self.assertEqual(result.job_id, 41)
        self.assertEqual(result.resolved_key, "claimed-group")
        self.assertEqual(result.job_payload, {"alert_id": "alert-unit"})

    def test_incomplete_controlled_identity_fails_before_transport(self) -> None:
        with self.assertRaisesRegex(ControlledClaimRejected, "incomplete"):
            transition_ai_job_status(
                self.sources,
                "http://127.0.0.1:8787",
                "group-unit",
                "processing",
                expected_job_id=41,
            )
        self.assertEqual(self.requests, [])

    def test_exact_claim_retries_indeterminate_transport_with_identical_payload(self) -> None:
        self.responses.extend([
            urllib.error.URLError("lost response"),
            self.response({
                "ok": True,
                "lease_token": "lease-unit",
                "claim": {"payload": {}, "job_id": 41},
            }),
        ])
        result = transition_ai_job_status(
            self.sources,
            "http://127.0.0.1:8787",
            "group-unit",
            "processing",
            **self.exact_fields(),
        )
        self.assertEqual(result, "lease-unit")
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.requests[0].data, self.requests[1].data)
        self.assertEqual(self.sleeps, [0.05])

    def test_exact_claim_rejects_missing_server_payload_after_bounded_retries(self) -> None:
        self.responses.extend([
            self.response({"ok": True, "lease_token": "lease-unit"})
            for _ in range(3)
        ])
        with self.assertRaisesRegex(RuntimeError, "exact lease receipt"):
            transition_ai_job_status(
                self.sources,
                "http://127.0.0.1:8787",
                "group-unit",
                "processing",
                **self.exact_fields(),
            )
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.sleeps, [0.05, 0.1])

    def test_rolling_404_returns_false_and_conflict_rejects_claim(self) -> None:
        for code, expected in ((404, False), (409, ControlledClaimRejected)):
            error = urllib.error.HTTPError(
                "http://127.0.0.1/jobs/status", code, "error", {}, None
            )
            self.responses.append(error)
            if expected is False:
                self.assertIs(
                    transition_ai_job_status(
                        self.sources,
                        "http://127.0.0.1:8787",
                        "group-unit",
                        "completed",
                    ),
                    False,
                )
            else:
                with self.assertRaises(expected):
                    transition_ai_job_status(
                        self.sources,
                        "http://127.0.0.1:8787",
                        "group-unit",
                        "processing",
                        **self.exact_fields(),
                    )


if __name__ == "__main__":
    unittest.main()
