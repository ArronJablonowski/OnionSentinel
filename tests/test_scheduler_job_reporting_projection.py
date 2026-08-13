from __future__ import annotations

import json
import re
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))

import scheduler_job_reporting as reporting  # noqa: E402


PRIMARY = "codex-cli:gpt-5.5:high"
REVIEWER = "codex-cli:gpt-5.6-sol:xhigh"


class SchedulerJobReportingProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sleeps: list[float] = []
        self.sources = reporting.SchedulerReportingSources(
            request_factory=lambda *args, **kwargs: None,
            open_url=lambda *args, **kwargs: None,
            read_json=lambda *args, **kwargs: {},
            mutation_headers=lambda: {"X-Synthetic": "yes"},
            sleep=self.sleeps.append,
            valid_stable_group_key=lambda value: value == "v2|synthetic",
            model_route_pattern=re.compile(
                r"codex-cli:(?:gpt-5\.5|gpt-5\.6-sol):(high|xhigh)"
            ),
            max_response_bytes=1024,
            exact_claim_attempts=3,
        )

    @staticmethod
    def exact_fields() -> dict[str, object]:
        return {
            "expected_job_id": 41,
            "expected_representative_alert_id": "alert-synthetic",
            "expected_dispatch_id": "a" * 64,
            "expected_stable_group_key": "v2|synthetic",
            "expected_assigned_route": PRIMARY,
            "expected_reviewer_route": REVIEWER,
            "reviewer_required": True,
        }

    def test_rolling_transition_prepares_one_request_with_exact_defaults(self) -> None:
        calls: list[tuple[object, ...]] = []
        empty_claim = reporting.ExactClaim(0, "", "", "", "", "", False)

        def exact_claim(**kwargs: object) -> reporting.ExactClaim:
            calls.append(("exact_claim", kwargs))
            return empty_claim

        def request_payload(
            sources: reporting.SchedulerReportingSources,
            **kwargs: object,
        ) -> bytes:
            calls.append(("request_payload", sources, kwargs))
            return b"synthetic-payload"

        def transition_attempt(
            sources: reporting.SchedulerReportingSources,
            **kwargs: object,
        ) -> str:
            calls.append(("transition_attempt", sources, kwargs))
            return "rolling-result"

        with (
            mock.patch.object(reporting, "_exact_claim", side_effect=exact_claim),
            mock.patch.object(reporting, "_request_payload", side_effect=request_payload),
            mock.patch.object(reporting, "_transition_attempt", side_effect=transition_attempt),
        ):
            result = reporting.transition_ai_job_status(
                self.sources,
                "http://127.0.0.1:8787/",
                "group-synthetic",
                "completed",
                error="terminal error",
                lease_token="lease-synthetic",
                job_type="incident_response_analysis",
                retryable=False,
            )

        self.assertEqual(result, "rolling-result")
        self.assertEqual(self.sleeps, [])
        self.assertEqual(
            calls,
            [
                ("exact_claim", {
                    "expected_job_id": 0,
                    "expected_representative_alert_id": "",
                    "expected_dispatch_id": "",
                    "expected_stable_group_key": "",
                    "expected_assigned_route": "",
                    "expected_reviewer_route": "",
                    "reviewer_required": False,
                }),
                ("request_payload", self.sources, {
                    "group_id": "group-synthetic",
                    "status": "completed",
                    "error": "terminal error",
                    "lease_token": "lease-synthetic",
                    "job_type": "incident_response_analysis",
                    "retryable": False,
                    "exact_claim": empty_claim,
                }),
                ("transition_attempt", self.sources, {
                    "base_url": "http://127.0.0.1:8787/",
                    "payload": b"synthetic-payload",
                    "status": "completed",
                    "group_id": "group-synthetic",
                    "exact": False,
                }),
            ],
        )

    def test_exact_claim_retries_with_identical_payload_and_linear_backoff(self) -> None:
        attempts: list[dict[str, object]] = []
        result = reporting.ClaimedAiLease(
            "lease-synthetic",
            job_id=41,
            resolved_key="group-synthetic",
        )

        def transition_attempt(
            sources: reporting.SchedulerReportingSources,
            **kwargs: object,
        ) -> bool | reporting.ClaimedAiLease:
            attempts.append(kwargs)
            if len(attempts) < 3:
                raise reporting._IndeterminateStatus(
                    RuntimeError(f"indeterminate-{len(attempts)}")
                )
            return result

        with mock.patch.object(
            reporting,
            "_transition_attempt",
            side_effect=transition_attempt,
        ):
            actual = reporting.transition_ai_job_status(
                self.sources,
                "http://127.0.0.1:8787",
                "group-synthetic",
                "processing",
                **self.exact_fields(),
            )

        self.assertIs(actual, result)
        self.assertEqual(self.sleeps, [0.05, 0.1])
        self.assertEqual(len(attempts), 3)
        self.assertIs(attempts[0]["payload"], attempts[1]["payload"])
        self.assertIs(attempts[1]["payload"], attempts[2]["payload"])
        self.assertEqual(
            json.loads(attempts[0]["payload"]),
            {
                "job_type": "ai_analysis",
                "dedupe_key": "group-synthetic",
                "status": "processing",
                "error": "",
                "lease_token": "",
                "retryable": True,
                "expected_job_id": 41,
                "expected_representative_alert_id": "alert-synthetic",
                "expected_dispatch_id": "a" * 64,
                "expected_stable_group_key": "v2|synthetic",
                "expected_assigned_route": PRIMARY,
                "expected_reviewer_route": REVIEWER,
                "reviewer_required": True,
            },
        )
        for attempt in attempts:
            self.assertEqual(attempt["base_url"], "http://127.0.0.1:8787")
            self.assertEqual(attempt["status"], "processing")
            self.assertEqual(attempt["group_id"], "group-synthetic")
            self.assertIs(attempt["exact"], True)

    def test_rolling_indeterminate_failure_does_not_retry_and_keeps_cause(self) -> None:
        cause = OSError("synthetic transport cause")
        failure = reporting._IndeterminateStatus(
            RuntimeError("synthetic transition failure"),
            cause,
        )
        with mock.patch.object(
            reporting,
            "_transition_attempt",
            side_effect=failure,
        ) as transition:
            with self.assertRaisesRegex(
                RuntimeError,
                "^synthetic transition failure$",
            ) as caught:
                reporting.transition_ai_job_status(
                    self.sources,
                    "http://127.0.0.1:8787",
                    "group-synthetic",
                    "completed",
                )
        self.assertIs(caught.exception.__cause__, cause)
        self.assertEqual(transition.call_count, 1)
        self.assertEqual(self.sleeps, [])

    def test_exact_exhaustion_retries_then_keeps_final_cause(self) -> None:
        failures = [
            reporting._IndeterminateStatus(
                RuntimeError(f"failure-{index}"),
                OSError(f"cause-{index}"),
            )
            for index in range(1, 4)
        ]
        with mock.patch.object(
            reporting,
            "_transition_attempt",
            side_effect=failures,
        ) as transition:
            with self.assertRaisesRegex(RuntimeError, "^failure-3$") as caught:
                reporting.transition_ai_job_status(
                    self.sources,
                    "http://127.0.0.1:8787",
                    "group-synthetic",
                    "processing",
                    **self.exact_fields(),
                )
        self.assertEqual(str(caught.exception.__cause__), "cause-3")
        self.assertEqual(transition.call_count, 3)
        self.assertEqual(self.sleeps, [0.05, 0.1])

    def test_zero_exact_attempts_reaches_the_terminal_retry_invariant(self) -> None:
        sources = replace(self.sources, exact_claim_attempts=0)
        with mock.patch.object(reporting, "_transition_attempt") as transition:
            with self.assertRaisesRegex(
                RuntimeError,
                "^AI job status retry invariant failed$",
            ):
                reporting.transition_ai_job_status(
                    sources,
                    "http://127.0.0.1:8787",
                    "group-synthetic",
                    "processing",
                    **self.exact_fields(),
                )
        transition.assert_not_called()
        self.assertEqual(self.sleeps, [])


if __name__ == "__main__":
    unittest.main()
