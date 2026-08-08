from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_soc_action_service import (  # noqa: E402
    SocActionServiceSources,
    escalate_soc_alert,
    forward_controlled_dispatch_contract,
    queue_soc_alert_analysis,
)


class RequestFailure(RuntimeError):
    def __init__(self, message: str, status: int):
        super().__init__(message)
        self.status = status


class SocActionServiceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.calls = []

        def post(path, payload, **kwargs):
            self.calls.append((path, payload, kwargs))
            return {"ok": True, "job": {"status": "pending"}}

        self.sources = SocActionServiceSources(
            post_json=post,
            api_error=lambda message, status=400: (
                status, {"ok": False, "error": message}
            ),
            now_local=lambda: "2026-08-08  17:00:00-06:00",
            request_error_status=lambda exc: (
                exc.status if isinstance(exc, RequestFailure) else None
            ),
        )

    def test_analysis_queue_bounds_fields_and_uses_expected_defaults(self) -> None:
        status, response = queue_soc_alert_analysis(
            self.sources,
            "ABCDEF123456",
            {
                "reason": "r" * 700,
                "requested_by": "u" * 200,
                "related_limit": 999,
                "pcap_analysis_limit": 0,
            },
        )
        self.assertEqual(status, 202)
        self.assertEqual(response["ai_status_key"], "queued")
        path, request, kwargs = self.calls[0]
        self.assertEqual(path, "/ai/request")
        self.assertEqual(request["group_id"], "abcdef123456")
        self.assertEqual(len(request["reason"]), 500)
        self.assertEqual(len(request["requested_by"]), 100)
        self.assertEqual(request["related_limit"], 500)
        self.assertEqual(request["pcap_analysis_limit"], 1)
        self.assertEqual(kwargs["timeout"], 10.0)

    def test_escalation_uses_distinct_defaults_and_status_projection(self) -> None:
        status, response = escalate_soc_alert(
            self.sources, "a" * 12, {}
        )
        self.assertEqual(status, 202)
        self.assertEqual(response["agent_status"], "queued")
        path, request, _ = self.calls[0]
        self.assertEqual(path, "/incidents/escalate")
        self.assertEqual(request["related_limit"], 250)
        self.assertEqual(request["pcap_analysis_limit"], 25)
        self.assertIn("Escalated from SOC Alerts", request["reason"])

    def test_controlled_identity_fields_are_forwarded_exactly(self) -> None:
        payload = {
            "cohort_id": "cohort",
            "dispatch_id": "not-normalized",
            "representative_alert_id": "opaque:alert",
            "stable_group_id": "stable",
            "stable_group_key": "v2|key",
            "release_id": "release",
            "expected_assigned_route": "route-a",
            "expected_reviewer_route": "route-b",
            "reviewer_required": False,
        }
        queue_soc_alert_analysis(self.sources, "b" * 12, payload)
        request = self.calls[0][1]
        for field, value in payload.items():
            self.assertEqual(request[field], value)

    def test_route_fields_are_not_forwarded_without_controlled_identity(self) -> None:
        request = {}
        forward_controlled_dispatch_contract(
            {"release_id": "ignored", "reviewer_required": True}, request
        )
        self.assertEqual(request, {})

    def test_invalid_group_and_limits_are_rejected_before_transport(self) -> None:
        status, _ = queue_soc_alert_analysis(self.sources, "not-a-group", {})
        self.assertEqual(status, 400)
        status, response = escalate_soc_alert(
            self.sources, "a" * 12, {"related_limit": "bad"}
        )
        self.assertEqual(status, 400)
        self.assertIn("integers", response["error"])
        self.assertEqual(self.calls, [])

    def test_transport_conflict_and_unavailable_statuses_are_preserved(self) -> None:
        for failure, expected in (
            (RequestFailure("identity conflict", 409), 409),
            (RuntimeError("offline"), 503),
            (ValueError("invalid transport value"), 400),
        ):
            with self.subTest(expected=expected):
                sources = SocActionServiceSources(
                    **{
                        **self.sources.__dict__,
                        "post_json": lambda *args, failure=failure, **kwargs: (
                            _ for _ in ()
                        ).throw(failure),
                    }
                )
                status, response = queue_soc_alert_analysis(
                    sources, "c" * 12, {}
                )
                self.assertEqual(status, expected)
                self.assertFalse(response["ok"])


if __name__ == "__main__":
    unittest.main()
