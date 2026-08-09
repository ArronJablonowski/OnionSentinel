from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_controlled_payload import (  # noqa: E402
    ControlledPayloadPolicy,
    ControlledPayloadSources,
    validate_controlled_recovery_payload,
)


def digest(value: object, *, ensure_ascii: bool = True) -> str:
    body = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
    ).encode()
    return hashlib.sha256(body).hexdigest()


class SchedulerControlledPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.args = SimpleNamespace(
            only_dispatch_id="dispatch-1",
            only_alert_id="alert-1",
            only_group_id="group-1",
            only_stable_group_key="v2|group-1",
        )
        self.identity = {
            "job_id": 7,
            "job_type": "ai_analysis",
            "lease_token": "lease-token-12345678",
            "cohort_id": "cohort-1",
            "dispatch_id": "dispatch-1",
            "representative_alert_id": "alert-1",
            "stable_group_id": "group-1",
            "stable_group_key": "v2|group-1",
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": "",
            "release_id": "a" * 40,
            "expected_assigned_route": "codex:gpt-5.5:high",
            "expected_reviewer_route": "codex:gpt-5.6:xhigh",
            "reviewer_required": True,
        }
        claim_digest = digest(self.identity, ensure_ascii=False)
        self.response = {
            "_analysis_evaluation_memory_frozen": True,
            "_analysis_controlled_claim_sha256": claim_digest,
            "_analysis_model_route": "codex:gpt-5.5:high",
            "_second_opinion": {
                "status": "completed",
                "model_route": "codex:gpt-5.6:xhigh",
                "response": {
                    "_analysis_model_route": "codex:gpt-5.6:xhigh"
                },
            },
        }
        self.payload = {
            "analysis_id": "analysis-1",
            "alert_id": "alert-1",
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": "",
            "controlled_job": self.identity,
            "response": self.response,
        }
        self.policy = ControlledPayloadPolicy(
            lease_token_pattern=re.compile(r"[a-z0-9-]{16,64}"),
            cohort_id_pattern=re.compile(r"[A-Za-z0-9._-]{3,64}"),
            model_route_pattern=re.compile(
                r"[a-z0-9.-]+(?::[a-z0-9.-]+)+"
            ),
            analysis_id_pattern=re.compile(r"[a-z0-9_-]{8,120}"),
        )
        self.sources = ControlledPayloadSources(
            current_release_id=mock.Mock(return_value="a" * 40),
            incident_attempt_id=mock.Mock(
                side_effect=lambda lease: f"attempt-{lease}"
            ),
            canonical_digest=digest,
            storage_canonical_digest=mock.Mock(return_value="b" * 64),
            expected_accepted_fields=mock.Mock(
                return_value={"model": "gpt-5.5-high"}
            ),
        )

    def validate(self) -> dict[str, object]:
        return validate_controlled_recovery_payload(
            self.policy, self.sources, self.payload, self.args
        )

    def test_valid_soc_payload_produces_immutable_projection(self) -> None:
        recovery = self.validate()

        self.assertEqual(recovery["job_id"], 7)
        self.assertEqual(recovery["stable_group_id"], "group-1")
        self.assertEqual(recovery["response_digest"], digest(self.response))
        self.assertEqual(recovery["stored_response_fallback_digest"], "b" * 64)
        self.assertEqual(recovery["identity"], self.identity)
        self.sources.incident_attempt_id.assert_not_called()

    def test_ir_payload_binds_lease_derived_attempt(self) -> None:
        self.identity["job_type"] = "incident_response_analysis"
        self.identity["agent_role"] = "incident-responder"
        self.identity["reanalysis_attempt_id"] = (
            "attempt-lease-token-12345678"
        )
        self.payload["agent_role"] = "incident-responder"
        self.payload["reanalysis_attempt_id"] = (
            "attempt-lease-token-12345678"
        )
        self.response["_analysis_controlled_claim_sha256"] = digest(
            self.identity, ensure_ascii=False
        )

        self.assertEqual(
            self.validate()["job_type"], "incident_response_analysis"
        )
        self.sources.incident_attempt_id.assert_called_once_with(
            "lease-token-12345678"
        )

    def test_identity_requires_exact_field_set(self) -> None:
        self.identity["unexpected"] = "not allowed"
        with self.assertRaisesRegex(RuntimeError, "incomplete"):
            self.validate()

    def test_frozen_pins_and_independent_routes_are_required(self) -> None:
        mutations = (
            (self.identity, "dispatch_id", "different"),
            (self.identity, "release_id", "different"),
            (self.identity, "expected_reviewer_route", "codex:gpt-5.5:high"),
            (self.response, "_analysis_evaluation_memory_frozen", False),
            (self.response["_second_opinion"], "status", "failed"),
        )
        for target, field, value in mutations:
            with self.subTest(field=field):
                original = target[field]
                target[field] = value
                with self.assertRaisesRegex(RuntimeError, "frozen scheduler"):
                    self.validate()
                target[field] = original

    def test_claim_digest_and_reviewer_response_route_are_exact(self) -> None:
        for target, field, value in (
            (self.response, "_analysis_controlled_claim_sha256", "0" * 64),
            (
                self.response["_second_opinion"]["response"],
                "_analysis_model_route",
                "codex:other",
            ),
        ):
            with self.subTest(field=field):
                original = target[field]
                target[field] = value
                with self.assertRaisesRegex(RuntimeError, "frozen scheduler"):
                    self.validate()
                target[field] = original


if __name__ == "__main__":
    unittest.main()
