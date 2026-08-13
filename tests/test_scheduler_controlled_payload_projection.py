from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))

from scheduler_controlled_payload import (  # noqa: E402
    ControlledPayloadPolicy,
    ControlledPayloadSources,
    IDENTITY_FIELDS,
    validate_controlled_recovery_payload,
)


class RecordingPattern:
    def __init__(
        self,
        calls: list[tuple[object, ...]],
        name: str,
        *,
        valid: bool = True,
    ) -> None:
        self.calls = calls
        self.name = name
        self.valid = valid

    def fullmatch(self, value: object) -> bool:
        self.calls.append((self.name, value))
        return self.valid


class SchedulerControlledPayloadProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.args = SimpleNamespace(
            only_dispatch_id="dispatch-1",
            only_alert_id="alert-1",
            only_group_id="group-1",
            only_stable_group_key="v2|group-1",
        )
        self.identity: dict[str, Any] = {
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
            "release_id": "release-1",
            "expected_assigned_route": "codex:primary:high",
            "expected_reviewer_route": "codex:reviewer:xhigh",
            "reviewer_required": True,
        }
        self.response: dict[str, Any] = {
            "_analysis_evaluation_memory_frozen": True,
            "_analysis_controlled_claim_sha256": "claim-digest",
            "_analysis_model_route": "codex:primary:high",
            "_second_opinion": {
                "status": "completed",
                "model_route": "codex:reviewer:xhigh",
                "response": {
                    "_analysis_model_route": "codex:reviewer:xhigh",
                },
            },
        }
        self.payload: dict[str, Any] = {
            "analysis_id": "analysis-1",
            "alert_id": "alert-1",
            "agent_role": "soc-analyst",
            "reanalysis_attempt_id": "",
            "controlled_job": self.identity,
            "response": self.response,
        }

    def policy(
        self,
        *,
        lease_valid: bool = True,
        cohort_valid: bool = True,
        route_valid: bool = True,
        analysis_valid: bool = True,
    ) -> ControlledPayloadPolicy:
        return ControlledPayloadPolicy(
            lease_token_pattern=RecordingPattern(
                self.calls, "lease_pattern", valid=lease_valid
            ),  # type: ignore[arg-type]
            cohort_id_pattern=RecordingPattern(
                self.calls, "cohort_pattern", valid=cohort_valid
            ),  # type: ignore[arg-type]
            model_route_pattern=RecordingPattern(
                self.calls, "route_pattern", valid=route_valid
            ),  # type: ignore[arg-type]
            analysis_id_pattern=RecordingPattern(
                self.calls, "analysis_pattern", valid=analysis_valid
            ),  # type: ignore[arg-type]
        )

    def sources(self) -> ControlledPayloadSources:
        def current_release_id() -> str:
            self.calls.append(("current_release_id",))
            return "release-1"

        def incident_attempt_id(lease_token: str) -> str:
            self.calls.append(("incident_attempt_id", lease_token))
            return f"attempt-{lease_token}"

        def canonical_digest(
            value: object,
            *,
            ensure_ascii: bool = True,
        ) -> str:
            self.calls.append(("canonical_digest", value, ensure_ascii))
            return "claim-digest" if value is self.identity else "response-digest"

        def storage_canonical_digest(value: object) -> str:
            self.calls.append(("storage_canonical_digest", value))
            return "storage-digest"

        def expected_accepted_fields(
            payload: dict[str, Any],
            response: dict[str, Any],
        ) -> dict[str, str | None]:
            self.calls.append(("expected_accepted_fields", payload, response))
            return {"model": "synthetic-model"}

        return ControlledPayloadSources(
            current_release_id=current_release_id,
            incident_attempt_id=incident_attempt_id,
            canonical_digest=canonical_digest,
            storage_canonical_digest=storage_canonical_digest,
            expected_accepted_fields=expected_accepted_fields,
        )

    def validate(
        self,
        policy: ControlledPayloadPolicy | None = None,
    ) -> dict[str, Any]:
        return validate_controlled_recovery_payload(
            policy or self.policy(),
            self.sources(),
            self.payload,
            self.args,
        )

    def expected_identity_calls(self) -> list[tuple[object, ...]]:
        return [
            ("canonical_digest", self.identity, False),
            ("current_release_id",),
            ("lease_pattern", "lease-token-12345678"),
            ("cohort_pattern", "cohort-1"),
            ("route_pattern", "codex:primary:high"),
            ("route_pattern", "codex:reviewer:xhigh"),
        ]

    def test_soc_recovery_result_and_source_call_order_are_exact(self) -> None:
        recovery = self.validate()
        self.assertEqual(
            recovery,
            {
                "analysis_id": "analysis-1",
                "job_id": 7,
                "job_type": "ai_analysis",
                "lease_token": "lease-token-12345678",
                "stable_group_id": "group-1",
                "response_digest": "response-digest",
                "stored_response_fallback_digest": "storage-digest",
                "accepted_fields": {"model": "synthetic-model"},
                "claim_digest": "claim-digest",
                "identity": self.identity,
            },
        )
        self.assertEqual(
            self.calls,
            self.expected_identity_calls()
            + [
                ("analysis_pattern", "analysis-1"),
                ("canonical_digest", self.response, True),
                ("storage_canonical_digest", self.response),
                ("expected_accepted_fields", self.payload, self.response),
            ],
        )

    def test_incident_attempt_derivation_precedes_digest_and_matching(self) -> None:
        self.identity.update({
            "job_type": "incident_response_analysis",
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": "attempt-lease-token-12345678",
        })
        self.payload.update({
            "agent_role": "incident-responder",
            "reanalysis_attempt_id": "attempt-lease-token-12345678",
        })
        recovery = self.validate()
        self.assertEqual(recovery["job_type"], "incident_response_analysis")
        self.assertEqual(
            self.calls[0],
            ("incident_attempt_id", "lease-token-12345678"),
        )
        self.assertEqual(self.calls[1], ("canonical_digest", self.identity, False))

    def test_structural_admission_fails_before_every_source_or_policy_call(self) -> None:
        cases = [
            ("missing identity", None, self.response),
            ("non-mapping identity", [], self.response),
            ("missing field", {key: value for key, value in self.identity.items() if key != "release_id"}, self.response),
            ("extra field", {**self.identity, "extra": True}, self.response),
            ("non-mapping response", self.identity, []),
        ]
        self.assertEqual(set(self.identity), IDENTITY_FIELDS)
        for name, identity, response in cases:
            with self.subTest(name=name):
                self.calls.clear()
                self.payload["controlled_job"] = identity
                self.payload["response"] = response
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^controlled evaluation recovery identity is incomplete$",
                ):
                    self.validate()
                self.assertEqual(self.calls, [])
        self.payload["controlled_job"] = self.identity
        self.payload["response"] = self.response

    def test_identity_mismatch_eagerly_checks_identity_patterns_then_stops(self) -> None:
        self.identity["dispatch_id"] = "wrong-dispatch"
        with self.assertRaisesRegex(
            RuntimeError,
            "^controlled evaluation recovery identity does not match the frozen scheduler pins$",
        ):
            self.validate()
        self.assertEqual(self.calls, self.expected_identity_calls())

    def test_response_mismatch_checks_analysis_pattern_but_skips_projection(self) -> None:
        self.response["_analysis_evaluation_memory_frozen"] = False
        with self.assertRaisesRegex(
            RuntimeError,
            "^controlled evaluation recovery identity does not match the frozen scheduler pins$",
        ):
            self.validate()
        self.assertEqual(
            self.calls,
            self.expected_identity_calls()
            + [("analysis_pattern", "analysis-1")],
        )

    def test_unknown_job_type_still_derives_attempt_before_identity_rejection(self) -> None:
        self.identity["job_type"] = "unknown"
        with self.assertRaisesRegex(
            RuntimeError,
            "^controlled evaluation recovery identity does not match the frozen scheduler pins$",
        ):
            self.validate()
        self.assertEqual(
            self.calls[0],
            ("incident_attempt_id", "lease-token-12345678"),
        )
        self.assertNotIn(("analysis_pattern", "analysis-1"), self.calls)


if __name__ == "__main__":
    unittest.main()
