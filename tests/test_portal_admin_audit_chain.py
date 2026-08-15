from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_admin_audit_chain as audit  # noqa: E402


KEY = b"fixture-audit-key-material-32-bytes-minimum"


def fields(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "occurred_at": "2026-08-15T05:30:00Z",
        "request_id": "request-7",
        "principal_fingerprint": "1" * 64,
        "role": "analyst",
        "permission": "alert.escalate",
        "action": "soc-alert-escalate",
        "target_type": "soc-alert",
        "target_digest": "2" * 64,
        "outcome": "allowed",
        "http_status": 200,
        "reason_code": "authorized",
    }
    value.update(overrides)
    return value


class PortalAdminAuditChainTests(unittest.TestCase):
    def test_events_are_canonical_bounded_metadata_only_and_keyed(self) -> None:
        event = audit.build_event(None, fields(), signing_key=KEY)
        self.assertEqual(event["schema"], "onion-sentinel-admin-audit-event-v1")
        self.assertEqual(event["sequence"], 1)
        self.assertEqual(event["previous_digest"], "0" * 64)
        self.assertRegex(event["event_digest"], r"^[a-f0-9]{64}$")
        encoded = json.dumps(event, sort_keys=True)
        self.assertNotIn(KEY.decode(), encoded)
        self.assertNotIn("password", encoded.lower())
        self.assertEqual(
            tuple(event),
            (
                "schema",
                "sequence",
                "occurred_at",
                "request_id",
                "principal_fingerprint",
                "role",
                "permission",
                "action",
                "target_type",
                "target_digest",
                "outcome",
                "http_status",
                "reason_code",
                "previous_digest",
                "event_digest",
            ),
        )

    def test_chain_sequence_previous_digest_and_verification_are_exact(self) -> None:
        first = audit.build_event(None, fields(), signing_key=KEY)
        second = audit.build_event(
            first,
            fields(
                occurred_at="2026-08-15T05:31:00Z",
                request_id="request-8",
                outcome="denied",
                http_status=403,
                reason_code="role_denied",
            ),
            signing_key=KEY,
        )
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(second["previous_digest"], first["event_digest"])
        verification = audit.verify_chain([first, second], signing_key=KEY)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.event_count, 2)
        self.assertEqual(verification.head_digest, second["event_digest"])
        self.assertEqual(verification.reason, "verified")

    def test_tampering_reordering_deletion_and_wrong_key_fail_closed(self) -> None:
        first = audit.build_event(None, fields(), signing_key=KEY)
        second = audit.build_event(
            first,
            fields(request_id="request-8", target_digest="3" * 64),
            signing_key=KEY,
        )
        tampered = copy.deepcopy(second)
        tampered["outcome"] = "denied"
        cases = (
            ([first, tampered], KEY),
            ([second, first], KEY),
            ([second], KEY),
            ([first, second], b"different-signing-key-material-32-bytes"),
        )
        for events, key in cases:
            with self.subTest(events=events, key=key):
                verification = audit.verify_chain(events, signing_key=key)
                self.assertFalse(verification.valid)
                self.assertNotEqual(verification.reason, "verified")

    def test_empty_chain_has_zero_head_and_is_valid(self) -> None:
        verification = audit.verify_chain([], signing_key=KEY)
        self.assertTrue(verification.valid)
        self.assertEqual(verification.event_count, 0)
        self.assertEqual(verification.head_digest, "0" * 64)

    def test_unknown_secret_bearing_or_unbounded_fields_are_rejected(self) -> None:
        cases = (
            {**fields(), "password": "must-not-enter-audit"},
            fields(action="a" * 129),
            fields(target_digest="not-a-digest"),
            fields(principal_fingerprint="not-a-digest"),
            fields(permission="unknown.permission"),
            fields(role="service"),
            fields(outcome="maybe"),
            fields(http_status=999),
            fields(reason_code="Bearer token detail"),
            fields(occurred_at="not-a-time"),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(audit.AuditContractError):
                    audit.build_event(None, candidate, signing_key=KEY)

    def test_login_denial_uses_authentication_boundary_not_human_permission(self) -> None:
        event = audit.build_event(
            None,
            fields(
                role="unauthenticated",
                permission="authentication.login",
                action="login",
                target_type="session",
                outcome="denied",
                http_status=401,
                reason_code="credential_denied",
            ),
            signing_key=KEY,
        )
        self.assertEqual(event["permission"], "authentication.login")
        self.assertTrue(audit.verify_chain([event], signing_key=KEY).valid)

    def test_key_and_previous_event_contracts_fail_closed(self) -> None:
        for key in (b"", b"short", "not-bytes", None):
            with self.subTest(key=key):
                with self.assertRaises(audit.AuditContractError):
                    audit.build_event(None, fields(), signing_key=key)
        with self.assertRaises(audit.AuditContractError):
            audit.build_event({"event_digest": "bad"}, fields(), signing_key=KEY)


if __name__ == "__main__":
    unittest.main()
