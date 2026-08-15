from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_session_principal as sessions  # noqa: E402


class PortalSessionPrincipalTests(unittest.TestCase):
    def bundle(self, role: str = "analyst") -> sessions.SessionBundle:
        values = iter(("session-" + "s" * 36, "csrf-" + "c" * 38))
        return sessions.create_session_bundle(
            principal_id="operator-7",
            role=role,
            now_timestamp=1_000,
            absolute_ttl_seconds=3_600,
            idle_ttl_seconds=600,
            policy_generation=4,
            client_fingerprint="client-digest",
            new_token=lambda: next(values),
        )

    def test_new_record_contains_no_raw_session_or_csrf_material(self) -> None:
        bundle = self.bundle()
        self.assertEqual(bundle.session_id, "session-" + "s" * 36)
        self.assertEqual(bundle.csrf_token, "csrf-" + "c" * 38)
        encoded = json.dumps(bundle.record, sort_keys=True)
        self.assertNotIn(bundle.session_id, encoded)
        self.assertNotIn(bundle.csrf_token, encoded)
        self.assertEqual(bundle.record["schema"], "onion-sentinel-human-session-v1")
        self.assertEqual(bundle.record["principal_kind"], "human_session")
        self.assertEqual(bundle.record["principal_id"], "operator-7")
        self.assertEqual(bundle.record["role"], "analyst")
        self.assertEqual(bundle.record["absolute_expires_at"], 4_600)
        self.assertEqual(bundle.record["idle_expires_at"], 1_600)

    def test_valid_session_decision_returns_bounded_human_principal(self) -> None:
        decision = sessions.session_decision(
            self.bundle().record,
            now_timestamp=1_500,
            expected_policy_generation=4,
        )
        self.assertTrue(decision.authorized)
        self.assertEqual(decision.reason, "authorized")
        self.assertEqual(decision.principal.principal_kind, "human_session")
        self.assertEqual(decision.principal.principal_id, "operator-7")
        self.assertEqual(decision.principal.role, "analyst")

    def test_expiry_policy_generation_and_role_fail_closed(self) -> None:
        record = self.bundle().record
        cases = (
            (record, 1_600, 4, "idle_expired"),
            (record, 4_600, 4, "absolute_expired"),
            (record, 1_001, 5, "policy_generation_mismatch"),
            ({**record, "role": "service"}, 1_001, 4, "invalid_role"),
            (
                {**record, "principal_kind": "service_identity"},
                1_001,
                4,
                "invalid_principal_kind",
            ),
        )
        for candidate, now, generation, reason in cases:
            with self.subTest(reason=reason):
                decision = sessions.session_decision(
                    candidate,
                    now_timestamp=now,
                    expected_policy_generation=generation,
                )
                self.assertFalse(decision.authorized)
                self.assertEqual(decision.reason, reason)
                self.assertIsNone(decision.principal)

    def test_malformed_and_legacy_records_are_rejected_by_enforcement(self) -> None:
        for record in (
            None,
            [],
            {},
            {"created_at": 1_000, "expires_at": 4_600, "client_ip": "127.0.0.1"},
            {**self.bundle().record, "csrf_digest": "not-a-digest"},
        ):
            with self.subTest(record=record):
                decision = sessions.session_decision(
                    record,
                    now_timestamp=1_001,
                    expected_policy_generation=4,
                )
                self.assertFalse(decision.authorized)
                self.assertIsNone(decision.principal)

    def test_csrf_is_constant_shape_bound_and_fail_closed(self) -> None:
        record = self.bundle().record
        csrf_token = "csrf-" + "c" * 38
        self.assertTrue(sessions.csrf_authorized(csrf_token, record))
        for value in ("", "wrong", csrf_token + "extra", None):
            with self.subTest(value=value):
                self.assertFalse(sessions.csrf_authorized(value, record))
        self.assertFalse(
            sessions.csrf_authorized(
                csrf_token,
                {**record, "csrf_digest": "0" * 64},
            )
        )

    def test_touch_extends_idle_only_within_absolute_expiry(self) -> None:
        record = self.bundle().record
        touched = sessions.touch_session_record(
            record,
            now_timestamp=1_500,
            idle_ttl_seconds=600,
        )
        self.assertEqual(touched["last_activity_at"], 1_500)
        self.assertEqual(touched["idle_expires_at"], 2_100)
        self.assertEqual(touched["absolute_expires_at"], 4_600)
        capped = sessions.touch_session_record(
            touched,
            now_timestamp=4_500,
            idle_ttl_seconds=600,
        )
        self.assertEqual(capped["idle_expires_at"], 4_600)
        self.assertEqual(record["last_activity_at"], 1_000)

    def test_creation_rejects_unknown_roles_and_invalid_lifetimes(self) -> None:
        arguments = {
            "principal_id": "operator-7",
            "role": "analyst",
            "now_timestamp": 1_000,
            "absolute_ttl_seconds": 3_600,
            "idle_ttl_seconds": 600,
            "policy_generation": 4,
            "client_fingerprint": "client-digest",
            "new_token": lambda: "x" * 43,
        }
        for changes in (
            {"role": "service"},
            {"principal_id": ""},
            {"absolute_ttl_seconds": 0},
            {"idle_ttl_seconds": 3_601},
            {"policy_generation": -1},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(sessions.SessionPolicyError):
                    sessions.create_session_bundle(**{**arguments, **changes})


if __name__ == "__main__":
    unittest.main()
