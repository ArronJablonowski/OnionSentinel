from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_human_session_runtime as runtime  # noqa: E402


class PortalHumanSessionRuntimeTests(unittest.TestCase):
    def test_legacy_runtime_never_creates_or_reads_session_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            service = runtime.load_human_session_runtime(
                mode="legacy",
                home=home,
            )
            self.assertFalse(service.enabled)
            self.assertIsNone(
                service.create_session(
                    "session-" + "s" * 36,
                    client_identity="192.0.2.4",
                    now_timestamp=1_000,
                    new_token=lambda: "csrf-" + "c" * 38,
                )
            )
            self.assertEqual(list(home.rglob("*")), [])

    def test_observe_runtime_creates_resolves_touches_and_revokes(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = runtime.load_human_session_runtime(
                mode="observe",
                home=Path(tmp),
            )
            session_id = "session-" + "s" * 36
            csrf_token = "csrf-" + "c" * 38
            self.assertEqual(
                service.create_session(
                    session_id,
                    client_identity="192.0.2.4",
                    now_timestamp=1_000,
                    new_token=lambda: csrf_token,
                ),
                csrf_token,
            )
            denied = service.resolve_session(
                session_id,
                csrf_value="wrong",
                now_timestamp=1_200,
            )
            self.assertEqual(denied.reason, "authorized")
            self.assertEqual(denied.principal.role, "administrator")
            self.assertFalse(denied.csrf_authorized)

            allowed = service.resolve_session(
                session_id,
                csrf_value=csrf_token,
                now_timestamp=1_300,
            )
            self.assertTrue(allowed.csrf_authorized)
            self.assertEqual(allowed.principal.principal_id, "local-administrator")
            self.assertTrue(service.destroy_session(session_id))
            missing = service.resolve_session(
                session_id,
                csrf_value=csrf_token,
                now_timestamp=1_301,
            )
            self.assertIsNone(missing.principal)
            self.assertEqual(missing.reason, "session_missing")

    def test_admin_enforcement_uses_the_versioned_store_and_rbac_stays_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = runtime.load_human_session_runtime(
                mode="admin-enforce",
                home=Path(tmp),
            )
            self.assertTrue(service.enabled)
            self.assertTrue(service.enforcing)
            token = service.create_session(
                "session-" + "s" * 36,
                client_identity="192.0.2.4",
                now_timestamp=1_000,
                new_token=lambda: "csrf-" + "c" * 38,
            )
            self.assertEqual(token, "csrf-" + "c" * 38)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(runtime.HumanSessionConfigurationError):
                runtime.load_human_session_runtime(
                    mode="rbac-enforce",
                    home=Path(tmp),
                )

    def test_enforcement_fails_closed_when_idle_touch_loses_ownership(self):
        record = runtime.create_session_bundle(
            principal_id="local-administrator",
            role="administrator",
            now_timestamp=1_000,
            absolute_ttl_seconds=1_000,
            idle_ttl_seconds=500,
            policy_generation=1,
            client_fingerprint="1" * 64,
            new_token=iter(("session-" + "s" * 36, "csrf-" + "c" * 38)).__next__,
        ).record
        service = runtime.HumanSessionRuntime(
            mode="admin-enforce",
            store_path=Path("/not-used"),
            load_record=lambda *_args, **_kwargs: record,
            replace_record=lambda *_args, **_kwargs: False,
        )
        result = service.resolve_session(
            "session-" + "s" * 36,
            csrf_value="csrf-" + "c" * 38,
            now_timestamp=1_100,
        )
        self.assertIsNone(result.principal)
        self.assertFalse(result.csrf_authorized)
        self.assertEqual(result.reason, "session_touch_conflict")

    def test_expired_session_is_removed_and_reported_without_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = runtime.HumanSessionRuntime(
                mode="observe",
                store_path=Path(tmp) / "admin-state" / ".human_sessions.json",
                absolute_ttl_seconds=100,
                idle_ttl_seconds=50,
                policy_generation=1,
            )
            session_id = "session-" + "s" * 36
            service.create_session(
                session_id,
                client_identity="192.0.2.4",
                now_timestamp=1_000,
                new_token=lambda: "csrf-" + "c" * 38,
            )
            result = service.resolve_session(
                session_id,
                csrf_value="",
                now_timestamp=1_050,
            )
            self.assertIsNone(result.principal)
            self.assertEqual(result.reason, "idle_expired")
            self.assertEqual(
                service.resolve_session(
                    session_id,
                    csrf_value="",
                    now_timestamp=1_051,
                ).reason,
                "session_missing",
            )

    def test_unsafe_existing_store_fails_observe_startup(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            path = runtime.human_session_store_path(home)
            path.parent.mkdir(parents=True, mode=0o700)
            path.write_text("{}", encoding="utf-8")
            os.chmod(path, 0o640)
            with self.assertRaises(runtime.HumanSessionConfigurationError):
                runtime.load_human_session_runtime(mode="observe", home=home)

    def test_request_failures_are_type_only_and_never_escape(self):
        failures: list[str] = []

        def fail_load(*_args, **_kwargs):
            raise RuntimeError("credential-bearing detail")

        service = runtime.HumanSessionRuntime(
            mode="observe",
            store_path=Path("/not-used"),
            load_record=fail_load,
            failure_sink=failures.append,
        )
        result = service.resolve_session(
            "session-" + "s" * 36,
            csrf_value="csrf-" + "c" * 38,
            now_timestamp=1_000,
        )
        self.assertIsNone(result.principal)
        self.assertEqual(result.reason, "session_observation_failed")
        self.assertEqual(failures, ["RuntimeError"])
        self.assertNotIn("credential-bearing", str(service.snapshot()))

    def test_csrf_cookie_contract_is_host_only_same_site_and_expirable(self):
        token = "csrf-" + "c" * 38
        self.assertEqual(
            runtime.csrf_cookie_header(token, 600),
            "onion_sentinel_csrf=" + token
            + "; Path=/; Max-Age=600; SameSite=Strict",
        )
        self.assertEqual(
            runtime.expired_csrf_cookie_header(),
            "onion_sentinel_csrf=; Path=/; Max-Age=0; SameSite=Strict",
        )


if __name__ == "__main__":
    unittest.main()
