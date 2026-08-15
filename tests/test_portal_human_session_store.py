from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_human_session_store as store  # noqa: E402
import portal_session_principal as sessions  # noqa: E402


class PortalHumanSessionStoreTests(unittest.TestCase):
    def bundle(self) -> sessions.SessionBundle:
        values = iter(("session-" + "s" * 36, "csrf-" + "c" * 38))
        return sessions.create_session_bundle(
            principal_id="local-administrator",
            role="administrator",
            now_timestamp=1_000,
            absolute_ttl_seconds=3_600,
            idle_ttl_seconds=600,
            policy_generation=2,
            client_fingerprint="client-fingerprint",
            new_token=lambda: next(values),
        )

    def test_put_load_replace_and_delete_never_persist_browser_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admin-state" / ".human_sessions.json"
            bundle = self.bundle()
            store.put_session_record(path, bundle.session_id, bundle.record)
            self.assertEqual(
                store.load_session_record(path, bundle.session_id),
                bundle.record,
            )
            encoded = path.read_text(encoding="utf-8")
            self.assertNotIn(bundle.session_id, encoded)
            self.assertNotIn(bundle.csrf_token, encoded)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

            touched = sessions.touch_session_record(
                bundle.record,
                now_timestamp=1_200,
                idle_ttl_seconds=600,
            )
            self.assertTrue(
                store.replace_session_record(
                    path,
                    bundle.session_id,
                    expected_record=bundle.record,
                    replacement=touched,
                )
            )
            self.assertEqual(
                store.load_session_record(path, bundle.session_id), touched
            )
            self.assertTrue(store.delete_session_record(path, bundle.session_id))
            self.assertIsNone(
                store.load_session_record(path, bundle.session_id)
            )

    def test_compare_and_replace_refuses_a_stale_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admin-state" / ".human_sessions.json"
            bundle = self.bundle()
            store.put_session_record(path, bundle.session_id, bundle.record)
            stale = {**bundle.record, "last_activity_at": 999}
            self.assertFalse(
                store.replace_session_record(
                    path,
                    bundle.session_id,
                    expected_record=stale,
                    replacement=bundle.record,
                )
            )
            self.assertEqual(
                store.load_session_record(path, bundle.session_id),
                bundle.record,
            )

    def test_store_rejects_unsafe_custody_and_malformed_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "admin-state"
            parent.mkdir(mode=0o700)
            path = parent / ".human_sessions.json"
            bundle = self.bundle()
            store.put_session_record(path, bundle.session_id, bundle.record)
            os.chmod(path, 0o640)
            with self.assertRaises(store.HumanSessionStoreError):
                store.load_session_record(path, bundle.session_id)
            os.chmod(path, 0o600)
            os.chmod(parent, 0o755)
            with self.assertRaises(store.HumanSessionStoreError):
                store.load_session_record(path, bundle.session_id)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admin-state" / ".human_sessions.json"
            with self.assertRaises(store.HumanSessionStoreError):
                store.put_session_record(
                    path,
                    "session-" + "s" * 36,
                    {**self.bundle().record, "unexpected": "must-fail"},
                )

    def test_bounded_envelope_fails_closed_without_partial_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "admin-state"
            parent.mkdir(mode=0o700)
            path = parent / ".human_sessions.json"
            path.write_text(
                json.dumps(
                    {
                        "schema": store.STORE_SCHEMA,
                        "sessions": {"not-a-digest": self.bundle().record},
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            with self.assertRaises(store.HumanSessionStoreError):
                store.load_session_record(path, "session-" + "s" * 36)


if __name__ == "__main__":
    unittest.main()
