import datetime as dt
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))
import portal_admin_session_store as session_store  # noqa: E402


def load_portal():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    name = "report_portal_admin_session_contract"
    spec = importlib.util.spec_from_file_location(name, DASHBOARD / "report_portal.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PortalAdminSessionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.portal = load_portal()

    def test_admin_token_is_persistent_validated_and_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "state" / ".token"
            with mock.patch.object(self.portal, "ADMIN_TOKEN_FILE", token_file):
                token = self.portal.ensure_admin_token()
                self.assertRegex(token, r"^[a-f0-9]{64}$")
                self.assertEqual(self.portal.ensure_admin_token(), token)
                self.assertEqual(token_file.stat().st_mode & 0o777, 0o600)
                token_file.write_text("invalid", encoding="utf-8")
                self.assertNotEqual(self.portal.ensure_admin_token(), "invalid")

    def test_password_verification_requires_pbkdf2_and_minimum_iterations(self):
        with tempfile.TemporaryDirectory() as tmp:
            password_file = Path(tmp) / "password.json"
            salt = b"0123456789abcdef"
            password = "correct horse battery staple"
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
            record = {
                "algorithm": "pbkdf2_sha256",
                "iterations": 200_000,
                "salt": salt.hex(),
                "hash": digest.hex(),
            }
            password_file.write_text(json.dumps(record), encoding="utf-8")
            with mock.patch.object(self.portal, "ADMIN_PASSWORD_FILE", password_file):
                self.assertTrue(self.portal.admin_password_configured())
                self.assertTrue(self.portal.verify_admin_password(password))
                self.assertFalse(self.portal.verify_admin_password("wrong"))
                record["iterations"] = 199_999
                password_file.write_text(json.dumps(record), encoding="utf-8")
                self.assertFalse(self.portal.verify_admin_password(password))

    def test_enforcement_password_record_requires_strict_owner_only_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "password.json"
            salt = b"0123456789abcdef"
            digest = hashlib.pbkdf2_hmac(
                "sha256", b"correct horse battery staple", salt, 200_000
            )
            record = {
                "algorithm": "pbkdf2_sha256",
                "iterations": 200_000,
                "salt": salt.hex(),
                "hash": digest.hex(),
            }
            path.write_text(json.dumps(record), encoding="utf-8")
            os.chmod(path, 0o600)
            self.assertEqual(
                session_store.load_enforcement_admin_password_record(path),
                record,
            )
            os.chmod(path, 0o640)
            with self.assertRaises(
                session_store.AdminPasswordConfigurationError
            ):
                session_store.load_enforcement_admin_password_record(path)
            path.unlink()
            target = root / "target.json"
            target.write_text(json.dumps(record), encoding="utf-8")
            path.symlink_to(target)
            with self.assertRaises(
                session_store.AdminPasswordConfigurationError
            ):
                session_store.load_enforcement_admin_password_record(path)

    def test_enforcement_password_record_rejects_missing_or_ambiguous_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "password.json"
            with self.assertRaises(
                session_store.AdminPasswordConfigurationError
            ):
                session_store.load_enforcement_admin_password_record(path)
            path.write_text(
                json.dumps(
                    {
                        "algorithm": "pbkdf2_sha256",
                        "iterations": True,
                        "salt": "00" * 16,
                        "hash": "00" * 32,
                        "extra": "field",
                    }
                ),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            with self.assertRaises(
                session_store.AdminPasswordConfigurationError
            ):
                session_store.load_enforcement_admin_password_record(path)

    def test_session_pruning_and_creation_store_only_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state"
            sessions_file = state / "sessions.json"
            now = dt.datetime(2026, 8, 10, tzinfo=dt.timezone.utc)
            now_ts = int(now.timestamp())
            sessions_file.parent.mkdir()
            sessions_file.write_text(
                json.dumps({
                    "expired": {"expires_at": now_ts - 1},
                    "active": {"expires_at": now_ts + 1},
                }),
                encoding="utf-8",
            )
            with (
                mock.patch.object(self.portal, "ADMIN_STATE_DIR", state),
                mock.patch.object(self.portal, "ADMIN_SESSIONS_FILE", sessions_file),
                mock.patch.object(self.portal.dt, "datetime", wraps=dt.datetime) as clock,
                mock.patch.object(self.portal.secrets, "token_urlsafe", return_value="raw-session"),
            ):
                clock.now.return_value = now
                self.assertEqual(set(self.portal.prune_admin_sessions()), {"active"})
                session_id = self.portal.create_admin_session("127.0.0.1")
                self.assertEqual(session_id, "raw-session")
                stored = self.portal.load_admin_sessions()
                self.assertEqual(state.stat().st_mode & 0o777, 0o700)
                self.assertEqual(sessions_file.stat().st_mode & 0o777, 0o600)
                self.assertNotIn("raw-session", stored)
                hashed = self.portal.admin_session_hash("raw-session")
                self.assertEqual(stored[hashed]["client_ip"], "127.0.0.1")
                self.portal.destroy_admin_session("raw-session")
                self.assertNotIn(hashed, self.portal.load_admin_sessions())

    def test_legacy_session_save_refuses_symlink_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir(mode=0o700)
            target = root / "outside.json"
            target.write_text('{"outside":true}\n', encoding="utf-8")
            sessions = state / ".admin_sessions.json"
            sessions.symlink_to(target)
            with self.assertRaises(
                session_store.AdminSessionStoreError
            ):
                session_store.save_admin_sessions(
                    state, sessions, {"digest": {"expires_at": 2_000}}
                )
            self.assertEqual(target.read_text(), '{"outside":true}\n')

    def test_enforcement_validates_legacy_session_custody_without_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            sessions = state / ".admin_sessions.json"
            self.assertEqual(
                session_store.validate_admin_session_store(state, sessions), 0
            )
            self.assertFalse(state.exists())
            state.mkdir(mode=0o700)
            sessions.write_text('{"digest":{"expires_at":2000}}\n')
            os.chmod(sessions, 0o600)
            self.assertEqual(
                session_store.validate_admin_session_store(state, sessions), 1
            )
            os.chmod(sessions, 0o640)
            with self.assertRaises(session_store.AdminSessionStoreError):
                session_store.validate_admin_session_store(state, sessions)

    def test_legacy_session_store_must_remain_inside_state_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            outside = root / "outside.json"
            with self.assertRaises(session_store.AdminSessionStoreError):
                session_store.save_admin_sessions(state, outside, {})

    def test_cookie_parsing_and_headers_preserve_security_attributes(self):
        self.assertEqual(
            self.portal.parse_cookie_header("a=1; lan_portal_admin=session=part"),
            {"a": "1", "lan_portal_admin": "session=part"},
        )
        self.assertEqual(
            self.portal.admin_session_cookie_header("abc", 60),
            "lan_portal_admin=abc; Path=/; Max-Age=60; HttpOnly; SameSite=Strict",
        )
        self.assertEqual(
            self.portal.expired_admin_session_cookie_header(),
            "lan_portal_admin=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
        )


if __name__ == "__main__":
    unittest.main()
