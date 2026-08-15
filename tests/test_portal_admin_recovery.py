from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_admin_recovery as recovery  # noqa: E402
from portal_admin_session_store import verify_admin_password  # noqa: E402
from portal_human_session_store import STORE_SCHEMA  # noqa: E402


class PortalAdminRecoveryTests(unittest.TestCase):
    def private_directory(self, path: Path) -> None:
        path.mkdir(parents=True, mode=0o700)
        os.chmod(path, 0o700)

    def private_file(self, path: Path, payload: str) -> None:
        path.write_text(payload, encoding="utf-8")
        os.chmod(path, 0o600)

    def test_recovery_resets_password_and_revokes_both_session_generations(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp) / "n8n-local"
            config = stack / "config"
            state = stack / "admin-state"
            self.private_directory(config)
            self.private_directory(state)
            password_path = config / recovery.ADMIN_PASSWORD_FILENAME
            legacy_path = state / recovery.LEGACY_SESSION_FILENAME
            human_path = state / recovery.HUMAN_SESSION_FILENAME
            self.private_file(password_path, '{"old":"record"}\n')
            self.private_file(legacy_path, '{"session-digest":{}}\n')
            self.private_file(
                human_path,
                json.dumps(
                    {
                        "schema": STORE_SCHEMA,
                        "sessions": {"f" * 64: {}},
                    }
                )
                + "\n",
            )
            audit_path = stack / "logs" / "onion-sentinel-admin-audit.jsonl"
            self.private_directory(audit_path.parent)
            self.private_file(audit_path, "retained-audit-chain\n")

            result = recovery.recover_admin_access(
                stack,
                new_password="correct horse battery staple",
                revoke_sessions=True,
                random_bytes=lambda length: b"s" * length,
            )

            record = json.loads(password_path.read_text(encoding="utf-8"))
            self.assertTrue(
                verify_admin_password("correct horse battery staple", record)
            )
            self.assertFalse(verify_admin_password("wrong password", record))
            self.assertEqual(json.loads(legacy_path.read_text()), {})
            self.assertEqual(
                json.loads(human_path.read_text()),
                {"schema": STORE_SCHEMA, "sessions": {}},
            )
            self.assertEqual(audit_path.read_text(), "retained-audit-chain\n")
            self.assertEqual(stat.S_IMODE(password_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(legacy_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(human_path.stat().st_mode), 0o600)
            self.assertEqual(
                result,
                recovery.AdminRecoveryResult(
                    password_reset=True,
                    legacy_sessions_revoked=True,
                    human_sessions_revoked=True,
                ),
            )

    def test_revoke_only_is_idempotent_and_does_not_create_password_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp) / "n8n-local"
            self.private_directory(stack / "config")
            self.private_directory(stack / "admin-state")
            first = recovery.recover_admin_access(
                stack,
                new_password=None,
                revoke_sessions=True,
            )
            second = recovery.recover_admin_access(
                stack,
                new_password=None,
                revoke_sessions=True,
            )
            self.assertFalse(first.password_reset)
            self.assertEqual(first, second)
            self.assertFalse(
                (stack / "config" / recovery.ADMIN_PASSWORD_FILENAME).exists()
            )

    def test_unsafe_custody_fails_before_replacing_any_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp) / "n8n-local"
            config = stack / "config"
            state = stack / "admin-state"
            self.private_directory(config)
            self.private_directory(state)
            legacy = state / recovery.LEGACY_SESSION_FILENAME
            self.private_file(legacy, '{"keep":"unchanged"}\n')
            target = Path(tmp) / "target.json"
            target.write_text("outside\n", encoding="utf-8")
            (state / recovery.HUMAN_SESSION_FILENAME).symlink_to(target)

            with self.assertRaisesRegex(
                recovery.AdminRecoveryError, "owner-only regular file"
            ):
                recovery.recover_admin_access(
                    stack,
                    new_password="correct horse battery staple",
                    revoke_sessions=True,
                    random_bytes=lambda length: b"s" * length,
                )

            self.assertEqual(legacy.read_text(), '{"keep":"unchanged"}\n')
            self.assertEqual(target.read_text(), "outside\n")
            self.assertFalse(
                (config / recovery.ADMIN_PASSWORD_FILENAME).exists()
            )

    def test_password_policy_errors_never_echo_secret_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp) / "n8n-local"
            self.private_directory(stack / "config")
            self.private_directory(stack / "admin-state")
            secret = "too-short"
            with self.assertRaises(recovery.AdminRecoveryError) as raised:
                recovery.recover_admin_access(
                    stack,
                    new_password=secret,
                    revoke_sessions=False,
                )
            self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
