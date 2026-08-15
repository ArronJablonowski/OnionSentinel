from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_admin_audit_chain as chain  # noqa: E402
import portal_admin_audit_store as store  # noqa: E402


KEY = b"fixture-audit-key-material-32-bytes-minimum"


def fields(index: int) -> dict[str, object]:
    return {
        "occurred_at": f"2026-08-15T05:{index % 60:02d}:00Z",
        "request_id": f"request-{index}",
        "principal_fingerprint": "1" * 64,
        "role": "administrator",
        "permission": "settings.manage",
        "action": "settings-save",
        "target_type": "settings",
        "target_digest": f"{index % 16:x}" * 64,
        "outcome": "allowed",
        "http_status": 200,
        "reason_code": "authorized",
    }


class PortalAdminAuditStoreTests(unittest.TestCase):
    def test_audit_signing_identity_is_distinct_and_operator_managed(self) -> None:
        catalog = json.loads(
            (ROOT / "operations/security/credential-governance.json").read_text(
                encoding="utf-8"
            )
        )
        entries = {entry["id"]: entry for entry in catalog["entries"]}
        audit_identity = entries["dashboard.admin-audit-signing"]
        self.assertEqual(audit_identity["kind"], "host-local-signing-key")
        self.assertEqual(
            audit_identity["storage_class"], "mac-owner-runtime-file"
        )
        self.assertEqual(
            audit_identity["bindings"], ["file:mac-admin-audit-signing-key"]
        )
        self.assertEqual(
            audit_identity["allowed_actions"], ["dashboard.admin-audit-hmac"]
        )
        self.assertNotEqual(
            audit_identity["bindings"], entries["dashboard.admin-session"]["bindings"]
        )

    def test_missing_ledger_is_empty_and_append_is_owner_only_verified_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "private" / "admin-audit.jsonl"
            self.assertEqual(store.load_verified_events(path, signing_key=KEY), [])
            first = store.append_verified_event(path, fields(1), signing_key=KEY)
            second = store.append_verified_event(path, fields(2), signing_key=KEY)
            events = store.load_verified_events(path, signing_key=KEY)
            self.assertEqual(events, [first, second])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertTrue(chain.verify_chain(events, signing_key=KEY).valid)
            self.assertEqual([event["sequence"] for event in events], [1, 2])
            self.assertFalse(any(path.parent.glob(".*.tmp")))

    def test_tampered_ledger_fails_before_append_and_is_not_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            store.append_verified_event(path, fields(1), signing_key=KEY)
            event = json.loads(path.read_text(encoding="utf-8"))
            event["http_status"] = 403
            path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            original = path.read_bytes()
            with self.assertRaisesRegex(store.AuditStoreError, "verification failed"):
                store.append_verified_event(path, fields(2), signing_key=KEY)
            self.assertEqual(path.read_bytes(), original)

    def test_symlink_directory_and_malformed_ledger_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.jsonl"
            target.write_text("", encoding="utf-8")
            link = root / "link.jsonl"
            link.symlink_to(target)
            directory = root / "directory"
            directory.mkdir()
            malformed = root / "malformed.jsonl"
            malformed.write_text("not-json\n", encoding="utf-8")
            for path in (link, directory, malformed):
                with self.subTest(path=path):
                    with self.assertRaises(store.AuditStoreError):
                        store.load_verified_events(path, signing_key=KEY)

    def test_existing_ledger_and_parent_must_remain_owner_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "private"
            parent.mkdir()
            path = parent / "admin-audit.jsonl"
            path.write_text("", encoding="utf-8")
            os.chmod(path, 0o600)
            os.chmod(parent, 0o755)
            with self.assertRaisesRegex(store.AuditStoreError, "parent"):
                store.load_verified_events(path, signing_key=KEY)

            os.chmod(parent, 0o700)
            os.chmod(path, 0o640)
            with self.assertRaisesRegex(store.AuditStoreError, "owner-only"):
                store.load_verified_events(path, signing_key=KEY)

    def test_size_event_and_line_bounds_fail_without_partial_append(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oversized = root / "oversized.jsonl"
            oversized.write_bytes(b"x" * 65)
            os.chmod(oversized, 0o600)
            with self.assertRaisesRegex(store.AuditStoreError, "size limit"):
                store.load_verified_events(
                    oversized,
                    signing_key=KEY,
                    maximum_bytes=64,
                )

            ledger = root / "bounded.jsonl"
            store.append_verified_event(
                ledger, fields(1), signing_key=KEY, maximum_events=1
            )
            original = ledger.read_bytes()
            with self.assertRaisesRegex(store.AuditStoreError, "event limit"):
                store.append_verified_event(
                    ledger, fields(2), signing_key=KEY, maximum_events=1
                )
            self.assertEqual(ledger.read_bytes(), original)

    def test_concurrent_appends_serialize_one_valid_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admin-audit.jsonl"
            with ThreadPoolExecutor(max_workers=8) as pool:
                events = list(
                    pool.map(
                        lambda index: store.append_verified_event(
                            path, fields(index), signing_key=KEY
                        ),
                        range(1, 25),
                    )
                )
            persisted = store.load_verified_events(path, signing_key=KEY)
            self.assertEqual(len(events), 24)
            self.assertEqual(len(persisted), 24)
            self.assertEqual(
                [event["sequence"] for event in persisted], list(range(1, 25))
            )
            self.assertTrue(chain.verify_chain(persisted, signing_key=KEY).valid)

    def test_wrong_key_and_unknown_fields_never_create_or_replace_ledger(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "admin-audit.jsonl"
            invalid = {**fields(1), "request_body": "must-not-persist"}
            with self.assertRaises(chain.AuditContractError):
                store.append_verified_event(path, invalid, signing_key=KEY)
            self.assertFalse(path.exists())
            store.append_verified_event(path, fields(1), signing_key=KEY)
            original = path.read_bytes()
            with self.assertRaises(store.AuditStoreError):
                store.load_verified_events(
                    path,
                    signing_key=b"different-signing-key-material-32-bytes",
                )
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
