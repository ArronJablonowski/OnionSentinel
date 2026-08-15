from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_human_identity_store import (  # noqa: E402
    HumanIdentityConfigurationError,
    authenticate_human_identity,
    load_enforcement_human_identity_store,
)


def password_record(password: str, salt: bytes = b"0123456789abcdef") -> dict:
    iterations = 200_000
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        ).hex(),
    }


class PortalHumanIdentityStoreTests(unittest.TestCase):
    def write_store(self, root: Path, identities: list[dict], *, generation: int = 7) -> Path:
        root.mkdir(mode=0o700)
        os.chmod(root, 0o700)
        path = root / "onion-sentinel-human-identities.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "onion-sentinel-human-identities-v1",
                    "generation": generation,
                    "identities": identities,
                }
            ),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        return path

    def test_missing_optional_store_preserves_local_administrator_only_rollout(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config"
            config.mkdir(mode=0o700)
            os.chmod(config, 0o700)
            store = load_enforcement_human_identity_store(
                config / "onion-sentinel-human-identities.json"
            )
        self.assertEqual(store.generation, 0)
        self.assertEqual(store.identities, {})

    def test_owner_store_authenticates_exact_server_mapped_viewer_and_analyst(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.write_store(
                Path(tmp) / "config",
                [
                    {
                        "username": "viewer.one",
                        "principal_id": "viewer-1",
                        "role": "viewer",
                        "password": password_record("viewer password"),
                    },
                    {
                        "username": "analyst.one",
                        "principal_id": "analyst-1",
                        "role": "analyst",
                        "password": password_record(
                            "analyst password", b"fedcba9876543210"
                        ),
                    },
                ],
            )
            store = load_enforcement_human_identity_store(path)

        viewer = authenticate_human_identity(
            "viewer.one", "viewer password", store
        )
        analyst = authenticate_human_identity(
            "analyst.one", "analyst password", store
        )
        self.assertEqual(
            (viewer.principal_id, viewer.role), ("viewer-1", "viewer")
        )
        self.assertEqual(
            (analyst.principal_id, analyst.role), ("analyst-1", "analyst")
        )
        self.assertIsNone(
            authenticate_human_identity("viewer.one", "wrong", store)
        )
        self.assertIsNone(
            authenticate_human_identity("unknown", "viewer password", store)
        )

    def test_store_rejects_privileged_or_ambiguous_identity_configuration(self):
        invalid_sets = (
            [
                {
                    "username": "admin.two",
                    "principal_id": "admin-2",
                    "role": "administrator",
                    "password": password_record("password password"),
                }
            ],
            [
                {
                    "username": "local-administrator",
                    "principal_id": "viewer-1",
                    "role": "viewer",
                    "password": password_record("password password"),
                }
            ],
            [
                {
                    "username": "duplicate",
                    "principal_id": "viewer-1",
                    "role": "viewer",
                    "password": password_record("password password"),
                },
                {
                    "username": "duplicate",
                    "principal_id": "analyst-1",
                    "role": "analyst",
                    "password": password_record(
                        "password password", b"fedcba9876543210"
                    ),
                },
            ],
        )
        for identities in invalid_sets:
            with self.subTest(identities=identities), tempfile.TemporaryDirectory() as tmp:
                path = self.write_store(Path(tmp) / "config", identities)
                with self.assertRaises(HumanIdentityConfigurationError):
                    load_enforcement_human_identity_store(path)

    def test_store_requires_an_owner_only_regular_file_without_extra_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config"
            identity = {
                "username": "viewer.one",
                "principal_id": "viewer-1",
                "role": "viewer",
                "password": password_record("viewer password"),
            }
            path = self.write_store(config, [identity])
            os.chmod(path, 0o640)
            with self.assertRaisesRegex(
                HumanIdentityConfigurationError, "owner-only regular file"
            ):
                load_enforcement_human_identity_store(path)

            os.chmod(path, 0o600)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["browser_role"] = "viewer"
            path.write_text(json.dumps(payload), encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(
                HumanIdentityConfigurationError, "invalid format"
            ):
                load_enforcement_human_identity_store(path)


if __name__ == "__main__":
    unittest.main()
