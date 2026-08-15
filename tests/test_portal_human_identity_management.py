from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

import portal_human_identity_cli as cli  # noqa: E402
from portal_human_identity_management import (  # noqa: E402
    HumanIdentityManagementError,
    remove_human_identity,
    set_human_identity,
)
from portal_human_identity_store import (  # noqa: E402
    authenticate_human_identity,
    load_enforcement_human_identity_store,
)


class PortalHumanIdentityManagementTests(unittest.TestCase):
    def private_path(self, root: Path) -> Path:
        config = root / "config"
        config.mkdir(mode=0o700)
        os.chmod(config, 0o700)
        return config / "onion-sentinel-human-identities.json"

    def test_set_replace_and_remove_are_atomic_generation_bound_updates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.private_path(Path(tmp))
            created = set_human_identity(
                path,
                username="viewer.one",
                principal_id="viewer-1",
                role="viewer",
                password="viewer password!",
                random_bytes=lambda size: b"a" * size,
            )
            self.assertEqual(
                (created.action, created.generation, created.identity_count),
                ("set", 1, 1),
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            first = load_enforcement_human_identity_store(path)
            self.assertEqual(
                authenticate_human_identity(
                    "viewer.one", "viewer password!", first
                ).role,
                "viewer",
            )

            replaced = set_human_identity(
                path,
                username="viewer.one",
                principal_id="analyst-1",
                role="analyst",
                password="analyst password!",
                random_bytes=lambda size: b"b" * size,
            )
            self.assertEqual(replaced.generation, 2)
            second = load_enforcement_human_identity_store(path)
            self.assertIsNone(
                authenticate_human_identity(
                    "viewer.one", "viewer password!", second
                )
            )
            self.assertEqual(
                authenticate_human_identity(
                    "viewer.one", "analyst password!", second
                ).role,
                "analyst",
            )

            removed = remove_human_identity(path, username="viewer.one")
            self.assertEqual(
                (removed.action, removed.generation, removed.identity_count),
                ("remove", 3, 0),
            )
            empty = load_enforcement_human_identity_store(path)
            self.assertEqual(empty.identities, {})

    def test_invalid_update_never_replaces_the_last_good_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self.private_path(Path(tmp))
            set_human_identity(
                path,
                username="viewer.one",
                principal_id="viewer-1",
                role="viewer",
                password="viewer password!",
                random_bytes=lambda size: b"a" * size,
            )
            before = path.read_bytes()
            with self.assertRaises(HumanIdentityManagementError):
                set_human_identity(
                    path,
                    username="admin.two",
                    principal_id="admin-2",
                    role="administrator",
                    password="administrator password",
                    random_bytes=lambda size: b"b" * size,
                )
            self.assertEqual(path.read_bytes(), before)

    def test_cli_requires_stopped_service_and_never_projects_password_material(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp)
            self.private_path(stack)
            stdout = io.StringIO()
            stderr = io.StringIO()
            denied = cli.main(
                [
                    "--stack-dir", str(stack),
                    "--set", "viewer.one",
                    "--principal-id", "viewer-1",
                    "--role", "viewer",
                ],
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(denied, 2)
            self.assertIn("must be stopped", stderr.getvalue())

            secrets = iter(("viewer password!", "viewer password!"))
            stdout = io.StringIO()
            stderr = io.StringIO()
            allowed = cli.main(
                [
                    "--stack-dir", str(stack),
                    "--set", "viewer.one",
                    "--principal-id", "viewer-1",
                    "--role", "viewer",
                    "--confirm-service-stopped",
                ],
                read_password=lambda _prompt: next(secrets),
                stdout=stdout,
                stderr=stderr,
            )
            self.assertEqual(allowed, 0, stderr.getvalue())
            receipt = json.loads(stdout.getvalue())
            self.assertEqual(receipt["role"], "viewer")
            self.assertNotIn("password", stdout.getvalue())
            self.assertNotIn("hash", stdout.getvalue())
            self.assertNotIn("salt", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
