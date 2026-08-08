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

from portal_cli_provider_readiness import (  # noqa: E402
    enabled_cli_harnesses_ready,
    hermes_auth_readiness_error,
    resolve_cli_harness,
)


class CliProviderReadinessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _auth_file(self, payload: object) -> Path:
        path = self.root / "auth.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_resolver_accepts_only_matching_executable_regular_file(self) -> None:
        executable = self.root / "hermes"
        executable.write_text("#!/bin/sh\n", encoding="utf-8")
        executable.chmod(0o700)
        self.assertEqual(resolve_cli_harness(
            executable, "hermes", home=self.root, discover=lambda name: None
        ), executable)
        self.assertIsNone(resolve_cli_harness(
            executable, "openclaw", home=self.root, discover=lambda name: None
        ))
        executable.chmod(0o600)
        self.assertIsNone(resolve_cli_harness(
            executable, "hermes", home=self.root, discover=lambda name: None
        ))

    def test_hermes_auth_accepts_provider_or_valid_pool_without_exposing_data(self) -> None:
        provider = self._auth_file({
            "providers": {"openai-codex": {"account": "dedicated"}}
        })
        self.assertEqual(hermes_auth_readiness_error(provider, 2 * 1024 * 1024), "")
        pool = self._auth_file({
            "credential_pool": {
                "openai-codex": [{"provider": "openai-codex", "opaque": "value"}]
            }
        })
        self.assertEqual(hermes_auth_readiness_error(pool, 2 * 1024 * 1024), "")

    def test_hermes_auth_rejects_symlink_permissions_size_and_wrong_provider(self) -> None:
        auth = self._auth_file({"providers": {"other": {"value": "unused"}}})
        self.assertIn("does not contain", hermes_auth_readiness_error(auth, 1000))
        auth.chmod(0o644)
        self.assertIn("0600", hermes_auth_readiness_error(auth, 1000))
        auth.chmod(0o600)
        self.assertIn("exceeds", hermes_auth_readiness_error(auth, 2))
        link = self.root / "link.json"
        link.symlink_to(auth)
        self.assertIn("non-symlink", hermes_auth_readiness_error(link, 1000))

    def test_enabled_provider_checks_executable_then_hermes_auth(self) -> None:
        calls = []
        settings = {"hermes_agent_enabled": True, "hermes_agent_path": "hermes"}
        ready, error = enabled_cli_harnesses_ready(
            settings,
            boolean_setting=bool,
            resolve=lambda configured, basename: self.root / basename,
            hermes_auth_error=lambda: calls.append("auth") or "credential unavailable",
        )
        self.assertFalse(ready)
        self.assertEqual(error, "credential unavailable")
        self.assertEqual(calls, ["auth"])

    def test_disabled_providers_require_no_files_or_credentials(self) -> None:
        ready, error = enabled_cli_harnesses_ready(
            {},
            boolean_setting=bool,
            resolve=lambda configured, basename: (_ for _ in ()).throw(AssertionError()),
            hermes_auth_error=lambda: (_ for _ in ()).throw(AssertionError()),
        )
        self.assertTrue(ready)
        self.assertEqual(error, "")


if __name__ == "__main__":
    unittest.main()
