"""Characterize the verified one-time asset migration compatibility CLI."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n/bin/migrate-assets-to-postgres.py"
BIN = MODULE_PATH.parent
SYNTHETIC_TOKEN = "T" * 32


def load_module(name: str = "migrate_assets_to_postgres_projection"):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("asset migration CLI cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(BIN))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(BIN))
    return module


migration = load_module()


class MigrationPorts:
    def __init__(
        self,
        *,
        token: str = SYNTHETIC_TOKEN,
        source_digest: str = "same-digest",
        target_digest: str = "same-digest",
        database_ids: tuple[str, ...] = ("a", "b"),
    ):
        self.inventory = {"assets": [{"asset_id": "synthetic"}]}
        self.dhcp = {
            "observations": [
                {"discovery_id": "b"},
                {"discovery_id": "a"},
            ]
        }
        self.snapshot = {"assets": [{"asset_id": "synthetic"}]}
        self.source_records = [{"asset_id": "synthetic"}]
        self.target_records = [{"asset_id": "synthetic"}]
        self.parent = mock.Mock()
        self.env_value = mock.Mock(return_value=token)
        self.controlled_json = mock.Mock(side_effect=(self.inventory, self.dhcp))
        self.canonical = mock.Mock(
            side_effect=(self.source_records, self.target_records)
        )
        self.digest = mock.Mock(side_effect=(source_digest, target_digest))
        self.request_json = mock.Mock(
            side_effect=(
                {"ok": True, "imported": 1},
                {"ok": True, "retained": 2},
                {"ok": True, "inventory": self.snapshot},
                {
                    "ok": True,
                    "state": {
                        "observations": [
                            {"discovery_id": value} for value in database_ids
                        ]
                    },
                },
            )
        )
        self.atomic_write = mock.Mock()
        for name in (
            "env_value",
            "controlled_json",
            "canonical",
            "digest",
            "request_json",
            "atomic_write",
        ):
            self.parent.attach_mock(getattr(self, name), name)

    def patches(self):
        return (
            mock.patch.object(migration, "env_value", self.env_value),
            mock.patch.object(
                migration, "controlled_json", self.controlled_json
            ),
            mock.patch.object(migration, "canonical", self.canonical),
            mock.patch.object(migration, "digest", self.digest),
            mock.patch.object(migration, "request_json", self.request_json),
            mock.patch.object(migration, "atomic_write", self.atomic_write),
        )


class MigrateAssetsToPostgresProjectionTests(unittest.TestCase):
    def invoke(self, argv, ports: MigrationPorts):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    sys, "argv", ["migrate-assets-to-postgres.py", *argv]
                )
            )
            for patch in ports.patches():
                stack.enter_context(patch)
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(
                stderr
            ):
                result = migration.main()
        return result, stdout.getvalue(), stderr.getvalue()

    def test_env_value_preserves_owner_gate_parsing_and_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "\n".join(
                    (
                        "# synthetic values only",
                        "IGNORED-WITHOUT-EQUALS",
                        " ASSET_STORE_WRITE_TOKEN = first ",
                        "ASSET_STORE_WRITE_TOKEN=second",
                        "N8N_POST_COMMIT_TOKEN=fallback",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            os.chmod(path, 0o600)
            self.assertEqual(
                migration.env_value(path, "ASSET_STORE_WRITE_TOKEN"), "second"
            )
            self.assertEqual(migration.env_value(path, "MISSING"), "fallback")
            os.chmod(path, 0o644)
            with self.assertRaisesRegex(
                ValueError, "runtime environment file is not owner-controlled"
            ):
                migration.env_value(path, "ASSET_STORE_WRITE_TOKEN")

    def test_success_preserves_call_order_payloads_verification_and_output(self):
        ports = MigrationPorts()
        result, stdout, stderr = self.invoke(
            (
                "--env", "/synthetic/runtime.env",
                "--inventory", "/synthetic/inventory.json",
                "--dhcp-state", "/synthetic/dhcp.json",
                "--export", "/synthetic/export.json",
                "--api-url", "http://127.0.0.1:9876/",
                "--replace",
                "--confirm", "MIGRATE-ASSETS-TO-POSTGRESQL",
            ),
            ports,
        )
        self.assertEqual(result, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(
            json.loads(stdout),
            {
                "ok": True,
                "asset_records": 1,
                "asset_digest": "same-digest",
                "dhcp_observations": 2,
                "imported": 1,
                "dhcp_retained": 2,
                "export": "/synthetic/export.json",
            },
        )
        self.assertEqual(
            ports.parent.mock_calls,
            [
                mock.call.env_value(
                    Path("/synthetic/runtime.env"), "ASSET_STORE_WRITE_TOKEN"
                ),
                mock.call.controlled_json(
                    Path("/synthetic/inventory.json"), 64 * 1024 * 1024
                ),
                mock.call.controlled_json(
                    Path("/synthetic/dhcp.json"), 64 * 1024 * 1024
                ),
                mock.call.canonical(ports.inventory),
                mock.call.digest(ports.source_records),
                mock.call.request_json(
                    "http://127.0.0.1:9876/assets/import",
                    method="POST",
                    token=SYNTHETIC_TOKEN,
                    payload={
                        "inventory": ports.inventory,
                        "replace": True,
                        "actor": "verified-json-migration",
                    },
                ),
                mock.call.request_json(
                    "http://127.0.0.1:9876/assets/dhcp-state",
                    method="POST",
                    token=SYNTHETIC_TOKEN,
                    payload={
                        "state": ports.dhcp,
                        "actor": "verified-json-migration",
                    },
                ),
                mock.call.request_json(
                    "http://127.0.0.1:9876/assets/snapshot"
                ),
                mock.call.canonical(ports.snapshot),
                mock.call.digest(ports.target_records),
                mock.call.request_json(
                    "http://127.0.0.1:9876/assets/dhcp-state"
                ),
                mock.call.atomic_write(
                    Path("/synthetic/export.json"), ports.snapshot
                ),
            ],
        )

    def test_confirmation_and_token_gates_fail_before_state_or_http_access(self):
        cases = (
            (
                ("--confirm", "wrong"),
                MigrationPorts(),
                "exact migration confirmation is required",
                [],
            ),
            (
                ("--confirm", "MIGRATE-ASSETS-TO-POSTGRESQL"),
                MigrationPorts(token="short"),
                "ASSET_STORE_WRITE_TOKEN is missing or too short",
                [
                    mock.call.env_value(
                        migration.DEFAULT_ENV, "ASSET_STORE_WRITE_TOKEN"
                    )
                ],
            ),
        )
        for argv, ports, message, expected_calls in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(SystemExit, message):
                    self.invoke(argv, ports)
                self.assertEqual(ports.parent.mock_calls, expected_calls)

    def test_asset_mismatch_stops_before_dhcp_readback_and_export(self):
        ports = MigrationPorts(source_digest="source", target_digest="target")
        with self.assertRaisesRegex(
            SystemExit,
            "PostgreSQL verification failed: asset snapshot differs",
        ):
            self.invoke(
                ("--confirm", "MIGRATE-ASSETS-TO-POSTGRESQL"), ports
            )
        self.assertEqual(ports.request_json.call_count, 3)
        ports.atomic_write.assert_not_called()

    def test_dhcp_mismatch_stops_before_export(self):
        ports = MigrationPorts(database_ids=("a", "different"))
        with self.assertRaisesRegex(
            SystemExit,
            "PostgreSQL verification failed: DHCP identities differ",
        ):
            self.invoke(
                ("--confirm", "MIGRATE-ASSETS-TO-POSTGRESQL"), ports
            )
        self.assertEqual(ports.request_json.call_count, 4)
        ports.atomic_write.assert_not_called()

    def test_parser_failure_preserves_exit_two_without_port_access(self):
        ports = MigrationPorts()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            sys, "argv", ["migrate-assets-to-postgres.py"]
        ), mock.patch.object(
            migration, "env_value", ports.env_value
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                migration.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("the following arguments are required: --confirm", stderr.getvalue())
        ports.env_value.assert_not_called()


if __name__ == "__main__":
    unittest.main()
