#!/usr/bin/env python3
"""Startup and rotation acceptance for credential lifecycle governance."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "operations" / "validate-credential-governance.py"
CATALOG = ROOT / "operations" / "security" / "credential-governance.json"
READINESS = ROOT / "n8n" / "bin" / "check-onion-sentinel-readiness.py"


def load_file(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def record(entry: dict, generation: int, state: str, predecessor=None) -> dict:
    return {
        "credential_id": entry["id"],
        "generation": generation,
        "state": state,
        "created_at": "2026-08-14T00:00:00Z",
        "expires_at": "2099-08-14T00:00:00Z",
        "rotation_due_at": "2099-02-14T00:00:00Z",
        "storage_class": entry["storage_class"],
        "allowed_actions": entry["allowed_actions"],
        "predecessor_generation": predecessor,
    }


def inventory(identifier: str, records: list[dict]) -> dict:
    return {
        "schema": "onion-sentinel-credential-inventory-v1",
        "generated_at": "2026-08-15T00:00:00Z",
        "required_ids": [identifier],
        "records": records,
    }


def write_private(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)


class CredentialStartupGovernanceTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.entry = self.catalog["entries"][0]

    def run_validator(self, path: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--catalog",
                str(CATALOG),
                "--inventory",
                str(path),
                "--at",
                "2026-08-15T00:00:00Z",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

    def test_private_inventory_declares_unique_enabled_catalog_ids(self) -> None:
        validator = load_file("credential_inventory_contract", VALIDATOR)
        good = inventory(self.entry["id"], [record(self.entry, 1, "active")])
        self.assertEqual(
            validator.validate_inventory(
                self.catalog,
                good,
                dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
            ),
            [],
        )
        missing = {**good, "records": []}
        self.assertIn(
            "required credential is missing",
            " ".join(
                validator.validate_inventory(
                    self.catalog,
                    missing,
                    dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
                )
            ),
        )
        duplicate = {**good, "required_ids": [self.entry["id"], self.entry["id"]]}
        self.assertIn(
            "required_ids are invalid",
            " ".join(
                validator.validate_inventory(
                    self.catalog,
                    duplicate,
                    dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
                )
            ),
        )

    def test_cli_proves_cutover_and_rollback_without_secret_projection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            phases = (
                inventory(self.entry["id"], [record(self.entry, 1, "active")]),
                inventory(
                    self.entry["id"],
                    [
                        record(self.entry, 2, "active", predecessor=1),
                        record(self.entry, 1, "rollback"),
                    ],
                ),
                inventory(
                    self.entry["id"],
                    [
                        record(self.entry, 1, "active"),
                        record(self.entry, 2, "revoked", predecessor=1),
                    ],
                ),
            )
            for payload in phases:
                write_private(path, payload)
                result = self.run_validator(path)
                self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
                self.assertEqual(json.loads(result.stdout)["status"], "inventory_valid")

            unsafe = dict(phases[-1])
            unsafe["token"] = "synthetic-value-that-must-not-appear"
            write_private(path, unsafe)
            result = self.run_validator(path)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("synthetic-value-that-must-not-appear", result.stdout)

    def test_readiness_uses_deployed_validator_and_categorical_result(self) -> None:
        readiness = load_file("credential_readiness_contract", READINESS)
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp)
            (stack / "bin").mkdir()
            (stack / "config").mkdir()
            (stack / "bin" / "validate-credential-governance.py").write_bytes(
                VALIDATOR.read_bytes()
            )
            (stack / "config" / "credential-governance.json").write_bytes(
                CATALOG.read_bytes()
            )
            private = stack / "config" / "service-identity-inventory.json"
            write_private(
                private,
                inventory(self.entry["id"], [record(self.entry, 1, "active")]),
            )
            value = readiness.check_credentials(stack)
            self.assertEqual(value["state"], "ready", value)
            self.assertEqual(value["reason_code"], "lifecycle_inventory_valid")

            private.unlink()
            value = readiness.check_credentials(stack)
            self.assertEqual(value["state"], "failed")
            self.assertEqual(value["reason_code"], "credential_governance_failed")
            self.assertNotIn(str(private), json.dumps(value))

    def test_installer_deploys_gate_and_alert_store_runs_it_before_node(self) -> None:
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        host = (ROOT / "n8n/bin/run-alert-store-host.zsh").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'cp "$REPO_DIR/operations/validate-credential-governance.py" '
            '"$STACK_DIR/bin/validate-credential-governance.py"',
            installer,
        )
        self.assertIn(
            'cp "$REPO_DIR/operations/security/credential-governance.json" '
            '"$STACK_DIR/config/credential-governance.json"',
            installer,
        )
        gate = '"$STACK_DIR/bin/validate-credential-governance.py"'
        self.assertIn(gate, host)
        self.assertIn("/usr/bin/env -i", host)
        self.assertLess(host.index(gate), host.index("exec node alert_store.js"))
        self.assertNotIn("service-identity-inventory.example.json", installer)

    def test_alert_store_startup_denies_invalid_and_admits_valid_inventory(self) -> None:
        host = ROOT / "n8n/bin/run-alert-store-host.zsh"
        with tempfile.TemporaryDirectory() as tmp:
            stack = Path(tmp)
            (stack / "bin").mkdir()
            (stack / "config").mkdir()
            alert_store = stack / "alert_store"
            alert_store.mkdir()
            (alert_store / "alert_store.js").write_text(
                'console.log("synthetic-node-started");\n', encoding="utf-8"
            )
            (stack / "bin" / "validate-credential-governance.py").write_bytes(
                VALIDATOR.read_bytes()
            )
            (stack / "config" / "credential-governance.json").write_bytes(
                CATALOG.read_bytes()
            )
            environment = {**os.environ, "STACK_DIR": str(stack)}
            denied = subprocess.run(
                ["/bin/zsh", str(host)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(denied.returncode, 78, denied.stderr)
            self.assertEqual(
                denied.stderr.strip(), "Credential lifecycle startup validation failed."
            )
            self.assertNotIn("synthetic-node-started", denied.stdout)

            write_private(
                stack / "config" / "service-identity-inventory.json",
                inventory(self.entry["id"], [record(self.entry, 1, "active")]),
            )
            admitted = subprocess.run(
                ["/bin/zsh", str(host)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(admitted.returncode, 0, admitted.stderr)
            self.assertEqual(admitted.stdout.strip(), "synthetic-node-started")


if __name__ == "__main__":
    unittest.main()
