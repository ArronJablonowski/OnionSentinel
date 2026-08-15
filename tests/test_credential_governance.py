#!/usr/bin/env python3
"""Acceptance tests for the secret-free credential lifecycle contract."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "operations" / "validate-credential-governance.py"
CATALOG = ROOT / "operations" / "security" / "credential-governance.json"


def load_validator():
    spec = importlib.util.spec_from_file_location("credential_governance", VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("credential governance validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CredentialGovernanceTests(unittest.TestCase):
    maxDiff = None

    def test_catalog_covers_every_declared_credential_binding(self) -> None:
        module = load_validator()
        catalog = module.load_catalog(CATALOG)
        self.assertEqual(module.validate_catalog(catalog, ROOT), [])
        bindings = {
            binding
            for entry in catalog["entries"]
            for binding in entry["bindings"]
        }
        required = {
            "env:TELEGRAM_BOT_TOKEN",
            "env:TELEGRAM_CHAT_ID",
            "env:N8N_POSTGRES_USER",
            "env:N8N_POSTGRES_PASSWORD",
            "env:ALERT_STORE_POSTGRES_USER",
            "env:ALERT_STORE_POSTGRES_PASSWORD",
            "env:ASSET_STORE_WRITE_TOKEN",
            "env:N8N_POST_COMMIT_TOKEN",
            "env:ONION_SENTINEL_EVALUATION_TOKEN",
            "n8n-var:RELAY_WEBHOOK_TOKEN",
            "n8n-var:PCAP_BROKER_TOKEN",
            "file:mac-admin-password-record",
            "file:mac-admin-session-token",
            "file:mac-ac-hunter-service-credential",
            "file:mac-hermes-openai-codex-auth",
            "file:security-onion-pcap-stream-signing-key",
            "ssh:relay-to-security-onion-alert-poll",
            "ssh:relay-to-security-onion-pcap",
            "ssh:relay-to-security-onion-incident-evidence",
            "ssh:relay-to-security-onion-live-osquery",
            "ssh:mac-to-relay-live-osquery",
            "ssh:mac-to-relay-incident-evidence",
            "ssh:mac-to-relay-ac-hunter",
            "ssh:relay-to-mac-alert-intake",
            "ssh:relay-to-mac-pcap-intake",
        }
        self.assertTrue(required <= bindings, sorted(required - bindings))
        for name in (
            "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "OTX_API_KEY",
            "URLHAUS_AUTH_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY",
            "GOOGLE_SAFE_BROWSING_API_KEY", "PHISHTANK_API_KEY",
            "MALWAREBAZAAR_AUTH_KEY", "THREATFOX_AUTH_KEY", "SHODAN_API_KEY",
            "CENSYS_API_ID", "CENSYS_API_SECRET", "CENSYS_API_TOKEN",
            "CENSYS_ORGANIZATION_ID", "NVD_API_KEY",
        ):
            self.assertIn(f"env:{name}", bindings)

    def test_inventory_rejects_missing_duplicate_expired_and_mismatched_active_records(self) -> None:
        module = load_validator()
        catalog = module.load_catalog(CATALOG)
        now = dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc)
        entry = catalog["entries"][0]
        good = {
            "schema": "onion-sentinel-credential-inventory-v1",
            "generated_at": "2026-08-15T00:00:00Z",
            "required_ids": [entry["id"]],
            "records": [
                {
                    "credential_id": entry["id"],
                    "generation": 2,
                    "state": "active",
                    "created_at": "2026-08-14T00:00:00Z",
                    "expires_at": "2027-08-14T00:00:00Z",
                    "rotation_due_at": "2027-02-14T00:00:00Z",
                    "storage_class": entry["storage_class"],
                    "allowed_actions": entry["allowed_actions"],
                    "predecessor_generation": 1,
                },
                {
                    "credential_id": entry["id"],
                    "generation": 1,
                    "state": "rollback",
                    "created_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-08-16T00:00:00Z",
                    "rotation_due_at": "2026-08-16T00:00:00Z",
                    "storage_class": entry["storage_class"],
                    "allowed_actions": entry["allowed_actions"],
                    "predecessor_generation": None,
                },
            ],
        }
        self.assertEqual(
            module.validate_inventory(catalog, good, now, {entry["id"]}), []
        )

        missing = {**good, "records": []}
        self.assertIn("required credential is missing", " ".join(
            module.validate_inventory(catalog, missing, now, {entry["id"]})
        ))
        duplicate = json.loads(json.dumps(good))
        duplicate["records"].append(dict(duplicate["records"][0]))
        self.assertIn("duplicate generation", " ".join(
            module.validate_inventory(catalog, duplicate, now, {entry["id"]})
        ))
        expired = json.loads(json.dumps(good))
        expired["records"][0]["expires_at"] = "2026-08-14T00:00:00Z"
        self.assertIn("active credential is expired", " ".join(
            module.validate_inventory(catalog, expired, now, {entry["id"]})
        ))
        mismatched = json.loads(json.dumps(good))
        mismatched["records"][0]["storage_class"] = "wrong-storage"
        self.assertIn("storage class mismatch", " ".join(
            module.validate_inventory(catalog, mismatched, now, {entry["id"]})
        ))

    def test_private_inventory_admission_never_returns_secret_fields(self) -> None:
        module = load_validator()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"
            path.write_text(
                json.dumps({
                    "schema": "onion-sentinel-credential-inventory-v1",
                    "generated_at": "2026-08-15T00:00:00Z",
                    "required_ids": ["notification.telegram"],
                    "records": [],
                    "token": "must-not-be-admitted",
                }),
                encoding="utf-8",
            )
            path.chmod(0o600)
            payload = module.load_private_inventory(path, owner_id=path.stat().st_uid)
        rendered = json.dumps(payload)
        self.assertNotIn("must-not-be-admitted", rendered)
        self.assertEqual(payload.get("status"), "invalid")

    def test_validator_cli_is_a_documented_release_gate(self) -> None:
        deployment = (ROOT / "docs/product-deployment-requirements.md").read_text(
            encoding="utf-8"
        )
        operations = (ROOT / "operations/README.md").read_text(encoding="utf-8")
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        command = "python3 operations/validate-credential-governance.py"
        self.assertIn(command, deployment)
        self.assertIn(command, operations)
        self.assertIn("validate-credential-governance.py", installer)
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "--catalog", str(CATALOG)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload, {
            "catalog_entries": len(json.loads(CATALOG.read_text())["entries"]),
            "ok": True,
            "schema": "onion-sentinel-credential-governance-result-v1",
            "status": "catalog_valid",
        })


if __name__ == "__main__":
    unittest.main()
