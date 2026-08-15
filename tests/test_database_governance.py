#!/usr/bin/env python3
"""Acceptance tests for the repository database-governance inventory."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "operations" / "validate-database-governance.py"
CATALOG = ROOT / "operations" / "quality" / "database-governance.json"


def load_validator():
    spec = importlib.util.spec_from_file_location("database_governance", VALIDATOR)
    if spec is None or spec.loader is None:
        raise AssertionError("database governance validator is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class DatabaseGovernanceTests(unittest.TestCase):
    maxDiff = None

    def test_catalog_covers_every_repository_owned_database(self) -> None:
        module = load_validator()
        catalog = module.load_catalog(CATALOG)
        result = module.validate_catalog(catalog, ROOT)
        self.assertEqual(result["errors"], [])
        self.assertEqual(
            {entry["id"] for entry in catalog["entries"]},
            {
                "mac.alert-store-sqlite",
                "mac.investigation-harness-sqlite",
                "mac.n8n-postgresql",
                "mac.alert-store-postgresql",
                "relay.alert-delivery-sqlite",
            },
        )
        self.assertEqual(
            result["declared_gaps"],
            sorted([
                "relay.alert-delivery-sqlite: schema version is not persisted",
                "relay.alert-delivery-sqlite: schema migration is not atomic",
            ]),
        )

    def test_catalog_rejects_missing_recovery_and_provenance_contracts(self) -> None:
        module = load_validator()
        catalog = module.load_catalog(CATALOG)
        entry = json.loads(json.dumps(catalog["entries"][0]))
        entry["restore_validation"] = []
        entry["provenance_controls"] = []
        result = module.validate_catalog(
            {"schema": catalog["schema"], "entries": [entry]},
            ROOT,
            required_ids={entry["id"]},
        )
        rendered = " ".join(result["errors"])
        self.assertIn("restore_validation is invalid", rendered)
        self.assertIn("provenance_controls is invalid", rendered)

    def test_catalog_rejects_missing_or_escaping_source_anchors(self) -> None:
        module = load_validator()
        catalog = module.load_catalog(CATALOG)
        entry = json.loads(json.dumps(catalog["entries"][0]))
        entry["source_anchors"] = ["../outside-repository"]
        result = module.validate_catalog(
            {"schema": catalog["schema"], "entries": [entry]},
            ROOT,
            required_ids={entry["id"]},
        )
        self.assertIn("source_anchors are invalid", " ".join(result["errors"]))

    def test_catalog_rejects_source_anchors_through_symlinks(self) -> None:
        module = load_validator()
        catalog = module.load_catalog(CATALOG)
        entry = json.loads(json.dumps(catalog["entries"][0]))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            (real / "owner.py").write_text("# owner\n", encoding="utf-8")
            (root / "linked").symlink_to(real, target_is_directory=True)
            entry["source_anchors"] = ["linked/owner.py"]
            result = module.validate_catalog(
                {"schema": catalog["schema"], "entries": [entry]},
                root,
                required_ids={entry["id"]},
            )
        self.assertIn("source_anchors are invalid", " ".join(result["errors"]))

    def test_validator_cli_is_a_documented_release_gate(self) -> None:
        operations = (ROOT / "operations" / "README.md").read_text(encoding="utf-8")
        deployment = (ROOT / "docs" / "product-deployment-requirements.md").read_text(
            encoding="utf-8"
        )
        command = "python3 operations/validate-database-governance.py"
        self.assertIn(command, operations)
        self.assertIn(command, deployment)
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
        self.assertEqual(payload["schema"], "onion-sentinel-database-governance-result-v1")
        self.assertEqual(payload["catalog_entries"], 5)
        self.assertEqual(payload["declared_gap_count"], 2)
        self.assertEqual(payload["status"], "catalog_valid_with_declared_gaps")
        self.assertTrue(payload["ok"])

    def test_loader_rejects_oversized_catalogs(self) -> None:
        module = load_validator()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            path.write_bytes(b" " * (module.MAX_FILE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "byte budget"):
                module.load_catalog(path)


if __name__ == "__main__":
    unittest.main()
