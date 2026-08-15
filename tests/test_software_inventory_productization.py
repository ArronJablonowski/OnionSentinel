#!/usr/bin/env python3
"""ARR-31 product evidence and analyst-facing conflict contracts."""
from __future__ import annotations

import copy
import tempfile
from pathlib import Path
import unittest

from tests.test_software_inventory_api import NOW, inventory, state


ROOT = Path(__file__).resolve().parents[1]
PAGE = (
    ROOT
    / "onion-sentinel-dashboard"
    / "scripts"
    / "dashboard_software_inventory_page.py"
)
EVIDENCE_MODEL = ROOT / "docs" / "software-inventory-evidence-model.md"


class SoftwareInventoryProductizationTests(unittest.TestCase):
    def test_simultaneous_version_disagreement_is_explicit(self) -> None:
        raw = state()
        conflicting = copy.deepcopy(raw["records"][0])
        conflicting["evidence_id"] = "000000000000000000000006"
        conflicting["version"] = "141.0"
        raw["records"].append(conflicting)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "software-inventory.json"
            path.write_text(__import__("json").dumps(raw), encoding="utf-8")
            path.chmod(0o600)
            status, payload = inventory.build_response(path, observed_at=NOW)

        self.assertEqual(status, 200)
        firefox = [
            item for item in payload["items"] if item["product"] == "Firefox"
        ]
        self.assertEqual(len(firefox), 2)
        self.assertEqual(
            {item["evidence_conflict"] for item in firefox},
            {"simultaneous-version-disagreement"},
        )
        self.assertEqual(payload["summary"]["conflicting_records"], 2)
        self.assertTrue(
            any("simultaneous version" in item.lower() for item in payload["warnings"])
        )

    def test_page_exposes_evidence_identity_and_conflict_state(self) -> None:
        source = PAGE.read_text(encoding="utf-8")
        self.assertIn('<dt>Evidence ID</dt>', source)
        self.assertIn('<dt>Conflict state</dt>', source)
        self.assertIn('id="software-conflicting-total"', source)
        self.assertIn("item?.evidence_conflict", source)

    def test_evidence_model_documents_database_and_uncertainty_semantics(self) -> None:
        source = EVIDENCE_MODEL.read_text(encoding="utf-8")
        for expected in (
            "onion_sentinel_software.snapshots",
            "onion_sentinel_software.inventory_records",
            "installed",
            "observed",
            "inferred",
            "evidence_id",
            "simultaneous-version-disagreement",
            "host-resolution uncertainty",
            "expired",
            "observed_user_agent",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, source)


if __name__ == "__main__":
    unittest.main()
