"""Characterization for collector-owned incident-evidence anchors."""
from __future__ import annotations

from contextlib import closing
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sqlite3
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
SCRIPT = BIN_DIR / "collect-incident-evidence.py"


def load_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_evidence_anchor", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = load_module()
INDEX = ".ds-logs-suricata.alerts-so-2026.07.22-000001"
ALIAS = "logs-suricata.alerts-so"


class IncidentEvidenceAnchorCharacterization(unittest.TestCase):
    def test_public_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(collector) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (53, "2f885f63c1abbdea61adfc088b452bb5c4cb24e72135d23f3e741039f2c20ecc"),
        )
        self.assertEqual(
            str(inspect.signature(collector.representative_alert_anchor)),
            "(selected: 'sqlite3.Row | dict') -> 'dict[str, str] | None'",
        )

    def test_complete_trimmed_metadata_has_precedence_over_alert_id(self) -> None:
        selected = {
            "alert_json": json.dumps(
                {"elastic_index": f" {INDEX} ", "elastic_id": " preferred-id "}
            ),
            "alert_id": f"{ALIAS}:fallback-id",
        }
        self.assertEqual(
            collector.representative_alert_anchor(selected),
            {"index": INDEX, "id": "preferred-id"},
        )

    def test_rightmost_colon_split_rejects_an_index_with_colon_segments(self) -> None:
        self.assertIsNone(
            collector.representative_alert_anchor(
                {"alert_id": f"{INDEX}:id:with:colons"}
            )
        )

    def test_partial_metadata_is_filled_independently_from_fallback(self) -> None:
        cases = (
            (
                {"elastic_index": INDEX},
                f"{ALIAS}:fallback-id",
                {"index": INDEX, "id": "fallback-id"},
            ),
            (
                {"elastic_id": "preferred-id"},
                f"{ALIAS}:fallback-id",
                {"index": ALIAS, "id": "preferred-id"},
            ),
        )
        for metadata, alert_id, expected in cases:
            with self.subTest(metadata=metadata):
                self.assertEqual(
                    collector.representative_alert_anchor(
                        {"alert_json": json.dumps(metadata), "alert_id": alert_id}
                    ),
                    expected,
                )

    def test_malformed_or_non_object_metadata_falls_back(self) -> None:
        for alert_json in ("{", "[]", "null", "42"):
            with self.subTest(alert_json=alert_json):
                self.assertEqual(
                    collector.representative_alert_anchor(
                        {"alert_json": alert_json, "alert_id": f"{ALIAS}:fallback"}
                    ),
                    {"index": ALIAS, "id": "fallback"},
                )

    def test_invalid_or_incomplete_candidates_fail_closed(self) -> None:
        cases = (
            {},
            {"alert_id": "no-colon"},
            {"alert_id": "logs-system.auth-default:valid-id"},
            {"alert_id": f"{ALIAS}:unsafe/id"},
            {
                "alert_json": json.dumps(
                    {"elastic_index": INDEX, "elastic_id": "unsafe/id"}
                )
            },
        )
        for selected in cases:
            with self.subTest(selected=selected):
                self.assertIsNone(collector.representative_alert_anchor(selected))

    def test_sqlite_row_uses_the_same_contract(self) -> None:
        with closing(sqlite3.connect(":memory:")) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT ? AS alert_id, ? AS alert_json",
                (f"{ALIAS}:row-id", "{}"),
            ).fetchone()
            self.assertEqual(
                collector.representative_alert_anchor(row),
                {"index": ALIAS, "id": "row-id"},
            )


if __name__ == "__main__":
    unittest.main()
