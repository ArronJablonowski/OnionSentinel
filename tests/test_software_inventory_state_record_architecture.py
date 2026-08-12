from __future__ import annotations

import copy
import datetime as dt
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_state as inventory_state
from tests.test_software_inventory_api import NOW, record


class SoftwareInventoryStateRecordArchitectureTests(unittest.TestCase):
    @staticmethod
    def valid(source: str = "osquery_apps") -> dict[str, object]:
        asset_ref = (
            "aaaaaaaaaaaaaaaaaaaaaaaa"
            if source == "osquery_apps"
            else "10.100.4.21"
        )
        value = record(
            "000000000000000000000001",
            source,
            asset_ref,
            "Firefox" if source != "http_user_agent" else "Mozilla/5.0",
            version="140.0" if source != "http_user_agent" else "",
        )
        value["ignored_secret"] = "must-not-project"
        return value

    def test_private_signature_owner_budget_and_output_shape_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(inventory_state._sanitize_record)),
            "(raw: 'object') -> 'dict[str, object]'",
        )
        self.assertLessEqual(
            len(
                (DASHBOARD / "software_inventory_state.py")
                .read_text()
                .splitlines()
            ),
            800,
        )
        raw = self.valid()
        before = copy.deepcopy(raw)
        result = inventory_state._sanitize_record(raw)
        self.assertEqual(raw, before)
        self.assertEqual(
            list(result),
            [
                "evidence_id",
                "source",
                "source_dataset",
                "tier",
                "confidence",
                "asset_ref_type",
                "asset_ref",
                "platform",
                "operating_system_type",
                "operating_system_version",
                "operating_system_source",
                "operating_system_confidence",
                "product",
                "version",
                "category",
                "first_seen",
                "last_seen",
                "observation_count",
                "_first_seen",
                "_last_seen",
            ],
        )
        self.assertNotIn("ignored_secret", result)
        self.assertIsInstance(result["_first_seen"], dt.datetime)
        self.assertIsInstance(result["_last_seen"], dt.datetime)

    def test_all_sources_preserve_provenance_and_normalization(self) -> None:
        for source in ("osquery_apps", "zeek_software", "http_user_agent"):
            with self.subTest(source=source):
                raw = self.valid(source)
                raw["evidence_id"] = "ABCDEF000000000000000001"
                raw["source"] = f" {source.upper()} "
                raw["tier"] = f" {raw['tier'].upper()} "
                raw["confidence"] = f" {raw['confidence'].upper()} "
                raw["asset_ref_type"] = (
                    f" {str(raw['asset_ref_type']).upper()} "
                )
                result = inventory_state._sanitize_record(raw)
                self.assertEqual(
                    result["evidence_id"], "abcdef000000000000000001"
                )
                self.assertEqual(result["source"], source)
                self.assertEqual(
                    result["first_seen"],
                    (NOW - dt.timedelta(days=1))
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z"),
                )
                self.assertEqual(
                    result["last_seen"],
                    NOW.isoformat(timespec="seconds").replace(
                        "+00:00", "Z"
                    ),
                )

    def test_identity_provenance_and_reference_error_order_is_exact(self) -> None:
        cases: tuple[tuple[object, str], ...] = (
            (None, "records must contain objects"),
            (
                self.valid() | {"evidence_id": "bad"},
                "evidence_id must be 24 lowercase hex characters",
            ),
            (
                self.valid() | {"source": "unsupported"},
                "record source is unsupported",
            ),
            (
                self.valid() | {"tier": "observed"},
                "record provenance does not match its source",
            ),
            (
                self.valid() | {"asset_ref_type": "ip"},
                "asset_ref_type does not match its source",
            ),
            (
                self.valid() | {"asset_ref": "not-a-pseudonym"},
                "OSQuery asset references must be pseudonymous identifiers",
            ),
            (
                self.valid("zeek_software")
                | {"asset_ref": "b8a8c75a-6d61-4ea8-a5bf-b08ddf6f3f22"},
                "raw endpoint identifiers are not public",
            ),
            (
                self.valid("zeek_software") | {"asset_ref": "8.8.8.8"},
                "passive asset_ref is not a canonical LAN IP",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    inventory_state.InventoryStateError,
                    f"^{message}$",
                ):
                    inventory_state._sanitize_record(value)

    def test_malformed_passive_ip_preserves_value_error_cause(self) -> None:
        raw = self.valid("zeek_software") | {
            "asset_ref": "host.example.test"
        }
        with self.assertRaisesRegex(
            inventory_state.InventoryStateError,
            "^passive asset_ref must be an IP address$",
        ) as caught:
            inventory_state._sanitize_record(raw)
        self.assertIsInstance(caught.exception.__cause__, ValueError)

    def test_observation_dataset_and_user_agent_errors_are_exact(self) -> None:
        cases = (
            (
                self.valid()
                | {
                    "first_seen": "2026-08-01T00:00:00Z",
                    "last_seen": "2026-07-31T00:00:00Z",
                },
                "first_seen is after last_seen",
            ),
            (
                self.valid() | {"observation_count": True},
                "observation_count is invalid",
            ),
            (
                self.valid() | {"source_dataset": "zeek.software"},
                "source_dataset does not match its source",
            ),
            (
                self.valid("http_user_agent") | {"version": "invented"},
                "HTTP User-Agent evidence cannot invent a version",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    inventory_state.InventoryStateError,
                    f"^{message}$",
                ):
                    inventory_state._sanitize_record(value)

    def test_operating_system_provenance_matrix_is_fail_closed(self) -> None:
        cases = (
            (
                self.valid()
                | {"operating_system_confidence": "certain"},
                "operating_system_confidence is unsupported",
            ),
            (
                self.valid()
                | {"operating_system_source": "untrusted"},
                "endpoint operating-system provenance is invalid",
            ),
            (
                self.valid()
                | {
                    "operating_system_type": "",
                    "operating_system_version": "",
                    "operating_system_source": (
                        "osquery_manager.result:host.os"
                    ),
                    "operating_system_confidence": "high",
                },
                "empty endpoint operating-system evidence claims provenance",
            ),
            (
                self.valid("zeek_software")
                | {"operating_system_type": "Linux"},
                "passive software evidence cannot assert an exact operating system",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(
                    inventory_state.InventoryStateError,
                    f"^{message}$",
                ):
                    inventory_state._sanitize_record(value)

    def test_final_projection_text_validation_occurs_after_os_provenance(self) -> None:
        raw = self.valid() | {
            "operating_system_source": "untrusted",
            "product": "",
        }
        with self.assertRaisesRegex(
            inventory_state.InventoryStateError,
            "^endpoint operating-system provenance is invalid$",
        ):
            inventory_state._sanitize_record(raw)
        raw["operating_system_source"] = "osquery_manager.result:host.os"
        with self.assertRaisesRegex(
            inventory_state.InventoryStateError,
            "^product is required$",
        ):
            inventory_state._sanitize_record(raw)


if __name__ == "__main__":
    unittest.main()
