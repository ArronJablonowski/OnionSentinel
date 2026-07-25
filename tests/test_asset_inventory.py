import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "asset_inventory.py"
SPEC = importlib.util.spec_from_file_location("asset_inventory", MODULE_PATH)
asset_inventory = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(asset_inventory)


def record(asset_id, ip, valid_from, valid_until=None, **overrides):
    value = {
        "asset_id": asset_id,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "identifiers": {
            "ip_addresses": [ip],
            "mac_addresses": [],
            "hostnames": [],
        },
        "role": "workstation",
        "platform": "macOS",
        "owner_ref": "team-blue",
        "criticality": "medium",
        "expected_services": [],
        "expected_behaviors": [],
        "source_type": "cmdb",
        "source_ref": "asset-record",
        "confidence": "high",
    }
    value.update(overrides)
    return value


class AssetInventoryTests(unittest.TestCase):
    def inventory(self, assets):
        return asset_inventory.validate_asset_inventory(
            {
                "schema": asset_inventory.ASSET_INVENTORY_SCHEMA,
                "version": 1,
                "generated_at": "2026-07-24T00:00:00Z",
                "assets": assets,
            }
        ) | {"inventory_status": "loaded"}

    def test_resolves_reused_ip_by_event_time(self):
        inventory = self.inventory(
            [
                record("old-laptop", "192.0.2.8", "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z"),
                record("new-laptop", "192.0.2.8", "2026-07-01T00:00:00Z"),
            ]
        )
        context = asset_inventory.resolve_asset_context(
            inventory,
            [{"type": "ip", "value": "192.0.2.8", "role": "source"}],
            "2026-07-24T12:00:00-06:00",
        )
        self.assertEqual([item["asset_id"] for item in context["matched_assets"]], ["new-laptop"])
        self.assertEqual(context["conflicts"], [])

    def test_accepts_production_timestamp_with_two_spaces(self):
        inventory = self.inventory(
            [record("sensor", "192.0.2.9", "2026-01-01T00:00:00Z")]
        )
        context = asset_inventory.resolve_asset_context(
            inventory,
            [{"type": "ip", "value": "192.0.2.9", "role": "source"}],
            "2026-07-24  12:00:00-06:00",
        )
        self.assertEqual(context["resolution_status"], "resolved")
        self.assertEqual(context["matched_assets"][0]["asset_id"], "sensor")

    def test_same_asset_id_can_have_nonoverlapping_identifier_history(self):
        inventory = self.inventory(
            [
                record("laptop", "192.0.2.8", "2026-01-01T00:00:00Z", "2026-07-01T00:00:00Z"),
                record("laptop", "192.0.2.9", "2026-07-01T00:00:00Z"),
            ]
        )
        context = asset_inventory.resolve_asset_context(
            inventory,
            [{"type": "ip", "value": "192.0.2.9", "role": "source"}],
            "2026-07-24T18:00:00Z",
        )
        self.assertEqual([item["asset_id"] for item in context["matched_assets"]], ["laptop"])
        with self.assertRaisesRegex(ValueError, "overlapping validity"):
            self.inventory(
                [
                    record("laptop", "192.0.2.8", "2026-01-01T00:00:00Z"),
                    record("laptop", "192.0.2.9", "2026-07-01T00:00:00Z"),
                ]
            )

    def test_reports_ambiguous_overlapping_claims(self):
        inventory = self.inventory(
            [
                record("asset-a", "192.0.2.8", "2026-01-01T00:00:00Z"),
                record("asset-b", "192.0.2.8", "2026-01-01T00:00:00Z"),
            ]
        )
        context = asset_inventory.resolve_asset_context(
            inventory,
            [{"type": "ip", "value": "192.0.2.8", "role": "destination"}],
            "2026-07-24T18:00:00Z",
        )
        self.assertEqual(len(context["matched_assets"]), 2)
        self.assertEqual(context["conflicts"][0]["active_asset_ids"], ["asset-a", "asset-b"])

    def test_expected_service_is_context_not_authorization(self):
        inventory = self.inventory(
            [
                record(
                    "dns-service",
                    "192.0.2.53",
                    "2026-01-01T00:00:00Z",
                    expected_services=[{"protocol": "udp", "port": 53, "purpose": "internal DNS"}],
                )
            ]
        )
        context = asset_inventory.resolve_asset_context(
            inventory,
            [{"type": "ip", "value": "192.0.2.53", "role": "destination"}],
            "2026-07-24T18:00:00Z",
            [{"destination_ip": "192.0.2.53", "destination_port": 53, "protocol": "udp"}],
        )
        match = context["registered_expectation_matches"][0]
        self.assertIn("does not prove", match["interpretation"])

    def test_context_output_and_expectation_traversal_are_bounded(self):
        assets = [
            record(
                f"asset-{index}",
                "192.0.2.53",
                "2026-01-01T00:00:00Z",
                expected_services=[
                    {"protocol": "udp", "port": 53, "purpose": f"dns-{index}"}
                ],
            )
            for index in range(asset_inventory.MAX_MATCHED_ASSETS + 20)
        ]
        context = asset_inventory.resolve_asset_context(
            self.inventory(assets),
            [{"type": "ip", "value": "192.0.2.53", "role": "destination"}],
            "2026-07-24T18:00:00Z",
            [
                {"destination_ip": "192.0.2.53", "destination_port": 53, "protocol": "udp"}
                for _ in range(asset_inventory.MAX_NETWORK_EVENTS + 20)
            ],
        )
        self.assertEqual(len(context["matched_assets"]), asset_inventory.MAX_MATCHED_ASSETS)
        self.assertLessEqual(
            len(context["conflicts"][0]["active_asset_ids"]),
            asset_inventory.MAX_CONFLICT_ASSET_IDS,
        )
        self.assertEqual(
            len(context["registered_expectation_matches"]),
            asset_inventory.MAX_EXPECTATION_MATCHES,
        )
        self.assertTrue(context["truncation"]["matched_assets"])
        self.assertTrue(context["truncation"]["network_events"])
        self.assertTrue(context["truncation"]["registered_expectation_matches"])

    def test_invalid_or_naive_dates_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "UTC offset"):
            self.inventory([record("asset-a", "192.0.2.8", "2026-01-01T00:00:00")])
        inventory = self.inventory([record("asset-a", "192.0.2.8", "2026-01-01T00:00:00Z")])
        context = asset_inventory.resolve_asset_context(
            inventory,
            [{"type": "ip", "value": "192.0.2.8", "role": "source"}],
            "not-a-time",
        )
        self.assertEqual(context["resolution_status"], "event_time_invalid")
        self.assertEqual(context["matched_assets"], [])

    def test_missing_file_yields_empty_missing_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = asset_inventory.load_asset_inventory(Path(directory) / "missing.json")
        self.assertEqual(inventory["inventory_status"], "missing")
        self.assertEqual(inventory["assets"], [])

    def test_rejects_unknown_schema_and_oversized_fields(self):
        with self.assertRaisesRegex(ValueError, "schema"):
            asset_inventory.validate_asset_inventory({"schema": "wrong", "assets": []})
        with self.assertRaisesRegex(ValueError, "owner_ref"):
            self.inventory(
                [
                    record(
                        "asset-a",
                        "192.0.2.8",
                        "2026-01-01T00:00:00Z",
                        owner_ref="x" * 301,
                    )
                ]
            )
        with self.assertRaisesRegex(ValueError, "must be boolean"):
            self.inventory(
                [
                    record(
                        "asset-a",
                        "192.0.2.8",
                        "2026-01-01T00:00:00Z",
                        share_with_hosted_models="false",
                    )
                ]
            )

    def test_loads_valid_json_from_disk(self):
        payload = {
            "schema": asset_inventory.ASSET_INVENTORY_SCHEMA,
            "version": 1,
            "generated_at": "",
            "assets": [record("asset-a", "2001:db8::8", "2026-01-01T00:00:00Z")],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = asset_inventory.load_asset_inventory(path)
        self.assertEqual(loaded["assets"][0]["identifiers"]["ip"], ["2001:db8::8"])


if __name__ == "__main__":
    unittest.main()
