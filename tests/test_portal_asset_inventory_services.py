#!/usr/bin/env python3
"""Direct contracts for Asset Inventory projection and DHCP overlay policy."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_asset_dhcp_overlay import (  # noqa: E402
    annotate_exact_ip_dhcp_macs,
    dhcp_asset_inventory_overlay,
)
from portal_asset_inventory_service import (  # noqa: E402
    asset_public_record,
    database_query_parameters,
)


NOW = dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc)


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def authoritative_asset(
    asset_id: str = "studio",
    *,
    address: str = "10.0.0.10",
    hostname: str = "studio.lan",
    mac: str = "00:11:22:33:44:55",
) -> dict:
    return {
        "asset_id": asset_id,
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": None,
        "identifiers": {
            "ip": [address],
            "hostname": [hostname],
            "mac": [mac],
        },
        "role": "server",
        "platform": "macOS",
        "confidence": "high",
    }


def observation(
    discovery_id: str,
    *,
    address: str,
    hostname: str = "",
    mac: str = "",
    last_seen: str = "2026-07-29T17:30:00Z",
    lease_expires: str = "2026-07-29T19:00:00Z",
) -> dict:
    return {
        "discovery_id": discovery_id,
        "current_ip": address,
        "hostname": hostname,
        "mac_address": mac,
        "first_seen": "2026-07-29T17:00:00Z",
        "last_seen": last_seen,
        "lease_expires_at": lease_expires,
    }


def state(*observations: dict) -> dict:
    return {
        "updated_at": "2026-07-29T17:30:00Z",
        "collection": {"status": "ok"},
        "observations": list(observations),
    }


class PortalAssetInventoryServiceTests(unittest.TestCase):
    def test_database_query_projection_allowlists_known_fields(self) -> None:
        projected = database_query_parameters({
            "limit": ["25"],
            "sort": ["platform"],
            "untrusted": ["must-not-pass"],
        })
        self.assertEqual(projected, {
            "limit": "25",
            "offset": "0",
            "search": "",
            "sort": "platform",
            "direction": "asc",
            "state": "current",
        })

    def test_public_record_withholds_private_context(self) -> None:
        raw = authoritative_asset()
        raw["owner_ref"] = "private-owner"
        raw["expected_behaviors"] = ["private behavior"]
        public = asset_public_record(raw, "current")
        self.assertEqual(public["ip_addresses"], ["10.0.0.10"])
        self.assertNotIn("owner_ref", public)
        self.assertNotIn("expected_behaviors", public)

    def test_exact_ip_annotation_preserves_authoritative_mac(self) -> None:
        records = [{
            "asset_id": "studio",
            "ip_addresses": ["10.0.0.10"],
            "mac_addresses": ["00:11:22:33:44:55"],
        }]
        dhcp = state(observation(
            "one", address="10.0.0.10", mac="02:aa:bb:cc:dd:ee",
        ))
        annotate_exact_ip_dhcp_macs(records, NOW, dhcp, "", parse_timestamp)
        self.assertEqual(records[0]["mac_addresses"], ["00:11:22:33:44:55"])
        self.assertEqual(
            records[0]["observed_mac_addresses"],
            ["02:aa:bb:cc:dd:ee"],
        )

    def test_multiple_fresh_exact_ip_macs_are_ambiguous(self) -> None:
        records = [{"asset_id": "studio", "ip_addresses": ["10.0.0.10"]}]
        dhcp = state(
            observation("one", address="10.0.0.10", mac="02:aa:bb:cc:dd:01"),
            observation("two", address="10.0.0.10", mac="02:aa:bb:cc:dd:02"),
        )
        annotate_exact_ip_dhcp_macs(records, NOW, dhcp, "", parse_timestamp)
        self.assertTrue(records[0]["observed_mac_ambiguous"])
        self.assertNotIn("observed_mac_addresses", records[0])

    def test_unique_stable_identity_can_overlay_a_moved_address(self) -> None:
        inventory = {"assets": [authoritative_asset()]}
        dhcp = state(observation(
            "moved", address="10.0.0.20", hostname="studio.lan",
        ))
        overlays, discovered, _status = dhcp_asset_inventory_overlay(
            inventory, NOW, dhcp, "", parse_timestamp,
        )
        self.assertEqual(overlays["studio"]["ip_addresses"], ["10.0.0.20"])
        self.assertEqual(
            overlays["studio"]["configured_ip_addresses"],
            ["10.0.0.10"],
        )
        self.assertEqual(discovered, [])

    def test_conflicting_ip_claim_never_overwrites_identity(self) -> None:
        inventory = {"assets": [
            authoritative_asset(),
            authoritative_asset(
                "other",
                address="10.0.0.20",
                hostname="other.lan",
                mac="00:11:22:33:44:66",
            ),
        ]}
        dhcp = state(observation(
            "collision", address="10.0.0.20", hostname="studio.lan",
        ))
        overlays, discovered, _status = dhcp_asset_inventory_overlay(
            inventory, NOW, dhcp, "", parse_timestamp,
        )
        self.assertEqual(overlays, {})
        self.assertEqual(discovered, [])

    def test_unmatched_fresh_observation_is_provisional(self) -> None:
        dhcp = state(observation(
            "new-client",
            address="10.0.0.30",
            hostname="new-client.lan",
            mac="02:aa:bb:cc:dd:ee",
        ))
        _overlays, discovered, _status = dhcp_asset_inventory_overlay(
            {"assets": []}, NOW, dhcp, "", parse_timestamp,
        )
        self.assertEqual(discovered[0]["asset_id"], "dhcp-new-client")
        self.assertEqual(discovered[0]["confidence"], "low")
        self.assertEqual(discovered[0]["source_type"], "zeek-dhcp-observation")

    def test_stale_observation_is_not_promoted_to_inventory_view(self) -> None:
        dhcp = state(observation(
            "stale",
            address="10.0.0.30",
            last_seen="2026-07-27T12:00:00Z",
            lease_expires="2026-07-27T13:00:00Z",
        ))
        overlays, discovered, _status = dhcp_asset_inventory_overlay(
            {"assets": []}, NOW, dhcp, "", parse_timestamp,
        )
        self.assertEqual(overlays, {})
        self.assertEqual(discovered, [])


if __name__ == "__main__":
    unittest.main()
