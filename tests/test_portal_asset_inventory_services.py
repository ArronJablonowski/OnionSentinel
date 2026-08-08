#!/usr/bin/env python3
"""Direct contracts for Asset Inventory projection and DHCP overlay policy."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import tempfile
import threading
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
    resolve_asset_ip,
)
from portal_asset_repository import (  # noqa: E402
    AssetInventoryRepository,
    DhcpStateRepository,
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

    def test_resolution_does_not_load_inventory_for_invalid_inputs(self) -> None:
        loads: list[bool] = []
        loader = lambda: loads.append(True) or ({"assets": []}, "")
        invalid_ip = resolve_asset_ip(
            "not-an-ip", "2026-07-29T18:00:00Z", None,
            parse_timestamp=parse_timestamp, load_inventory=loader,
        )
        invalid_time = resolve_asset_ip(
            "192.0.2.10", "not-a-time", None,
            parse_timestamp=parse_timestamp, load_inventory=loader,
        )
        self.assertEqual(invalid_ip["status"], "not_applicable")
        self.assertEqual(invalid_time["status"], "time_invalid")
        self.assertEqual(loads, [])

    def test_resolution_is_event_time_scoped_and_fail_closed(self) -> None:
        old = authoritative_asset("old", address="192.0.2.10")
        old["valid_until"] = "2026-07-01T00:00:00Z"
        current = authoritative_asset("current", address="192.0.2.10")
        current["valid_from"] = "2026-07-01T00:00:00Z"
        inventory = {"assets": [old, current]}
        resolved = resolve_asset_ip(
            "192.0.2.10", "2026-07-29T18:00:00Z", inventory,
            parse_timestamp=parse_timestamp,
            load_inventory=lambda: self.fail("explicit inventory must be used"),
        )
        unavailable = resolve_asset_ip(
            "192.0.2.10", "2026-07-29T18:00:00Z", None,
            parse_timestamp=parse_timestamp,
            load_inventory=lambda: ({"assets": []}, "database unavailable"),
        )
        self.assertEqual(resolved["asset_id"], "current")
        self.assertEqual(unavailable["status"], "inventory_unavailable")


class PortalAssetRepositoryTests(unittest.TestCase):
    def repository(self, root: Path, **overrides) -> AssetInventoryRepository:
        options = {
            "database_enabled": False,
            "cache": {},
            "cache_lock": threading.RLock(),
            "epoch_seconds": lambda: 100.0,
            "fetch_json": lambda _path, timeout=5.0: {},
            "validate_inventory": lambda value: dict(value),
            "load_inventory_file": lambda path: json.loads(path.read_text()),
            "inventory_path": root / "inventory.json",
            "maximum_bytes": 1024 * 1024,
        }
        options.update(overrides)
        return AssetInventoryRepository(**options)

    def test_database_inventory_is_validated_cached_and_never_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fetches: list[str] = []
            repository = self.repository(
                root,
                database_enabled=True,
                fetch_json=lambda path, timeout=5.0: (
                    fetches.append(path) or {"inventory": {"assets": []}}
                ),
            )
            first, first_error = repository.load()
            second, second_error = repository.load()
            self.assertEqual(first["inventory_status"], "database")
            self.assertEqual((first_error, second_error), ("", ""))
            self.assertEqual(second, first)
            self.assertEqual(fetches, ["/assets/snapshot"])

            repository.fetch_json = lambda _path, timeout=5.0: (
                _ for _ in ()
            ).throw(RuntimeError("offline"))
            repository.cache.clear()
            unavailable, error = repository.load()
            self.assertEqual(unavailable["inventory_status"], "unavailable")
            self.assertIn("PostgreSQL asset inventory unavailable", error)

    def test_missing_and_valid_file_inventory_keep_distinct_states(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = self.repository(root)
            missing, error = repository.load()
            self.assertEqual(missing["inventory_status"], "missing")
            self.assertEqual(error, "")
            repository.inventory_path.write_text(
                json.dumps({"assets": [], "inventory_status": "loaded"}),
                encoding="utf-8",
            )
            loaded, error = repository.load()
            self.assertEqual(loaded["inventory_status"], "loaded")
            self.assertEqual(error, "")

    def test_dhcp_repository_bounds_database_and_file_state(self) -> None:
        valid = {
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            **state(),
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "dhcp.json"
            missing, error = DhcpStateRepository(
                False, lambda *_args, **_kwargs: {}, path, 1024,
            ).load()
            self.assertEqual(missing["collection"]["status"], "never_run")
            self.assertEqual(error, "")
            path.write_text(json.dumps(valid), encoding="utf-8")
            loaded, error = DhcpStateRepository(
                False, lambda *_args, **_kwargs: {}, path, 1024,
            ).load()
            self.assertEqual(loaded["collection"]["status"], "ok")
            self.assertEqual(error, "")

            unavailable, error = DhcpStateRepository(
                True,
                lambda *_args, **_kwargs: {"state": {"observations": []}},
                path,
                1024,
            ).load()
            self.assertEqual(unavailable["collection"]["status"], "unavailable")
            self.assertIn("PostgreSQL DHCP state unavailable", error)


if __name__ == "__main__":
    unittest.main()
