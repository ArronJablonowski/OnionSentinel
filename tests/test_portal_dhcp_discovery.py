"""Direct contracts for modular DHCP discovery reconciliation."""
from __future__ import annotations

import datetime as dt
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_dhcp_discovery import (  # noqa: E402
    DhcpDiscoveryDependencies,
    compose_dhcp_discovery_response,
)


NOW = dt.datetime(2026, 8, 7, 18, 0, tzinfo=dt.timezone.utc)


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def public_asset(raw: dict, state: str) -> dict:
    identities = raw.get("identifiers") or {}
    return {
        "asset_id": raw.get("asset_id"),
        "state": state,
        "ip_addresses": list(identities.get("ip") or []),
        "hostnames": list(identities.get("hostname") or []),
        "mac_addresses": list(identities.get("mac") or []),
        "role": raw.get("role") or "",
        "platform": raw.get("platform") or "",
        "criticality": raw.get("criticality") or "unknown",
    }


def mac_scope(value: object) -> str:
    text = str(value or "").lower()
    return "globally_administered" if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", text) else "unknown"


class DhcpDiscoveryServiceTests(unittest.TestCase):
    def dependencies(self) -> DhcpDiscoveryDependencies:
        return DhcpDiscoveryDependencies(
            asset_record_state=lambda raw, _now: str(raw.get("state") or "current"),
            asset_public_record=public_asset,
            parse_timestamp=parse_timestamp,
            format_timestamp=lambda value, **kwargs: value.isoformat().replace("+00:00", "Z"),
            mac_address_scope=mac_scope,
        )

    def asset(self, asset_id: str, ip: str, hostname: str, mac: str = "") -> dict:
        return {
            "asset_id": asset_id,
            "identifiers": {"ip": [ip], "hostname": [hostname], "mac": [mac] if mac else []},
            "role": "workstation",
            "platform": "macOS",
            "criticality": "medium",
        }

    def observation(self, discovery_id: str, ip: str, hostname: str, *,
                    mac: str = "", last_seen: str = "2026-08-07T17:30:00Z") -> dict:
        return {
            "discovery_id": discovery_id,
            "current_ip": ip,
            "ip_addresses": [ip],
            "mac_address": mac,
            "hostname": hostname,
            "hostnames": [hostname],
            "first_seen": "2026-08-07T17:00:00Z",
            "last_seen": last_seen,
            "lease_expires_at": "2026-08-07T19:00:00Z",
            "message_types": ["ACK"],
            "sensors": ["sensor-1"],
            "observation_count": 3,
        }

    def compose(self, state: dict, inventory: dict, *, state_error: str = "",
                inventory_error: str = "") -> tuple[int, dict]:
        return compose_dhcp_discovery_response(
            state=state,
            state_error=state_error,
            inventory=inventory,
            inventory_error=inventory_error,
            observed_at=NOW,
            dependencies=self.dependencies(),
        )

    def test_state_failure_returns_stable_unavailable_contract(self) -> None:
        status, payload = self.compose({}, {}, state_error="invalid JSON")

        self.assertEqual(status, 503)
        self.assertFalse(payload["ok"])
        self.assertIn("invalid JSON", payload["error"])
        self.assertEqual(payload["counts"], {
            "total": 0, "verified_match": 0, "candidate": 0, "conflict": 0, "stale": 0,
        })
        self.assertEqual(payload["observations"], [])

    def test_reconciles_exact_stable_moved_conflicting_and_new_identities(self) -> None:
        inventory = {"inventory_status": "loaded", "assets": [
            self.asset("studio", "10.0.0.10", "studio.lan", "00:11:22:33:44:55"),
            self.asset("server", "10.0.0.20", "server.lan"),
        ]}
        state = {"updated_at": "2026-08-07T17:30:00Z", "observations": [
            self.observation("exact", "10.0.0.10", "studio.lan"),
            self.observation("moved", "10.0.0.11", "studio.lan"),
            self.observation("conflict", "10.0.0.20", "other.lan"),
            self.observation("candidate", "10.0.0.30", "new.lan"),
        ]}

        status, payload = self.compose(state, inventory)

        self.assertEqual(status, 200)
        self.assertEqual(payload["counts"], {
            "total": 4, "verified_match": 2, "candidate": 1, "conflict": 1, "stale": 0,
        })
        self.assertEqual([item["reconciliation"] for item in payload["observations"]], [
            "conflict", "candidate", "verified_match", "verified_match",
        ])
        moved = next(item for item in payload["observations"] if item["discovery_id"] == "moved")
        self.assertIn("new current address", moved["reconciliation_detail"])
        self.assertEqual(moved["authoritative_asset"]["configured_ip_addresses"], ["10.0.0.10"])

    def test_bounds_public_metadata_skips_invalid_rows_and_withholds_inventory_details(self) -> None:
        stale = self.observation(
            "stale", "10.0.0.40", "old.lan", last_seen="2026-08-05T12:00:00Z",
        )
        stale["lease_expires_at"] = "2026-08-05T13:00:00Z"
        stale["message_types"] = ["x" * 100] * 30
        stale["sensors"] = ["s" * 200] * 30
        stale["observation_count"] = -50
        state = {
            "collection": {
                "status": "x" * 80,
                "last_returned": 5000,
                "last_query_segments": 500,
                "last_error": "e" * 500,
            },
            "backfill": {"last_returned": 2_000_000, "last_query_segments": 100},
            "observations": [
                {"current_ip": "invalid", "last_seen": "not-a-time"},
                stale,
            ],
        }

        status, payload = self.compose(state, {"assets": []}, inventory_error="database offline")

        self.assertEqual(status, 200)
        self.assertEqual(payload["authoritative_inventory_status"], "unavailable")
        self.assertEqual(payload["counts"]["total"], 1)
        self.assertEqual(payload["counts"]["stale"], 1)
        record = payload["observations"][0]
        self.assertEqual(record["reconciliation"], "candidate")
        self.assertIsNone(record["authoritative_asset"])
        self.assertEqual(record["observation_count"], 0)
        self.assertEqual(len(record["message_types"]), 16)
        self.assertLessEqual(len(record["message_types"][0]), 80)
        self.assertEqual(payload["collection"]["last_returned"], 1000)
        self.assertEqual(payload["collection"]["last_query_segments"], 64)
        self.assertEqual(payload["backfill"]["last_returned"], 1_000_000)
        self.assertNotIn("database offline", str(payload))


if __name__ == "__main__":
    unittest.main()
