#!/usr/bin/env python3
"""Contracts for authoritative asset identity APIs and dashboard rendering."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PORTAL_PATH = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
BUILDER_PATH = (
    ROOT
    / "onion-sentinel-dashboard"
    / "scripts"
    / "build_soc_alerts_dashboard.py"
)
INSTALLER_PATH = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AssetInventoryPageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.inventory_path = Path(self.tmp.name) / "asset_inventory.json"
        self.dhcp_state_path = (
            Path(self.tmp.name) / "dhcp-observations.json"
        )
        self.portal = load_module("asset_inventory_page_portal", PORTAL_PATH)
        self.portal.ASSET_INVENTORY_FILE = self.inventory_path
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE = self.dhcp_state_path
        self.portal.ASSET_INVENTORY_CACHE = {
            "signature": None,
            "inventory": None,
        }

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def asset(
        asset_id: str,
        ip: str,
        hostname: str,
        valid_from: str,
        valid_until: str | None = None,
    ) -> dict:
        return {
            "asset_id": asset_id,
            "valid_from": valid_from,
            "valid_until": valid_until,
            "identifiers": {
                "ip_addresses": [ip],
                "hostnames": [hostname] if hostname else [],
            },
            "role": "workstation",
            "platform": "macOS",
            "owner_ref": "must-not-be-exposed",
            "criticality": "medium",
            "expected_services": [],
            "expected_behaviors": ["operator-only context"],
            "source_type": "operator-verified",
            "source_ref": "inventory-ticket",
            "confidence": "high",
            "share_with_hosted_models": False,
        }

    def write_inventory(self, assets: list[dict]) -> None:
        self.inventory_path.write_text(
            json.dumps(
                {
                    "schema": "onion-sentinel-asset-inventory-v1",
                    "version": 1,
                    "generated_at": "2026-07-29T12:00:00-06:00",
                    "assets": assets,
                }
            ),
            encoding="utf-8",
        )

    def test_api_returns_only_current_sanitized_assignments(self) -> None:
        self.write_inventory(
            [
                self.asset(
                    "current-mac",
                    "10.66.6.210",
                    "current-mac.example.lan",
                    "2026-07-01T00:00:00-06:00",
                ),
                self.asset(
                    "retired-mac",
                    "10.66.6.211",
                    "retired-mac.example.lan",
                    "2025-01-01T00:00:00-07:00",
                    "2026-01-01T00:00:00-07:00",
                ),
            ]
        )

        status, payload = self.portal.asset_inventory_response(
            observed_at=dt.datetime(
                2026,
                7,
                29,
                18,
                0,
                tzinfo=dt.timezone.utc,
            )
        )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["records_total"], 2)
        self.assertEqual(payload["current_asset_count"], 1)
        self.assertEqual(payload["state_counts"]["expired"], 1)
        self.assertEqual(payload["assets"][0]["asset_id"], "current-mac")
        self.assertEqual(payload["assets"][0]["ip_addresses"], ["10.66.6.210"])
        self.assertEqual(
            payload["assets"][0]["hostnames"],
            ["current-mac.example.lan"],
        )
        self.assertNotIn("owner_ref", payload["assets"][0])
        self.assertNotIn("expected_behaviors", payload["assets"][0])

    def test_api_overlays_moved_known_asset_and_adds_provisional_client(
        self,
    ) -> None:
        self.write_inventory(
            [
                self.asset(
                    "current-mac",
                    "10.66.6.210",
                    "current-mac.example.lan",
                    "2026-07-01T00:00:00-06:00",
                )
            ]
        )
        self.dhcp_state_path.write_text(
            json.dumps(
                {
                    "schema": "onion-sentinel-dhcp-asset-observations-v1",
                    "version": 1,
                    "updated_at": "2026-07-29T17:30:00Z",
                    "collection": {
                        "status": "ok",
                        "last_success_at": "2026-07-29T17:30:00Z",
                    },
                    "observations": [
                        {
                            "discovery_id": "known",
                            "current_ip": "10.66.6.220",
                            "mac_address": "",
                            "hostname": "current-mac.example.lan",
                            "first_seen": "2026-07-29T17:00:00Z",
                            "last_seen": "2026-07-29T17:30:00Z",
                            "lease_expires_at": "2026-07-29T18:30:00Z",
                        },
                        {
                            "discovery_id": "candidate",
                            "current_ip": "10.66.6.230",
                            "mac_address": "aa:bb:cc:dd:ee:ff",
                            "hostname": "new-client.example.lan",
                            "first_seen": "2026-07-29T17:05:00Z",
                            "last_seen": "2026-07-29T17:25:00Z",
                            "lease_expires_at": "2026-07-29T18:25:00Z",
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.asset_inventory_response(
            observed_at=dt.datetime(
                2026,
                7,
                29,
                18,
                0,
                tzinfo=dt.timezone.utc,
            )
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["authoritative_asset_count"], 1)
        self.assertEqual(payload["discovered_asset_count"], 1)
        self.assertEqual(payload["current_asset_count"], 2)
        by_id = {item["asset_id"]: item for item in payload["assets"]}
        known = by_id["current-mac"]
        self.assertEqual(known["ip_addresses"], ["10.66.6.220"])
        self.assertEqual(
            known["configured_ip_addresses"],
            ["10.66.6.210"],
        )
        self.assertEqual(known["current_ip_source"], "zeek-dhcp")
        candidate = by_id["dhcp-candidate"]
        self.assertEqual(candidate["state"], "observed")
        self.assertEqual(candidate["ip_addresses"], ["10.66.6.230"])
        self.assertEqual(
            candidate["source_type"],
            "zeek-dhcp-observation",
        )
        self.assertEqual(
            candidate["mac_address_scope"],
            "locally_administered",
        )

    def test_ip_resolution_uses_event_time_and_refuses_ambiguity(self) -> None:
        old = self.asset(
            "old-owner",
            "10.66.6.210",
            "old-owner.example.lan",
            "2025-01-01T00:00:00-07:00",
            "2026-07-01T00:00:00-06:00",
        )
        current = self.asset(
            "current-owner",
            "10.66.6.210",
            "current-owner.example.lan",
            "2026-07-01T00:00:00-06:00",
        )
        self.write_inventory([old, current])
        inventory, error = self.portal.load_asset_inventory_data()
        self.assertEqual(error, "")

        historical = self.portal.resolve_asset_ip(
            "10.66.6.210",
            "2026-06-15  12:00:00-06:00",
            inventory,
        )
        present = self.portal.resolve_asset_ip(
            "10.66.6.210",
            "2026-07-29  12:00:00-06:00",
            inventory,
        )

        self.assertEqual(historical["hostname"], "old-owner.example.lan")
        self.assertEqual(present["hostname"], "current-owner.example.lan")

        conflict = self.asset(
            "conflicting-owner",
            "10.66.6.210",
            "conflict.example.lan",
            "2026-07-01T00:00:00-06:00",
        )
        self.write_inventory([current, conflict])
        self.portal.ASSET_INVENTORY_CACHE = {
            "signature": None,
            "inventory": None,
        }
        inventory, error = self.portal.load_asset_inventory_data()
        self.assertEqual(error, "")
        ambiguous = self.portal.resolve_asset_ip(
            "10.66.6.210",
            "2026-07-29  12:00:00-06:00",
            inventory,
        )
        self.assertEqual(ambiguous["status"], "ambiguous")
        self.assertNotIn("hostname", ambiguous)

    def test_asset_page_and_navigation_are_generated(self) -> None:
        builder = load_module("asset_inventory_page_builder", BUILDER_PATH)
        builder.DB_PATH = Path(self.tmp.name) / "missing.sqlite3"
        builder.PCAP_ARTIFACT_DIR = Path(self.tmp.name) / "pcap-artifacts"

        page = builder.render_static_page(
            builder.build_html([]),
            "asset_inventory",
            [],
        )
        incident_page = builder.render_static_page(
            builder.build_html([]),
            "investigations",
            [],
        )

        self.assertIn('<h1 id="page-title">Asset Inventory</h1>', page)
        self.assertIn('id="asset-inventory-view"', page)
        self.assertIn("fetch('/api/asset-inventory'", page)
        self.assertIn("Current IP address", page)
        self.assertIn("<th>Asset</th><th>State</th><th>Current IP address</th>", page)
        self.assertIn(
            '<td><strong class="asset-name" title="${esc(item.asset_id)}">'
            '${esc(item.asset_id)}</strong></td>'
            '<td><span class="asset-state">${esc(item.state||\'current\')}</span></td>',
            page,
        )
        self.assertIn("<th>From</th><th>Until</th><th>Source</th>", page)
        self.assertIn(
            '<td class="asset-validity">${timestamp(item.valid_from)}</td>'
            '<td class="asset-validity">${timestamp(item.valid_until)}',
            page,
        )
        self.assertNotIn("<th>Validity</th>", page)
        self.assertIn('colspan="10" class="ir-loading">Loading known assets', page)
        self.assertIn(".asset-table th:nth-child(10){width:190px}", page)
        self.assertIn(".asset-table th:nth-child(1){width:220px}", page)
        self.assertIn("text-overflow:ellipsis;white-space:nowrap", page)
        self.assertIn("Current address from passive DHCP", page)
        self.assertIn("provisional DHCP observation", page)
        self.assertIn("Historical backfill has not run", page)
        self.assertIn("mac_address_scope", page)
        self.assertIn("asset-inventory.html", page)
        self.assertIn("const assetIdentityHtml=asset=>", incident_page)
        self.assertIn("item.source_asset", incident_page)
        self.assertIn("item.destination_asset", incident_page)

    def test_installer_deploys_shared_inventory_validator(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/asset_inventory.py" '
            '"$DASHBOARD_RUNTIME_DIR/asset_inventory.py"',
            installer,
        )


if __name__ == "__main__":
    unittest.main()
