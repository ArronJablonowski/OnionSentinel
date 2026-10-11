from __future__ import annotations

from dhcp_asset_discovery_fixtures import (
    BROKER,
    BUILDER,
    COLLECTOR,
    INSTALLER,
    PORTAL,
    PROMOTER,
    Path,
    QUERY_CLIENT,
    ROOT,
    SimpleNamespace,
    WRAPPER,
    contextlib,
    dt,
    hashlib,
    importlib,
    inspect,
    io,
    json,
    load_module,
    mock,
    shutil,
    stat,
    subprocess,
    sys,
    tempfile,
    unittest,
)

class DhcpDiscoveryApiAndPageTestsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.portal = load_module("dhcp_portal_test", PORTAL)
        self.portal.ASSET_INVENTORY_FILE = self.root / "asset_inventory.json"
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE = self.root / "dhcp-observations.json"
        self.portal.ASSET_INVENTORY_CACHE = {"signature": None, "inventory": None}
        self.portal.ASSET_INVENTORY_FILE.write_text(json.dumps({
            "schema": "onion-sentinel-asset-inventory-v1",
            "version": 1,
            "generated_at": "2026-07-29T12:00:00-06:00",
            "assets": [{
                "asset_id": "studio",
                "valid_from": "2026-07-01T00:00:00-06:00",
                "valid_until": None,
                "identifiers": {
                    "ip_addresses": ["10.66.6.210"],
                    "hostnames": ["studio.example.lan"],
                    "mac_addresses": [],
                },
                "role": "workstation",
                "platform": "macOS",
                "criticality": "medium",
                "source_type": "operator-verified",
                "source_ref": "ticket",
                "confidence": "high",
                "owner_ref": "",
                "expected_services": [],
                "expected_behaviors": [],
                "share_with_hosted_models": False,
            }],
        }), encoding="utf-8")


    def tearDown(self) -> None:
        self.tmp.cleanup()
