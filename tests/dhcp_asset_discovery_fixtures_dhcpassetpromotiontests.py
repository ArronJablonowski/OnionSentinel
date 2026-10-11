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

class DhcpAssetPromotionTestsFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.promoter = load_module("dhcp_asset_promoter_test", PROMOTER)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.inventory = self.root / "asset_inventory.json"
        self.state = self.root / "dhcp-observations.json"
        self.inventory.write_text(json.dumps({
            "schema": "onion-sentinel-asset-inventory-v1",
            "version": 1,
            "generated_at": "2026-07-29T00:00:00Z",
            "assets": [],
        }), encoding="utf-8")
        self.state.write_text(json.dumps({
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            "version": 1,
            "updated_at": "2026-07-30T18:00:00Z",
            "collection": {"status": "ok"},
            "observations": [{
                "discovery_id": "a" * 20,
                "current_ip": "10.66.6.210",
                "mac_address": "00:11:22:33:44:55",
                "hostname": "reserved-client",
                "last_seen": "2026-07-30T17:55:00Z",
                "lease_expires_at": "2026-07-31T17:55:00Z",
                "observation_count": 12,
            }],
        }), encoding="utf-8")
        self.inventory.chmod(0o600)
        self.state.chmod(0o600)


    def tearDown(self) -> None:
        self.tmp.cleanup()


    def args(self, **overrides):
        values = {
            "inventory": self.inventory,
            "state": self.state,
            "discovery_id": "a" * 20,
            "expected_ip": "10.66.6.210",
            "expected_mac": "00:11:22:33:44:55",
            "expected_hostname": "reserved-client",
            "asset_id": "reserved-client",
            "hostname": "",
            "role": "Reviewed LAN client",
            "platform": "",
            "owner_ref": "operator-reviewed",
            "criticality": "unknown",
            "accept_locally_administered_mac": False,
            "confirm": f"PROMOTE:{'a' * 20}",
        }
        values.update(overrides)
        return SimpleNamespace(**values)
