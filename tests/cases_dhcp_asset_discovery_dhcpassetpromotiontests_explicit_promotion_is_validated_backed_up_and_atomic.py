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

class DhcpAssetPromotionTestsExplicitPromotionIsValidatedBackedUpAndAtomicCases:
    def test_explicit_promotion_is_validated_backed_up_and_atomic(self) -> None:
        now = dt.datetime(2026, 7, 30, 18, tzinfo=dt.timezone.utc)
        result, backup = self.promoter.promote(self.args(), now)
        payload = json.loads(self.inventory.read_text(encoding="utf-8"))
        self.assertEqual(result["asset_id"], "reserved-client")
        self.assertEqual(result["mac_address_scope"], "globally_administered")
        self.assertTrue(backup.is_file())
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
        self.assertEqual(payload["assets"][0]["identifiers"]["ip_addresses"], ["10.66.6.210"])
        self.assertEqual(payload["assets"][0]["identifiers"]["mac_addresses"], ["00:11:22:33:44:55"])
        self.assertEqual(payload["assets"][0]["source_type"], "operator-approved-dhcp")
        self.assertFalse(payload["assets"][0]["share_with_hosted_models"])


    def test_promotion_rejects_changed_identity_and_private_mac_without_override(self) -> None:
        now = dt.datetime(2026, 7, 30, 18, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(ValueError, "changed after operator review"):
            self.promoter.promote(
                self.args(expected_ip="10.66.6.211"),
                now,
            )
        payload = json.loads(self.state.read_text(encoding="utf-8"))
        payload["observations"][0]["mac_address"] = "02:11:22:33:44:55"
        self.state.write_text(json.dumps(payload), encoding="utf-8")
        self.state.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "locally administered"):
            self.promoter.promote(
                self.args(expected_mac="02:11:22:33:44:55"),
                now,
            )
