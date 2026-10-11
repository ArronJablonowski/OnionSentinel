from __future__ import annotations

from installer_source_fixture import read_installer_source

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

class DhcpDiscoveryApiAndPageTestsApiClassifiesMatchCandidateAndConflictCases:
    def test_api_classifies_match_candidate_and_conflict(self) -> None:
        def record(identifier: str, ip: str, hostname: str) -> dict:
            return {
                "discovery_id": identifier,
                "identity_type": "hostname",
                "identity_value": hostname,
                "current_ip": ip,
                "ip_addresses": [ip],
                "mac_address": "",
                "hostname": hostname,
                "hostnames": [hostname],
                "first_seen": "2026-07-29T17:00:00Z",
                "last_seen": "2026-07-29T17:30:00Z",
                "lease_expires_at": "2026-07-29T18:30:00Z",
                "message_types": ["ACK"],
                "sensors": ["so-sensor-1"],
                "evidence_ids": ["a" * 24],
                "observation_count": 1,
            }
        self.portal.DHCP_ASSET_DISCOVERY_STATE_FILE.write_text(json.dumps({
            "schema": "onion-sentinel-dhcp-asset-observations-v1",
            "version": 1,
            "updated_at": "2026-07-29T17:30:00Z",
            "collection": {"status": "ok", "last_success_at": "2026-07-29T17:30:00Z"},
            "observations": [
                record("match", "10.66.6.210", "studio.example.lan"),
                record("conflict", "10.66.6.210", "other.example.lan"),
                record("candidate", "10.66.6.220", "new.example.lan"),
                record("moved", "10.66.6.211", "studio.example.lan"),
            ],
        }), encoding="utf-8")
        status, payload = self.portal.dhcp_asset_discovery_response(
            observed_at=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc)
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["counts"]["verified_match"], 2)
        self.assertEqual(payload["counts"]["conflict"], 1)
        self.assertEqual(payload["counts"]["candidate"], 1)
        self.assertEqual(payload["observations"][0]["reconciliation"], "conflict")
        moved = next(
            item
            for item in payload["observations"]
            if item["discovery_id"] == "moved"
        )
        self.assertEqual(moved["reconciliation"], "verified_match")
        self.assertIn("new current address", moved["reconciliation_detail"])
        self.assertEqual(payload["backfill"]["status"], "never_run")
        self.assertEqual(
            moved["authoritative_asset"]["configured_ip_addresses"],
            ["10.66.6.210"],
        )
        self.assertNotIn("owner_ref", json.dumps(payload))


    def test_page_route_scheduler_and_installers_are_wired(self) -> None:
        builder = load_module("dhcp_builder_test", BUILDER)
        builder.DB_PATH = self.root / "missing.sqlite3"
        builder.PCAP_ARTIFACT_DIR = self.root / "pcap"
        page = builder.render_static_page(builder.build_html([]), "asset_inventory", [])
        self.assertIn("DHCP network discovery", page)
        self.assertIn("fetch('/api/dhcp-asset-discovery'", page)
        self.assertIn(
            "Candidates and conflicts remain non-authoritative",
            page,
        )
        installer = read_installer_source(INSTALLER)
        self.assertIn("collect-dhcp-asset-discovery.py", installer)
        for name in (
            "dhcp_asset_contract.py",
            "dhcp_asset_state.py",
            "dhcp_asset_adapters.py",
            "dhcp_asset_workflow.py",
        ):
            self.assertIn(
                f'cp "$REPO_DIR/n8n/bin/{name}" "$STACK_DIR/bin/{name}"',
                installer,
            )
        self.assertIn("query-security-onion.py", installer)
        self.assertIn("promote-dhcp-asset.py", installer)
        self.assertIn("com.arron.soc.dhcp-asset-discovery.plist", installer)
        config = (
            ROOT / "n8n" / "config" / "dhcp-asset-discovery.example.json"
        ).read_text(encoding="utf-8")
        self.assertIn("onion-sentinel-incident-evidence_ed25519", config)
        self.assertNotIn("onion-sentinel-dhcp-discovery_ed25519", config)
        self.assertIn('"query_window_minutes": 1440', config)
        plist = (ROOT / "n8n" / "launchd" / "com.arron.soc.dhcp-asset-discovery.plist").read_text(encoding="utf-8")
        self.assertIn("<integer>900</integer>", plist)

