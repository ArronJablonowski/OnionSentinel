#!/usr/bin/env python3
"""Contracts for bounded, read-only DHCP asset discovery."""
from __future__ import annotations

import datetime as dt
import importlib.machinery
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "n8n" / "bin" / "collect-dhcp-asset-discovery.py"
WRAPPER = ROOT / "security-onion" / "bin" / "export-dhcp-observations"
BROKER = ROOT / "relay" / "app" / "dhcp_asset_discovery_broker.py"
PORTAL = ROOT / "onion-sentinel-dashboard" / "report_portal.py"
BUILDER = ROOT / "onion-sentinel-dashboard" / "scripts" / "build_soc_alerts_dashboard.py"
INSTALLER = ROOT / "n8n" / "bin" / "install-macstudio-stack.zsh"


def load_module(name: str, path: Path):
    for dependency in (ROOT / "n8n" / "bin", ROOT / "relay" / "app"):
        if str(dependency) not in sys.path:
            sys.path.insert(0, str(dependency))
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


class DhcpWrapperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.wrapper = load_module("dhcp_so_wrapper_test", WRAPPER)

    def test_contract_rejects_caller_dsl_and_long_windows(self) -> None:
        valid = {
            "contract": self.wrapper.CONTRACT,
            "operation": "dhcp_observations",
            "window": {
                "start": "2026-07-29T17:00:00Z",
                "end": "2026-07-29T17:30:00Z",
            },
            "size": 1000,
        }
        start, end, size = self.wrapper.validate_request(
            valid,
            now=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(size, 1000)
        self.assertLess(start, end)
        with self.assertRaises(ValueError):
            self.wrapper.validate_request(
                {**valid, "query": {"match_all": {}}},
                now=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc),
            )
        too_long = json.loads(json.dumps(valid))
        too_long["window"]["start"] = "2026-07-28T16:59:00Z"
        with self.assertRaises(ValueError):
            self.wrapper.validate_request(
                too_long,
                now=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc),
            )

    def test_zeek_observation_is_normalized_and_bounded(self) -> None:
        result = self.wrapper.normalized_observation({
            "_source": {
                "@timestamp": "2026-07-29T17:05:00Z",
                "zeek": {
                    "dhcp": {
                        "assigned_addr": "10.66.6.210",
                        "host_name": "Studio.EXAMPLE.LAN.",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "msg_type": "ACK",
                        "lease_time": 3600,
                    }
                },
                "observer": {"name": "so-sensor-1"},
            }
        })
        self.assertEqual(result["ip_address"], "10.66.6.210")
        self.assertEqual(result["hostname"], "studio.example.lan")
        self.assertEqual(result["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["message_type"], "ACK")
        self.assertEqual(len(result["evidence_id"]), 24)

    def test_source_uses_search_only_and_fixed_dataset(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('INDEX = "logs-zeek-so"', source)
        self.assertIn('DATASET = "zeek.dhcp"', source)
        self.assertIn('endpoint = f"{INDEX}/_search"', source)
        self.assertNotIn("/_update", source)
        self.assertNotIn("/_delete", source)
        self.assertNotIn("/_bulk", source)


class DhcpRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.broker = load_module("dhcp_relay_broker_test", BROKER)

    def test_relay_revalidates_the_fixed_contract(self) -> None:
        request = {
            "contract": self.broker.CONTRACT,
            "operation": "dhcp_observations",
            "window": {
                "start": "2026-07-29T17:00:00Z",
                "end": "2026-07-29T17:15:00Z",
            },
            "size": 500,
        }
        self.broker.validate_request(request)
        with self.assertRaises(ValueError):
            self.broker.validate_request({**request, "index": "*"})


class DhcpCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.collector = load_module("dhcp_collector_test", COLLECTOR)
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def observation(
        self,
        *,
        observed_at: str,
        address: str,
        mac: str,
        hostname: str,
        evidence_id: str,
    ) -> dict:
        return {
            "observed_at": observed_at,
            "ip_address": address,
            "mac_address": mac,
            "hostname": hostname,
            "message_type": "ACK",
            "lease_seconds": 3600,
            "sensor": "so-sensor-1",
            "evidence_id": evidence_id,
        }

    def test_merge_tracks_ip_movement_by_mac_without_promoting_inventory(self) -> None:
        now = dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc)
        merged = self.collector.merge_observations(
            self.collector.empty_state(),
            [
                self.observation(
                    observed_at="2026-07-29T17:00:00Z",
                    address="10.66.6.210",
                    mac="aa:bb:cc:dd:ee:ff",
                    hostname="studio.example.lan",
                    evidence_id="a" * 24,
                ),
                self.observation(
                    observed_at="2026-07-29T17:30:00Z",
                    address="10.66.6.211",
                    mac="aa:bb:cc:dd:ee:ff",
                    hostname="studio.example.lan",
                    evidence_id="b" * 24,
                ),
            ],
            now,
            30,
        )
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["current_ip"], "10.66.6.211")
        self.assertEqual(merged[0]["ip_addresses"], ["10.66.6.210", "10.66.6.211"])
        self.assertEqual(merged[0]["observation_count"], 2)
        self.assertNotIn("authoritative", merged[0])

    def test_disabled_collector_writes_timestamped_state_without_ssh(self) -> None:
        config = self.root / "config.json"
        state = self.root / "state.json"
        log = self.root / "collector.jsonl"
        config.write_text(json.dumps({
            "enabled": False,
            "host": "10.88.8.8",
            "ssh_user": "aj",
            "ssh_key": str(self.root / "key"),
            "known_hosts": str(self.root / "known_hosts"),
            "connect_timeout_seconds": 20,
            "timeout_seconds": 90,
            "max_response_bytes": 4194304,
            "max_stderr_bytes": 131072,
            "query_window_minutes": 30,
            "query_size": 1000,
            "retention_days": 30,
        }), encoding="utf-8")
        with mock.patch.object(
            sys,
            "argv",
            ["collector", "--config", str(config), "--state", str(state), "--log", str(log)],
        ), mock.patch.object(
            self.collector,
            "run_bounded_command",
            side_effect=AssertionError("SSH must not run while disabled"),
        ):
            self.assertEqual(self.collector.main(), 0)
        payload = json.loads(state.read_text(encoding="utf-8"))
        record = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(payload["collection"]["status"], "disabled")
        self.assertTrue(payload["collection"]["last_attempt_at"].endswith("Z"))
        self.assertTrue(record["timestamp"].endswith("Z"))
        self.assertEqual(record["event"], "dhcp_asset_discovery.disabled")


class DhcpDiscoveryApiAndPageTests(unittest.TestCase):
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
            ],
        }), encoding="utf-8")
        status, payload = self.portal.dhcp_asset_discovery_response(
            observed_at=dt.datetime(2026, 7, 29, 18, tzinfo=dt.timezone.utc)
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["counts"]["verified_match"], 1)
        self.assertEqual(payload["counts"]["conflict"], 1)
        self.assertEqual(payload["counts"]["candidate"], 1)
        self.assertEqual(payload["observations"][0]["reconciliation"], "conflict")
        self.assertNotIn("owner_ref", json.dumps(payload))

    def test_page_route_scheduler_and_installers_are_wired(self) -> None:
        builder = load_module("dhcp_builder_test", BUILDER)
        builder.DB_PATH = self.root / "missing.sqlite3"
        builder.PCAP_ARTIFACT_DIR = self.root / "pcap"
        page = builder.render_static_page(builder.build_html([]), "asset_inventory", [])
        self.assertIn("DHCP network discovery", page)
        self.assertIn("fetch('/api/dhcp-asset-discovery'", page)
        self.assertIn("Candidates and conflicts require operator review", page)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("collect-dhcp-asset-discovery.py", installer)
        self.assertIn("com.arron.soc.dhcp-asset-discovery.plist", installer)
        plist = (ROOT / "n8n" / "launchd" / "com.arron.soc.dhcp-asset-discovery.plist").read_text(encoding="utf-8")
        self.assertIn("<integer>900</integer>", plist)


if __name__ == "__main__":
    unittest.main()
