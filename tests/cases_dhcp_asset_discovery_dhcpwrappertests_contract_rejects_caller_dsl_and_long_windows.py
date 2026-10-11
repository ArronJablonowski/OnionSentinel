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

class DhcpWrapperTestsContractRejectsCallerDslAndLongWindowsCases:
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


    def test_live_security_onion_ecs_observation_is_normalized(self) -> None:
        result = self.wrapper.normalized_observation({
            "_source": {
                "@timestamp": "2026-07-29T17:05:00Z",
                "dhcp": {
                    "assigned_ip": ["10.66.6.210"],
                    "requested_address": "10.66.6.209",
                    "lease_time": 7200,
                    "message_types": ["ACK"],
                },
                "client": {"address": "10.66.6.208"},
                "server": {"address": "10.66.6.1"},
                "host": {
                    "mac": ["AA:BB:CC:DD:EE:FF"],
                    "hostname": "Studio.EXAMPLE.LAN.",
                },
                "observer": {"name": "so-sensor-1"},
            }
        })
        self.assertEqual(result["ip_address"], "10.66.6.210")
        self.assertEqual(result["hostname"], "studio.example.lan")
        self.assertEqual(result["mac_address"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["message_type"], "ACK")
        self.assertEqual(result["lease_seconds"], 7200)


    def test_server_address_is_never_used_as_a_client_asset(self) -> None:
        result = self.wrapper.normalized_observation({
            "_source": {
                "@timestamp": "2026-07-29T17:05:00Z",
                "server": {"address": "10.66.6.1"},
                "host": {"mac": ["AA:BB:CC:DD:EE:FF"]},
            }
        })
        self.assertIsNone(result)


    def test_source_uses_search_only_and_fixed_dataset(self) -> None:
        source = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('INDEX = "logs-zeek-so"', source)
        self.assertIn('DATASET = "zeek.dhcp"', source)
        self.assertIn('endpoint = f"{INDEX}/_search"', source)
        self.assertNotIn("/_update", source)
        self.assertNotIn("/_delete", source)
        self.assertNotIn("/_bulk", source)
        for field in (
            "dhcp.assigned_ip",
            "dhcp.requested_address",
            "dhcp.lease_time",
            "dhcp.message_types",
            "host.mac",
            "client.address",
        ):
            self.assertIn(field, self.wrapper.SOURCE_FIELDS)
        self.assertNotIn("server.address", self.wrapper.SOURCE_FIELDS)
        incident_source = (
            ROOT / "security-onion" / "bin" / "export-incident-evidence"
        ).read_text(encoding="utf-8")
        self.assertIn("DHCP_DISCOVERY_CONTRACT", incident_source)
        self.assertIn("so_evidence_dispatch.execute_dhcp_discovery", incident_source)
        dispatcher = (ROOT / "security-onion/bin/so_evidence_dispatch.py").read_text()
        self.assertIn("r.execute_dhcp_discovery(request_data)", dispatcher)
