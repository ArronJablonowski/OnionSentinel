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

class DhcpCollectorTestsFixtures(unittest.TestCase):
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


