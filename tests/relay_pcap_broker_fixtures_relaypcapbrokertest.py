from __future__ import annotations

from relay_pcap_broker_fixtures import (
    Path,
    RELAY_PATH,
    REPO_ROOT,
    contextlib,
    fcntl,
    hashlib,
    importlib,
    io,
    json,
    load_relay,
    mock,
    os,
    subprocess,
    sys,
    tarfile,
    tempfile,
    time,
    unittest,
)

class RelayPcapBrokerTestFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.relay = load_relay()
        self.lock_directory = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-relay-pcap-test-"
        )
        self.addCleanup(self.lock_directory.cleanup)
        test_lock_path = str(Path(self.lock_directory.name) / "pcap-broker.lock")
        process_pcap_requests = self.relay.process_pcap_requests

        def process_with_isolated_lock(config):
            isolated_config = dict(config)
            broker = dict(isolated_config.get("pcap_broker") or {})
            broker.setdefault("lock_path", test_lock_path)
            isolated_config["pcap_broker"] = broker
            return process_pcap_requests(isolated_config)

        self.relay.process_pcap_requests = process_with_isolated_lock
        self.healthy_capture_status = {
            "ok": True,
            "status": "storage_status",
            "read_only_export": True,
            "disk_read_gate_enabled": False,
            "zeek_capture_loss_available": True,
            "zeek_capture_loss_max_percent": 0.0,
            "zeek_capture_loss_age_seconds": 30,
        }
        storage = mock.patch.object(
            self.relay,
            "security_onion_storage_status",
            return_value=self.healthy_capture_status,
        )
        storage.start()
        self.addCleanup(storage.stop)


    @staticmethod
    def streamed_result(request_id: str) -> dict:
        return {
            "request_id": request_id,
            "artifact_path": f"{request_id}.tar",
            "relay_spool_path": f"/relay-spool/{request_id}.tar",
            "artifact_sha256": "a" * 64,
            "artifact_size_bytes": 1024,
            "source_mode": "streamed_chunks",
            "security_onion_staging_bytes": 0,
        }
