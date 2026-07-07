#!/usr/bin/env python3
"""Regression checks for relay-side PCAP broker fulfillment."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
RELAY_PATH = REPO_ROOT / "relay" / "app" / "relay.py"


def load_relay():
    spec = importlib.util.spec_from_file_location("relay", RELAY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RelayPcapBrokerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.relay = load_relay()

    def test_disabled_broker_does_not_poll(self) -> None:
        with mock.patch.object(self.relay, "broker_request") as broker_request:
            result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": False}})

        self.assertEqual(result, {"ok": True, "enabled": False, "processed": 0})
        broker_request.assert_not_called()

    def test_claimed_request_is_exported_and_completed(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if method == "GET":
                return {"ok": True, "requests": [request]}
            if path == "/pcap/claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap/complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "run_ssh_pcap_export",
                return_value={
                    "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 1024,
                },
            ) as export:
                result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["failed"], 0)
        export.assert_called_once()
        self.assertEqual(calls[-1][1], "/pcap/complete")
        self.assertEqual(calls[-1][2]["status"], "fulfilled")


if __name__ == "__main__":
    unittest.main()
