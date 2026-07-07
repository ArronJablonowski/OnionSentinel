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
            if path.startswith("/pcap/requests"):
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

    def test_broker_paths_can_match_n8n_webhook_routes(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap-complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        config = {
            "pcap_broker": {
                "enabled": True,
                "limit": 1,
                "requests_method": "POST",
                "paths": {
                    "requests": "/pcap-requests",
                    "claim": "/pcap-claim",
                    "complete": "/pcap-complete",
                },
            }
        }
        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "run_ssh_pcap_export",
                return_value={
                    "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 1024,
                },
            ):
                result = self.relay.process_pcap_requests(config)

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][1], "/pcap-requests?status=pending&limit=1")
        self.assertEqual(calls[0][2], {"status": "pending", "limit": 1})
        self.assertEqual(calls[1][1], "/pcap-claim")
        self.assertEqual(calls[2][1], "/pcap-complete")

    def test_relay_uploads_inline_artifact_before_completion(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap-artifact":
                return {"ok": True, "status": "artifact_stored"}
            if path == "/pcap-complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        config = {
            "pcap_broker": {
                "enabled": True,
                "limit": 1,
                "requests_method": "POST",
                "upload_artifact": True,
                "paths": {
                    "requests": "/pcap-requests",
                    "claim": "/pcap-claim",
                    "complete": "/pcap-complete",
                    "artifact": "/pcap-artifact",
                },
            }
        }
        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "run_ssh_pcap_export",
                return_value={
                    "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 12,
                    "artifact_base64": "ZmFrZS1wY2FwLXRhcg==",
                },
            ) as export:
                result = self.relay.process_pcap_requests(config)

        export.assert_called_once()
        self.assertTrue(export.call_args.args[1]["inline_artifact_base64"])
        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual([call[1] for call in calls], ["/pcap-requests?status=pending&limit=1", "/pcap-claim", "/pcap-artifact", "/pcap-complete"])
        self.assertEqual(calls[2][2]["artifact_base64"], "ZmFrZS1wY2FwLXRhcg==")
        self.assertTrue(calls[3][2]["artifact_ingested"])

    def test_pcap_export_parses_json_after_login_banner(self) -> None:
        config = {
            "security_onion": {
                "ssh_user": "so-ai-relay",
                "host": "security-onion.example.test",
                "pcap_ssh_key": "/tmp/pcap-key",
                "ssh_key": "/tmp/regular-key",
            },
            "relay": {"ssh_timeout_seconds": 5, "pcap_timeout_seconds": 10},
        }
        stdout = "\n".join(
            [
                "##########################################",
                "###   UNAUTHORIZED ACCESS PROHIBITED   ###",
                "##########################################",
                '{"ok": true, "artifact_path": "/nsm/pcapout/onion-sentinel/test.tar", "artifact_sha256": "'
                + ("a" * 64)
                + '", "artifact_size_bytes": 4096}',
            ]
        )
        completed = self.relay.subprocess.CompletedProcess(["ssh"], 0, stdout, "")

        with mock.patch.object(self.relay.subprocess, "run", return_value=completed):
            result = self.relay.run_ssh_pcap_export(config, {"request_id": "pcap-unit-test"})

        self.assertEqual(result["artifact_path"], "/nsm/pcapout/onion-sentinel/test.tar")
        self.assertEqual(result["artifact_size_bytes"], 4096)


if __name__ == "__main__":
    unittest.main()
