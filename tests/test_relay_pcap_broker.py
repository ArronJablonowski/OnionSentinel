#!/usr/bin/env python3
"""Regression checks for relay-side PCAP broker fulfillment."""
from __future__ import annotations

import importlib.util
import contextlib
import io
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

    def test_mixed_broker_history_only_processes_pending_requests(self) -> None:
        history = [
            {"request_id": "old-failed", "status": "failed", "source_ip": "192.0.2.1"},
            {"request_id": "new-pending", "status": "pending", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"},
            {"request_id": "old-fulfilled", "status": "fulfilled", "source_ip": "192.0.2.2"},
        ]
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": history}
            if path == "/pcap/claim":
                self.assertEqual(payload_data["request_id"], "new-pending")
                return {"ok": True, "claimed": True, "request": history[1]}
            if path == "/pcap/complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "run_ssh_pcap_export",
                return_value={
                    "artifact_path": "/nsm/pcapout/onion-sentinel/new-pending.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 1024,
                },
            ) as export:
                result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 3}})

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 1)
        export.assert_called_once()
        self.assertEqual([call[2]["request_id"] for call in calls if call[1] == "/pcap/claim"], ["new-pending"])

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

    def test_relay_can_upload_artifact_in_verified_chunks(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        artifact = (b"chunked-pcap-artifact-" * 120)[:2500]
        artifact_sha256 = self.relay.hashlib.sha256(artifact).hexdigest()
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap-artifact":
                self.assertIn("chunk_base64", payload_data)
                return {"ok": True, "status": "chunk_stored"}
            if path == "/pcap-complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        config = {
            "pcap_broker": {
                "enabled": True,
                "limit": 1,
                "requests_method": "POST",
                "upload_artifact": True,
                "artifact_upload_mode": "chunked",
                "artifact_chunk_size_bytes": 1024,
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
                    "artifact_sha256": artifact_sha256,
                    "artifact_size_bytes": len(artifact),
                    "artifact_base64": self.relay.base64.b64encode(artifact).decode("ascii"),
                },
            ):
                result = self.relay.process_pcap_requests(config)

        chunk_calls = [call for call in calls if call[1] == "/pcap-artifact"]
        self.assertEqual(len(chunk_calls), 3)
        self.assertEqual([call[2]["chunk_index"] for call in chunk_calls], [0, 1, 2])
        self.assertTrue(all(call[2]["chunk_count"] == 3 for call in chunk_calls))
        self.assertEqual(result["fulfilled"], 1)
        self.assertTrue(calls[-1][2]["artifact_ingested"])

    def test_artifact_upload_failure_records_fulfillment_metadata(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        completions: list[dict] = []

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap-artifact":
                raise RuntimeError("artifact endpoint unavailable")
            if path == "/pcap-complete":
                completions.append(payload_data)
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
            ):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = self.relay.process_pcap_requests(config)

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["artifact_upload_failed"], 1)
        self.assertEqual(completions[0]["status"], "fulfilled")
        self.assertFalse(completions[0]["artifact_ingested"])
        self.assertIn("artifact endpoint unavailable", completions[0]["artifact_ingest_error"])
        self.assertIn("pcap_artifact_upload_failed", stderr.getvalue())

    def test_completion_failure_does_not_abort_remaining_pcap_requests(self) -> None:
        requests = [
            {"request_id": "pcap-unit-test-1", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"},
            {"request_id": "pcap-unit-test-2", "source_ip": "192.0.2.11", "destination_ip": "198.51.100.11"},
        ]
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": requests}
            if path == "/pcap/claim":
                request_id = payload_data["request_id"]
                return {"ok": True, "claimed": True, "request": next(item for item in requests if item["request_id"] == request_id)}
            if path == "/pcap/complete" and payload_data["request_id"] == "pcap-unit-test-1":
                raise RuntimeError("completion endpoint unavailable")
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
            ):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 2}})

        self.assertEqual(result["processed"], 2)
        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["completion_failed"], 1)
        self.assertIn("pcap_complete_failed", stderr.getvalue())
        self.assertEqual([call[2]["request_id"] for call in calls if call[1] == "/pcap/claim"], ["pcap-unit-test-1", "pcap-unit-test-2"])

    def test_failed_export_completion_failure_is_counted_and_loop_continues(self) -> None:
        requests = [
            {"request_id": "pcap-unit-test-1", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"},
            {"request_id": "pcap-unit-test-2", "source_ip": "192.0.2.11", "destination_ip": "198.51.100.11"},
        ]

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": requests}
            if path == "/pcap/claim":
                request_id = payload_data["request_id"]
                return {"ok": True, "claimed": True, "request": next(item for item in requests if item["request_id"] == request_id)}
            if path == "/pcap/complete" and payload_data["request_id"] == "pcap-unit-test-1":
                raise RuntimeError("completion endpoint unavailable")
            if path == "/pcap/complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        export_results = [RuntimeError("pcap export failed"), {"artifact_path": "/tmp/pcap.tar", "artifact_sha256": "b" * 64, "artifact_size_bytes": 32}]

        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(self.relay, "run_ssh_pcap_export", side_effect=export_results):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 2}})

        self.assertEqual(result["processed"], 2)
        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["completion_failed"], 1)
        self.assertIn("pcap_complete_failed", stderr.getvalue())

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
