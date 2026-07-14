#!/usr/bin/env python3
"""Regression checks for relay-side PCAP broker fulfillment."""
from __future__ import annotations

import importlib.util
import contextlib
import hashlib
import io
import os
import sys
import tempfile
import time
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
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True):
                        result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["failed"], 0)
        export.assert_called_once()
        self.assertEqual(calls[-1][1], "/pcap/complete")
        self.assertEqual(calls[-1][2]["status"], "fulfilled")

    def test_successful_ingest_and_completion_triggers_security_onion_cleanup(self) -> None:
        request = {"request_id": "pcap-cleanup-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}

        def fake_broker(config, method, path, payload_data=None):
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
                    "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-cleanup-test.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 1024,
                },
            ):
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True) as cleanup:
                        result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["artifact_cleanup_succeeded"], 1)
        cleanup.assert_called_once_with(mock.ANY, "pcap-cleanup-test")

    def test_terminal_oversize_failure_triggers_security_onion_cleanup(self) -> None:
        request = {"request_id": "pcap-oversize-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap/claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap/complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(self.relay, "run_ssh_pcap_export", side_effect=RuntimeError("PCAP artifact exceeds relay spool limit")):
                with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True) as cleanup:
                    result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["artifact_cleanup_succeeded"], 1)
        cleanup.assert_called_once_with(mock.ANY, "pcap-oversize-test")

    def test_stale_relay_spool_partials_are_pruned_without_touching_active_transfer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir)
            old_part = spool / "old-request.tar.part"
            active_part = spool / "active-request.tar.part"
            completed_tar = spool / "completed-request.tar"
            old_part.write_bytes(b"stale")
            active_part.write_bytes(b"active")
            completed_tar.write_bytes(b"complete")
            old_mtime = time.time() - 7200
            active_mtime = time.time()
            os.utime(old_part, (old_mtime, old_mtime))
            os.utime(active_part, (active_mtime, active_mtime))

            removed = self.relay.cleanup_stale_spool_partials(
                {
                    "pcap_broker": {
                        "artifact_spool_dir": str(spool),
                        "artifact_spool_partial_ttl_seconds": 3600,
                    }
                }
            )

            self.assertEqual(removed, 1)
            self.assertFalse(old_part.exists())
            self.assertTrue(active_part.exists())
            self.assertTrue(completed_tar.exists())

    def test_stale_completed_spool_artifacts_are_pruned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir)
            stale = spool / "stale-request.tar"
            recent = spool / "recent-request.tar"
            stale.write_bytes(b"stale")
            recent.write_bytes(b"recent")
            old_mtime = time.time() - 7200
            os.utime(stale, (old_mtime, old_mtime))

            removed = self.relay.cleanup_stale_spool_artifacts(
                {
                    "pcap_broker": {
                        "artifact_spool_dir": str(spool),
                        "artifact_spool_completed_ttl_seconds": 3600,
                    }
                }
            )

            self.assertEqual(removed, 1)
            self.assertFalse(stale.exists())
            self.assertTrue(recent.exists())

    def test_retry_reuses_verified_completed_spool_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir)
            artifact = spool / "pcap-unit-test.tar"
            artifact.write_bytes(b"verified retry artifact")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            config = {"pcap_broker": {"artifact_spool_dir": str(spool)}}
            result = {
                "request_id": "pcap-unit-test",
                "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
                "artifact_size_bytes": artifact.stat().st_size,
                "artifact_sha256": digest,
            }

            with mock.patch.object(self.relay, "require_spool_capacity") as capacity:
                with mock.patch.object(self.relay.subprocess, "run") as run:
                    returned = self.relay.spool_pcap_artifact_from_security_onion(config, {}, result)

            self.assertEqual(returned, artifact)
            capacity.assert_not_called()
            run.assert_not_called()

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
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True):
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
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True):
                        result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 3}})

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 1)
        export.assert_called_once()
        self.assertEqual([call[2]["request_id"] for call in calls if call[1] == "/pcap/claim"], ["new-pending"])

    def test_legacy_n8n_artifact_modes_fail_without_blob_fallback(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        completions: list[dict] = []

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
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
                "artifact_upload_mode": "chunked",
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
                    "artifact_size_bytes": 12,
                },
            ) as export:
                result = self.relay.process_pcap_requests(config)

        self.assertNotIn("inline_artifact_payload", export.call_args.args[1])
        self.assertEqual(result["failed"], 1)
        self.assertEqual(completions[0]["status"], "failed")
        self.assertIn("inline n8n artifact transfer has been removed", completions[0]["error"])

    def test_spooled_rsync_does_not_request_inline_artifact_and_records_mac_path(self) -> None:
        request = {"request_id": "pcap-rsync-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        completions: list[dict] = []

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap-complete":
                completions.append(payload_data)
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "run_ssh_pcap_export",
                return_value={
                    "request_id": "pcap-rsync-test",
                    "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-rsync-test.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 1024,
                },
            ) as export:
                with mock.patch.object(
                    self.relay,
                    "upload_pcap_artifact",
                    return_value={
                        "ok": True,
                        "status": "artifact_rsynced",
                        "path": "n8n-local/pcap-evidence/artifacts/pcap-rsync-test/pcap-rsync-test.tar",
                    },
                ):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True):
                        result = self.relay.process_pcap_requests(
                            {
                                "pcap_broker": {
                                    "enabled": True,
                                    "limit": 1,
                                    "requests_method": "POST",
                                    "artifact_upload_mode": "spooled_rsync",
                                    "paths": {
                                        "requests": "/pcap-requests",
                                        "claim": "/pcap-claim",
                                        "complete": "/pcap-complete",
                                    },
                                }
                            }
                        )

        self.assertEqual(result["fulfilled"], 1)
        self.assertNotIn("inline_artifact_payload", export.call_args.args[1])
        self.assertEqual(
            completions[0]["artifact_path"],
            "n8n-local/pcap-evidence/artifacts/pcap-rsync-test/pcap-rsync-test.tar",
        )

    def test_security_onion_to_relay_transfer_requires_dedicated_rsync_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "security_onion": {
                    "host": "security-onion.example.test",
                    "ssh_user": "so-ai-relay",
                    "ssh_key": "/tmp/regular-key",
                    "pcap_ssh_key": "/tmp/pcap-key",
                },
                "relay": {"pcap_timeout_seconds": 10},
                "pcap_broker": {"artifact_spool_dir": temp_dir, "artifact_spool_min_free_bytes": 0},
            }

            with self.assertRaisesRegex(RuntimeError, "pcap_artifact_transfer requires"):
                self.relay.spool_pcap_artifact_from_security_onion(
                    config,
                    {"request_id": "pcap-unit-test"},
                    {
                        "request_id": "pcap-unit-test",
                        "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
                        "artifact_sha256": "a" * 64,
                        "artifact_size_bytes": 12,
                    },
                )

    def test_spool_mount_guard_rejects_sd_card_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir) / "pcap"
            spool.mkdir()
            config = {
                "pcap_broker": {
                    "artifact_spool_dir": str(spool),
                    "artifact_spool_require_mount": True,
                    "artifact_spool_min_free_bytes": 0,
                }
            }
            with self.assertRaisesRegex(RuntimeError, "filesystem is not mounted"):
                self.relay.require_spool_capacity(config, 1)

    def test_security_onion_to_relay_transfer_uses_rsync_without_inline_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir) / "spool"
            spool.mkdir()
            payload = b"pcap artifact"
            digest = self.relay.hashlib.sha256(payload).hexdigest()
            config = {
                "security_onion": {
                    "host": "security-onion.example.test",
                    "ssh_user": "so-ai-relay",
                    "ssh_key": "/tmp/regular-key",
                    "pcap_ssh_key": "/tmp/pcap-key",
                    "pcap_artifact_transfer": {
                        "ssh_user": "so-ai-relay-pcap-rsync",
                        "ssh_key": "/tmp/pcap-rsync-key",
                        "rsync_timeout_seconds": 10,
                    },
                },
                "relay": {"pcap_timeout_seconds": 10, "ssh_timeout_seconds": 5},
                "pcap_broker": {
                    "artifact_spool_dir": str(spool),
                    "artifact_spool_min_free_bytes": 0,
                    "artifact_spool_max_bytes": 1024 * 1024,
                },
            }
            commands = []

            def fake_run(command, check=False, capture_output=True, text=True, timeout=None, **kwargs):
                commands.append(command)
                self.assertEqual(command[0], "rsync")
                destination = Path(command[-1])
                destination.write_bytes(payload)
                return self.relay.subprocess.CompletedProcess(command, 0, "sent\n", "")

            with mock.patch.object(self.relay.subprocess, "run", side_effect=fake_run):
                artifact = self.relay.spool_pcap_artifact_from_security_onion(
                    config,
                    {"request_id": "pcap-unit-test"},
                    {
                        "request_id": "pcap-unit-test",
                        "artifact_path": "/nsm/pcapout/onion-sentinel/pcap-unit-test.tar",
                        "artifact_sha256": digest,
                        "artifact_size_bytes": len(payload),
                    },
                )

            self.assertEqual(artifact.read_bytes(), payload)
            self.assertNotIn("artifact_chunk", str(commands))
            self.assertNotIn("inline", str(commands).lower())

    def test_artifact_upload_failure_records_fulfillment_metadata(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        completions: list[dict] = []

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
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
                "artifact_upload_mode": "spooled_rsync",
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
                    "artifact_size_bytes": 12,
                },
            ):
                with mock.patch.object(self.relay, "upload_pcap_artifact", side_effect=RuntimeError("rsync endpoint unavailable")):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        result = self.relay.process_pcap_requests(config)

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 0)
        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["artifact_upload_failed"], 1)
        self.assertEqual(completions[0]["status"], "failed")
        self.assertFalse(completions[0]["artifact_ingested"])
        self.assertIn("rsync endpoint unavailable", completions[0]["artifact_ingest_error"])
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
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True):
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
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_pcap_artifact", return_value=True):
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

    def test_failed_export_forwards_wrapper_diagnostics_to_broker(self) -> None:
        request = {"request_id": "pcap-diagnostics-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        completions: list[dict] = []

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap/claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap/complete":
                completions.append(payload_data)
                return {"ok": True, "status": payload_data["status"]}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        diagnostics = {"candidate_count": 3, "search_strategy": "capture-epoch-near-window"}
        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "run_ssh_pcap_export",
                side_effect=self.relay.PcapExportError("no matching packets found", diagnostics),
            ):
                result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["outcomes"], {"no_packets_available": 1})
        self.assertEqual(result["operational_failures"], 0)
        self.assertEqual(completions[0]["status"], "failed")
        self.assertEqual(completions[0]["outcome"], "no_packets_available")
        self.assertEqual(completions[0]["diagnostics"], diagnostics)

    def test_required_missing_spool_fails_before_polling(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir) / "pcap"
            spool.mkdir()
            config = {
                "pcap_broker": {
                    "enabled": True,
                    "artifact_spool_dir": str(spool),
                    "artifact_spool_require_mount": True,
                }
            }
            with mock.patch.object(self.relay, "broker_request") as broker_request:
                result = self.relay.process_pcap_requests(config)

        self.assertFalse(result["ok"])
        self.assertEqual(result["operational_failures"], 1)
        self.assertIn("not mounted", result["spool"]["reason"])
        broker_request.assert_not_called()

    def test_completion_retries_a_transient_broker_failure(self) -> None:
        config = {
            "pcap_broker": {
                "completion_retry_attempts": 3,
                "completion_retry_delay_seconds": 0,
            }
        }
        with mock.patch.object(
            self.relay,
            "broker_request",
            side_effect=[RuntimeError("socket hang up"), {"ok": True}],
        ) as broker_request:
            completed = self.relay.complete_pcap_request(config, "pcap-retry-test", "failed", {"error": "test"})

        self.assertTrue(completed)
        self.assertEqual(broker_request.call_count, 2)


if __name__ == "__main__":
    unittest.main()
