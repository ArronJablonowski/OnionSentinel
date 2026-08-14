#!/usr/bin/env python3
"""Regression checks for relay-side PCAP broker fulfillment."""
from __future__ import annotations

import importlib.util
import contextlib
import fcntl
import hashlib
import io
import os
import subprocess
import sys
import tarfile
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

    def test_broker_request_preserves_http_lifecycle_and_request_shape(self) -> None:
        events = []

        class Response:
            def __enter__(self):
                events.append("enter")
                return self

            def __exit__(self, exc_type, exc, traceback):
                events.append(("exit", exc_type, exc, traceback))

        response = Response()
        config = {
            "pcap_broker": {
                "url": "https://broker.example/",
                "token": "test-token",
                "timeout_seconds": 17,
                "response_max_bytes": 123,
            }
        }
        with mock.patch.object(
            self.relay.request,
            "urlopen",
            return_value=response,
        ) as urlopen:
            with mock.patch.object(
                self.relay,
                "read_bounded_http_body",
                return_value=b'{"ok":true,"value":7}',
            ) as read_body:
                result = self.relay.broker_request(
                    config,
                    "POST",
                    "/pcap/progress",
                    {"z": 1, "a": 2},
                )

        self.assertEqual(result, {"ok": True, "value": 7})
        request_value = urlopen.call_args.args[0]
        self.assertEqual(request_value.full_url, "https://broker.example/pcap/progress")
        self.assertEqual(request_value.method, "POST")
        self.assertEqual(request_value.data, b'{"a": 2, "z": 1}')
        self.assertEqual(request_value.get_header("Content-type"), "application/json")
        self.assertEqual(request_value.get_header("User-agent"), "so-alert-relay-dev/0.1")
        self.assertEqual(request_value.get_header("X-relay-token"), "test-token")
        self.assertEqual(urlopen.call_args.kwargs, {"timeout": 17})
        read_body.assert_called_once_with(response, 123)
        self.assertEqual(events, ["enter", ("exit", None, None, None)])

    def test_broker_request_preserves_error_and_rejection_boundaries(self) -> None:
        config = {"pcap_broker": {"url": "https://broker.example"}}
        with mock.patch.object(self.relay.request, "urlopen") as urlopen:
            with self.assertRaisesRegex(RuntimeError, "pcap_broker.url is empty"):
                self.relay.broker_request({"pcap_broker": {}}, "GET", "/pcap")
        urlopen.assert_not_called()

        http_error = self.relay.HTTPError(
            "https://broker.example/pcap",
            503,
            "unavailable",
            None,
            None,
        )
        with mock.patch.object(
            self.relay.request,
            "urlopen",
            side_effect=http_error,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "PCAP broker returned HTTP 503: unavailable",
            ) as raised:
                self.relay.broker_request(config, "GET", "/pcap")
        self.assertIs(raised.exception.__cause__, http_error)

        url_error = self.relay.URLError("offline")
        with mock.patch.object(
            self.relay.request,
            "urlopen",
            side_effect=url_error,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "PCAP broker request failed: offline",
            ) as raised:
                self.relay.broker_request(config, "GET", "/pcap")
        self.assertIs(raised.exception.__cause__, url_error)

        for body, expected in (
            (b'{"ok":false,"reason":"reason","error":"error"}', "reason"),
            (b'{"ok":false,"error":"error"}', "error"),
            (b'{"ok":false}', "PCAP broker rejected request"),
        ):
            with self.subTest(body=body):
                with mock.patch.object(self.relay.request, "urlopen", return_value=mock.MagicMock()):
                    with mock.patch.object(
                        self.relay,
                        "read_bounded_http_body",
                        return_value=body,
                    ):
                        with self.assertRaisesRegex(RuntimeError, expected):
                            self.relay.broker_request(config, "GET", "/pcap")

        with mock.patch.object(self.relay.request, "urlopen", return_value=mock.MagicMock()):
            with mock.patch.object(
                self.relay,
                "read_bounded_http_body",
                return_value=b"{",
            ):
                with self.assertRaisesRegex(RuntimeError, "PCAP broker returned invalid JSON") as raised:
                    self.relay.broker_request(config, "GET", "/pcap")
        self.assertIsInstance(raised.exception.__cause__, self.relay.json.JSONDecodeError)

        with mock.patch.object(self.relay.request, "urlopen", return_value=mock.MagicMock()):
            with mock.patch.object(
                self.relay,
                "read_bounded_http_body",
                return_value=b"[]",
            ):
                with self.assertRaises(AttributeError):
                    self.relay.broker_request(config, "GET", "/pcap")

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

    def test_stream_wait_allows_unbounded_total_runtime_while_bytes_advance(self) -> None:
        class FakeProcess:
            def __init__(self) -> None:
                self.polls = 0
                self.stderr = io.BytesIO(b"")

            def poll(self):
                self.polls += 1
                return None if self.polls <= 3 else 0

        with tempfile.TemporaryDirectory() as temp_dir:
            partial = Path(temp_dir) / "capture.part"
            partial.write_bytes(b"")

            def advance(_seconds):
                with partial.open("ab") as handle:
                    handle.write(b"packet")

            proc = FakeProcess()
            with mock.patch.object(self.relay.time, "sleep", side_effect=advance):
                stderr = self.relay.wait_for_stream_progress(proc, partial, idle_timeout=60)

        self.assertEqual(stderr, b"")
        self.assertEqual(proc.polls, 4)

    def test_stream_wait_stops_only_after_no_progress_idle_timeout(self) -> None:
        class FakeProcess:
            def __init__(self) -> None:
                self.stderr = io.BytesIO(b"")
                self.killed = False
                self.waited = False

            def poll(self):
                return None

            def kill(self) -> None:
                self.killed = True

            def wait(self) -> int:
                self.waited = True
                return -9

        with tempfile.TemporaryDirectory() as temp_dir:
            partial = Path(temp_dir) / "capture.part"
            partial.write_bytes(b"")
            proc = FakeProcess()
            with mock.patch.object(self.relay.time, "monotonic", side_effect=[0.0, 0.0, 61.0]):
                with mock.patch.object(self.relay.time, "sleep"):
                    with self.assertRaisesRegex(RuntimeError, "made no progress for 60 seconds"):
                        self.relay.wait_for_stream_progress(proc, partial, idle_timeout=60)

        self.assertTrue(proc.killed)
        self.assertTrue(proc.waited)

    def test_disabled_broker_does_not_poll(self) -> None:
        with mock.patch.object(self.relay, "broker_request") as broker_request:
            result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": False}})

        self.assertEqual(result, {
            "ok": True,
            "enabled": False,
            "processed": 0,
            "operational_failures": 0,
        })
        broker_request.assert_not_called()

    def test_broker_lock_prevents_overlapping_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path = Path(temp_dir) / "pcap-broker.lock"
            config = {
                "pcap_broker": {
                    "enabled": True,
                    "lock_path": str(lock_path),
                }
            }
            with lock_path.open("w", encoding="utf-8") as lock_handle:
                fcntl.flock(
                    lock_handle.fileno(),
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
                with mock.patch.object(self.relay, "broker_request") as broker_request:
                    result = self.relay.process_pcap_requests(config)
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)

        self.assertEqual(
            result,
            {
                "ok": True,
                "enabled": True,
                "locked": True,
                "processed": 0,
                "operational_failures": 0,
            },
        )
        broker_request.assert_not_called()

    def test_broker_fixture_is_isolated_across_processes(self) -> None:
        command = [
            sys.executable,
            "-m",
            "unittest",
            (
                "tests.test_relay_pcap_broker.RelayPcapBrokerTest."
                "test_claimed_request_is_exported_and_completed"
            ),
        ]
        processes = [
            subprocess.Popen(
                command,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(4)
        ]
        try:
            results = [process.communicate(timeout=30) for process in processes]
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

        for process, (_stdout, stderr) in zip(processes, results):
            self.assertEqual(process.returncode, 0, stderr)

    def test_spool_configuration_cannot_raise_admission_above_seventy_five_percent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            usage = type("Usage", (), {"total": 1000, "used": 760, "free": 240})()
            config = {"pcap_broker": {
                "artifact_spool_dir": temp_dir,
                "artifact_spool_max_bytes": 0,
                "artifact_spool_min_free_bytes": 0,
                "artifact_spool_max_used_percent": 95,
            }}
            with mock.patch.object(self.relay.shutil, "disk_usage", return_value=usage):
                with self.assertRaisesRegex(RuntimeError, "limit=75.0%"):
                    self.relay.require_spool_capacity(config, 0)

    def test_progress_reporter_posts_current_stage_and_bytes(self) -> None:
        config = {"pcap_broker": {"url": "http://127.0.0.1:5678", "paths": {"progress": "/pcap/progress"}}}
        with mock.patch.object(self.relay, "broker_request", return_value={"ok": True}) as broker_request:
            reporter = self.relay.PcapProgressReporter(config, "pcap-progress-test")
            reporter.update("security_onion_to_relay", 4096, lambda: 1024)

        broker_request.assert_called_once_with(
            config,
            "POST",
            "/pcap/progress",
            {
                "request_id": "pcap-progress-test",
                "stage": "security_onion_to_relay",
                "transferred_bytes": 1024,
                "total_bytes": 4096,
            },
        )

    def test_singular_no_matching_packet_error_is_negative_evidence(self) -> None:
        self.assertEqual(
            self.relay.pcap_outcome_from_error("no matching packet capture files found"),
            "no_packets_available",
        )

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
                "streamed_spool_artifact",
                return_value=self.streamed_result("pcap-unit-test"),
            ) as export:
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["failed"], 0)
        self.assertTrue(result["broker_contacted"])
        export.assert_called_once()
        self.assertEqual(calls[-1][1], "/pcap/complete")
        self.assertEqual(calls[-1][2]["status"], "fulfilled")

    def test_successful_ingest_cleans_only_the_relay_spool(self) -> None:
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
                "streamed_spool_artifact",
                return_value=self.streamed_result("pcap-cleanup-test"),
            ):
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_relay_spool_artifact", return_value=True) as cleanup:
                        result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["artifact_cleanup_succeeded"], 0)
        self.assertEqual(result["relay_spool_cleanup_succeeded"], 1)
        cleanup.assert_called_once_with(mock.ANY, "pcap-cleanup-test")

    def test_terminal_oversize_failure_creates_no_security_onion_cleanup(self) -> None:
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
            with mock.patch.object(
                self.relay,
                "streamed_spool_artifact",
                side_effect=RuntimeError("PCAP artifact exceeds relay spool limit"),
            ):
                result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 1}})

        self.assertEqual(result["failed"], 1)
        self.assertEqual(result["artifact_cleanup_succeeded"], 0)

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
            (spool / "pcap-unit-test.stream.json").write_text(
                '{"artifact_sha256":"%s","artifact_size_bytes":%d,"part_count":2}\n'
                % (digest, artifact.stat().st_size),
                encoding="utf-8",
            )

            with mock.patch.object(self.relay, "run_ssh_pcap_export") as export:
                returned = self.relay.streamed_spool_artifact(
                    config,
                    {"request_id": "pcap-unit-test"},
                )

            self.assertEqual(returned["relay_spool_path"], str(artifact))
            self.assertTrue(returned["reused_existing_artifact"])
            self.assertEqual(returned["part_count"], 2)
            export.assert_not_called()

    def test_mac_verification_failure_cleans_and_retries_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir)
            artifact = spool / "pcap-mac-retry.tar"
            artifact.write_bytes(b"verified relay artifact")
            digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
            config = {
                "pcap_broker": {
                    "artifact_spool_dir": str(spool),
                    "artifact_spool_delete_after_upload": True,
                    "mac_transfer": {
                        "host": "192.0.2.20",
                        "user": "relay-intake",
                        "ssh_key": "/tmp/test-key",
                    },
                }
            }
            export_result = {
                "request_id": "pcap-mac-retry",
                "artifact_path": "pcap-mac-retry.tar",
                "artifact_size_bytes": artifact.stat().st_size,
                "artifact_sha256": digest,
                "relay_spool_path": str(artifact),
            }

            completed = lambda returncode=0, stdout="", stderr="": subprocess.CompletedProcess([], returncode, stdout, stderr)
            remote_calls = [
                completed(stdout='{"ok":true,"status":"prepared"}\n'),
                completed(1, stderr='{"ok":false,"error":"artifact size or sha256 did not match"}\n'),
                completed(stdout='{"ok":true,"status":"cleaned","request_id":"pcap-mac-retry"}\n'),
                completed(stdout='{"ok":true,"status":"prepared"}\n'),
                completed(stdout=f'{{"ok":true,"status":"verified","size":{artifact.stat().st_size},"sha256":"{digest}"}}\n'),
            ]
            with mock.patch.object(self.relay, "run_mac_ssh", side_effect=remote_calls) as remote:
                with mock.patch.object(
                    self.relay.process_io,
                    "run_bounded_command",
                    side_effect=[completed(stdout=b"", stderr=b""), completed(stdout=b"", stderr=b"")],
                ) as rsync:
                    result = self.relay.upload_pcap_artifact_via_rsync(config, {}, export_result)

            self.assertEqual(result["status"], "artifact_rsynced")
            self.assertEqual(remote.call_count, 5)
            self.assertIn("cleanup pcap-mac-retry", remote.call_args_list[2].args[1])
            self.assertEqual(rsync.call_count, 2)
            self.assertTrue(all("--checksum" in call.args[0] for call in rsync.call_args_list))
            self.assertTrue(all("--bwlimit=4096" in call.args[0] for call in rsync.call_args_list))
            self.assertTrue(all(call.kwargs["max_stdout_bytes"] == 1024 * 1024 for call in rsync.call_args_list))
            self.assertEqual(result["max_bytes_per_second"], 4 * 1024 * 1024)
            self.assertTrue(artifact.exists(), "verified relay evidence must survive until the durable completion callback")
            self.assertTrue(self.relay.cleanup_relay_spool_artifact(config, "pcap-mac-retry"))
            self.assertFalse(artifact.exists())

    def test_transfer_timeout_accounts_for_relay_to_mac_bandwidth_ceiling(self) -> None:
        config = {
            "pcap_broker": {
                "mac_transfer": {
                    "rsync_timeout_seconds": 300,
                    "minimum_bytes_per_second": 16 * 1024 * 1024,
                    "max_bytes_per_second": 2 * 1024 * 1024,
                }
            }
        }

        timeout = self.relay.transfer_timeout(config, 8 * 1024 * 1024 * 1024)

        self.assertGreaterEqual(timeout, 4696)
        self.assertEqual(self.relay.rsync_max_bytes_per_second(config), 2 * 1024 * 1024)

    def test_relay_to_mac_bandwidth_ceiling_cannot_exceed_eight_mebibytes(self) -> None:
        config = {
            "pcap_broker": {
                "mac_transfer": {"max_bytes_per_second": 128 * 1024 * 1024}
            }
        }

        self.assertEqual(self.relay.rsync_max_bytes_per_second(config), 8 * 1024 * 1024)

    def test_broker_paths_can_match_n8n_webhook_routes(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        calls: list[tuple[str, str, dict | None]] = []

        def fake_broker(config, method, path, payload_data=None):
            calls.append((method, path, payload_data))
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap/progress":
                return {"ok": True, "request_id": payload_data["request_id"]}
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
                    "progress": "/pcap/progress",
                    "complete": "/pcap-complete",
                },
            }
        }
        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(
                self.relay,
                "streamed_spool_artifact",
                return_value=self.streamed_result("pcap-unit-test"),
            ):
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    result = self.relay.process_pcap_requests(config)

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(calls[0][1], "/pcap-requests?status=pending&limit=1")
        self.assertEqual(calls[0][2], {"status": "pending", "limit": 1})
        self.assertEqual(calls[1][1], "/pcap-claim")
        self.assertTrue(any(path == "/pcap/progress" for _, path, _ in calls))
        self.assertEqual(calls[-1][1], "/pcap-complete")

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
                "streamed_spool_artifact",
                return_value=self.streamed_result("new-pending"),
            ) as export:
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 3}})

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 1)
        export.assert_called_once()
        self.assertEqual([call[2]["request_id"] for call in calls if call[1] == "/pcap/claim"], ["new-pending"])

    def test_legacy_n8n_artifact_modes_fail_without_blob_fallback(self) -> None:
        config = {"pcap_broker": {"enabled": True, "artifact_upload_mode": "chunked"}}
        with mock.patch.object(self.relay, "broker_request") as broker_request:
            with self.assertRaisesRegex(RuntimeError, "must use read-only streamed_chunks"):
                self.relay.process_pcap_requests(config)
        broker_request.assert_not_called()

    def test_security_onion_staged_rsync_mode_is_rejected_before_polling(self) -> None:
        config = {"pcap_broker": {"enabled": True, "artifact_upload_mode": "spooled_rsync"}}
        with mock.patch.object(self.relay, "broker_request") as broker_request:
            with self.assertRaisesRegex(RuntimeError, "staging modes have been removed"):
                self.relay.process_pcap_requests(config)
        broker_request.assert_not_called()

    def test_relay_source_has_no_security_onion_staging_or_rsync_helper(self) -> None:
        source = RELAY_PATH.read_text(encoding="utf-8")

        self.assertNotIn("spool_pcap_artifact_from_security_onion", source)
        self.assertNotIn("security_onion_transfer_config", source)
        self.assertNotIn("/nsm/pcapout/onion-sentinel", source)

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

    def test_mac_upload_rejects_results_without_a_verified_relay_spool_path(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "missing its relay spool path"):
            self.relay.upload_pcap_artifact_via_rsync(
                {"pcap_broker": {}},
                {"request_id": "pcap-unit-test"},
                {
                    "request_id": "pcap-unit-test",
                    "artifact_path": "pcap-unit-test.tar",
                    "artifact_sha256": "a" * 64,
                    "artifact_size_bytes": 12,
                },
            )

    def test_artifact_upload_failure_records_fulfillment_metadata(self) -> None:
        request = {"request_id": "pcap-unit-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}
        completions: list[dict] = []
        retries: list[dict] = []

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap-requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap-claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap-complete":
                completions.append(payload_data)
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            if path == "/pcap-retry":
                retries.append(payload_data)
                return {"ok": True, "retry_scheduled": True, "exhausted": False}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        config = {
            "pcap_broker": {
                "enabled": True,
                "limit": 1,
                "requests_method": "POST",
                "upload_artifact": True,
                "artifact_upload_mode": "streamed_chunks",
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
                "streamed_spool_artifact",
                return_value=self.streamed_result("pcap-unit-test"),
            ):
                with mock.patch.object(self.relay, "upload_pcap_artifact", side_effect=RuntimeError("rsync endpoint unavailable")):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        result = self.relay.process_pcap_requests(config)

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["artifact_upload_failed"], 1)
        self.assertEqual(result["retry_scheduled"], 1)
        self.assertEqual(completions, [])
        self.assertEqual(retries[0]["stage"], "exporting")
        self.assertIn("rsync endpoint unavailable", retries[0]["error"])
        self.assertIn("pcap_artifact_upload_failed", stderr.getvalue())

    def test_broker_response_overflow_cannot_bypass_one_request_per_run(self) -> None:
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
                "streamed_spool_artifact",
                return_value=self.streamed_result("pcap-unit-test-1"),
            ):
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    with mock.patch.object(self.relay, "cleanup_relay_spool_artifact", return_value=True) as cleanup_relay:
                        stderr = io.StringIO()
                        with contextlib.redirect_stderr(stderr):
                            result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 2}})

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["completion_failed"], 1)
        self.assertIn("pcap_complete_failed", stderr.getvalue())
        self.assertEqual([call[2]["request_id"] for call in calls if call[1] == "/pcap/claim"], ["pcap-unit-test-1"])
        cleanup_relay.assert_not_called()

    def test_failed_stream_export_is_deferred_without_aborting_the_broker(self) -> None:
        requests = [
            {"request_id": "pcap-unit-test-1", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"},
        ]

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": requests}
            if path == "/pcap/claim":
                request_id = payload_data["request_id"]
                return {"ok": True, "claimed": True, "request": next(item for item in requests if item["request_id"] == request_id)}
            if path == "/pcap/complete":
                return {"ok": True, "status": payload_data["status"], "request": payload_data}
            if path == "/pcap-retry":
                return {"ok": True, "retry_scheduled": True, "exhausted": False}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(self.relay, "streamed_spool_artifact", side_effect=RuntimeError("pcap export failed")):
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    result = self.relay.process_pcap_requests({"pcap_broker": {"enabled": True, "limit": 2}})

        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["fulfilled"], 0)
        self.assertEqual(result["failed"], 0)
        self.assertEqual(result["retry_scheduled"], 1)
        self.assertEqual(result["completion_failed"], 0)

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
                '{"ok": true, "status": "storage_status", "read_only_export": true, '
                '"zeek_capture_loss_max_percent": 0.0}',
            ]
        )
        completed = self.relay.subprocess.CompletedProcess(
            ["ssh"], 0, stdout.encode("utf-8"), b""
        )

        with mock.patch.object(
            self.relay.process_io, "run_bounded_command", return_value=completed
        ):
            result = self.relay.run_ssh_pcap_export(config, {"request_id": "pcap-unit-test"})

        self.assertEqual(result["status"], "storage_status")
        self.assertTrue(result["read_only_export"])

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
                "streamed_spool_artifact",
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

    def test_streamed_chunks_are_staged_only_on_relay_ssd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            spool = Path(temp_dir)
            request = {
                "request_id": "pcap-stream-test",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
            }
            manifest = {
                "ok": True,
                "status": "stream_manifest",
                "manifest_id": "a" * 64,
                "storage_status": self.healthy_capture_status,
                "chunks": [
                    {"chunk_id": "001", "source_size_bytes": 1024},
                    {"chunk_id": "002", "source_size_bytes": 1024},
                ],
            }
            config = {
                "pcap_broker": {
                    "artifact_upload_mode": "streamed_chunks",
                    "artifact_spool_dir": str(spool),
                    "artifact_spool_min_free_bytes": 0,
                    "artifact_spool_max_bytes": 1024 * 1024,
                }
            }

            def fake_stream(_config, payload, destination, _source_size):
                if payload["chunk_id"] == "001":
                    destination.write_bytes(b"pcap-one")
                    return destination.stat().st_size
                destination.write_bytes(b"pcap-two")
                return destination.stat().st_size

            progress = mock.Mock()
            with mock.patch.object(self.relay, "require_spool_capacity"):
                with mock.patch.object(self.relay, "run_ssh_pcap_export", return_value=manifest):
                    with mock.patch.object(self.relay, "stream_one_security_onion_chunk", side_effect=fake_stream):
                        result = self.relay.streamed_spool_artifact(config, request, progress)

            artifact = Path(result["relay_spool_path"])
            self.assertTrue(artifact.is_file())
            self.assertEqual(result["source_mode"], "streamed_chunks")
            self.assertEqual(result["security_onion_staging_bytes"], 0)
            self.assertFalse((spool / "pcap-stream-test").exists())
            progress.update.assert_called_once_with(
                "security_onion_to_relay",
                2048,
                mock.ANY,
            )
            with tarfile.open(artifact) as archive:
                self.assertEqual(sorted(archive.getnames()), ["part-001.pcap", "part-002.pcap"])

    def test_streamed_broker_does_not_call_legacy_security_onion_cleanup(self) -> None:
        request = {"request_id": "pcap-stream-test", "source_ip": "192.0.2.10", "destination_ip": "198.51.100.10"}

        def fake_broker(config, method, path, payload_data=None):
            if path.startswith("/pcap/requests"):
                return {"ok": True, "requests": [request]}
            if path == "/pcap/claim":
                return {"ok": True, "claimed": True, "request": request}
            if path == "/pcap/complete":
                return {"ok": True, "status": payload_data["status"]}
            raise AssertionError(f"unexpected broker call: {method} {path}")

        streamed = {
            "request_id": "pcap-stream-test",
            "artifact_path": "pcap-stream-test.tar",
            "artifact_sha256": "a" * 64,
            "artifact_size_bytes": 1024,
            "source_mode": "streamed_chunks",
            "security_onion_staging_bytes": 0,
        }
        config = {"pcap_broker": {"enabled": True, "limit": 1, "artifact_upload_mode": "streamed_chunks"}}
        with mock.patch.object(self.relay, "broker_request", side_effect=fake_broker):
            with mock.patch.object(self.relay, "streamed_spool_artifact", return_value=streamed):
                with mock.patch.object(self.relay, "upload_pcap_artifact", return_value={"ok": True}):
                    result = self.relay.process_pcap_requests(config)

        self.assertEqual(result["fulfilled"], 1)
        self.assertEqual(result["artifact_cleanup_succeeded"], 0)
        self.assertNotIn("cleanup_pcap_artifact", RELAY_PATH.read_text(encoding="utf-8"))

    def test_streamed_broker_skips_security_onion_telemetry_without_pending_work(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "pcap_broker": {
                    "enabled": True,
                    "artifact_upload_mode": "streamed_chunks",
                    "artifact_spool_dir": temp_dir,
                    "security_onion_storage_telemetry": True,
                }
            }
            storage = {
                **self.healthy_capture_status,
                "disk_read_gate_enabled": False,
                "pcap_root_used_percent": 99.0,
            }
            with mock.patch.object(self.relay, "security_onion_storage_status", return_value=storage) as storage_status:
                with mock.patch.object(
                    self.relay,
                    "broker_request",
                    return_value={"ok": True, "requests": []},
                ) as broker_request:
                    result = self.relay.process_pcap_requests(config)

        self.assertTrue(result["ok"])
        self.assertEqual(result["processed"], 0)
        self.assertEqual(result["capture_protection"]["reason"], "no_pending_requests")
        storage_status.assert_not_called()
        broker_request.assert_called_once()

    def test_streamed_broker_defers_when_capture_telemetry_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = {
                "pcap_broker": {
                    "enabled": True,
                    "artifact_upload_mode": "streamed_chunks",
                    "artifact_spool_dir": temp_dir,
                    "security_onion_storage_telemetry": True,
                }
            }
            with mock.patch.object(
                self.relay,
                "security_onion_storage_status",
                side_effect=RuntimeError("telemetry unavailable"),
            ):
                with mock.patch.object(
                    self.relay,
                    "broker_request",
                    return_value={"ok": True, "requests": [{"request_id": "waiting"}]},
                ) as broker_request:
                    result = self.relay.process_pcap_requests(config)

        self.assertTrue(result["ok"])
        self.assertEqual(result["processed"], 0)
        self.assertTrue(result["deferred"])
        self.assertEqual(result["operational_failures"], 0)
        self.assertFalse(result["security_onion_storage"]["available"])
        self.assertIn("telemetry unavailable", result["security_onion_storage"]["error"])
        broker_request.assert_called_once()

    def test_streamed_broker_defers_before_claim_when_capture_loss_is_high(self) -> None:
        unhealthy = {
            **self.healthy_capture_status,
            "zeek_capture_loss_max_percent": 45.2958,
            "zeek_capture_loss_age_seconds": 30,
        }
        config = {
            "pcap_broker": {
                "enabled": True,
                "artifact_upload_mode": "streamed_chunks",
                "capture_loss_threshold_percent": 1.0,
            }
        }
        with mock.patch.object(self.relay, "security_onion_storage_status", return_value=unhealthy):
            with mock.patch.object(
                self.relay,
                "broker_request",
                return_value={
                    "ok": True,
                    "requests": [{"request_id": "waiting"}],
                    "policy": {"capture_loss_threshold_percent": 1.0},
                },
            ) as broker_request:
                result = self.relay.process_pcap_requests(config)

        self.assertTrue(result["ok"])
        self.assertTrue(result["deferred"])
        self.assertIn("45.2958% exceeds 1.0000%", result["defer_reason"])
        self.assertEqual(result["operational_failures"], 0)
        broker_request.assert_called_once()

    def test_capture_protection_default_is_five_percent(self) -> None:
        status = {
            **self.healthy_capture_status,
            "zeek_capture_loss_max_percent": 0.8361,
            "zeek_capture_loss_age_seconds": 30,
        }

        decision = self.relay.capture_protection_decision({"pcap_broker": {}}, status)

        self.assertFalse(decision["deferred"])
        self.assertEqual(decision["threshold_percent"], 5.0)

    def test_capture_protection_accepts_bounded_dynamic_threshold(self) -> None:
        status = {
            **self.healthy_capture_status,
            "zeek_capture_loss_max_percent": 4.5,
            "zeek_capture_loss_age_seconds": 30,
        }

        decision = self.relay.capture_protection_decision(
            {"pcap_broker": {"capture_loss_threshold_percent": 1.0}},
            status,
            capture_loss_threshold_percent=5.0,
        )

        self.assertFalse(decision["deferred"])
        self.assertEqual(decision["threshold_percent"], 5.0)

    def test_capture_protection_defers_on_fresh_zeek_packet_loss(self) -> None:
        status = {
            **self.healthy_capture_status,
            "zeek_packet_loss_available": True,
            "zeek_packet_loss_percent": 0.25,
            "zeek_packet_loss_age_seconds": 20,
        }
        decision = self.relay.capture_protection_decision(
            {"pcap_broker": {"sensor_packet_loss_threshold_percent": 0.1}},
            status,
        )

        self.assertTrue(decision["deferred"])
        self.assertEqual(decision["metric"], "zeek_packet_loss")
        self.assertIn("0.2500% exceeds 0.1000%", decision["reason"])

    def test_capture_protection_defers_on_fresh_suricata_packet_loss(self) -> None:
        status = {
            **self.healthy_capture_status,
            "suricata_packet_loss_available": True,
            "suricata_packet_loss_percent": 0.15,
            "suricata_packet_loss_age_seconds": 20,
        }
        decision = self.relay.capture_protection_decision(
            {"pcap_broker": {"sensor_packet_loss_threshold_percent": 0.1}},
            status,
        )

        self.assertTrue(decision["deferred"])
        self.assertEqual(decision["metric"], "suricata_packet_loss")
        self.assertIn("0.1500% exceeds 0.1000%", decision["reason"])

    def test_capture_protection_unavailable_and_stale_shapes_are_exact(self) -> None:
        optional = self.relay.capture_protection_decision(
            {"pcap_broker": {"capture_protection_require_telemetry": False}},
            None,
        )
        stale = self.relay.capture_protection_decision(
            {
                "pcap_broker": {
                    "capture_loss_threshold_percent": 2.5,
                    "capture_loss_freshness_seconds": 60,
                }
            },
            {
                "zeek_capture_loss_available": True,
                "zeek_capture_loss_age_seconds": 61,
                "zeek_capture_loss_max_percent": 1.25,
            },
        )

        self.assertEqual(
            optional,
            {
                "deferred": False,
                "reason": "Zeek capture-loss telemetry is unavailable",
                "threshold_percent": 5.0,
            },
        )
        self.assertEqual(
            stale,
            {
                "deferred": True,
                "reason": "Zeek capture-loss telemetry is stale (61s)",
                "observed_percent": 1.25,
                "threshold_percent": 2.5,
                "age_seconds": 61,
            },
        )

    def test_capture_protection_disabled_precedes_invalid_telemetry(self) -> None:
        decision = self.relay.capture_protection_decision(
            {
                "pcap_broker": {
                    "capture_protection_enabled": False,
                    "sensor_packet_loss_threshold_percent": "invalid",
                }
            },
            {"zeek_packet_loss_percent": "invalid"},
        )

        self.assertEqual(decision, {"deferred": False, "reason": "disabled"})

    def test_require_capture_safe_preserves_retryable_diagnostics(self) -> None:
        status = {
            **self.healthy_capture_status,
            "zeek_capture_loss_max_percent": 6.0,
        }

        with self.assertRaises(self.relay.PcapCaptureProtectionDeferred) as raised:
            self.relay.require_capture_safe({"pcap_broker": {}}, status)

        self.assertEqual(str(raised.exception), "Zeek capture loss 6.0000% exceeds 5.0000%")
        self.assertEqual(raised.exception.diagnostics["observed_percent"], 6.0)
        self.assertEqual(raised.exception.diagnostics["threshold_percent"], 5.0)


if __name__ == "__main__":
    unittest.main()
