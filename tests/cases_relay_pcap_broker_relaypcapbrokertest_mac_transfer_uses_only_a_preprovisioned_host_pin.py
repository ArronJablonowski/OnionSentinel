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

class RelayPcapBrokerTestMacTransferUsesOnlyAPreprovisionedHostPinCases:
    def test_mac_transfer_uses_only_a_preprovisioned_host_pin(self) -> None:
        config = {
            "pcap_broker": {
                "mac_transfer": {
                    "host": "192.0.2.20",
                    "user": "relay-intake",
                    "ssh_key": "/private/relay-key",
                    "known_hosts": "/private/mac-known-hosts",
                }
            }
        }

        command = self.relay.mac_ssh_base(config)

        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("UserKnownHostsFile=/private/mac-known-hosts", command)
        self.assertNotIn("StrictHostKeyChecking=accept-new", command)


    def test_mac_transfer_example_and_runbook_require_the_host_pin(self) -> None:
        example = json.loads(
            (REPO_ROOT / "relay/config/config.example.json").read_text(
                encoding="utf-8"
            )
        )
        transfer = example["pcap_broker"]["mac_transfer"]
        self.assertEqual(
            transfer["known_hosts"],
            "/opt/so-alert-relay/keys/macstudio_known_hosts",
        )
        readme = (REPO_ROOT / "relay/README.md").read_text(encoding="utf-8")
        self.assertIn('"known_hosts": "/opt/so-alert-relay/keys/macstudio_known_hosts"', readme)
        self.assertIn("StrictHostKeyChecking=yes", readme)


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
            io.BytesIO(b"bounded error body"),
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
        self.assertTrue(http_error.closed)

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


    def test_pcap_error_outcomes_preserve_ordered_overlap_policy(self) -> None:
        cases = {
            None: "failed",
            "": "failed",
            "generic failure": "failed",
            "NO MATCHING PACKET capture expired after timeout": "no_packets_available",
            "retention artifact exceeded size": "expired",
            "capture expired while checksum failed": "expired",
            "artifact exceeded configured ceiling": "oversize",
            "size exceeded configured ceiling": "oversize",
            "operation timed out with sha256 mismatch": "timeout",
            "request timeout": "timeout",
            "artifact sha256 mismatch": "checksum_failed",
            "checksum mismatch": "checksum_failed",
            "unsupported rsync transport": "rejected",
            "staging has been removed": "rejected",
            "request rejected": "rejected",
            "rsync exited 1": "transport_failed",
            "artifact upload failed": "transport_failed",
            "connection refused": "transport_failed",
            "ssh unavailable": "transport_failed",
            "spool filesystem unavailable": "transport_failed",
            "artifact exceeded policy without size marker": "oversize",
            "capture exceeded policy": "failed",
        }
        for detail, expected in cases.items():
            with self.subTest(detail=detail):
                self.assertEqual(
                    self.relay.pcap_outcome_from_error(detail),
                    expected,
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


