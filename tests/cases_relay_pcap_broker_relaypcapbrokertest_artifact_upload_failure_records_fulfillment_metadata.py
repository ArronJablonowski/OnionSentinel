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

class RelayPcapBrokerTestArtifactUploadFailureRecordsFulfillmentMetadataCases:
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


