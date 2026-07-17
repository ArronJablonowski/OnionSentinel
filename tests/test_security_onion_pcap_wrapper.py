#!/usr/bin/env python3
"""Regression checks for the Security Onion bounded PCAP wrapper."""
from __future__ import annotations

import datetime as dt
import io
import importlib.util
import importlib.machinery
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
WRAPPER_PATH = REPO_ROOT / "security-onion" / "bin" / "export-pcap-window"
INSTALLER_PATH = REPO_ROOT / "security-onion" / "bin" / "install-security-onion-wrapper.sh"


def load_wrapper():
    loader = importlib.machinery.SourceFileLoader("export_pcap_window", str(WRAPPER_PATH))
    spec = importlib.util.spec_from_loader("export_pcap_window", loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SecurityOnionPcapWrapperTest(unittest.TestCase):
    def test_storage_pressure_is_telemetry_and_never_a_read_guard(self) -> None:
        wrapper = load_wrapper()
        usage = mock.Mock(total=100, used=99, free=1)

        with mock.patch.object(wrapper.shutil, "disk_usage", return_value=usage):
            status = wrapper.pcap_root_status()

        self.assertEqual(status["pcap_root_used_percent"], 99.0)
        self.assertTrue(status["read_only_export"])
        self.assertFalse(status["disk_read_gate_enabled"])

    def test_candidate_files_selects_capture_epochs_nearest_alert_window(self) -> None:
        wrapper = load_wrapper()
        wrapper.MAX_CANDIDATE_FILES = 3
        reference = int(dt.datetime.now(dt.timezone.utc).timestamp())

        output = "\n".join(
            [
                f"so-pcap.{reference - 300}\t/nsm/suripcap/oldish/so-pcap.{reference - 300}",
                f"so-pcap.{reference - 900}\t/nsm/suripcap/old/so-pcap.{reference - 900}",
                f"so-pcap.{reference + 120}\t/nsm/suripcap/newest/so-pcap.{reference + 120}",
                f"so-pcap.{reference - 60}\t/nsm/suripcap/mid/so-pcap.{reference - 60}",
                f"so-pcap.{reference + 30}\t/nsm/suripcap/newer/so-pcap.{reference + 30}",
            ]
        )
        completed = subprocess.CompletedProcess(args=["find"], returncode=0, stdout=output, stderr="")

        with mock.patch.object(wrapper.subprocess, "run", return_value=completed):
            files = wrapper.candidate_files(
                dt.datetime.fromtimestamp(reference - 10, dt.timezone.utc),
                dt.datetime.fromtimestamp(reference, dt.timezone.utc),
            )

        self.assertEqual(
            [str(path) for path in files],
            [
                f"/nsm/suripcap/newer/so-pcap.{reference + 30}",
                f"/nsm/suripcap/mid/so-pcap.{reference - 60}",
                f"/nsm/suripcap/newest/so-pcap.{reference + 120}",
            ],
        )

    def test_candidate_files_prefers_valid_capture_file_from_request(self) -> None:
        wrapper = load_wrapper()
        wrapper.MAX_CANDIDATE_FILES = 2
        wrapper.PCAP_ROOT = Path("/nsm/suripcap")
        preferred = Path("/nsm/suripcap/3/so-pcap.300")

        output = "\n".join(
            [
                "100 /nsm/suripcap/1/so-pcap.100",
                "200 /nsm/suripcap/2/so-pcap.200",
                "300 /nsm/suripcap/3/so-pcap.300",
            ]
        )
        completed = subprocess.CompletedProcess(args=["find"], returncode=0, stdout=output, stderr="")

        with mock.patch.object(wrapper.subprocess, "run", return_value=completed):
            with mock.patch.object(Path, "exists", return_value=True):
                files = wrapper.candidate_files(
                    dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10),
                    dt.datetime.now(dt.timezone.utc),
                    {"capture_file": str(preferred)},
                )

        self.assertEqual(str(files[0]), str(preferred))

    def test_stream_candidates_use_exact_capture_hint_without_directory_scan(self) -> None:
        wrapper = load_wrapper()
        wrapper.PCAP_ROOT = Path("/nsm/suripcap")
        preferred = Path("/nsm/suripcap/3/so-pcap.300")

        with mock.patch.object(Path, "exists", return_value=True):
            with mock.patch.object(wrapper.subprocess, "run") as enumerator:
                files = wrapper.stream_candidate_files(
                    dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10),
                    dt.datetime.now(dt.timezone.utc),
                    {"capture_file": str(preferred)},
                )

        self.assertEqual(files, [preferred])
        enumerator.assert_not_called()

    def test_vlan_bpf_variant_preserves_flow_tuple(self) -> None:
        wrapper = load_wrapper()
        request = {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
        }

        self.assertEqual(
            wrapper.bpf_for_request(request, vlan=True),
            "vlan and host 192.0.2.10 and host 198.51.100.20 and port 443",
        )

    def test_wrapper_has_a_bounded_source_read_rate_and_no_staging_surface(self) -> None:
        wrapper = load_wrapper()
        source = WRAPPER_PATH.read_text(encoding="utf-8")

        self.assertGreaterEqual(wrapper.MAX_SOURCE_READ_BPS, 1024 * 1024)
        self.assertLessEqual(wrapper.MAX_SOURCE_READ_BPS, 32 * 1024 * 1024)
        self.assertNotIn("OUTPUT_ROOT", source)
        self.assertNotIn("LEGACY_STAGING_ENABLED", source)
        self.assertNotIn("/nsm/pcapout", source)
        self.assertNotIn("import tarfile", source)

    def test_artifact_chunk_mode_is_not_supported(self) -> None:
        wrapper = load_wrapper()
        with self.assertRaises(SystemExit):
            with mock.patch("builtins.print") as printed:
                with mock.patch.object(sys, "stdin", new=io.StringIO('{"mode":"artifact_chunk","request_id":"pcap-unit-test"}')):
                    wrapper.main()
        payload = printed.call_args.args[0]
        self.assertIn("unsupported mode", payload)

    def test_stream_manifest_is_stateless_and_bounds_each_rotation_file(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.PCAP_ROOT = root
            wrapper.STREAM_TOKEN_KEY_PATH = root / "stream-token.key"
            wrapper.STREAM_TOKEN_KEY_PATH.write_bytes(b"t" * 32)
            wrapper.MAX_STREAM_CANDIDATES = 2
            wrapper.MAX_STREAM_SOURCE_BYTES = 2048
            reference = int(dt.datetime.now(dt.timezone.utc).timestamp())
            capture = root / f"so-pcap.{reference}"
            capture.write_bytes(b"p" * 1024)
            completed = subprocess.CompletedProcess(
                args=["find"],
                returncode=0,
                stdout=f"{capture.name}\t{capture}\n",
                stderr="",
            )
            request = {
                "request_id": "pcap-stream-test",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "first_seen": dt.datetime.fromtimestamp(reference - 10, dt.timezone.utc).isoformat(),
                "last_seen": dt.datetime.fromtimestamp(reference, dt.timezone.utc).isoformat(),
            }

            with mock.patch.object(wrapper.subprocess, "run", return_value=completed):
                manifest = wrapper.stream_manifest(request)

            self.assertEqual(manifest["status"], "stream_manifest")
            self.assertEqual(manifest["security_onion_staging_bytes"], 0)
            self.assertEqual(manifest["chunk_count"], 1)
            self.assertEqual(manifest["max_source_read_bytes_per_second"], wrapper.MAX_SOURCE_READ_BPS)
            self.assertTrue(all(item["source_size_bytes"] == 1024 for item in manifest["chunks"]))
            self.assertIn("vlan and host 192.0.2.10", manifest["chunks"][0]["bpf"])
            self.assertIn("or (host 192.0.2.10", manifest["chunks"][0]["bpf"])

    def test_stream_manifest_rejects_rotation_files_over_source_ceiling(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.PCAP_ROOT = root
            wrapper.STREAM_TOKEN_KEY_PATH = root / "stream-token.key"
            wrapper.STREAM_TOKEN_KEY_PATH.write_bytes(b"t" * 32)
            wrapper.STREAM_LOCK = root / "stream.lock"
            wrapper.MAX_STREAM_SOURCE_BYTES = 128
            reference = int(dt.datetime.now(dt.timezone.utc).timestamp())
            capture = root / f"so-pcap.{reference}"
            capture.write_bytes(b"p" * 256)
            completed = subprocess.CompletedProcess(
                args=["find"], returncode=0, stdout=f"{capture.name}\t{capture}\n", stderr=""
            )
            request = {
                "request_id": "pcap-stream-test",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "first_seen": dt.datetime.fromtimestamp(reference - 10, dt.timezone.utc).isoformat(),
                "last_seen": dt.datetime.fromtimestamp(reference, dt.timezone.utc).isoformat(),
            }

            with mock.patch.object(wrapper.subprocess, "run", return_value=completed):
                manifest = wrapper.stream_manifest(request)

            self.assertEqual(manifest["chunk_count"], 0)

    def test_signed_stream_chunk_survives_capture_directory_rotation(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.PCAP_ROOT = root
            wrapper.STREAM_TOKEN_KEY_PATH = root / "stream-token.key"
            wrapper.STREAM_TOKEN_KEY_PATH.write_bytes(b"t" * 32)
            wrapper.STREAM_LOCK = root / "stream.lock"
            reference = int(dt.datetime.now(dt.timezone.utc).timestamp())
            capture = root / f"so-pcap.{reference}"
            capture.write_bytes(b"p" * 1024)
            listing = subprocess.CompletedProcess(
                args=["find"], returncode=0, stdout=f"{capture.name}\t{capture}\n", stderr=""
            )
            request = {
                "request_id": "pcap-stream-test",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "destination_port": 443,
                "first_seen": dt.datetime.fromtimestamp(reference - 10, dt.timezone.utc).isoformat(),
                "last_seen": dt.datetime.fromtimestamp(reference, dt.timezone.utc).isoformat(),
            }
            with mock.patch.object(wrapper.subprocess, "run", return_value=listing):
                manifest = wrapper.stream_manifest(request)

            chunk = manifest["chunks"][0]
            # A later rotation changes the live directory, but the signed
            # descriptor remains valid while its exact source inode exists.
            (root / f"so-pcap.{reference + 60}").write_bytes(b"new rotation")
            stream_request = {
                **request,
                "mode": "stream_chunk",
                **{key: chunk[key] for key in (
                    "chunk_id", "capture_ref", "source_size_bytes",
                    "source_device", "source_inode", "bpf_variant",
                )},
            }
            with mock.patch.object(wrapper, "stream_filtered_capture", return_value=(0, "")) as stream:
                self.assertEqual(wrapper.stream_chunk(stream_request), 0)
            stream.assert_called_once()
            self.assertIn("vlan and host 192.0.2.10", stream.call_args.args[2])
            self.assertIn("or (host 192.0.2.10", stream.call_args.args[2])

    def test_signed_stream_chunk_rejects_tampered_source(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.PCAP_ROOT = root
            wrapper.STREAM_TOKEN_KEY_PATH = root / "stream-token.key"
            wrapper.STREAM_TOKEN_KEY_PATH.write_bytes(b"t" * 32)
            reference = int(dt.datetime.now(dt.timezone.utc).timestamp())
            capture = root / f"so-pcap.{reference}"
            capture.write_bytes(b"p" * 1024)
            listing = subprocess.CompletedProcess(
                args=["find"], returncode=0, stdout=f"{capture.name}\t{capture}\n", stderr=""
            )
            request = {
                "request_id": "pcap-stream-test",
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.20",
                "first_seen": dt.datetime.fromtimestamp(reference - 10, dt.timezone.utc).isoformat(),
                "last_seen": dt.datetime.fromtimestamp(reference, dt.timezone.utc).isoformat(),
            }
            with mock.patch.object(wrapper.subprocess, "run", return_value=listing):
                chunk = wrapper.stream_manifest(request)["chunks"][0]
            stream_request = {
                **request,
                **{key: chunk[key] for key in (
                    "chunk_id", "capture_ref", "source_size_bytes",
                    "source_device", "source_inode", "bpf_variant",
                )},
                "capture_ref": "tampered/so-pcap.1",
            }
            self.assertEqual(wrapper.stream_chunk(stream_request), 3)

    def test_runtime_wrapper_does_not_create_missing_stream_signing_key(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            wrapper.STREAM_TOKEN_KEY_PATH = Path(temp_dir) / "missing-stream-token.key"
            with self.assertRaises(SystemExit):
                wrapper.stream_token_key()
            self.assertFalse(wrapper.STREAM_TOKEN_KEY_PATH.exists())

    def test_stream_candidates_exclude_rotations_outside_the_request_window(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.PCAP_ROOT = root
            wrapper.MAX_STREAM_CANDIDATES = 12
            reference = int(dt.datetime.now(dt.timezone.utc).timestamp())
            sensor = root / "sensor-a"
            sensor.mkdir()
            distant = sensor / f"so-pcap.{reference - 7200}"
            predecessor = sensor / f"so-pcap.{reference - 3600}"
            overlap = sensor / f"so-pcap.{reference - 30}"
            future = sensor / f"so-pcap.{reference + 600}"
            output = "\n".join(
                f"{path.name}\t{path}" for path in (distant, predecessor, overlap, future)
            )
            completed = subprocess.CompletedProcess(args=["find"], returncode=0, stdout=output, stderr="")

            with mock.patch.object(wrapper.subprocess, "run", return_value=completed):
                candidates = wrapper.stream_candidate_files(
                    dt.datetime.fromtimestamp(reference - 10, dt.timezone.utc),
                    dt.datetime.fromtimestamp(reference + 30, dt.timezone.utc),
                )

            self.assertIn(overlap, candidates)
            self.assertNotIn(distant, candidates)
            self.assertNotIn(future, candidates)

    def test_storage_status_remains_available_above_eighty_percent(self) -> None:
        wrapper = load_wrapper()
        usage = mock.Mock(total=100, used=90, free=10)

        with mock.patch.object(wrapper.shutil, "disk_usage", return_value=usage):
            status = wrapper.pcap_root_status()

        self.assertEqual(status["pcap_root_used_percent"], 90.0)
        self.assertFalse(status["disk_read_gate_enabled"])

    def test_missing_mode_cannot_reenable_retired_disk_staging(self) -> None:
        wrapper = load_wrapper()
        request = {
            "request_id": "pcap-legacy-test",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        }

        with self.assertRaises(SystemExit):
            with mock.patch("builtins.print") as printed:
                with mock.patch.object(sys, "stdin", new=io.StringIO(json.dumps(request))):
                    wrapper.main()

        payload = printed.call_args.args[0]
        self.assertIn("unsupported mode: missing", payload)
        self.assertIn("storage_status, stream_manifest, stream_chunk", payload)

    def test_capture_loss_status_reports_only_the_latest_worker_interval(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "capture_loss.log"
            log_path.write_text(
                "\n".join(
                    [
                        json.dumps({"ts": 1000.0, "peer": "worker-1", "percent_lost": 45.0}),
                        json.dumps({"ts": 1300.0, "peer": "worker-1", "percent_lost": 0.25}),
                        json.dumps({"ts": 1300.4, "peer": "worker-2", "percent_lost": 1.5}),
                        json.dumps({"ts": 1300.8, "peer": "worker-3", "percent_lost": 0.0}),
                    ]
                ),
                encoding="utf-8",
            )
            wrapper.ZEEK_CAPTURE_LOSS_LOG = log_path

            status = wrapper.zeek_capture_loss_status(now_epoch=1310.0)

        self.assertTrue(status["zeek_capture_loss_available"])
        self.assertEqual(status["zeek_capture_loss_sample_count"], 3)
        self.assertEqual(status["zeek_capture_loss_max_percent"], 1.5)
        self.assertEqual(status["zeek_capture_loss_avg_percent"], round(1.75 / 3, 4))
        self.assertEqual(status["zeek_capture_loss_age_seconds"], 9)

    def test_zeek_packet_loss_status_uses_latest_counter_delta(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "packetloss.log"
            log_path.write_text(
                "worker-1 rcvd: 1000 dropped: 2 total: 1002\n"
                "worker-1 rcvd: 1998 dropped: 4 total: 2002\n",
                encoding="utf-8",
            )
            os.utime(log_path, (1300.0, 1300.0))
            wrapper.ZEEK_PACKET_LOSS_LOG = log_path

            status = wrapper.zeek_packet_loss_status(now_epoch=1310.0)

        self.assertTrue(status["zeek_packet_loss_available"])
        self.assertEqual(status["zeek_packet_loss_received_delta"], 998)
        self.assertEqual(status["zeek_packet_loss_dropped_delta"], 2)
        self.assertEqual(status["zeek_packet_loss_total_delta"], 1000)
        self.assertEqual(status["zeek_packet_loss_percent"], 0.2)
        self.assertEqual(status["zeek_packet_loss_age_seconds"], 10)

    def test_suricata_packet_loss_status_uses_latest_stats_blocks(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "stats.log"
            log_path.write_text(
                "capture.kernel_packets | Total | 1000\n"
                "capture.kernel_drops   | Total | 5\n"
                "capture.kernel_packets | Total | 2000\n"
                "capture.kernel_drops   | Total | 7\n",
                encoding="utf-8",
            )
            os.utime(log_path, (1300.0, 1300.0))
            wrapper.SURICATA_STATS_LOG = log_path

            status = wrapper.suricata_packet_loss_status(now_epoch=1315.0)

        self.assertTrue(status["suricata_packet_loss_available"])
        self.assertEqual(status["suricata_packet_loss_packets_delta"], 1000)
        self.assertEqual(status["suricata_packet_loss_dropped_delta"], 2)
        self.assertEqual(status["suricata_packet_loss_percent"], round(2 / 1002 * 100, 6))
        self.assertEqual(status["suricata_packet_loss_age_seconds"], 15)

    def test_installer_retires_legacy_staging_and_provisions_stream_signing(self) -> None:
        installer = INSTALLER_PATH.read_text(encoding="utf-8")

        self.assertIn("rm -f /usr/local/sbin/onion-sentinel-rsync-pcapout", installer)
        self.assertIn("rm -f /etc/onion-sentinel/pcapout-rsync.conf", installer)
        self.assertIn("/etc/systemd/system/onion-sentinel-pcapout-retention.service", installer)
        self.assertIn("rmdir /nsm/pcapout/onion-sentinel", installer)
        self.assertIn("usermod --lock --shell /usr/sbin/nologin so-ai-relay-pcap-rsync", installer)
        self.assertIn("head -c 32 /dev/urandom > /etc/onion-sentinel/pcap-stream-token.key", installer)
        self.assertIn("chmod 0600 /etc/onion-sentinel/pcap-stream-token.key", installer)


if __name__ == "__main__":
    unittest.main()
