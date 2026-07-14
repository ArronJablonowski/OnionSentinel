#!/usr/bin/env python3
"""Regression checks for the Security Onion bounded PCAP wrapper."""
from __future__ import annotations

import datetime as dt
import io
import importlib.util
import importlib.machinery
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
WRAPPER_PATH = REPO_ROOT / "security-onion" / "bin" / "export-pcap-window"


def load_wrapper():
    loader = importlib.machinery.SourceFileLoader("export_pcap_window", str(WRAPPER_PATH))
    spec = importlib.util.spec_from_loader("export_pcap_window", loader)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SecurityOnionPcapWrapperTest(unittest.TestCase):
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

    def test_wrapper_has_an_extraction_size_ceiling(self) -> None:
        wrapper = load_wrapper()
        self.assertGreater(wrapper.MAX_ARTIFACT_BYTES, 0)
        self.assertTrue(callable(wrapper.limit_output_file_size))

    def test_artifact_cleanup_removes_only_request_outputs(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.OUTPUT_ROOT = root
            artifact = root / "pcap-unit-test.tar"
            work_dir = root / "pcap-unit-test"
            unrelated = root / "keep-me.tar"
            artifact.write_text("artifact", encoding="utf-8")
            work_dir.mkdir()
            (work_dir / "part-001.pcap").write_text("pcap", encoding="utf-8")
            unrelated.write_text("unrelated", encoding="utf-8")

            with mock.patch("builtins.print") as printed:
                status = wrapper.cleanup_artifact({"request_id": "pcap-unit-test"})

            self.assertEqual(status, 0)
            self.assertFalse(artifact.exists())
            self.assertFalse(work_dir.exists())
            self.assertTrue(unrelated.exists())
            payload = printed.call_args.args[0]
            self.assertIn("artifact_cleaned", payload)

    def test_remove_request_outputs_cleans_partial_work_without_touching_other_requests(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.OUTPUT_ROOT = root
            partial = root / "failed-request"
            partial.mkdir()
            (partial / "part-001.pcap").write_bytes(b"partial")
            unrelated = root / "other-request.tar"
            unrelated.write_bytes(b"keep")

            removed = wrapper.remove_request_outputs("failed-request")

            self.assertEqual(removed, [str(partial.resolve())])
            self.assertFalse(partial.exists())
            self.assertTrue(unrelated.exists())

    def test_complete_existing_artifact_is_reused(self) -> None:
        wrapper = load_wrapper()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            wrapper.OUTPUT_ROOT = root
            part = root / "part-001.pcap"
            part.write_bytes(b"pcap evidence")
            artifact = root / "pcap-unit-test.tar"
            with tarfile.open(artifact, "w") as archive:
                archive.add(part, arcname=part.name)

            payload = wrapper.reusable_artifact_payload("pcap-unit-test")

            self.assertIsNotNone(payload)
            self.assertTrue(payload["reused_existing_artifact"])
            self.assertEqual(payload["part_count"], 1)
            self.assertEqual(payload["artifact_size_bytes"], artifact.stat().st_size)

    def test_artifact_chunk_mode_is_not_supported(self) -> None:
        wrapper = load_wrapper()
        with self.assertRaises(SystemExit):
            with mock.patch("builtins.print") as printed:
                with mock.patch.object(sys, "stdin", new=io.StringIO('{"mode":"artifact_chunk","request_id":"pcap-unit-test"}')):
                    wrapper.main()
        payload = printed.call_args.args[0]
        self.assertIn("unsupported mode", payload)


if __name__ == "__main__":
    unittest.main()
