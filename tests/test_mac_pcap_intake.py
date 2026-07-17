#!/usr/bin/env python3
"""Security regression tests for the forced relay-to-Mac intake command."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n" / "bin" / "onion-sentinel-pcap-intake.py"


def load_module():
    spec = importlib.util.spec_from_file_location("pcap_intake", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class MacPcapIntakeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.module = load_module()
        self.module.ROOT = Path(self.temp.name) / "artifacts"
        # Intake behavior must not depend on the developer workstation's
        # current disk usage. Capacity boundaries have dedicated policy tests.
        self.capacity_patch = mock.patch.object(
            self.module,
            "require_runtime_capacity",
            return_value={"used_percent": 10.0, "projected_used_percent": 10.0},
        )
        self.capacity_patch.start()

    def tearDown(self) -> None:
        self.capacity_patch.stop()
        self.temp.cleanup()

    def test_prepare_and_verify_one_matching_tar(self) -> None:
        self.assertEqual(self.module.prepare("request-1", "9"), 0)
        artifact = self.module.request_dir("request-1") / "request-1.tar"
        artifact.write_bytes(b"pcap-test")
        import hashlib
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        self.assertEqual(self.module.verify("request-1", artifact.name, str(artifact.stat().st_size), digest), 0)

    def test_rejects_shell_and_paths_outside_intake_root(self) -> None:
        with self.assertRaises(SystemExit):
            self.module.validate_rsync(["sh", "-c", "id"])
        with self.assertRaises(SystemExit):
            self.module.validate_rsync(["rsync", "--server", ".", "../escape/"])

    def test_accepts_inbound_rsync_for_one_request_directory(self) -> None:
        target = self.module.ROOT / "request-2"
        self.module.prepare("request-2", "1024")
        args = ["rsync", "--server", "-logDtpre.iLsfxCIvu", ".", str(target)]
        validated = self.module.validate_rsync(args)
        self.assertIn("--max-size=1024", validated)

    def test_prepare_rejects_projected_capacity_failure(self) -> None:
        with mock.patch.object(
            self.module,
            "require_runtime_capacity",
            side_effect=self.module.DiskCapacityError("projected disk use is unsafe"),
        ):
            with self.assertRaises(SystemExit):
                self.module.prepare("request-full", "1024")

    def test_reservation_size_cannot_change_during_retry(self) -> None:
        self.module.prepare("request-retry", "1024")
        with self.assertRaises(SystemExit):
            self.module.prepare("request-retry", "2048")

    def test_verify_requires_matching_reservation(self) -> None:
        self.module.prepare("request-size", "16")
        artifact = self.module.request_dir("request-size") / "request-size.tar"
        artifact.write_bytes(b"pcap-test")
        import hashlib
        digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
        with self.assertRaises(SystemExit):
            self.module.verify("request-size", artifact.name, "9", digest)

    def test_interactive_session_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": ""}, clear=False):
            with self.assertRaises(SystemExit):
                self.module.main()

    def test_cleanup_removes_only_one_valid_request_directory(self) -> None:
        self.module.prepare("request-clean", "9")
        artifact = self.module.request_dir("request-clean") / "request-clean.tar"
        artifact.write_bytes(b"pcap-test")
        sibling = self.module.ROOT / "request-keep"
        sibling.mkdir(parents=True)

        self.assertEqual(self.module.cleanup("request-clean"), 0)

        self.assertFalse(self.module.request_dir("request-clean").exists())
        self.assertTrue(sibling.is_dir())

    def test_cleanup_rejects_request_path_symlink(self) -> None:
        self.module.ROOT.mkdir(parents=True)
        target = Path(self.temp.name) / "outside"
        target.mkdir()
        (self.module.ROOT / "request-link").symlink_to(target, target_is_directory=True)

        with self.assertRaises(SystemExit):
            self.module.cleanup("request-link")

        self.assertTrue(target.is_dir())


if __name__ == "__main__":
    unittest.main()
