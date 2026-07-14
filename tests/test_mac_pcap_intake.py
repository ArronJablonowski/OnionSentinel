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

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_prepare_and_verify_one_matching_tar(self) -> None:
        self.assertEqual(self.module.prepare("request-1"), 0)
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
        target = Path.home() / "n8n-local" / "pcap-evidence" / "artifacts" / "request-2"
        self.module.ROOT = target.parent
        args = ["rsync", "--server", "-logDtpre.iLsfxCIvu", ".", str(target)]
        self.assertEqual(self.module.validate_rsync(args), args)

    def test_interactive_session_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": ""}, clear=False):
            with self.assertRaises(SystemExit):
                self.module.main()


if __name__ == "__main__":
    unittest.main()
