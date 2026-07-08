#!/usr/bin/env python3
"""Regression checks for the Security Onion bounded PCAP wrapper."""
from __future__ import annotations

import datetime as dt
import importlib.util
import importlib.machinery
import subprocess
import sys
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
    def test_candidate_files_sorts_by_mtime_before_limiting(self) -> None:
        wrapper = load_wrapper()
        wrapper.MAX_CANDIDATE_FILES = 3

        output = "\n".join(
            [
                "300 /nsm/suripcap/oldish/so-pcap.300",
                "100 /nsm/suripcap/old/so-pcap.100",
                "500 /nsm/suripcap/newest/so-pcap.500",
                "200 /nsm/suripcap/mid/so-pcap.200",
                "400 /nsm/suripcap/newer/so-pcap.400",
            ]
        )
        completed = subprocess.CompletedProcess(args=["find"], returncode=0, stdout=output, stderr="")

        with mock.patch.object(wrapper.subprocess, "run", return_value=completed):
            files = wrapper.candidate_files(
                dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10),
                dt.datetime.now(dt.timezone.utc),
            )

        self.assertEqual(
            [str(path) for path in files],
            [
                "/nsm/suripcap/oldish/so-pcap.300",
                "/nsm/suripcap/newer/so-pcap.400",
                "/nsm/suripcap/newest/so-pcap.500",
            ],
        )


if __name__ == "__main__":
    unittest.main()
