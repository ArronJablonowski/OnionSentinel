#!/usr/bin/env python3
"""Regression checks for PCAP evidence retention cleanup."""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "n8n" / "bin" / "maintain-pcap-evidence.py"


def load_module():
    spec = importlib.util.spec_from_file_location("maintain_pcap_evidence", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class PcapRetentionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.safe_root = self.root / "n8n-local"
        self.artifact_dir = self.safe_root / "pcap-evidence" / "artifacts"
        self.analysis_dir = self.safe_root / "soc-alerts" / "pcap-analysis"
        self.artifact_dir.mkdir(parents=True)
        self.analysis_dir.mkdir(parents=True)
        self.original_home = self.module.HOME
        self.module.HOME = self.root

    def tearDown(self) -> None:
        self.module.HOME = self.original_home
        self.tmp.cleanup()

    def write_file(self, path: Path, age_days: int) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("unit-test", encoding="utf-8")
        timestamp = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=age_days)).timestamp()
        os.utime(path, (timestamp, timestamp))
        return path

    def test_dry_run_reports_stale_files_without_deleting(self) -> None:
        old_pcap = self.write_file(self.artifact_dir / "request" / "capture.pcap", 20)
        fresh_pcap = self.write_file(self.artifact_dir / "request" / "fresh.pcap", 1)
        args = type(
            "Args",
            (),
            {
                "artifact_dir": self.artifact_dir,
                "analysis_dir": self.analysis_dir,
                "artifact_retention_days": 14,
                "analysis_retention_days": 30,
                "apply": False,
            },
        )()

        result = self.module.run(args, dt.datetime.now(dt.timezone.utc))

        self.assertEqual(result["mode"], "dry-run")
        self.assertEqual(result["artifact_cleanup"]["matched_files"], 1)
        self.assertIn(str(old_pcap.resolve()), result["artifact_cleanup"]["files"])
        self.assertTrue(old_pcap.exists())
        self.assertTrue(fresh_pcap.exists())

    def test_apply_deletes_only_expired_files(self) -> None:
        old_analysis = self.write_file(self.analysis_dir / "old-pcap-analysis.json", 45)
        fresh_analysis = self.write_file(self.analysis_dir / "fresh-pcap-analysis.json", 5)
        args = type(
            "Args",
            (),
            {
                "artifact_dir": self.artifact_dir,
                "analysis_dir": self.analysis_dir,
                "artifact_retention_days": 14,
                "analysis_retention_days": 30,
                "apply": True,
            },
        )()

        result = self.module.run(args, dt.datetime.now(dt.timezone.utc))

        self.assertEqual(result["mode"], "apply")
        self.assertFalse(old_analysis.exists())
        self.assertTrue(fresh_analysis.exists())

    def test_refuses_paths_outside_n8n_local(self) -> None:
        with self.assertRaises(ValueError):
            self.module.validate_runtime_path(self.root / "Documents")

    def test_analyzed_only_deletes_only_dual_parser_artifacts(self) -> None:
        complete_dir = self.artifact_dir / "complete-request"
        partial_dir = self.artifact_dir / "partial-request"
        self.write_file(complete_dir / "capture.pcap", 0)
        self.write_file(partial_dir / "capture.pcap", 0)
        complete = {
            "request": {"request_id": "complete-request"},
            "pcap_files": [{"name": "capture.pcap"}],
            "zeek": {"available": True, "commands": [{"ok": True}]},
            "tshark": {"available": True, "commands": [{"ok": True}]},
        }
        partial = {
            "request": {"request_id": "partial-request"},
            "pcap_files": [{"name": "capture.pcap"}],
            "zeek": {"available": True, "commands": [{"ok": True}]},
            "tshark": {"available": True, "commands": [{"ok": False}]},
        }
        (self.analysis_dir / "complete-request-pcap-analysis.json").write_text(json.dumps(complete), encoding="utf-8")
        (self.analysis_dir / "partial-request-pcap-analysis.json").write_text(json.dumps(partial), encoding="utf-8")
        args = type("Args", (), {
            "artifact_dir": self.artifact_dir,
            "analysis_dir": self.analysis_dir,
            "artifact_retention_days": 14,
            "analysis_retention_days": 30,
            "apply": True,
            "analyzed_only": True,
        })()
        result = self.module.run(args)
        self.assertEqual(result["analyzed_artifact_cleanup"]["matched_requests"], 1)
        self.assertFalse(complete_dir.exists())
        self.assertTrue(partial_dir.exists())


if __name__ == "__main__":
    unittest.main()
