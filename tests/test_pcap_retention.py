#!/usr/bin/env python3
"""Regression checks for PCAP evidence retention cleanup."""
from __future__ import annotations

import datetime as dt
import importlib.util
import os
import json
import sys
import tempfile
import sqlite3
import unittest
from pathlib import Path
from unittest import mock


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
        # DEFAULT_DB is computed when the script is imported, before HOME is
        # rebound below. Keep every minimal Args fixture inside this test root.
        self.module.DEFAULT_DB = self.safe_root / "alert_store_data" / "alerts.sqlite3"
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

    def test_terminal_non_artifact_outcome_removes_legacy_request_directory(self) -> None:
        request_dir = self.artifact_dir / "no-packets-request"
        self.write_file(request_dir / ".chunks" / "00000001.chunk", 0)
        db_path = self.safe_root / "alert_store_data" / "alerts.sqlite3"
        db_path.parent.mkdir(parents=True)
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE pcap_requests (request_id TEXT, status TEXT, outcome TEXT)")
        conn.execute("INSERT INTO pcap_requests VALUES (?, ?, ?)", ("no-packets-request", "failed", "no_packets_available"))
        conn.commit()
        conn.close()

        result = self.module.cleanup_terminal_artifacts(self.artifact_dir, db_path, True)

        self.assertEqual(result["matched_requests"], 1)
        self.assertFalse(request_dir.exists())

    def test_analyzed_admission_order_projection_and_receipt_merge_are_exact(self) -> None:
        payloads = {
            "z-invalid-pcap-analysis.json": "{bad-json",
            "a-list-pcap-analysis.json": "[]",
            "b-empty-pcap-analysis.json": json.dumps({"request": {"request_id": ""}}),
            "c-incomplete-pcap-analysis.json": json.dumps({
                "request": {"request_id": "incomplete"},
                "complete": False,
            }),
            "d-escape-pcap-analysis.json": json.dumps({
                "request": {"request_id": "../escape"},
                "complete": True,
            }),
            "e-missing-dir-pcap-analysis.json": json.dumps({
                "request": {"request_id": "missing"},
                "complete": True,
            }),
            "f-complete-pcap-analysis.json": json.dumps({
                "request": {"request_id": "complete"},
                "complete": True,
            }),
        }
        for name, value in payloads.items():
            (self.analysis_dir / name).write_text(value, encoding="utf-8")
        complete = self.artifact_dir / "complete"
        (complete / "nested").mkdir(parents=True)
        (complete / "one.bin").write_bytes(b"123")
        (complete / "nested" / "two.bin").write_bytes(b"4567")
        completion_calls = []
        deletion_calls = []

        def completed(value):
            completion_calls.append(value["request"]["request_id"])
            return bool(value.get("complete"))

        def delete(root, request_id):
            deletion_calls.append([root, request_id])
            return {
                "request_id": "receipt-identity",
                "files": 99,
                "deleted": True,
            }

        with (
            mock.patch.object(self.module, "analysis_completed", side_effect=completed),
            mock.patch.object(
                self.module,
                "delete_request_artifacts",
                side_effect=delete,
            ),
        ):
            dry_run = self.module.cleanup_analyzed_artifacts(
                self.artifact_dir,
                self.analysis_dir,
                False,
            )
            applied = self.module.cleanup_analyzed_artifacts(
                self.artifact_dir,
                self.analysis_dir,
                True,
            )

        self.assertEqual(
            completion_calls,
            ["incomplete", "../escape", "missing", "complete"] * 2,
        )
        self.assertEqual(dry_run, {
            "matched_requests": 1,
            "matched_bytes": 7,
            "requests": [{"request_id": "complete", "bytes": 7, "files": 2}],
        })
        self.assertEqual(applied, {
            "matched_requests": 1,
            "matched_bytes": 7,
            "requests": [{
                "request_id": "receipt-identity",
                "bytes": 7,
                "files": 99,
                "deleted": True,
            }],
        })
        self.assertEqual(
            deletion_calls,
            [[self.artifact_dir.resolve(), "complete"]],
        )

    def test_per_request_io_and_value_failures_skip_without_stopping_later_rows(self) -> None:
        for request_id in ("io-failure", "value-failure", "accepted"):
            (self.analysis_dir / f"{request_id}-pcap-analysis.json").write_text(
                json.dumps({
                    "request": {"request_id": request_id},
                    "complete": True,
                }),
                encoding="utf-8",
            )
            directory = self.artifact_dir / request_id
            directory.mkdir()
            (directory / "capture.pcap").write_bytes(b"data")
        calls = []

        def delete(root, request_id):
            calls.append(request_id)
            if request_id == "io-failure":
                raise OSError("synthetic I/O failure")
            if request_id == "value-failure":
                raise ValueError("synthetic value failure")
            return {"deleted": True}

        with (
            mock.patch.object(self.module, "analysis_completed", return_value=True),
            mock.patch.object(
                self.module,
                "delete_request_artifacts",
                side_effect=delete,
            ),
        ):
            result = self.module.cleanup_analyzed_artifacts(
                self.artifact_dir,
                self.analysis_dir,
                True,
            )

        self.assertEqual(calls, ["accepted", "io-failure", "value-failure"])
        self.assertEqual(result, {
            "matched_requests": 1,
            "matched_bytes": 4,
            "requests": [{
                "request_id": "accepted",
                "bytes": 4,
                "files": 1,
                "deleted": True,
            }],
        })

    def test_non_isolated_completion_and_deletion_errors_still_propagate(self) -> None:
        analysis_path = self.analysis_dir / "request-pcap-analysis.json"
        analysis_path.write_text(
            json.dumps({"request": {"request_id": "request"}}),
            encoding="utf-8",
        )
        request_dir = self.artifact_dir / "request"
        request_dir.mkdir()
        (request_dir / "capture.pcap").write_bytes(b"data")

        with (
            mock.patch.object(
                self.module,
                "analysis_completed",
                side_effect=RuntimeError("completion failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "completion failure"),
        ):
            self.module.cleanup_analyzed_artifacts(
                self.artifact_dir,
                self.analysis_dir,
                False,
            )
        with (
            mock.patch.object(self.module, "analysis_completed", return_value=True),
            mock.patch.object(
                self.module,
                "delete_request_artifacts",
                side_effect=RuntimeError("deletion failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "deletion failure"),
        ):
            self.module.cleanup_analyzed_artifacts(
                self.artifact_dir,
                self.analysis_dir,
                True,
            )

    def test_terminal_database_contract_row_order_and_close_are_exact(self) -> None:
        db_path = self.safe_root / "alert_store_data" / "alerts.sqlite3"
        db_path.parent.mkdir(parents=True)
        db_path.touch()
        for request_id in ("second", "first"):
            directory = self.artifact_dir / request_id
            directory.mkdir()
            (directory / "capture.pcap").write_bytes(request_id.encode())
        trace = []

        class Cursor:
            def fetchall(self):
                trace.append(["fetchall"])
                return [("second",), ("../escape",), ("missing",), ("first",)]

        class Connection:
            def execute(self, statement):
                trace.append(["execute", statement])
                return Cursor()

            def close(self):
                trace.append(["close"])

        def connect(connection_uri, *, uri=True):
            trace.append(["connect", connection_uri, uri])
            return Connection()

        def delete(root, request_id):
            trace.append(["delete", str(root), request_id])
            return {"deleted": request_id}

        with (
            mock.patch.object(self.module.sqlite3, "connect", side_effect=connect),
            mock.patch.object(
                self.module,
                "delete_request_artifacts",
                side_effect=delete,
            ),
        ):
            result = self.module.cleanup_terminal_artifacts(
                self.artifact_dir,
                db_path,
                True,
            )

        self.assertEqual(trace[0], ["connect", f"file:{db_path}?mode=ro", True])
        self.assertIn("WHERE status IN ('failed', 'rejected')", trace[1][1])
        self.assertIn("outcome IN ('no_packets_available', 'expired', 'oversize')", trace[1][1])
        self.assertEqual(trace[2:4], [["fetchall"], ["close"]])
        self.assertEqual(
            [event[-1] for event in trace if event[0] == "delete"],
            ["second", "first"],
        )
        self.assertEqual(
            [item["request_id"] for item in result["requests"]],
            ["second", "first"],
        )
        self.assertEqual(
            result["matched_bytes"],
            len("second") + len("first"),
        )

    def test_terminal_fetch_failure_closes_connection_and_missing_db_is_bounded(self) -> None:
        missing = self.safe_root / "missing.sqlite3"
        self.assertEqual(
            self.module.cleanup_terminal_artifacts(
                self.artifact_dir,
                missing,
                False,
            ),
            {
                "matched_requests": 0,
                "matched_bytes": 0,
                "requests": [],
                "reason": "database not found",
            },
        )
        database = self.safe_root / "failing.sqlite3"
        database.touch()
        trace = []

        class Cursor:
            def fetchall(self):
                raise sqlite3.DatabaseError("synthetic fetch failure")

        class Connection:
            def execute(self, _statement):
                return Cursor()

            def close(self):
                trace.append("closed")

        with (
            mock.patch.object(
                self.module.sqlite3,
                "connect",
                return_value=Connection(),
            ),
            self.assertRaisesRegex(sqlite3.DatabaseError, "synthetic fetch failure"),
        ):
            self.module.cleanup_terminal_artifacts(
                self.artifact_dir,
                database,
                False,
            )
        self.assertEqual(trace, ["closed"])


if __name__ == "__main__":
    unittest.main()
