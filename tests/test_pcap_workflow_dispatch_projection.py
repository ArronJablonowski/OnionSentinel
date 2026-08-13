"""Characterize PCAP processor workflow dispatch and status lifecycle."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n/bin"
MODULE_PATH = BIN / "pcap_processor_workflow.py"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_workflow(name: str):
    spec = importlib.util.spec_from_file_location(name, MODULE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("PCAP processor workflow cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PcapWorkflowDispatchProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.workflow = load_workflow(f"pcap_workflow_projection_{id(self)}")

    def tearDown(self):
        self.temp.cleanup()

    def _args(self, **overrides):
        values = {
            "out_dir": self.root / "out",
            "wake_file": self.root / "run/pcap.wake",
            "pcap": None,
            "alert_id": None,
            "group_id": None,
            "stdout": False,
            "db": self.root / "alerts.sqlite3",
            "request_id": None,
            "limit": 3,
            "overwrite": False,
            "alert_store_url": "http://synthetic.invalid:8787",
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def _ports(self, args):
        parent = mock.Mock()
        ports = {
            "parse_args": mock.Mock(return_value=args),
            "require_runtime_capacity": mock.Mock(),
            "consume_wake_marker": mock.Mock(),
            "safe_filename": mock.Mock(side_effect=lambda value: f"safe-{value}"),
            "process_one": mock.Mock(),
            "pending_requests": mock.Mock(return_value=[]),
            "analysis_json_path": mock.Mock(),
            "report_analysis_status": mock.Mock(),
            "signal_follow_up": mock.Mock(),
        }
        for name, port in ports.items():
            parent.attach_mock(port, name)
        return parent, ports

    def _invoke(self, ports):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, port in ports.items():
                stack.enter_context(mock.patch.object(self.workflow, name, port))
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = self.workflow.main()
        return result, stdout.getvalue(), stderr.getvalue()

    def test_manual_request_preserves_admission_shape_call_and_path_output(self):
        capture = self.root / "capture-one.pcap"
        args = self._args(
            pcap=capture,
            alert_id="alert-1",
            group_id="group-1",
        )
        parent, ports = self._ports(args)
        analysis = {
            "_markdown_path": "/synthetic/analysis.md",
            "_json_path": "/synthetic/analysis.json",
        }
        ports["process_one"].return_value = analysis

        result, stdout, stderr = self._invoke(ports)

        self.assertEqual((result, stdout, stderr), (
            0,
            "/synthetic/analysis.md\n/synthetic/analysis.json\n",
            "",
        ))
        self.assertEqual(
            parent.mock_calls,
            [
                mock.call.parse_args(),
                mock.call.require_runtime_capacity(
                    args.out_dir, 0, label="PCAP analysis"
                ),
                mock.call.consume_wake_marker(args.wake_file),
                mock.call.safe_filename("capture-one"),
                mock.call.process_one(
                    {
                        "request_id": "safe-capture-one",
                        "alert_id": "alert-1",
                        "group_id": "group-1",
                        "artifact_path": str(capture),
                        "status": "manual",
                    },
                    args,
                    capture,
                ),
            ],
        )

    def test_pending_batch_preserves_cache_status_failure_isolation_and_follow_up(self):
        args = self._args(limit=3)
        parent, ports = self._ports(args)
        requests = [
            {"request_id": "cached"},
            {"request_id": "bad"},
            {"request_id": "new"},
        ]
        before = copy.deepcopy(requests)
        ports["pending_requests"].return_value = requests
        cached = args.out_dir / "safe-cached-pcap-analysis.json"
        cached.parent.mkdir(parents=True)
        cached.write_text(
            json.dumps({"kind": "cached", "_json_path": "stale"}),
            encoding="utf-8",
        )
        paths = {
            "safe-cached": cached,
            "safe-bad": args.out_dir / "safe-bad-pcap-analysis.json",
            "safe-new": args.out_dir / "safe-new-pcap-analysis.json",
        }
        ports["analysis_json_path"].side_effect = (
            lambda _out_dir, request_id: paths[request_id]
        )

        def process(request, _args):
            if request["request_id"] == "bad":
                raise ValueError("synthetic process failure")
            return {
                "kind": "new",
                "_markdown_path": "/synthetic/new.md",
                "_json_path": "/synthetic/new.json",
            }

        ports["process_one"].side_effect = process

        def report(_base_url, request_id, status, error=""):
            if request_id == "safe-bad" and status == "failed":
                raise RuntimeError("synthetic status failure")

        ports["report_analysis_status"].side_effect = report

        result, stdout, stderr = self._invoke(ports)

        cached_markdown = str(
            cached.with_name("safe-cached-pcap-analysis.md")
        )
        self.assertEqual(requests, before)
        self.assertEqual(result, 1)
        self.assertEqual(
            stdout,
            f"{cached_markdown}\n{cached}\n/synthetic/new.md\n/synthetic/new.json\n",
        )
        self.assertEqual(
            stderr,
            "status update failed for safe-bad: synthetic status failure\n"
            "PCAP analysis failed for safe-bad: synthetic process failure\n",
        )
        self.assertEqual(
            ports["pending_requests"].mock_calls,
            [
                mock.call(
                    args.db,
                    args.request_id,
                    args.limit,
                    args.out_dir,
                    args.overwrite,
                )
            ],
        )
        self.assertEqual(
            ports["report_analysis_status"].mock_calls,
            [
                mock.call(args.alert_store_url, "safe-cached", "processing"),
                mock.call(args.alert_store_url, "safe-cached", "completed"),
                mock.call(args.alert_store_url, "safe-bad", "processing"),
                mock.call(
                    args.alert_store_url,
                    "safe-bad",
                    "failed",
                    "synthetic process failure",
                ),
                mock.call(args.alert_store_url, "safe-new", "processing"),
                mock.call(args.alert_store_url, "safe-new", "completed"),
            ],
        )
        self.assertEqual(
            ports["process_one"].mock_calls,
            [mock.call(requests[1], args), mock.call(requests[2], args)],
        )
        ports["signal_follow_up"].assert_called_once_with(args.wake_file)

    def test_overwrite_request_id_and_stdout_preserve_exact_projection(self):
        args = self._args(request_id="one", limit=1, overwrite=True, stdout=True)
        _parent, ports = self._ports(args)
        request = {"request_id": "one"}
        ports["pending_requests"].return_value = [request]
        existing = args.out_dir / "safe-one-pcap-analysis.json"
        existing.parent.mkdir(parents=True)
        existing.write_text("{}", encoding="utf-8")
        ports["analysis_json_path"].return_value = existing
        analysis = {
            "z": 2,
            "a": 1,
            "_markdown_path": "/synthetic/one.md",
            "_json_path": "/synthetic/one.json",
        }
        ports["process_one"].return_value = analysis

        result, stdout, stderr = self._invoke(ports)

        self.assertEqual((result, stderr), (0, ""))
        self.assertEqual(stdout, json.dumps([analysis], indent=2, sort_keys=True) + "\n")
        ports["process_one"].assert_called_once_with(request, args)
        ports["signal_follow_up"].assert_not_called()


if __name__ == "__main__":
    unittest.main()
