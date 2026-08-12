"""Characterization for incident-evidence collection orchestration."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
SCRIPT = BIN_DIR / "collect-incident-evidence.py"


def load_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_collection_workflow", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = load_module()


class FakeConnection:
    def __init__(self) -> None:
        self.row_factory = None
        self.closed = False

    def close(self) -> None:
        self.closed = True


class IncidentEvidenceWorkflowCharacterization(unittest.TestCase):
    def test_public_surface_and_main_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(collector) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (53, "2f885f63c1abbdea61adfc088b452bb5c4cb24e72135d23f3e741039f2c20ecc"),
        )
        self.assertEqual(str(inspect.signature(collector.main)), "() -> 'int'")

    def args(self, root: str, *, alert_id: str = "group/alert") -> argparse.Namespace:
        return argparse.Namespace(
            alert_id=alert_id,
            db=Path(root) / "alerts.sqlite3",
            config=Path(root) / "incident.json",
            out_dir=Path(root) / "output",
            size=37,
        )

    def config(self) -> dict[str, object]:
        return {
            "host": "relay.example",
            "ssh_user": "collector",
            "ssh_key": "$ARR173_HOME/key",
            "known_hosts": "~/known_hosts",
            "connect_timeout_seconds": "17",
            "timeout_seconds": "123.5",
            "max_response_bytes": "4567",
            "max_stderr_bytes": "891",
        }

    def response(self) -> dict[str, object]:
        return {"ok": True, "synthetic": "response"}

    def test_success_contract_order_request_transport_artifact_and_publish_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as root, mock.patch.dict(
            os.environ,
            {"ARR173_HOME": "/synthetic/home", "HOME": "/synthetic/user"},
        ):
            args = self.args(root)
            connection = FakeConnection()
            selected = {"stable_group_id": " group/id "}
            grouped = [{"alert_id": "one"}, {"alert_id": "two"}]
            exact = {
                "ips": ["192.0.2.1"],
                "domains": [],
                "hosts": [],
                "users": [],
            }
            windows = [{"start": "start", "end": "end"}]
            anchor = {"index": "logs-suricata.alerts-so", "id": "id"}
            process = mock.Mock(
                returncode=0,
                stdout=json.dumps(self.response()),
                stderr="",
            )
            datetime_type = dt.datetime

            class FixedDateTime(datetime_type):
                @classmethod
                def now(cls, tz=None):
                    return cls(2026, 1, 2, 3, 4, 5, 999999, tzinfo=dt.timezone.utc)

                def astimezone(self, tz=None):
                    return self
            events: list[str] = []

            def observe(name, value):
                def invoke(*_args, **_kwargs):
                    events.append(name)
                    return value
                return invoke

            stdout = io.StringIO()
            with mock.patch.object(collector, "parse_args", side_effect=observe("parse", args)), mock.patch.object(
                collector, "load_config", side_effect=observe("config", self.config())
            ) as load_config, mock.patch.object(
                collector.sqlite3, "connect", side_effect=observe("connect", connection)
            ) as connect, mock.patch.object(
                collector, "selected_group", side_effect=observe("select", (selected, grouped))
            ), mock.patch.object(
                collector, "observables", side_effect=observe("observables", exact)
            ), mock.patch.object(
                collector, "evidence_windows", side_effect=observe("windows", (windows, "coverage"))
            ), mock.patch.object(
                collector, "representative_alert_anchor", side_effect=observe("anchor", anchor)
            ), mock.patch.object(
                collector, "run_bounded_command", side_effect=observe("transport", process)
            ) as run, mock.patch.object(
                collector, "validate_incident_evidence_artifact", side_effect=lambda value: events.append("validate")
            ) as validate, mock.patch.object(
                collector, "atomic_json", side_effect=lambda path, value: events.append("publish")
            ) as publish, mock.patch.object(
                collector.dt, "datetime", FixedDateTime
            ), redirect_stdout(stdout):
                return_code = collector.main()

        self.assertEqual(return_code, 0)
        self.assertEqual(
            events,
            ["parse", "config", "connect", "select", "observables", "windows", "anchor", "transport", "validate", "publish"],
        )
        load_config.assert_called_once_with(args.config)
        connect.assert_called_once_with(f"file:{args.db}?mode=ro", uri=True)
        self.assertIs(connection.row_factory, sqlite3.Row)
        self.assertTrue(connection.closed)
        expected_request = {
            "packs": [
                "alert_context", "network_flow", "dns_activity",
                "osquery_history", "cross_sensor_timeline",
            ],
            "osquery_packs": list(collector.OSQUERY_PACKS),
            "windows": windows,
            "observables": exact,
            "size": 37,
            "anchor": anchor,
        }
        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o",
                "IdentitiesOnly=yes", "-o", "ConnectTimeout=17", "-o",
                "StrictHostKeyChecking=yes", "-o",
                "UserKnownHostsFile=/synthetic/user/known_hosts", "-i",
                "/synthetic/home/key", "collector@relay.example",
            ],
        )
        self.assertEqual(
            run.call_args.kwargs,
            {
                "stdin_text": json.dumps(expected_request, separators=(",", ":")),
                "timeout_seconds": 123.5,
                "max_stdout_bytes": 4567,
                "max_stderr_bytes": 891,
            },
        )
        artifact = validate.call_args.args[0]
        self.assertEqual(
            artifact,
            {
                "schema": collector.INCIDENT_EVIDENCE_CONTRACT,
                "generated_at": "2026-01-02  03:04:05+00:00",
                "alert_id": "group/alert",
                "group_id": " group/id ",
                "group_alert_rows": 2,
                "coverage_note": "coverage",
                "request": expected_request,
                "security_onion_response": self.response(),
            },
        )
        destination, published = publish.call_args.args
        self.assertEqual(destination, args.out_dir / " group-id -incident-evidence.json")
        self.assertIs(published, artifact)
        self.assertEqual(stdout.getvalue(), f"{destination}\n")

    def test_selection_failure_still_closes_read_only_connection(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            connection = FakeConnection()
            with mock.patch.object(collector, "parse_args", return_value=self.args(root)), mock.patch.object(
                collector, "load_config", return_value=self.config()
            ), mock.patch.object(
                collector.sqlite3, "connect", return_value=connection
            ), mock.patch.object(
                collector, "selected_group", side_effect=RuntimeError("selection failed")
            ):
                with self.assertRaisesRegex(RuntimeError, "^selection failed$"):
                    collector.main()
            self.assertTrue(connection.closed)

    def test_empty_observables_fail_before_windows_anchor_or_transport(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            connection = FakeConnection()
            selected = {"stable_group_id": "group"}
            with mock.patch.object(collector, "parse_args", return_value=self.args(root)), mock.patch.object(
                collector, "load_config", return_value=self.config()
            ), mock.patch.object(
                collector.sqlite3, "connect", return_value=connection
            ), mock.patch.object(
                collector, "selected_group", return_value=(selected, [selected])
            ), mock.patch.object(
                collector, "observables", return_value={"ips": [], "domains": [], "hosts": [], "users": []}
            ), mock.patch.object(collector, "evidence_windows") as windows, mock.patch.object(
                collector, "representative_alert_anchor"
            ) as anchor, mock.patch.object(collector, "run_bounded_command") as run:
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^no validated exact observables were available for restricted evidence queries$",
                ):
                    collector.main()
            windows.assert_not_called()
            anchor.assert_not_called()
            run.assert_not_called()

    def transport_case(self, process: mock.Mock) -> None:
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        connection = FakeConnection()
        selected = {"stable_group_id": "group"}
        patches = (
            mock.patch.object(collector, "parse_args", return_value=self.args(root.name)),
            mock.patch.object(collector, "load_config", return_value=self.config()),
            mock.patch.object(collector.sqlite3, "connect", return_value=connection),
            mock.patch.object(collector, "selected_group", return_value=(selected, [selected])),
            mock.patch.object(collector, "observables", return_value={"ips": ["192.0.2.1"]}),
            mock.patch.object(collector, "evidence_windows", return_value=([], "coverage")),
            mock.patch.object(collector, "representative_alert_anchor", return_value=None),
            mock.patch.object(collector, "run_bounded_command", return_value=process),
        )
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_transport_failure_includes_rc_and_first_1000_stderr_characters(self) -> None:
        self.transport_case(mock.Mock(returncode=7, stdout="", stderr="x" * 1005))
        with self.assertRaises(RuntimeError) as raised:
            collector.main()
        self.assertEqual(
            str(raised.exception),
            "restricted incident evidence transport failed rc=7: " + "x" * 1000,
        )

    def test_protocol_rejects_non_object_and_non_true_ok(self) -> None:
        for stdout in ("[]", '{"ok":false}'):
            with self.subTest(stdout=stdout):
                self.transport_case(mock.Mock(returncode=0, stdout=stdout, stderr=""))
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^restricted incident evidence response failed its protocol contract$",
                ):
                    collector.main()


if __name__ == "__main__":
    unittest.main()
