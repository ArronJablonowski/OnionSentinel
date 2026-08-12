from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/controlled_evaluation_isolation.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "controlled_evaluation_isolation_admission_under_test",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ControlledEvaluationIsolationAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_module()

    def _route_fixture(self, root: Path):
        runtime = root / "runtime"
        home = root / "home"
        ssh_dir = home / ".ssh"
        runtime.mkdir(mode=0o700)
        ssh_dir.mkdir(parents=True, mode=0o700)
        key = ssh_dir / self.module.INCIDENT_EVIDENCE_KEY_BASENAME
        known_hosts = runtime / self.module.INCIDENT_EVIDENCE_KNOWN_HOSTS_BASENAME
        key.write_text("synthetic-private-key\n", encoding="utf-8")
        known_hosts.write_text("synthetic-known-host\n", encoding="utf-8")
        key.chmod(0o600)
        known_hosts.chmod(0o600)
        document = {
            "investigation_query_contract": self.module.INCIDENT_EVIDENCE_CONTRACT,
            "host": self.module.INCIDENT_EVIDENCE_HOST,
            "ssh_user": self.module.INCIDENT_EVIDENCE_SSH_USER,
            "ssh_key": str(key),
            "known_hosts": str(known_hosts),
            "connect_timeout_seconds": 7,
            "timeout_seconds": 90,
            "max_response_bytes": 4096,
            "max_stderr_bytes": 1024,
        }
        route = runtime / "incident-evidence.json"
        route.write_text(json.dumps(document) + "\n", encoding="utf-8")
        route.chmod(0o600)
        return runtime, home, route, document

    def _descriptor_metadata(self, payload: bytes, **changes):
        values = {
            "st_mode": stat.S_IFREG | 0o600,
            "st_uid": os.getuid(),
            "st_size": len(payload),
        }
        values.update(changes)
        return SimpleNamespace(**values)

    def test_private_config_read_preserves_descriptor_contract_and_chunks(self):
        payload = b'{"synthetic":true}\n'
        calls = []
        chunks = iter((payload[:5], payload[5:], b""))

        def fake_open(path, flags):
            calls.append(("open", path, flags))
            return 41

        def fake_fstat(descriptor):
            calls.append(("fstat", descriptor))
            return self._descriptor_metadata(payload)

        def fake_read(descriptor, remaining):
            calls.append(("read", descriptor, remaining))
            return next(chunks)

        def fake_close(descriptor):
            calls.append(("close", descriptor))

        with (
            mock.patch.object(self.module.os, "open", side_effect=fake_open),
            mock.patch.object(self.module.os, "fstat", side_effect=fake_fstat),
            mock.patch.object(self.module.os, "read", side_effect=fake_read),
            mock.patch.object(self.module.os, "close", side_effect=fake_close),
        ):
            self.assertEqual(
                self.module._read_private_config(Path("/synthetic")),
                payload,
            )

        expected_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        self.assertEqual(calls[0], ("open", Path("/synthetic"), expected_flags))
        self.assertEqual(calls[1], ("fstat", 41))
        self.assertEqual(calls[-1], ("close", 41))
        self.assertEqual([call[0] for call in calls], ["open", "fstat", "read", "read", "read", "close"])
        self.assertEqual(calls[2][2], self.module.MAX_INCIDENT_EVIDENCE_CONFIG_BYTES + 1)
        self.assertEqual(calls[3][2], self.module.MAX_INCIDENT_EVIDENCE_CONFIG_BYTES - 4)

    def test_private_config_open_and_read_failures_preserve_causes_and_close(self):
        opened = OSError("synthetic open")
        with mock.patch.object(self.module.os, "open", side_effect=opened):
            with self.assertRaisesRegex(
                self.module.ControlledEvaluationIsolationError,
                "transport config is invalid",
            ) as raised:
                self.module._read_private_config(Path("/synthetic"))
        self.assertIs(raised.exception.__cause__, opened)

        payload = b"{}"
        read_error = OSError("synthetic read")
        with (
            mock.patch.object(self.module.os, "open", return_value=42),
            mock.patch.object(
                self.module.os,
                "fstat",
                return_value=self._descriptor_metadata(payload),
            ),
            mock.patch.object(self.module.os, "read", side_effect=read_error),
            mock.patch.object(self.module.os, "close") as close,
        ):
            with self.assertRaises(OSError) as raised:
                self.module._read_private_config(Path("/synthetic"))
        self.assertIs(raised.exception, read_error)
        close.assert_called_once_with(42)

    def test_private_config_metadata_contract_fails_closed_and_closes_once(self):
        payload = b"{}"
        invalid = (
            {"st_mode": stat.S_IFDIR | 0o700},
            {"st_uid": os.getuid() + 1},
            {"st_mode": stat.S_IFREG | 0o640},
            {"st_size": 1},
            {"st_size": self.module.MAX_INCIDENT_EVIDENCE_CONFIG_BYTES + 1},
        )
        for changes in invalid:
            with self.subTest(changes=changes):
                with (
                    mock.patch.object(self.module.os, "open", return_value=43),
                    mock.patch.object(
                        self.module.os,
                        "fstat",
                        return_value=self._descriptor_metadata(payload, **changes),
                    ),
                    mock.patch.object(self.module.os, "read") as read,
                    mock.patch.object(self.module.os, "close") as close,
                ):
                    with self.assertRaisesRegex(
                        self.module.ControlledEvaluationIsolationError,
                        "exceeds its byte contract",
                    ):
                        self.module._read_private_config(Path("/synthetic"))
                read.assert_not_called()
                close.assert_called_once_with(43)

    def test_private_config_detects_short_and_growing_reads(self):
        cases = ((b"{}", 3), (b"{}\n", 2))
        for payload, admitted_size in cases:
            with self.subTest(payload=payload, admitted_size=admitted_size):
                with (
                    mock.patch.object(self.module.os, "open", return_value=44),
                    mock.patch.object(
                        self.module.os,
                        "fstat",
                        return_value=self._descriptor_metadata(
                            payload,
                            st_size=admitted_size,
                        ),
                    ),
                    mock.patch.object(
                        self.module.os,
                        "read",
                        side_effect=(payload, b""),
                    ),
                    mock.patch.object(self.module.os, "close") as close,
                ):
                    with self.assertRaisesRegex(
                        self.module.ControlledEvaluationIsolationError,
                        "changed while it was read",
                    ):
                        self.module._read_private_config(Path("/synthetic"))
                close.assert_called_once_with(44)

    def test_valid_route_returns_the_decoded_document_without_mutating_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            runtime, home, route, expected = self._route_fixture(root)
            inputs = (route, runtime, home)
            result = self.module.validate_controlled_incident_evidence_route(
                route,
                runtime,
                expected_home=home,
            )
        self.assertEqual(result, expected)
        self.assertIsInstance(result, dict)
        self.assertEqual(inputs, (route, runtime, home))

    def test_route_document_and_exact_identity_failures_preserve_messages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            runtime, home, route, baseline = self._route_fixture(root)
            cases = (
                (b"\xff", "transport config is invalid", UnicodeError),
                (b"{", "transport config is invalid", json.JSONDecodeError),
                (b"[]", "contain only the exact read-only route fields", None),
                (
                    json.dumps({**baseline, "extra": True}).encode(),
                    "contain only the exact read-only route fields",
                    None,
                ),
                (
                    json.dumps({**baseline, "host": "10.88.8.9"}).encode(),
                    "does not select the exact read-only route",
                    None,
                ),
            )
            for payload, message, cause_type in cases:
                with self.subTest(message=message, payload=payload):
                    with mock.patch.object(
                        self.module,
                        "_read_private_config",
                        return_value=payload,
                    ):
                        with self.assertRaisesRegex(
                            self.module.ControlledEvaluationIsolationError,
                            message,
                        ) as raised:
                            self.module.validate_controlled_incident_evidence_route(
                                route,
                                runtime,
                                expected_home=home,
                            )
                    if cause_type is None:
                        self.assertIsNone(raised.exception.__cause__)
                    else:
                        self.assertIsInstance(raised.exception.__cause__, cause_type)

    def test_route_paths_and_all_numeric_limits_are_exact_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            runtime, home, route, baseline = self._route_fixture(root)
            rogue = root / "rogue"
            rogue.write_text("synthetic\n", encoding="utf-8")
            rogue.chmod(0o600)
            path_cases = (
                ("ssh_key", str(rogue), "SSH key path is not approved"),
                (
                    "known_hosts",
                    str(rogue),
                    "known-hosts path is not approved",
                ),
            )
            for field, value, message in path_cases:
                with self.subTest(field=field):
                    document = {**baseline, field: value}
                    route.write_text(json.dumps(document), encoding="utf-8")
                    route.chmod(0o600)
                    with self.assertRaisesRegex(
                        self.module.ControlledEvaluationIsolationError,
                        message,
                    ):
                        self.module.validate_controlled_incident_evidence_route(
                            route,
                            runtime,
                            expected_home=home,
                        )

            limits = {
                "connect_timeout_seconds": self.module.MAX_INCIDENT_EVIDENCE_CONNECT_TIMEOUT_SECONDS,
                "timeout_seconds": self.module.MAX_INCIDENT_EVIDENCE_TIMEOUT_SECONDS,
                "max_response_bytes": self.module.MAX_INCIDENT_EVIDENCE_RESPONSE_BYTES,
                "max_stderr_bytes": self.module.MAX_INCIDENT_EVIDENCE_STDERR_BYTES,
            }
            route.write_text(json.dumps({**baseline, **limits}), encoding="utf-8")
            route.chmod(0o600)
            self.assertEqual(
                self.module.validate_controlled_incident_evidence_route(
                    route,
                    runtime,
                    expected_home=home,
                ),
                {**baseline, **limits},
            )
            for field, maximum in limits.items():
                for value in (True, 0, maximum + 1):
                    with self.subTest(field=field, value=value):
                        document = {**baseline, field: value}
                        route.write_text(json.dumps(document), encoding="utf-8")
                        route.chmod(0o600)
                        with self.assertRaisesRegex(
                            self.module.ControlledEvaluationIsolationError,
                            f"Relay evidence {field} exceeds its bounded transport limit",
                        ):
                            self.module.validate_controlled_incident_evidence_route(
                                route,
                                runtime,
                                expected_home=home,
                            )


if __name__ == "__main__":
    unittest.main()
