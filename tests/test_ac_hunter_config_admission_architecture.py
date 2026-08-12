from __future__ import annotations

import copy
import importlib
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
ADMISSION_PATH = DASHBOARD / "ac_hunter_config_admission.py"
BASELINE = ROOT / "operations/quality/module-quality-baseline.json"


def load_config_module():
    if str(DASHBOARD) not in sys.path:
        sys.path.insert(0, str(DASHBOARD))
    return importlib.import_module("ac_hunter_config")


class AcHunterConfigAdmissionArchitectureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = load_config_module()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config_path = self.root / "config.json"
        self.cache = self.root / "cache.json"

    def source(self, **overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": self.config.CONFIG_SCHEMA,
            "enabled": False,
            "dataset": self.config.FIXED_DATASET,
            "relay_host": self.config.FIXED_RELAY_HOST,
            "relay_user": self.config.FIXED_RELAY_USER,
            "relay_port": self.config.FIXED_RELAY_PORT,
            "ssh_key": str(self.root / "ssh-key"),
            "known_hosts": str(self.root / "known-hosts"),
            "credentials_file": str(self.root / "credentials.json"),
            "cache_file": str(self.cache),
        }
        value.update(overrides)
        return value

    def call(
        self,
        source: dict[str, object],
        *,
        secure_effect: object = None,
        credentials_effect: object = ("service@example.invalid", "secret"),
    ) -> tuple[dict[str, object], list[list[object]]]:
        trace: list[list[object]] = []

        def private_json(path: Path, maximum: int):
            trace.append(["private_json", str(path), maximum])
            return source

        def secure_file(path: Path, **kwargs: object):
            trace.append(
                ["secure_file", str(path), dict(sorted(kwargs.items()))]
            )
            if isinstance(secure_effect, list) and secure_effect:
                effect = secure_effect.pop(0)
                if isinstance(effect, BaseException):
                    raise effect
                return effect
            if isinstance(secure_effect, BaseException):
                raise secure_effect
            return secure_effect

        def credentials(path: Path):
            trace.append(["credentials", str(path)])
            if isinstance(credentials_effect, BaseException):
                raise credentials_effect
            return credentials_effect

        before = copy.deepcopy(source)
        with mock.patch.object(
            self.config, "DEFAULT_CACHE", self.cache
        ), mock.patch.object(
            self.config, "_private_json", side_effect=private_json
        ), mock.patch.object(
            self.config, "_secure_file_bytes", side_effect=secure_file
        ), mock.patch.object(
            self.config, "load_credentials", side_effect=credentials
        ):
            try:
                result = self.config.load_config(self.config_path)
            except Exception as exc:
                cause = exc.__cause__
                outcome: dict[str, object] = {
                    "status": "error",
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "cause": (
                        None
                        if cause is None
                        else [type(cause).__name__, str(cause)]
                    ),
                }
            else:
                outcome = {
                    "status": "ok",
                    "keys": list(result),
                    "types": {
                        key: type(value).__name__
                        for key, value in result.items()
                    },
                    "result": {
                        key: str(value) if isinstance(value, Path) else value
                        for key, value in result.items()
                    },
                }
        self.assertEqual(source, before)
        return outcome, trace

    def test_signature_module_boundaries_defaults_order_types_and_io_are_exact(
        self,
    ) -> None:
        signature = inspect.signature(self.config.load_config)
        self.assertEqual(list(signature.parameters), ["path"])
        self.assertIs(
            signature.parameters["path"].default,
            self.config.DEFAULT_CONFIG,
        )
        self.assertEqual(str(signature.return_annotation), "Dict[str, Any]")
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        self.assertNotIn(
            "onion-sentinel-dashboard/ac_hunter_config.py::load_config",
            baseline["functions"],
        )
        self.assertLessEqual(len(ADMISSION_PATH.read_text().splitlines()), 600)
        self.assertNotIn(
            "from ac_hunter_config import",
            ADMISSION_PATH.read_text(),
        )
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text()
        config_copy = (
            'ac_hunter_config.py" "$DASHBOARD_RUNTIME_DIR/ac_hunter_config.py"'
        )
        owner_copy = (
            'ac_hunter_config_admission.py" '
            '"$DASHBOARD_RUNTIME_DIR/ac_hunter_config_admission.py"'
        )
        self.assertIn(config_copy, installer)
        self.assertIn(owner_copy, installer)
        self.assertLess(installer.index(owner_copy), installer.index(config_copy))

        outcome, trace = self.call(self.source())
        self.assertEqual(outcome["status"], "ok")
        self.assertEqual(
            outcome["keys"],
            [
                "schema",
                "enabled",
                "dataset",
                "relay_host",
                "relay_user",
                "relay_port",
                "ssh_key",
                "known_hosts",
                "credentials_file",
                "cache_file",
                "cache_ttl_seconds",
                "connect_timeout_seconds",
                "timeout_seconds",
                "max_response_bytes",
                "max_stderr_bytes",
            ],
        )
        self.assertEqual(
            outcome["types"],
            {
                "schema": "str",
                "enabled": "bool",
                "dataset": "str",
                "relay_host": "str",
                "relay_user": "str",
                "relay_port": "int",
                "ssh_key": "PosixPath",
                "known_hosts": "PosixPath",
                "credentials_file": "PosixPath",
                "cache_file": "PosixPath",
                "cache_ttl_seconds": "int",
                "connect_timeout_seconds": "int",
                "timeout_seconds": "int",
                "max_response_bytes": "int",
                "max_stderr_bytes": "int",
            },
        )
        result = outcome["result"]
        self.assertEqual(result["cache_ttl_seconds"], 300)
        self.assertEqual(result["connect_timeout_seconds"], 8)
        self.assertEqual(result["timeout_seconds"], 45)
        self.assertEqual(result["max_response_bytes"], 8 * 1024 * 1024)
        self.assertEqual(
            result["max_stderr_bytes"], self.config.MAX_RELAY_STDERR_BYTES
        )
        self.assertEqual(
            trace,
            [["private_json", str(self.config_path), self.config.MAX_CONFIG_BYTES]],
        )

    def test_schema_fixed_allowlist_and_error_precedence_are_exact(self) -> None:
        cases = [
            ({**self.source(), "extra": 1, "enabled": "bad"}, "schema is unsupported"),
            (self.source(schema="bad", enabled="bad"), "schema is unsupported"),
            (self.source(enabled=None, dataset="bad"), "enabled must be boolean"),
            (self.source(dataset="bad", relay_host="bad"), "dataset is outside"),
            (self.source(relay_host="bad", relay_user="bad"), "Relay host is outside"),
            (self.source(relay_user="bad", relay_port=80), "Relay user is outside"),
            (self.source(relay_port=True), "Relay port must be an integer"),
            (self.source(relay_port="22"), "Relay port must be an integer"),
            (self.source(relay_port=23), "Relay port must be between 22 and 22"),
        ]
        for source, message in cases:
            with self.subTest(message=message):
                outcome, trace = self.call(source)
                self.assertEqual(outcome["status"], "error")
                self.assertIn(message, outcome["message"])
                self.assertIsNone(outcome["cause"])
                self.assertEqual(trace[0][0], "private_json")

    def test_configured_paths_cache_identity_and_distinctness_are_exact(self) -> None:
        invalid_paths = [None, "", "relative", "x" * 2049, "/tmp/a\x00b", "/tmp/a\rb", "/tmp/a\nb"]
        for value in invalid_paths:
            with self.subTest(value=repr(value)):
                outcome, _trace = self.call(self.source(ssh_key=value))
                self.assertEqual(outcome["status"], "error")
                expected = "must be absolute" if value == "relative" else "is invalid"
                self.assertIn(f"AC Hunter SSH key {expected}", outcome["message"])

        outcome, _trace = self.call(
            self.source(cache_file=str(self.root / "other-cache.json"))
        )
        self.assertIn("cache path is outside", outcome["message"])

        duplicate_cases = [
            self.source(ssh_key=str(self.config_path)),
            self.source(known_hosts=str(self.root / "ssh-key")),
            self.source(
                known_hosts=str(self.root / "subdirectory" / ".." / "ssh-key")
            ),
        ]
        for source in duplicate_cases:
            outcome, _trace = self.call(source)
            self.assertIn("paths must be distinct", outcome["message"])

    def test_numeric_defaults_boundaries_types_and_order_are_exact(self) -> None:
        policies = [
            ("cache_ttl_seconds", 30, 3600),
            ("connect_timeout_seconds", 1, 15),
            ("timeout_seconds", 5, 120),
            ("max_response_bytes", 1024, 8 * 1024 * 1024),
            ("max_stderr_bytes", 1024, self.config.MAX_RELAY_STDERR_BYTES),
        ]
        for key, minimum, maximum in policies:
            for value in (minimum, maximum):
                with self.subTest(key=key, value=value):
                    outcome, _trace = self.call(self.source(**{key: value}))
                    self.assertEqual(outcome["status"], "ok")
                    self.assertEqual(outcome["result"][key], value)
            for value, message in (
                (True, "must be an integer"),
                (str(minimum), "must be an integer"),
                (minimum - 1, "must be between"),
                (maximum + 1, "must be between"),
            ):
                with self.subTest(key=key, value=value):
                    outcome, _trace = self.call(self.source(**{key: value}))
                    self.assertIn(f"AC Hunter {key} {message}", outcome["message"])

        source = self.source(
            cache_ttl_seconds=29,
            connect_timeout_seconds=0,
            timeout_seconds=4,
        )
        outcome, _trace = self.call(source)
        self.assertIn("cache_ttl_seconds", outcome["message"])

    def test_enabled_validation_order_patch_seams_and_failures_are_exact(self) -> None:
        enabled = self.source(enabled=True)
        outcome, trace = self.call(enabled)
        self.assertEqual(outcome["status"], "ok")
        self.assertEqual(
            trace,
            [
                ["private_json", str(self.config_path), self.config.MAX_CONFIG_BYTES],
                [
                    "secure_file",
                    str(self.root / "ssh-key"),
                    {"maximum_bytes": self.config.MAX_KEY_BYTES},
                ],
                [
                    "secure_file",
                    str(self.root / "known-hosts"),
                    {"maximum_bytes": self.config.MAX_KNOWN_HOSTS_BYTES},
                ],
                ["credentials", str(self.root / "credentials.json")],
            ],
        )

        first = self.config.AcHunterConfigurationError("first trust failure")
        outcome, trace = self.call(enabled, secure_effect=first)
        self.assertEqual(outcome["message"], "first trust failure")
        self.assertEqual([item[0] for item in trace], ["private_json", "secure_file"])

        second = self.config.AcHunterConfigurationError("second trust failure")
        outcome, trace = self.call(enabled, secure_effect=[b"ok", second])
        self.assertEqual(outcome["message"], "second trust failure")
        self.assertEqual(
            [item[0] for item in trace],
            ["private_json", "secure_file", "secure_file"],
        )

        credential = self.config.AcHunterConfigurationError("credential failure")
        outcome, trace = self.call(enabled, credentials_effect=credential)
        self.assertEqual(outcome["message"], "credential failure")
        self.assertEqual(
            [item[0] for item in trace],
            ["private_json", "secure_file", "secure_file", "credentials"],
        )


if __name__ == "__main__":
    unittest.main()
