from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_contract.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_config_projection_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryConfigProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    @staticmethod
    def config(*, enabled: bool = True) -> dict[str, object]:
        return {
            "enabled": enabled,
            "host": "10.88.8.8",
            "ssh_user": "collector_user",
            "ssh_key": "/synthetic/owner-key",
            "known_hosts": "/synthetic/known-hosts",
            "port": 22,
            "connect_timeout_seconds": 20,
            "timeout_seconds": 120,
            "max_collection_seconds": 900,
            "max_response_bytes": 4 * 1024 * 1024,
            "max_stderr_bytes": 128 * 1024,
            "page_size": 500,
            "max_pages_per_source": 512,
        }

    def test_disabled_config_normalizes_paths_and_preserves_key_order(self) -> None:
        value = self.config(enabled=False)
        value["ssh_key"] = "~/synthetic-owner-key"
        value["known_hosts"] = "~/synthetic-known-hosts"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "software-inventory.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(path, 0o600)

            loaded = self.module.load_config(path)

        self.assertEqual(
            list(loaded),
            [
                "enabled",
                "host",
                "ssh_user",
                "port",
                "connect_timeout_seconds",
                "timeout_seconds",
                "max_collection_seconds",
                "max_response_bytes",
                "max_stderr_bytes",
                "page_size",
                "max_pages_per_source",
                "ssh_key",
                "known_hosts",
            ],
        )
        self.assertEqual(loaded["ssh_key"], str(Path.home() / "synthetic-owner-key"))
        self.assertEqual(loaded["known_hosts"], str(Path.home() / "synthetic-known-hosts"))
        self.assertEqual(value["ssh_key"], "~/synthetic-owner-key")
        self.assertEqual(value["known_hosts"], "~/synthetic-known-hosts")

    def test_normalization_and_owner_file_call_order_is_exact(self) -> None:
        value = self.config()
        path = Path("synthetic-config.json")
        calls: list[tuple[object, ...]] = []
        bounded_text = self.module._bounded_text
        bounded_integer = self.module._bounded_integer

        def read_json(*args, **kwargs):
            calls.append(("read_json", args, kwargs))
            return value

        def normalize_text(*args, **kwargs):
            calls.append(("text", args, kwargs))
            return bounded_text(*args, **kwargs)

        def normalize_integer(*args, **kwargs):
            calls.append(("integer", args, kwargs))
            return bounded_integer(*args, **kwargs)

        def owner_file(*args, **kwargs):
            calls.append(("owner_file", args, kwargs))
            return mock.sentinel.stat_result

        with (
            mock.patch.object(self.module, "_read_json_file", side_effect=read_json),
            mock.patch.object(self.module, "_bounded_text", side_effect=normalize_text),
            mock.patch.object(self.module, "_bounded_integer", side_effect=normalize_integer),
            mock.patch.object(self.module, "_owner_file", side_effect=owner_file),
        ):
            loaded = self.module.load_config(path)

        self.assertEqual(loaded, value)
        self.assertEqual(
            calls,
            [
                ("read_json", (path, self.module.MAX_CONFIG_BYTES), {"exact_mode": 0o600}),
                ("text", ("10.88.8.8",), {"field": "software inventory host", "maximum": 255, "required": True}),
                ("text", ("collector_user",), {"field": "software inventory SSH user", "maximum": 64, "required": True}),
                ("integer", (22,), {"field": "software inventory config port", "minimum": 1, "maximum": 65535}),
                ("integer", (20,), {"field": "software inventory config connect_timeout_seconds", "minimum": 1, "maximum": 60}),
                ("integer", (120,), {"field": "software inventory config timeout_seconds", "minimum": 5, "maximum": 300}),
                ("integer", (900,), {"field": "software inventory config max_collection_seconds", "minimum": 30, "maximum": 1800}),
                ("integer", (4 * 1024 * 1024,), {"field": "software inventory config max_response_bytes", "minimum": 1024, "maximum": self.module.MAX_RESPONSE_BYTES}),
                ("integer", (128 * 1024,), {"field": "software inventory config max_stderr_bytes", "minimum": 1024, "maximum": self.module.MAX_STDERR_BYTES}),
                ("integer", (500,), {"field": "software inventory config page_size", "minimum": 1, "maximum": self.module.MAX_PAGE_SIZE}),
                ("integer", (512,), {"field": "software inventory config max_pages_per_source", "minimum": 1, "maximum": self.module.MAX_PAGES_PER_SOURCE}),
                ("text", ("/synthetic/owner-key",), {"field": "software inventory ssh_key", "maximum": 1024, "required": True}),
                ("text", ("/synthetic/known-hosts",), {"field": "software inventory known_hosts", "maximum": 1024, "required": True}),
                ("owner_file", (Path("/synthetic/owner-key"),), {"maximum_bytes": 1024 * 1024, "exact_mode": 0o600}),
                ("owner_file", (Path("/synthetic/known-hosts"),), {"maximum_bytes": 1024 * 1024}),
            ],
        )

    def test_schema_enabled_and_endpoint_error_precedence_is_exact(self) -> None:
        cases = []
        missing = self.config()
        missing.pop("port")
        cases.append((missing, "software inventory config contains unsupported or missing fields"))
        wrong_enabled = self.config()
        wrong_enabled["enabled"] = 1
        cases.append((wrong_enabled, "software inventory config enabled must be boolean"))
        wrong_host_type = self.config()
        wrong_host_type["host"] = None
        cases.append((wrong_host_type, "software inventory host must be a string"))
        wrong_user = self.config()
        wrong_user["ssh_user"] = " collector"
        cases.append((wrong_user, "software inventory SSH user is invalid"))
        wrong_endpoint = self.config()
        wrong_endpoint["host"] = "invalid host"
        cases.append((wrong_endpoint, "software inventory SSH endpoint is invalid"))

        for value, message in cases:
            with self.subTest(message=message):
                with mock.patch.object(self.module, "_read_json_file", return_value=value):
                    with self.assertRaisesRegex(ValueError, f"^{message}$"):
                        self.module.load_config(Path("synthetic-config.json"))

    def test_numeric_limits_and_validation_order_are_exact(self) -> None:
        cases = [
            ("port", True, "software inventory config port must be an integer"),
            ("connect_timeout_seconds", 0, "software inventory config connect_timeout_seconds must be from 1 through 60"),
            ("timeout_seconds", 301, "software inventory config timeout_seconds must be from 5 through 300"),
            ("max_collection_seconds", 29, "software inventory config max_collection_seconds must be from 30 through 1800"),
            ("max_response_bytes", 1023, "software inventory config max_response_bytes must be from 1024 through 4194304"),
            ("max_stderr_bytes", 131073, "software inventory config max_stderr_bytes must be from 1024 through 131072"),
            ("page_size", 501, "software inventory config page_size must be from 1 through 500"),
            ("max_pages_per_source", 513, "software inventory config max_pages_per_source must be from 1 through 512"),
        ]
        for key, invalid, message in cases:
            with self.subTest(key=key):
                value = self.config()
                value[key] = invalid
                with mock.patch.object(self.module, "_read_json_file", return_value=value):
                    with self.assertRaisesRegex(ValueError, f"^{message}$"):
                        self.module.load_config(Path("synthetic-config.json"))

    def test_paths_validate_after_all_numeric_fields_and_before_owner_files(self) -> None:
        value = self.config()
        value["ssh_key"] = None
        with (
            mock.patch.object(self.module, "_read_json_file", return_value=value),
            mock.patch.object(self.module, "_owner_file") as owner_file,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "^software inventory ssh_key must be a string$",
            ):
                self.module.load_config(Path("synthetic-config.json"))
        owner_file.assert_not_called()

    def test_disabled_config_skips_both_owner_file_checks(self) -> None:
        value = self.config(enabled=False)
        with (
            mock.patch.object(self.module, "_read_json_file", return_value=value),
            mock.patch.object(self.module, "_owner_file") as owner_file,
        ):
            loaded = self.module.load_config(Path("synthetic-config.json"))
        self.assertFalse(loaded["enabled"])
        owner_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
