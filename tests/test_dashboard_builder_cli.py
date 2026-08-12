"""Characterization and admission tests for the dashboard builder CLI."""
from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "onion-sentinel-dashboard" / "scripts"
BUILDER_PATH = SCRIPT_DIR / "build_soc_alerts_dashboard.py"
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "dashboard_builder_cli_test",
        BUILDER_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sha256_json(value: object) -> str:
    encoded = json.dumps(
        value,
        default=str,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class DashboardBuilderCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = load_builder()

    def test_facade_namespace_and_main_signature_are_exact(self) -> None:
        names = sorted(
            name for name in dir(self.builder) if not name.startswith("__")
        )
        self.assertEqual(
            (len(names), sha256_json(names)),
            (480, "75c4d9372093624308e6a2e89b821fd7ba7a4d7bee1e3bd5a355ebb8d54324bd"),
        )
        signature = str(inspect.signature(self.builder.main))
        self.assertEqual(
            (signature, hashlib.sha256(signature.encode("utf-8")).hexdigest()),
            (
                "() -> 'int'",
                "02679bd5daed5c118d1b717b87c82a8baa899c19863417657e07e83efbbf34fd",
            ),
        )

    def test_zero_argument_main_forwards_once_and_returns_exact_status(self) -> None:
        with mock.patch.object(
            self.builder._runtime,
            "main",
            return_value=17,
        ) as runtime_main:
            self.assertEqual(self.builder.main(), 17)
        runtime_main.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
