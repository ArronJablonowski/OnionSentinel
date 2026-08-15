#!/usr/bin/env python3
"""ARR-30 contracts for complete, bounded application-log operations."""
from __future__ import annotations

import importlib.util
import plistlib
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_DIR = ROOT / "onion-sentinel-dashboard"
BIN_DIR = ROOT / "n8n" / "bin"
LAUNCHD_DIR = ROOT / "n8n" / "launchd"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


sys.path.insert(0, str(DASHBOARD_DIR))
application_logs = load_module(
    "arr30_application_logs_contract",
    DASHBOARD_DIR / "application_logs.py",
)


class ApplicationLogProductizationTests(unittest.TestCase):
    def test_every_launchagent_output_is_cataloged(self) -> None:
        cataloged = {spec.basename for spec in application_logs.LOG_SPECS}
        expected: set[str] = set()
        for path in LAUNCHD_DIR.glob("*.plist"):
            with path.open("rb") as handle:
                value = plistlib.load(handle)
            expected.add(Path(value["StandardOutPath"]).name)
            expected.add(Path(value["StandardErrorPath"]).name)

        self.assertEqual(expected.difference(cataloged), set())

    def test_every_log_has_an_enforceable_operations_contract(self) -> None:
        expected_fields = {
            "owner",
            "path_class",
            "maximum_size_bytes",
            "compression",
            "disk_pressure",
            "retention_days",
            "maintenance",
        }
        self.assertEqual(
            expected_fields.difference(application_logs.LogSpec.__dataclass_fields__),
            set(),
        )
        for spec in application_logs.LOG_SPECS:
            with self.subTest(log_id=spec.id):
                self.assertTrue(spec.owner)
                self.assertIn(spec.path_class, {"runtime", "analysis-audit"})
                self.assertGreater(spec.maximum_size_bytes, 0)
                self.assertIn(spec.compression, {"none", "gzip"})
                self.assertTrue(spec.disk_pressure)
                self.assertGreater(spec.retention_days, 0)
                self.assertNotIn("unbounded", spec.retention.lower())

    def test_maintenance_entrypoint_launchagent_and_installer_are_owned(self) -> None:
        entrypoint = BIN_DIR / "maintain-application-logs.py"
        owner = BIN_DIR / "application_log_maintenance.py"
        launchagent = LAUNCHD_DIR / "com.arron.onion-sentinel.application-log-maintenance.plist"
        installer = (BIN_DIR / "install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )

        self.assertTrue(entrypoint.is_file())
        self.assertTrue(owner.is_file())
        self.assertTrue(launchagent.is_file())
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/application_log_maintenance.py" '
            '"$STACK_DIR/bin/application_log_maintenance.py"',
            installer,
        )
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/maintain-application-logs.py" '
            '"$STACK_DIR/bin/maintain-application-logs.py"',
            installer,
        )
        self.assertIn(launchagent.name, installer)


if __name__ == "__main__":
    unittest.main()
