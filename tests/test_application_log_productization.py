#!/usr/bin/env python3
"""ARR-30 contracts for complete, bounded application-log operations."""
from __future__ import annotations

import importlib.util
import dataclasses
import datetime as dt
import gzip
import json
import os
import plistlib
from pathlib import Path
import subprocess
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
application_log_maintenance = load_module(
    "arr30_application_log_maintenance",
    BIN_DIR / "application_log_maintenance.py",
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

    def test_every_structured_runtime_log_producer_is_cataloged(self) -> None:
        cataloged = {spec.basename for spec in application_logs.LOG_SPECS}
        producers = {
            "onion-sentinel-application.jsonl": ROOT / "onion-sentinel-dashboard" / "onion_sentinel_server.py",
            "alert-store-application.jsonl": ROOT / "n8n" / "alert_store" / "lib" / "runtime_configuration.js",
            "investigation-harness.jsonl": BIN_DIR / "harness_policy_primitives.py",
            "software-inventory.jsonl": BIN_DIR / "software_inventory_contract.py",
            "endpoint-software-inventory.jsonl": BIN_DIR / "collect-endpoint-software-inventory.py",
            "dhcp-asset-discovery.jsonl": BIN_DIR / "collect-dhcp-asset-discovery.py",
            "dhcp-asset-review.jsonl": BIN_DIR / "promote-dhcp-asset.py",
            "security-onion-query.jsonl": BIN_DIR / "query-security-onion.py",
            "operational-slo-history.jsonl": BIN_DIR / "operational_slo_state.py",
            "llm-analysis-log.jsonl": BIN_DIR / "local_ai_runtime_contract.py",
        }
        for basename, source in producers.items():
            with self.subTest(basename=basename):
                self.assertTrue(source.is_file())
                self.assertIn(basename, source.read_text(encoding="utf-8"))
                self.assertIn(basename, cataloged)

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

    def test_timestamped_ensure_logs_have_size_and_age_enforcement(self) -> None:
        source = (BIN_DIR / "ensure-n8n-stack.zsh").read_text(encoding="utf-8")
        self.assertIn("MAX_LOG_BYTES=10485760", source)
        self.assertIn("trap finalize_log EXIT", source)
        self.assertIn('/usr/bin/tail -c "$MAX_LOG_BYTES"', source)
        self.assertIn("-mtime +30 -delete", source)


class ApplicationLogMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.temporary = tempfile.TemporaryDirectory()
        self.stack_dir = Path(self.temporary.name) / "n8n-local"
        self.runtime = self.stack_dir / "logs"
        self.analysis = self.stack_dir / "soc-alerts" / "llm-analysis-logs"
        self.run = self.stack_dir / "run"
        for path in (self.stack_dir, self.runtime, self.analysis, self.run):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
        source = application_logs.LOG_SPECS_BY_ID["launchd-monitor-stack-out"]
        self.spec = dataclasses.replace(
            source,
            maximum_size_bytes=64,
            backups=3,
            retention_days=7,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_log(self, content: bytes) -> Path:
        path = self.runtime / self.spec.basename
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def write_archive(self, generation: int, content: bytes, *, age_days: int = 0) -> Path:
        path = self.runtime / f"{self.spec.basename}.{generation}.gz"
        with path.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as handle:
                handle.write(content)
        path.chmod(0o600)
        when = dt.datetime.now(dt.timezone.utc).timestamp() - age_days * 86400
        os.utime(path, (when, when))
        return path

    def test_rotation_compresses_a_bounded_suffix_and_copy_truncates_current(self) -> None:
        original = bytes(range(100))
        current = self.write_log(original)

        result = application_log_maintenance.rotate_spec(
            self.runtime,
            self.spec,
            apply=True,
        )

        archive = self.runtime / f"{self.spec.basename}.1.gz"
        self.assertTrue(result["rotated"])
        self.assertEqual(result["source_bytes"], 100)
        self.assertEqual(result["archived_bytes"], 64)
        self.assertTrue(result["archive_truncated"])
        self.assertEqual(current.read_bytes(), b"")
        self.assertEqual(gzip.decompress(archive.read_bytes()), original[-64:])
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)

    def test_preview_and_within_limit_do_not_mutate_files(self) -> None:
        current = self.write_log(b"x" * 65)
        preview = application_log_maintenance.rotate_spec(
            self.runtime,
            self.spec,
            apply=False,
        )
        self.assertEqual(preview["status"], "rotation_required")
        self.assertEqual(current.read_bytes(), b"x" * 65)
        self.assertFalse((self.runtime / f"{self.spec.basename}.1.gz").exists())

        current.write_bytes(b"within-limit")
        result = application_log_maintenance.rotate_spec(
            self.runtime,
            self.spec,
            apply=True,
        )
        self.assertEqual(result["status"], "within_limit")
        self.assertEqual(current.read_bytes(), b"within-limit")

    def test_apply_hardens_owner_readable_current_file_without_rotating(self) -> None:
        current = self.write_log(b"small")
        current.chmod(0o644)
        preview = application_log_maintenance.rotate_spec(
            self.runtime,
            self.spec,
            apply=False,
        )
        self.assertEqual(preview["status"], "permission_hardening_required")
        self.assertEqual(current.stat().st_mode & 0o777, 0o644)

        applied = application_log_maintenance.rotate_spec(
            self.runtime,
            self.spec,
            apply=True,
        )
        self.assertEqual(applied["status"], "permissions_hardened")
        self.assertTrue(applied["permission_hardened"])
        self.assertEqual(current.stat().st_mode & 0o777, 0o600)

    def test_rotation_shifts_only_fixed_owner_controlled_archives(self) -> None:
        first = self.write_archive(1, b"first")
        self.write_log(b"second" * 20)

        application_log_maintenance.rotate_spec(self.runtime, self.spec, apply=True)

        shifted = self.runtime / f"{self.spec.basename}.2.gz"
        self.assertTrue(first.exists())
        self.assertEqual(gzip.decompress(shifted.read_bytes()), b"first")
        self.assertEqual(
            gzip.decompress(
                (self.runtime / f"{self.spec.basename}.1.gz").read_bytes()
            ),
            (b"second" * 20)[-64:],
        )

    def test_cleanup_expires_archives_and_prunes_oldest_first_under_pressure(self) -> None:
        first = self.write_archive(1, b"newest")
        second = self.write_archive(2, b"middle")
        third = self.write_archive(3, b"expired", age_days=8)
        now = dt.datetime.now(dt.timezone.utc)

        preview = application_log_maintenance.cleanup_spec(
            self.runtime,
            self.spec,
            now=now,
            apply=False,
            disk_pressure=True,
        )
        self.assertEqual(preview["removed_generations"], [3, 2])
        self.assertTrue(first.exists() and second.exists() and third.exists())

        applied = application_log_maintenance.cleanup_spec(
            self.runtime,
            self.spec,
            now=now,
            apply=True,
            disk_pressure=True,
        )
        self.assertEqual(applied["removed_generations"], [3, 2])
        self.assertTrue(first.exists())
        self.assertFalse(second.exists())
        self.assertFalse(third.exists())

    def test_symlink_and_unsafe_modes_fail_closed_without_touching_target(self) -> None:
        outside = Path(self.temporary.name) / "outside.log"
        outside.write_bytes(b"outside")
        (self.runtime / self.spec.basename).symlink_to(outside)
        with self.assertRaisesRegex(
            application_log_maintenance.ApplicationLogMaintenanceError,
            "opened safely",
        ):
            application_log_maintenance.rotate_spec(self.runtime, self.spec, apply=True)
        self.assertEqual(outside.read_bytes(), b"outside")

        (self.runtime / self.spec.basename).unlink()
        current = self.write_log(b"unsafe" * 20)
        current.chmod(0o620)
        with self.assertRaisesRegex(
            application_log_maintenance.ApplicationLogMaintenanceError,
            "security validation",
        ):
            application_log_maintenance.rotate_spec(self.runtime, self.spec, apply=True)
        self.assertEqual(current.read_bytes(), b"unsafe" * 20)

    def test_unsafe_archive_blocks_rotation_before_any_generation_moves(self) -> None:
        current = self.write_log(b"current" * 20)
        safe = self.write_archive(1, b"safe")
        outside = Path(self.temporary.name) / "outside.gz"
        outside.write_bytes(gzip.compress(b"outside"))
        unsafe = self.runtime / f"{self.spec.basename}.2.gz"
        unsafe.symlink_to(outside)

        with self.assertRaisesRegex(
            application_log_maintenance.ApplicationLogMaintenanceError,
            "security validation",
        ):
            application_log_maintenance.rotate_spec(self.runtime, self.spec, apply=True)

        self.assertEqual(current.read_bytes(), b"current" * 20)
        self.assertEqual(gzip.decompress(safe.read_bytes()), b"safe")
        self.assertTrue(unsafe.is_symlink())
        self.assertEqual(gzip.decompress(outside.read_bytes()), b"outside")

    def test_maintenance_report_is_content_free_and_disk_pressure_bounded(self) -> None:
        secret = b"token=must-not-escape" * 10
        self.write_log(secret)
        report = application_log_maintenance.maintain_logs(
            self.stack_dir,
            apply=False,
            used_percent=90.0,
        )
        serialized = json.dumps(report, sort_keys=True)
        self.assertTrue(report["disk_pressure"])
        self.assertNotIn("must-not-escape", serialized)
        self.assertNotIn(str(self.runtime), serialized)

    def test_cli_applies_fixed_policy_in_an_isolated_stack(self) -> None:
        current = self.runtime / self.spec.basename
        current.touch(mode=0o600)
        current.chmod(0o600)
        with current.open("r+b") as handle:
            handle.truncate(application_logs.DEFAULT_ROTATION_BYTES + 1)

        result = subprocess.run(
            [
                sys.executable,
                str(BIN_DIR / "maintain-application-logs.py"),
                "--stack-dir",
                str(self.stack_dir),
                "--apply",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["rotation_count"], 1)
        self.assertEqual(current.stat().st_size, 0)
        archive = self.runtime / f"{self.spec.basename}.1.gz"
        self.assertTrue(archive.is_file())
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
