"""Behavior contracts for Hermes backup health and inventory policy."""
from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

import portal_hermes_backup_health as backup_health  # noqa: E402
from portal_hermes_backup_health import (  # noqa: E402
    HermesBackupSources,
    backup_base_path,
    backup_timestamp_from_name,
    compose_backup_inventory,
    compose_latest_hermes_backup_metric,
)


class HermesBackupHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.backup_dir = Path(self.temp.name)
        self.redacted_values = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def sources(self) -> HermesBackupSources:
        def redact(value: str) -> str:
            self.redacted_values.append(value)
            return value.replace("secret-value", "[REDACTED]")

        return HermesBackupSources(
            backup_dir=self.backup_dir,
            remote_dest="backup@example",
            remote_directory="/backups/hermes",
            format_timestamp=lambda value: value.isoformat(),
            human_size=lambda value: f"{value} bytes",
            relative_time_label=lambda _timestamp: "two hours ago",
            redact_text=redact,
        )

    def create_set(
        self, stamp: str, *, encrypted: bool = False, size: int = 7
    ) -> Path:
        suffix = ".tar.zst.enc" if encrypted else ".tar.zst"
        archive = self.backup_dir / f"macstudio-hermes-dr_{stamp}{suffix}"
        archive.write_bytes(b"x" * size)
        archive.with_suffix(archive.suffix + ".sha256").write_text("checksum")
        Path(str(backup_base_path(archive)) + ".RESTORE.txt").write_text("restore")
        return archive

    def write_log(self, text: str) -> None:
        (self.backup_dir / "backup-cron.log").write_text(text)

    def test_complete_logged_set_is_selected_and_inventory_is_newest_first(self) -> None:
        older = self.create_set("20260801_010203Z")
        newer = self.create_set("20260802_040506Z", encrypted=True, size=11)
        self.write_log(
            f"Archive: {older}\nArchive: {newer}\nsecret-value\n"
            "[2026-08-02T04:05:00Z] Scheduled backup complete.\n"
        )

        value, detail, warning = compose_latest_hermes_backup_metric(self.sources())
        rows, metadata = compose_backup_inventory(self.sources())

        self.assertEqual(value, "two hours ago")
        self.assertFalse(warning)
        self.assertIn(newer.name, detail)
        self.assertIn("11 bytes", detail)
        self.assertEqual([row["archive"] for row in rows], [newer, older])
        self.assertTrue(all(row["ok"] for row in rows))
        self.assertEqual(metadata["successful"], 2)
        self.assertEqual(metadata["rating_percent"], 100.0)
        self.assertEqual(metadata["remote_location"], "backup@example:/backups/hermes")
        self.assertIn("[REDACTED]", metadata["log_tail"])
        self.assertTrue(self.redacted_values)

    def test_missing_companions_empty_archive_and_log_mismatch_are_reported(self) -> None:
        archive = self.backup_dir / "macstudio-hermes-dr_20260803_000000Z.tar.zst"
        archive.touch()
        other = self.backup_dir / "macstudio-hermes-dr_20260802_000000Z.tar.zst"
        self.write_log(f"Archive: {other}\n")

        value, detail, warning = compose_latest_hermes_backup_metric(self.sources())
        rows, metadata = compose_backup_inventory(self.sources())

        self.assertEqual(value, "⚠ None")
        self.assertTrue(warning)
        for expected in ("checksum", "restore notes", "non-empty archive", "success log entry"):
            self.assertIn(expected, detail)
            self.assertIn(expected, rows[0]["missing"])
        self.assertEqual(metadata["successful"], 0)
        self.assertEqual(metadata["rating_percent"], 0.0)

    def test_newer_incomplete_artifact_warns_but_preserves_last_success(self) -> None:
        complete = self.create_set("20260803_000000Z")
        incomplete = self.backup_dir / "macstudio-hermes-dr_20260804_000000Z.tar.zst"
        incomplete.write_bytes(b"partial")
        self.write_log(f"Archive: {complete}\n")

        value, detail, warning = compose_latest_hermes_backup_metric(self.sources())

        self.assertEqual(value, "⚠ two hours ago")
        self.assertTrue(warning)
        self.assertIn(complete.name, detail)
        self.assertIn(incomplete.name, detail)
        self.assertIn("Newer backup artifact is incomplete", detail)

    def test_failed_non_dry_scheduled_attempt_warns_while_dry_run_is_ignored(self) -> None:
        archive = self.create_set("20260803_000000Z")
        self.write_log(
            f"Archive: {archive}\n"
            "[2026-08-04T00:00:00Z] Scheduled backup start: dry_run=1\n"
            "[2026-08-05T00:00:00Z] Scheduled backup start: dry_run=0\n"
        )

        value, detail, warning = compose_latest_hermes_backup_metric(self.sources())

        self.assertEqual(value, "⚠ two hours ago")
        self.assertTrue(warning)
        expected_start = dt.datetime(
            2026, 8, 5, tzinfo=dt.timezone.utc
        ).astimezone().isoformat()
        self.assertIn(expected_start, detail)
        self.assertIn("did not log a successful completion", detail)

        self.write_log(
            f"Archive: {archive}\n"
            "[2026-08-05T00:00:00Z] Scheduled backup start: dry_run=0\n"
            "[2026-08-05T01:00:00Z] Scheduled backup complete.\n"
        )
        value, _detail, warning = compose_latest_hermes_backup_metric(self.sources())
        self.assertEqual(value, "two hours ago")
        self.assertFalse(warning)

    def test_missing_log_retains_legacy_set_validation_and_surfaces_warning(self) -> None:
        archive = self.create_set("20260803_000000Z")

        value, detail, warning = compose_latest_hermes_backup_metric(self.sources())
        rows, metadata = compose_backup_inventory(self.sources())

        self.assertEqual(value, "⚠ two hours ago")
        self.assertTrue(warning)
        self.assertIn("Could not read backup log", detail)
        self.assertTrue(rows[0]["ok"])
        self.assertEqual(metadata["log_tail"], "")
        self.assertEqual(metadata["log_file"], self.backup_dir / "backup-cron.log")
        self.assertIn(archive.name, detail)

    def test_malformed_scheduled_timestamp_is_bounded_to_log_warning(self) -> None:
        archive = self.create_set("20260803_000000Z")
        self.write_log(
            f"Archive: {archive}\n"
            "[2026-99-03T00:00:00Z] Scheduled backup start: dry_run=0\n"
        )

        value, detail, warning = compose_latest_hermes_backup_metric(self.sources())

        self.assertEqual(value, "⚠ two hours ago")
        self.assertTrue(warning)
        self.assertIn("Could not parse backup log", detail)

    def test_timestamp_parser_falls_back_to_mtime_for_nonstandard_name(self) -> None:
        archive = self.backup_dir / "macstudio-hermes-dr_manual.tar.zst"
        archive.write_bytes(b"data")
        expected = 1_788_000_000
        os.utime(archive, (expected, expected))

        parsed = backup_timestamp_from_name(archive)

        self.assertEqual(parsed, dt.datetime.fromtimestamp(expected, dt.timezone.utc))

    def test_latest_metric_projection_and_callback_trace_are_exact(self) -> None:
        callbacks = []
        sources = HermesBackupSources(
            backup_dir=Path("/synthetic/hermes-backups"),
            remote_dest="unused",
            remote_directory="unused",
            format_timestamp=lambda value: callbacks.append(("format", value)) or "STAMP",
            human_size=lambda value: callbacks.append(("size", value)) or "13 bytes",
            relative_time_label=lambda value: callbacks.append(("relative", value)) or "recently",
            redact_text=lambda value: value,
        )
        incomplete = [
            {
                "archive": Path(f"failed-{index}.tar.zst"),
                "created": dt.datetime(2026, 8, index + 1, tzinfo=dt.timezone.utc),
                "size": 0,
                "ok": False,
                "missing": [f"part-{index}"],
            }
            for index in range(4)
        ]
        unreadable_log = backup_health._BackupLog(
            "", frozenset(), (), (), "bounded log warning"
        )
        with mock.patch.object(
            backup_health, "_catalog", return_value=(incomplete, unreadable_log)
        ):
            self.assertEqual(
                compose_latest_hermes_backup_metric(sources),
                (
                    "⚠ None",
                    "WARNING: No successful full Hermes backup sets found in "
                    "/synthetic/hermes-backups · Incomplete artifacts: "
                    "failed-1.tar.zst missing part-1; failed-2.tar.zst missing part-2; "
                    "failed-3.tar.zst missing part-3 · bounded log warning",
                    True,
                ),
            )
        self.assertEqual(callbacks, [])

        successful = {
            "archive": Path("macstudio-hermes-dr_20260803_000000Z.tar.zst"),
            "created": dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
            "size": 13,
            "ok": True,
            "missing": [],
        }
        rows = [successful, incomplete[-1]]
        with (
            mock.patch.object(
                backup_health, "_catalog", return_value=(rows, unreadable_log)
            ),
            mock.patch.object(
                backup_health,
                "backup_timestamp_from_name",
                return_value=dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc),
            ),
            mock.patch.object(
                backup_health, "_attempt_warning", return_value="attempt warning"
            ),
        ):
            self.assertEqual(
                compose_latest_hermes_backup_metric(sources),
                (
                    "⚠ recently",
                    "WARNING: Newer backup artifact is incomplete/not confirmed successful: "
                    "failed-3.tar.zst missing part-3 | attempt warning | bounded log warning · "
                    "Latest successful full Hermes backup: "
                    "macstudio-hermes-dr_20260803_000000Z.tar.zst · STAMP · 13 bytes · "
                    "success confirmed by backup-cron.log",
                    True,
                ),
            )
        self.assertEqual(
            callbacks,
            [
                ("relative", successful["created"].timestamp()),
                ("format", successful["created"].astimezone()),
                ("size", 13),
            ],
        )


if __name__ == "__main__":
    unittest.main()
