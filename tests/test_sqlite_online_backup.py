"""Exercise online snapshot lock recovery against real SQLite connections."""
import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "n8n/bin/sqlite_online_backup.py"
SPEC = importlib.util.spec_from_file_location("sqlite_online_backup", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class OnlineBackupTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.source = Path(self.directory.name) / "source.sqlite3"
        self.target = Path(self.directory.name) / "snapshot.sqlite3"
        self.writer = sqlite3.connect(self.source, check_same_thread=False)
        self.addCleanup(self.writer.close)
        self.writer.execute("CREATE TABLE items (value TEXT)")
        self.writer.execute("INSERT INTO items VALUES ('before')")
        self.writer.commit()

    def test_recovers_when_exclusive_writer_releases_lock(self):
        self.writer.execute("BEGIN EXCLUSIVE")
        self.writer.execute("INSERT INTO items VALUES ('after')")
        timer = threading.Timer(0.3, self.writer.commit)
        timer.start()
        try:
            MODULE.backup(self.source, self.target, timeout=3)
        finally:
            timer.join()
        reader = sqlite3.connect(self.target)
        try:
            self.assertEqual(reader.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(reader.execute("SELECT count(*) FROM items").fetchone()[0], 2)
        finally:
            reader.close()
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_persistent_contention_has_deadline_and_no_partial_snapshot(self):
        self.writer.execute("BEGIN EXCLUSIVE")
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            MODULE.backup(self.source, self.target, timeout=0.3)
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(self.target.exists())
        self.writer.rollback()

    def test_does_not_overwrite_existing_recovery_artifact(self):
        self.target.write_bytes(b"preserved")
        with self.assertRaises(FileExistsError):
            MODULE.backup(self.source, self.target)
        self.assertEqual(self.target.read_bytes(), b"preserved")

    def test_rejects_source_symlink(self):
        alias = self.source.with_name("alias")
        alias.symlink_to(self.source)
        with self.assertRaises(ValueError):
            MODULE.backup(alias, self.target)

    def test_refuses_self_backup(self):
        with self.assertRaises(ValueError):
            MODULE.backup(self.source, self.source)
