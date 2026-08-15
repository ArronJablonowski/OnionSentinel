"""Characterization for the runtime SQLite backup and restore phases."""
from __future__ import annotations

from contextlib import closing
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BACKUP_PATH = ROOT / "n8n" / "bin" / "backup-onion-sentinel-runtime.py"


def load_backup_module():
    spec = importlib.util.spec_from_file_location(
        "runtime_backup_sqlite_phases",
        BACKUP_PATH,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


backup = load_backup_module()


class RuntimeBackupSqlitePhaseTests(unittest.TestCase):
    def test_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(backup) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (32, "09a2126219933bd4c09294e9af9504d800ae14702de6276a0e2f9bc24dea3565"),
        )
        self.assertEqual(
            str(inspect.signature(backup.backup_sqlite_database)),
            (
                "(source: 'Path', destination: 'Path', *, "
                "required_tables: 'tuple[str, ...]', count_table: 'str') "
                "-> 'dict[str, object]'"
            ),
        )

    def test_wal_snapshot_is_self_contained_and_restore_result_is_exact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.sqlite3"
            destination = root / "backup.sqlite3"
            with closing(sqlite3.connect(source)) as writer:
                self.assertEqual(
                    writer.execute("PRAGMA journal_mode = WAL").fetchone()[0],
                    "wal",
                )
                with writer:
                    writer.execute(
                        "CREATE TABLE items (id INTEGER PRIMARY KEY)"
                    )
                    writer.execute(
                        "CREATE TABLE children (item_id INTEGER "
                        "REFERENCES items(id))"
                    )
                    writer.executemany(
                        "INSERT INTO items VALUES (?)",
                        ((1,), (2,)),
                    )
                    writer.execute("INSERT INTO children VALUES (1)")
                self.assertTrue(Path(f"{source}-wal").is_file())

                result = backup.backup_sqlite_database(
                    source,
                    destination,
                    required_tables=("items", "children"),
                    count_table="items",
                )

            self.assertEqual(
                result,
                {
                    "rows": 2,
                    "quick_check": "ok",
                    "journal_mode": "delete",
                    "foreign_key_check_rows": 0,
                    "restore_drill": {
                        "quick_check": "ok",
                        "foreign_key_check_rows": 0,
                        "rows": 2,
                    },
                },
            )
            self.assertFalse(Path(f"{destination}-wal").exists())
            self.assertFalse(Path(f"{destination}-shm").exists())
            with closing(sqlite3.connect(destination)) as verified:
                self.assertEqual(
                    verified.execute("PRAGMA journal_mode").fetchone()[0],
                    "delete",
                )
                self.assertEqual(
                    verified.execute("SELECT COUNT(*) FROM items").fetchone()[0],
                    2,
                )

    def test_symlink_source_is_rejected_before_destination_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_source = root / "real.sqlite3"
            source = root / "source.sqlite3"
            destination = root / "backup.sqlite3"
            real_source.write_bytes(b"not opened")
            source.symlink_to(real_source)

            with self.assertRaisesRegex(
                RuntimeError,
                "SQLite source is not a regular file",
            ):
                backup.backup_sqlite_database(
                    source,
                    destination,
                    required_tables=("items",),
                    count_table="items",
                )

            self.assertFalse(destination.exists())

    def test_missing_required_table_retains_exact_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.sqlite3"
            destination = root / "backup.sqlite3"
            with closing(sqlite3.connect(source)) as connection:
                with connection:
                    connection.execute("CREATE TABLE items (id INTEGER)")

            with self.assertRaisesRegex(
                RuntimeError,
                r"SQLite backup is missing required table\(s\): children",
            ):
                backup.backup_sqlite_database(
                    source,
                    destination,
                    required_tables=("items", "children"),
                    count_table="items",
                )

    def test_persisted_foreign_key_failure_retains_exact_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.sqlite3"
            destination = root / "backup.sqlite3"
            with closing(sqlite3.connect(source)) as connection:
                with connection:
                    connection.execute(
                        "CREATE TABLE parents (id INTEGER PRIMARY KEY)"
                    )
                    connection.execute(
                        "CREATE TABLE children (parent_id INTEGER "
                        "REFERENCES parents(id))"
                    )
                    connection.execute("INSERT INTO children VALUES (404)")

            with self.assertRaisesRegex(
                RuntimeError,
                r"SQLite backup failed foreign_key_check: 1 row\(s\)",
            ):
                backup.backup_sqlite_database(
                    source,
                    destination,
                    required_tables=("parents", "children"),
                    count_table="children",
                )


if __name__ == "__main__":
    unittest.main()
