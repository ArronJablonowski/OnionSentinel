"""Transactional schema-governance checks for the Raspberry Pi Relay."""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT / "relay" / "app"


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, APP_DIR / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def schema_objects(connection: sqlite3.Connection) -> list[tuple[str, str, str]]:
    return connection.execute(
        """
        SELECT type, name, COALESCE(sql, '')
        FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        """
    ).fetchall()


class RelayDatabaseSchemaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "relay.sqlite3"
        self.outbox = load_module(
            f"relay_alert_outbox_schema_test_{id(self)}",
            "alert_outbox.py",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _config(self) -> dict:
        return {"relay": {"db_path": str(self.db_path)}}

    def test_legacy_database_is_admitted_without_data_loss(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute(
                """
                CREATE TABLE seen_alerts (
                    alert_id TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL DEFAULT 1
                )
                """
            )
            connection.execute(
                "INSERT INTO seen_alerts VALUES ('seen-1', 'first', 'last', 4)"
            )
            self.outbox.initialize(connection)
            self.outbox.enqueue(connection, [{"alert_id": "queued-1"}])
            self.assertTrue(self.outbox.claim(connection, "queued-1"))

        relay_core = load_module(
            f"relay_core_schema_test_{id(self)}",
            "relay_core.py",
        )
        connection = relay_core.connect_db(self._config())
        try:
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM relay_metadata WHERE key='schema_version'"
                ).fetchone(),
                ("1",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT first_seen, last_seen, seen_count FROM seen_alerts "
                    "WHERE alert_id='seen-1'"
                ).fetchone(),
                ("first", "last", 4),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT status, attempt_count FROM alert_delivery_outbox "
                    "WHERE alert_id='queued-1'"
                ).fetchone(),
                ("pending", 1),
            )
        finally:
            connection.close()

    def test_future_version_is_rejected_before_any_mutation(self) -> None:
        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            connection.execute(
                "CREATE TABLE relay_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "INSERT INTO relay_metadata VALUES ('schema_version', '2')"
            )
            connection.execute("CREATE TABLE sentinel (value TEXT NOT NULL)")
            connection.execute("INSERT INTO sentinel VALUES ('unchanged')")
            before = schema_objects(connection)

        relay_core = load_module(
            f"relay_core_future_schema_test_{id(self)}",
            "relay_core.py",
        )
        try:
            unexpected_connection = relay_core.connect_db(self._config())
        except RuntimeError as exc:
            self.assertRegex(str(exc), "schema version|newer|unsupported")
        else:
            unexpected_connection.close()
            self.fail("future Relay schema version was admitted")

        with closing(sqlite3.connect(self.db_path)) as connection, connection:
            self.assertEqual(schema_objects(connection), before)
            self.assertEqual(
                connection.execute("SELECT value FROM sentinel").fetchone(),
                ("unchanged",),
            )
            self.assertEqual(
                connection.execute(
                    "SELECT value FROM relay_metadata WHERE key='schema_version'"
                ).fetchone(),
                ("2",),
            )

    def test_version_write_failure_rolls_back_schema_and_crash_requeue(self) -> None:
        schema = load_module(
            f"relay_database_schema_test_{id(self)}",
            "relay_database_schema.py",
        )
        connection = sqlite3.connect(self.db_path)
        try:
            self.outbox.initialize(connection)
            self.outbox.enqueue(connection, [{"alert_id": "interrupted-1"}])
            self.assertTrue(self.outbox.claim(connection, "interrupted-1"))
            before = schema_objects(connection)

            def deny_version_write(action, table, _column, _database, _trigger):
                if action == sqlite3.SQLITE_INSERT and table == "relay_metadata":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            connection.set_authorizer(deny_version_write)
            with self.assertRaises(sqlite3.DatabaseError):
                schema.initialize(connection)
            # Python 3.9 does not reliably clear an authorizer with None.
            connection.set_authorizer(lambda *_args: sqlite3.SQLITE_OK)

            self.assertEqual(schema_objects(connection), before)
            self.assertEqual(
                connection.execute(
                    "SELECT status, attempt_count FROM alert_delivery_outbox "
                    "WHERE alert_id='interrupted-1'"
                ).fetchone(),
                ("delivering", 1),
            )
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='relay_metadata'"
                ).fetchone()
            )
        finally:
            connection.close()

    def test_schema_owner_is_registered_for_relay_deployment(self) -> None:
        source = "relay/app/relay_database_schema.py"
        runtime = "/opt/so-alert-relay/app/relay_database_schema.py"
        installer = (ROOT / "relay/bin/install-pi-relay.sh").read_text(
            encoding="utf-8"
        )
        contracts = (ROOT / "operations/quality/modularization-contracts.json").read_text(
            encoding="utf-8"
        )
        schema_install = f'"$REPO_DIR/{source}" {runtime}'
        core_install = (
            '"$REPO_DIR/relay/app/relay_core.py" '
            "/opt/so-alert-relay/app/relay_core.py"
        )
        self.assertIn(schema_install, installer)
        self.assertLess(installer.index(schema_install), installer.index(core_install))
        self.assertIn(f'"path": "{source}"', contracts)
        self.assertIn(f'"runtime_path": "{runtime}"', contracts)


if __name__ == "__main__":
    unittest.main()
