import importlib.util
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "onion-sentinel-dashboard" / "scripts" / "dashboard_pcap_request_index.py"
SPEC = importlib.util.spec_from_file_location("dashboard_pcap_request_index", MODULE)
assert SPEC and SPEC.loader
INDEX = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INDEX)


SCHEMA = """
CREATE TABLE pcap_requests (
  request_id TEXT PRIMARY KEY,
  group_id TEXT,
  alert_id TEXT,
  status TEXT,
  error TEXT,
  request_json TEXT,
  completed_at TEXT,
  updated_at TEXT,
  created_at TEXT
)
"""


class DashboardPcapRequestIndexTests(unittest.TestCase):
    def test_table_probe_short_circuits_before_schema_and_row_factory(self):
        trace = []

        class Missing:
            def __bool__(self):
                trace.append(("exists_bool",))
                return False

        class Cursor:
            def fetchone(self):
                trace.append(("fetchone",))
                return Missing()

        class Connection:
            def execute(self, query):
                trace.append(("execute", query))
                return Cursor()

        def empty_index():
            trace.append(("empty_index",))
            return {"fresh": {}}

        with mock.patch.object(INDEX, "_empty_index", side_effect=empty_index):
            result = INDEX.build_pcap_request_index(Connection())

        self.assertEqual(result, {"fresh": {}})
        self.assertEqual(
            trace,
            [
                (
                    "execute",
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pcap_requests'",
                ),
                ("fetchone",),
                ("exists_bool",),
                ("empty_index",),
            ],
        )

    def test_query_and_newest_index_projection_preserve_operation_order(self):
        trace = []
        expected_query = """
        SELECT request_id, group_id, alert_id,
               status, '' AS outcome, error,
               request_json,
               completed_at, updated_at, created_at
        FROM pcap_requests
        ORDER BY COALESCE(completed_at, updated_at, created_at) DESC, request_id DESC
        """

        class ColumnName:
            def __init__(self, value):
                self.value = value

            def __str__(self):
                trace.append(("column_str", self.value))
                return self.value

        class ColumnRow:
            def __init__(self, value):
                self.value = value

            def __getitem__(self, key):
                trace.append(("column_getitem", self.value, key))
                return ColumnName(self.value)

        class Value:
            def __init__(self, label, value):
                self.label = label
                self.value = value

            def __bool__(self):
                trace.append(("value_bool", self.label))
                return bool(self.value)

            def __str__(self):
                trace.append(("value_str", self.label))
                return self.value

        class Row:
            def __init__(self, label, group_id, alert_id):
                self.label = label
                self.values = {"group_id": group_id, "alert_id": alert_id}

            def __getitem__(self, key):
                trace.append(("row_getitem", self.label, key))
                return self.values[key]

        rows = [
            Row("new", Value("new_group", " group-a "), Value("new_alert", "alert-a")),
            Row("old", Value("old_group", "group-a"), Value("old_alert", " alert-b ")),
        ]
        columns = [
            "request_id",
            "group_id",
            "alert_id",
            "status",
            "error",
            "request_json",
            "completed_at",
            "updated_at",
            "created_at",
        ]

        class ProbeCursor:
            def __init__(self, label, values):
                self.label = label
                self.values = values

            def fetchone(self):
                trace.append(("fetchone", self.label))
                return (1,)

            def __iter__(self):
                trace.append(("iter", self.label))
                return iter(self.values)

            def fetchall(self):
                trace.append(("fetchall", self.label))
                return self.values

        class Connection:
            def __init__(self):
                self._row_factory = None

            @property
            def row_factory(self):
                return self._row_factory

            @row_factory.setter
            def row_factory(self, value):
                trace.append(("row_factory", value))
                self._row_factory = value

            def execute(self, query):
                trace.append(("execute", query))
                if query.startswith("SELECT 1"):
                    return ProbeCursor("exists", [])
                if query == "PRAGMA table_info(pcap_requests)":
                    return ProbeCursor("columns", [ColumnRow(name) for name in columns])
                self.assert_query(query)
                return ProbeCursor("rows", rows)

            def assert_query(self, query):
                if query != expected_query:
                    raise AssertionError(query)

        class Record(dict):
            def __init__(self, label):
                super().__init__(request_id=label)
                self.label = label

            def __getitem__(self, key):
                trace.append(("record_getitem", self.label, key))
                return super().__getitem__(key)

        class Bucket(dict):
            def __init__(self, label):
                super().__init__()
                self.label = label

            def setdefault(self, key, value):
                trace.append(("setdefault", self.label, key, value.label))
                return super().setdefault(key, value)

        def empty_index():
            trace.append(("empty_index",))
            return {
                "requests_by_group_id": Bucket("group"),
                "requests_by_alert_id": Bucket("alert"),
                "requests_by_request_id": Bucket("request"),
            }

        def record_from_row(row):
            trace.append(("record_from_row", row.label))
            return Record(row.label)

        with (
            mock.patch.object(INDEX, "_empty_index", side_effect=empty_index),
            mock.patch.object(INDEX, "_record_from_row", side_effect=record_from_row),
        ):
            result = INDEX.build_pcap_request_index(Connection())

        self.assertEqual(result["requests_by_group_id"]["group-a"].label, "new")
        self.assertEqual(result["requests_by_alert_id"]["alert-a"].label, "new")
        self.assertEqual(result["requests_by_alert_id"]["alert-b"].label, "old")
        self.assertEqual(result["requests_by_request_id"]["new"].label, "new")
        self.assertEqual(result["requests_by_request_id"]["old"].label, "old")
        self.assertEqual(
            [event for event in trace if event[0] in {"execute", "fetchone", "iter", "fetchall", "row_factory"}],
            [
                (
                    "execute",
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pcap_requests'",
                ),
                ("fetchone", "exists"),
                ("execute", "PRAGMA table_info(pcap_requests)"),
                ("iter", "columns"),
                ("row_factory", sqlite3.Row),
                ("execute", expected_query),
                ("fetchall", "rows"),
            ],
        )
        self.assertEqual(
            [event for event in trace if event[0] in {"record_from_row", "record_getitem", "row_getitem", "value_bool", "value_str", "setdefault"}],
            [
                ("record_from_row", "new"),
                ("record_getitem", "new", "request_id"),
                ("row_getitem", "new", "group_id"),
                ("value_bool", "new_group"),
                ("value_str", "new_group"),
                ("row_getitem", "new", "alert_id"),
                ("value_bool", "new_alert"),
                ("value_str", "new_alert"),
                ("setdefault", "request", "new", "new"),
                ("setdefault", "group", "group-a", "new"),
                ("setdefault", "alert", "alert-a", "new"),
                ("record_from_row", "old"),
                ("record_getitem", "old", "request_id"),
                ("row_getitem", "old", "group_id"),
                ("value_bool", "old_group"),
                ("value_str", "old_group"),
                ("row_getitem", "old", "alert_id"),
                ("value_bool", "old_alert"),
                ("value_str", "old_alert"),
                ("setdefault", "request", "old", "old"),
                ("setdefault", "group", "group-a", "old"),
                ("setdefault", "alert", "alert-b", "old"),
            ],
        )

    def test_minimal_legacy_schema_uses_exact_fallback_query(self):
        queries = []

        class Cursor:
            def __init__(self, values=()):
                self.values = values

            def fetchone(self):
                return (1,)

            def __iter__(self):
                return iter(self.values)

            def fetchall(self):
                return []

        class Connection:
            row_factory = None

            def execute(self, query):
                queries.append(query)
                if query == "PRAGMA table_info(pcap_requests)":
                    return Cursor([(0, "request_id")])
                return Cursor()

        INDEX.build_pcap_request_index(Connection())

        self.assertEqual(
            queries[-1],
            """
        SELECT request_id, '' AS group_id, '' AS alert_id,
               '' AS status, '' AS outcome, '' AS error,
               '{}' AS request_json,
               '' AS completed_at, '' AS updated_at, '' AS created_at
        FROM pcap_requests
        ORDER BY request_id DESC, request_id DESC
        """,
        )

    def test_newest_group_and_alert_state_is_indexed_in_one_scan(self):
        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute(SCHEMA)
        connection.executemany(
            "INSERT INTO pcap_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                ("old", "group-a", "alert-a", "failed", "old failure", "{}", None, "2026-01-01", "2026-01-01"),
                ("new", "group-a", "alert-b", "fulfilled", "", '{"capture_file":"capture.pcap"}', "2026-01-02", "2026-01-02", "2026-01-02"),
            ],
        )

        result = INDEX.build_pcap_request_index(connection)

        self.assertEqual(result["requests_by_group_id"]["group-a"]["request_id"], "new")
        self.assertEqual(result["requests_by_alert_id"]["alert-a"]["request_id"], "old")
        self.assertTrue(result["requests_by_request_id"]["new"]["used_capture_file"])
        self.assertEqual(
            INDEX.request_for_alert(result, group_id="group-a", alert_id="alert-a")["request_id"],
            "new",
        )

    def test_read_only_loader_handles_missing_database_and_missing_table(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(INDEX.load_pcap_request_index(root / "missing.sqlite3"), INDEX.EMPTY_REQUEST_INDEX)
            database = root / "empty.sqlite3"
            sqlite3.connect(database).close()
            self.assertEqual(INDEX.load_pcap_request_index(database), INDEX.EMPTY_REQUEST_INDEX)

    def test_partial_legacy_schema_is_indexed_without_a_build_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "legacy.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    "CREATE TABLE pcap_requests (request_id TEXT PRIMARY KEY, alert_id TEXT, status TEXT)"
                )
                connection.execute(
                    "INSERT INTO pcap_requests (request_id, alert_id, status) VALUES ('r1', 'a1', 'pending')"
                )

            index = INDEX.load_pcap_request_index(database)

        self.assertEqual(index["requests_by_alert_id"]["a1"]["request_id"], "r1")
        self.assertEqual(index["requests_by_alert_id"]["a1"]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
