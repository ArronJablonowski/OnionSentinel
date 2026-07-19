import importlib.util
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path


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
