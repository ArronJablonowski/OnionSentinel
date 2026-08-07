"""Direct behavior tests for the modular PCAP workflow-health service."""
from __future__ import annotations

import datetime as dt
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_pcap_health import PcapHealthSources, compose_pcap_workflow_health  # noqa: E402


NOW = dt.datetime(2026, 8, 7, 18, 0, tzinfo=dt.timezone.utc)


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("  ", "T").replace("Z", "+00:00"))


def transfer_duration(row: sqlite3.Row, *, has_transfer_duration: bool) -> int | None:
    if has_transfer_duration and row["transfer_duration_seconds"] is not None:
        return int(row["transfer_duration_seconds"])
    if not row["claimed_at"] or not row["completed_at"]:
        return None
    return int((parse_timestamp(row["completed_at"]) - parse_timestamp(row["claimed_at"])).total_seconds())


class PcapHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "alerts.sqlite3"
        self.artifacts = self.root / "artifacts"
        self.analyses = self.root / "analyses"
        self.relay_state = self.root / "pcap-workflow-state.json"
        self.artifacts.mkdir()
        self.analyses.mkdir()
        self._create_schema()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _create_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE pcap_requests (
                  request_id TEXT PRIMARY KEY, status TEXT, outcome TEXT, error TEXT,
                  group_id TEXT, artifact_size_bytes INTEGER DEFAULT 0,
                  created_at TEXT, claimed_at TEXT, updated_at TEXT, completed_at TEXT,
                  transfer_duration_seconds INTEGER, transfer_stage TEXT,
                  transfer_bytes INTEGER DEFAULT 0, transfer_total_bytes INTEGER DEFAULT 0,
                  transfer_progress_at TEXT
                )
                """
            )

    def _sources(self) -> PcapHealthSources:
        return PcapHealthSources(
            store_db=self.db_path,
            artifact_dir=self.artifacts,
            analysis_dir=self.analyses,
            relay_state_paths=(self.relay_state,),
            db_connect=self._connect,
            table_exists=lambda conn, name: bool(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
            ).fetchone()),
            parse_timestamp=parse_timestamp,
            format_timestamp=lambda value, **kwargs: value.isoformat(),
            directory_size=lambda path: sum(item.stat().st_size for item in path.glob("**/*") if item.is_file()),
            freshest_path=lambda paths: next((path for path in paths if path.exists()), None),
            read_json=lambda path, fallback: json.loads(path.read_text()) if path.exists() else fallback,
        )

    def _compose(self) -> dict[str, object]:
        return compose_pcap_workflow_health(self._sources(), transfer_duration, now_utc=NOW)

    def test_empty_store_has_stable_healthy_shape(self) -> None:
        payload = self._compose()

        self.assertTrue(payload["available"])
        self.assertEqual(payload["request_counts"]["total"], 0)
        self.assertEqual(payload["warning_count"], 0)
        self.assertFalse(payload["capture_protection"]["available"])

    def test_counts_outcomes_storage_oversize_and_analysis_inventory(self) -> None:
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO pcap_requests (
                  request_id, status, outcome, group_id, artifact_size_bytes,
                  created_at, claimed_at, updated_at, completed_at, transfer_duration_seconds
                ) VALUES (?, ?, ?, 'group', ?, ?, ?, ?, ?, ?)
                """,
                [
                    ("fulfilled", "fulfilled", "packets_available", 2048,
                     "2026-08-07T17:00:00Z", "2026-08-07T17:00:10Z",
                     "2026-08-07T17:01:10Z", "2026-08-07T17:01:10Z", 60),
                    ("oversize", "failed", "oversize", 0,
                     "2026-08-07T17:02:00Z", None,
                     "2026-08-07T17:03:00Z", "2026-08-07T17:03:00Z", None),
                    ("empty", "failed", "no_packets_available", 0,
                     "2026-08-07T17:04:00Z", None,
                     "2026-08-07T17:05:00Z", "2026-08-07T17:05:00Z", None),
                ],
            )
        (self.artifacts / "capture.pcap").write_bytes(b"pcap")
        (self.analyses / "case-pcap-analysis.json").write_text("{}")

        payload = self._compose()

        self.assertEqual(payload["request_counts"], {
            "pending": 0, "claimed": 0, "fulfilled": 1, "failed": 2, "total": 3,
        })
        self.assertEqual(payload["outcome_counts"]["oversize"], 1)
        self.assertEqual(payload["oversize_failures"], 1)
        self.assertEqual(payload["no_packet_failures"], 1)
        self.assertEqual(payload["storage"]["bytes_total"], 2048)
        self.assertEqual(payload["artifact_size_bytes"], 4)
        self.assertEqual(payload["analysis_count"], 1)
        self.assertEqual(payload["latest_request"]["request_id"], "empty")

    def test_stale_queue_recent_failure_and_operational_state_warn(self) -> None:
        old = "2026-08-07T16:00:00Z"
        recent = "2026-08-07T17:50:00Z"
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO pcap_requests (
                  request_id, status, outcome, error, created_at, updated_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    ("pending", "pending", None, None, old, old, None),
                    ("failed", "failed", "transport_failure", "relay reset", recent, recent, recent),
                ],
            )
        self.relay_state.write_text(json.dumps({
            "generated_at": "2026-08-07T17:59:30Z",
            "pcap_workflow": {"state": "operational_failure"},
        }))

        payload = self._compose()

        self.assertEqual(payload["warning_count"], 3)
        self.assertTrue(any("pending PCAP request" in warning for warning in payload["warnings"]))
        self.assertTrue(any("failure(s) need review" in warning for warning in payload["warnings"]))
        self.assertIn("PCAP broker reports an operational failure", payload["warnings"])

    def test_fresh_transfer_and_capture_hold_suppress_stale_pending_warning(self) -> None:
        old = "2026-08-07T15:00:00Z"
        fresh = "2026-08-07T17:59:30Z"
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO pcap_requests (
                  request_id, status, created_at, claimed_at, updated_at,
                  transfer_stage, transfer_bytes, transfer_total_bytes, transfer_progress_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    ("active", "claimed", old, old, fresh, "relay_to_studio", 1024, 4096, fresh),
                    ("queued", "pending", old, None, old, None, 0, 0, None),
                ],
            )
        self.relay_state.write_text(json.dumps({
            "generated_at": fresh,
            "relay_host": "relay-test",
            "pcap_workflow": {
                "state": "capture_protection_hold", "deferred": True,
                "reason": "capture loss exceeds threshold",
            },
        }))

        payload = self._compose()

        self.assertTrue(payload["queue_progressing"])
        self.assertEqual(payload["active_transfers"][0]["request_id"], "active")
        self.assertTrue(payload["capture_protection"]["active"])
        self.assertTrue(payload["advisories"])
        self.assertEqual(payload["warning_count"], 0)


if __name__ == "__main__":
    unittest.main()
