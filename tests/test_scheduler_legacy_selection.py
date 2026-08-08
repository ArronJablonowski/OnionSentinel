from __future__ import annotations

import datetime as dt
import hashlib
import sqlite3
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_legacy_selection import (  # noqa: E402
    LegacySelectionRequest,
    LegacySelectionSources,
    select_next_legacy_alert,
)


class SchedulerLegacySelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                first_seen TEXT,
                last_seen TEXT,
                timestamp TEXT,
                rule_name TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                triage_level TEXT,
                triage_score INTEGER,
                filter_status TEXT,
                stable_group_id TEXT,
                stable_group_key TEXT,
                routing TEXT,
                suppression_key TEXT
            );
            """
        )
        self.prompt_mtimes: dict[str, float] = {}
        self.analysis_mtimes: dict[str, float] = {}
        self.analyzed_groups: set[str] = set()
        self.pending_groups: set[str] = set()
        self.sources = LegacySelectionSources(
            now=lambda: dt.datetime.fromisoformat("2026-08-08T10:30:00+00:00"),
            alert_time_sql=lambda: (
                "COALESCE(NULLIF(last_seen, ''), NULLIF(timestamp, ''), first_seen)"
            ),
            alert_group_key_sql=lambda: (
                "COALESCE(NULLIF(stable_group_key, ''), stable_group_id, alert_id)"
            ),
            severity_priority_sql=lambda: (
                "CASE LOWER(COALESCE(triage_level, '')) "
                "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
            ),
            test_filter_sql=lambda: ("alert_id NOT LIKE ?", ["test-%"]),
            latest_prompt_mtimes=lambda _path: dict(self.prompt_mtimes),
            latest_analysis_mtimes=lambda _path: dict(self.analysis_mtimes),
            analyzed_alert_groups=lambda *_args: set(self.analyzed_groups),
            pending_ai_job_ids=lambda _conn: set(self.pending_groups),
            alert_group_key=lambda row: str(row["queue_group_key"]),
            alert_group_id=lambda key: hashlib.sha256(key.encode()).hexdigest()[:20],
            eligible_filter_statuses=(
                "accepted", "escalated", "unknown", "suppressed",
            ),
        )

    def tearDown(self) -> None:
        self.conn.close()

    def request(
        self,
        *,
        already_analyzed: set[str] | None = None,
        already_selected: set[str] | None = None,
        only_group_id: str = "",
        hours: int = 24,
        levels: str = "critical,high,medium,low,informational",
    ) -> LegacySelectionRequest:
        return LegacySelectionRequest(
            levels=levels,
            hours=hours,
            include_tests=True,
            only_group_id=only_group_id,
            analysis_dir=Path("/synthetic/analysis"),
            pcap_analysis_dir=Path("/synthetic/pcap"),
            prompt_dir=Path("/synthetic/prompts"),
            already_analyzed=frozenset(already_analyzed or set()),
            already_selected_groups=frozenset(already_selected or set()),
        )

    def insert_alert(
        self,
        alert_id: str,
        group_id: str,
        severity: str,
        seen_at: str,
        *,
        score: int = 50,
        status: str = "accepted",
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts VALUES (
                ?, ?, ?, ?, ?, '10.0.0.1', '10.0.0.2', ?, ?, ?, ?, ?, '', ''
            )
            """,
            (
                alert_id, seen_at, seen_at, seen_at, alert_id, severity,
                score, status, group_id, f"key-{group_id}",
            ),
        )

    def select(self, request: LegacySelectionRequest | None = None) -> sqlite3.Row | None:
        self.conn.commit()
        return select_next_legacy_alert(
            self.conn,
            request or self.request(),
            self.sources,
        )

    def test_strict_severity_and_newest_duplicate_representative(self) -> None:
        self.insert_alert("critical-old", "critical-group", "critical", "2026-08-08T09:00:00Z")
        self.insert_alert("critical-new", "critical-group", "critical", "2026-08-08T10:00:00Z")
        self.insert_alert("high-newer", "high-group", "high", "2026-08-08T10:20:00Z", score=100)
        self.assertEqual(self.select()["alert_id"], "critical-new")

    def test_manual_prompt_preempts_age_level_and_status_filters(self) -> None:
        self.insert_alert("critical", "critical-group", "critical", "2026-08-08T10:20:00Z")
        self.insert_alert(
            "manual-low",
            "manual-group",
            "low",
            "2020-01-01T00:00:00Z",
            status="duplicate",
        )
        self.prompt_mtimes["manual-low"] = 200
        self.analysis_mtimes["manual-low"] = 100
        selected = self.select(self.request(hours=1, levels="critical"))
        self.assertEqual(selected["alert_id"], "manual-low")

    def test_pending_intent_forces_analyzed_alert_to_run(self) -> None:
        group_id = "0123456789abcdefabcd"
        self.insert_alert("analyzed", group_id, "high", "2026-08-08T10:20:00Z")
        self.pending_groups.add(group_id)
        selected = self.select(self.request(already_analyzed={"analyzed"}))
        self.assertEqual(selected["alert_id"], "analyzed")

    def test_exact_group_and_selected_group_filters_are_fail_closed(self) -> None:
        target = "0123456789abcdefabcd"
        other = "fedcba9876543210abcd"
        self.insert_alert("target", target, "low", "2026-08-08T09:00:00Z")
        self.insert_alert("other", other, "critical", "2026-08-08T10:20:00Z")
        self.assertEqual(
            self.select(self.request(only_group_id=target))["alert_id"],
            "target",
        )
        self.assertEqual(
            self.select(self.request(already_selected={f"key-{other}"}))["alert_id"],
            "target",
        )
        with self.assertRaisesRegex(SystemExit, "one exact 20-hex"):
            self.select(self.request(only_group_id="not-exact"))

    def test_analyzed_group_is_skipped_for_next_eligible_group(self) -> None:
        self.insert_alert("first", "first-group", "critical", "2026-08-08T10:20:00Z")
        self.insert_alert("second", "second-group", "high", "2026-08-08T10:10:00Z")
        self.analyzed_groups.add("key-first-group")
        self.assertEqual(self.select()["alert_id"], "second")


if __name__ == "__main__":
    unittest.main()
