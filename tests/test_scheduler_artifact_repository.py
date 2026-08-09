from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_artifact_repository import (  # noqa: E402
    alert_group_id,
    alert_group_key,
    analyzed_alert_groups,
    analyzed_alert_ids,
    completed_analysis_group_ids,
    latest_analysis_mtimes,
    latest_pcap_analysis_mtimes,
    latest_prompt_group_mtimes,
    latest_prompt_mtimes,
    reusable_prompt_for_alert,
)


class SchedulerArtifactRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-artifacts-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.analysis_dir = self.root / "analysis"
        self.pcap_dir = self.root / "pcap"
        self.prompt_dir = self.root / "prompts"
        for path in (
            self.analysis_dir,
            self.pcap_dir,
            self.prompt_dir,
        ):
            path.mkdir()
        self.conn = sqlite3.connect(":memory:")
        self.addCleanup(self.conn.close)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                suppression_key TEXT,
                triage_level TEXT,
                rule_name TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                filter_status TEXT,
                stable_group_id TEXT
            )
            """
        )

    @staticmethod
    def write(path: Path, value: object, mtime: float) -> None:
        path.write_text(json.dumps(value), encoding="utf-8")
        os.utime(path, (mtime, mtime))

    def insert_alert(
        self,
        alert_id: str,
        *,
        suppression_key: str = "",
        stable_group_id: str = "",
    ) -> None:
        self.conn.execute(
            """
            INSERT INTO alerts VALUES (?, ?, 'medium', 'Rule',
                                       '192.0.2.1', '198.51.100.2',
                                       'accepted', ?)
            """,
            (alert_id, suppression_key, stable_group_id),
        )
        self.conn.commit()

    def test_indexes_newest_valid_artifacts_and_ignores_bad_json(self) -> None:
        self.write(
            self.analysis_dir / "old-local-ai-analysis.json",
            {"alert_id": "alert-a"},
            100,
        )
        self.write(
            self.analysis_dir / "new-local-ai-analysis.json",
            {"alert_id": "alert-a"},
            200,
        )
        (self.analysis_dir / "bad-local-ai-analysis.json").write_text(
            "{", encoding="utf-8"
        )
        self.write(
            self.pcap_dir / "direct-pcap-analysis.json",
            {"alert_id": "alert-a"},
            150,
        )
        self.write(
            self.pcap_dir / "nested-pcap-analysis.json",
            {"request": {"alert_id": "alert-b"}},
            175,
        )
        self.write(
            self.prompt_dir / "direct-ai-prompt.json",
            {"alert_id": "alert-a"},
            125,
        )
        self.write(
            self.prompt_dir / "nested-ai-prompt.json",
            {"alert": {"alert_id": "alert-b"}},
            225,
        )

        self.assertEqual(
            latest_analysis_mtimes(self.analysis_dir), {"alert-a": 200}
        )
        self.assertEqual(
            latest_pcap_analysis_mtimes(self.pcap_dir),
            {"alert-a": 150, "alert-b": 175},
        )
        self.assertEqual(
            latest_prompt_mtimes(self.prompt_dir),
            {"alert-a": 125, "alert-b": 225},
        )

    def test_prompt_groups_use_live_db_then_fallback_for_aged_out_alert(self) -> None:
        self.insert_alert("live-alert", suppression_key="live-group")
        self.write(
            self.prompt_dir / "live-ai-prompt.json",
            {
                "alert": {
                    "alert_id": "live-alert",
                    "suppression_key": "stale-prompt-group",
                }
            },
            100,
        )
        self.write(
            self.prompt_dir / "aged-out-ai-prompt.json",
            {
                "alert": {
                    "alert_id": "aged-out-alert",
                    "suppression_key": "aged-out-group",
                }
            },
            200,
        )

        self.assertEqual(
            latest_prompt_group_mtimes(self.conn, self.prompt_dir),
            {"live-group": 100, "aged-out-group": 200},
        )

    def test_alert_freshness_requires_analysis_newer_than_pcap_and_prompt(self) -> None:
        analysis = self.analysis_dir / "a-local-ai-analysis.json"
        pcap = self.pcap_dir / "a-pcap-analysis.json"
        prompt = self.prompt_dir / "a-ai-prompt.json"
        self.write(analysis, {"alert_id": "alert-a"}, 150)
        self.write(pcap, {"request": {"alert_id": "alert-a"}}, 200)
        self.write(prompt, {"alert": {"alert_id": "alert-a"}}, 100)
        self.assertEqual(
            analyzed_alert_ids(
                self.analysis_dir, self.pcap_dir, self.prompt_dir
            ),
            set(),
        )

        os.utime(pcap, (120, 120))
        self.assertEqual(
            analyzed_alert_ids(
                self.analysis_dir, self.pcap_dir, self.prompt_dir
            ),
            {"alert-a"},
        )
        os.utime(prompt, (250, 250))
        self.assertEqual(
            analyzed_alert_ids(
                self.analysis_dir, self.pcap_dir, self.prompt_dir
            ),
            set(),
        )

    def test_group_freshness_and_completion_prefer_stable_group_id(self) -> None:
        self.insert_alert(
            "alert-a",
            suppression_key="duplicate-group",
            stable_group_id="stable-v2-group",
        )
        self.write(
            self.analysis_dir / "a-local-ai-analysis.json",
            {"alert_id": "alert-a"},
            150,
        )
        group_id = alert_group_id("duplicate-group")
        pcap = self.pcap_dir / "group-pcap-analysis.json"
        self.write(pcap, {"request": {"group_id": group_id}}, 200)
        self.assertEqual(
            analyzed_alert_groups(
                self.conn,
                {"alert-a"},
                self.analysis_dir,
                self.pcap_dir,
                self.prompt_dir,
            ),
            set(),
        )

        os.utime(pcap, (100, 100))
        self.assertEqual(
            completed_analysis_group_ids(
                self.conn,
                {"alert-a"},
                self.analysis_dir,
                self.pcap_dir,
                self.prompt_dir,
            ),
            {"stable-v2-group"},
        )

    def test_reusable_prompt_requires_newest_prompt_after_matching_pcap(self) -> None:
        self.insert_alert("alert-a", suppression_key="duplicate-group")
        selected = self.conn.execute(
            """
            SELECT *, suppression_key AS queue_group_key
            FROM alerts WHERE alert_id = 'alert-a'
            """
        ).fetchone()
        self.assertIsNotNone(selected)
        old_prompt = self.prompt_dir / "old-ai-prompt.json"
        new_prompt = self.prompt_dir / "new-ai-prompt.json"
        self.write(old_prompt, {"alert": {"alert_id": "alert-a"}}, 100)
        self.write(new_prompt, {"alert": {"alert_id": "alert-a"}}, 200)
        pcap = self.pcap_dir / "group-pcap-analysis.json"
        self.write(
            pcap,
            {"request": {"group_id": alert_group_id("duplicate-group")}},
            250,
        )
        self.assertIsNone(
            reusable_prompt_for_alert(
                self.prompt_dir, selected, self.pcap_dir
            )
        )

        os.utime(pcap, (150, 150))
        self.assertEqual(
            reusable_prompt_for_alert(
                self.prompt_dir, selected, self.pcap_dir
            ),
            new_prompt,
        )
        self.assertEqual(alert_group_key(selected), "duplicate-group")


if __name__ == "__main__":
    unittest.main()
