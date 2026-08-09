from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_claim_snapshot import (  # noqa: E402
    ClaimSnapshotPolicy,
    claimed_durable_ai_job,
)


class SchedulerClaimSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="onion-sentinel-claim-snapshot-"
        )
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "alerts.sqlite3"
        connection = sqlite3.connect(self.database)
        connection.execute(
            """
            CREATE TABLE alerts (
                alert_id TEXT PRIMARY KEY,
                stable_group_id TEXT,
                stable_group_key TEXT,
                triage_level TEXT
            )
            """
        )
        connection.execute(
            "INSERT INTO alerts VALUES (?, ?, ?, ?)",
            ("alert-1", "group-1", "v2|group-1", "high"),
        )
        connection.commit()
        connection.close()
        self.policy = ClaimSnapshotPolicy(
            severity_priority=(
                "critical",
                "high",
                "medium",
                "low",
                "informational",
            ),
            stable_group_key_valid=lambda value: (
                isinstance(value, str) and value.startswith("v2|")
            ),
        )
        self.payload = {
            "group_id": "group-1",
            "alert_id": "alert-1",
            "representative_alert_id": "alert-1",
            "stable_group_key": "v2|group-1",
        }

    def transition(self, **changes: object) -> SimpleNamespace:
        values = {
            "job_payload": dict(self.payload),
            "job_type": "ai_analysis",
            "job_id": 7,
            "resolved_key": "group-1",
            **changes,
        }
        return SimpleNamespace(**values)

    def load(
        self,
        transition: object | None = None,
        *,
        database: Path | None = None,
    ) -> tuple[dict[str, object], str, str, str]:
        return claimed_durable_ai_job(
            self.policy,
            transition or self.transition(),
            database or self.database,
            expected_job_type="ai_analysis",
            expected_group_id="group-1",
            expected_job_id=7,
        )

    def test_exact_transition_and_database_snapshot_are_returned(self) -> None:
        self.assertEqual(
            self.load(),
            (self.payload, "alert-1", "group-1", "high"),
        )

    def test_one_canonical_alert_field_and_optional_stable_key_are_allowed(
        self,
    ) -> None:
        payload = dict(self.payload)
        payload.pop("alert_id")
        payload.pop("stable_group_key")
        loaded, alert_id, group_id, severity = self.load(
            self.transition(job_payload=payload)
        )
        self.assertEqual(loaded, payload)
        self.assertEqual((alert_id, group_id, severity), ("alert-1", "group-1", "high"))

    def test_missing_payload_and_transition_identity_drift_fail_closed(self) -> None:
        cases = (
            (self.transition(job_payload={}), "server-authoritative"),
            (self.transition(job_type="pcap_analysis"), "job identity"),
            (self.transition(job_id=8), "job identity"),
            (self.transition(job_id="invalid"), "job identity"),
            (self.transition(resolved_key="other-group"), "group identity"),
            (
                self.transition(job_payload={**self.payload, "group_id": "other"}),
                "group identity",
            ),
            (
                self.transition(
                    job_payload={
                        **self.payload,
                        "representative_alert_id": "alert-2",
                    }
                ),
                "alert identity",
            ),
        )
        for transition, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.load(transition)

    def test_database_group_key_and_severity_are_authoritative(self) -> None:
        connection = sqlite3.connect(self.database)
        mutations = (
            ("stable_group_id", "other-group", "alert identity"),
            ("stable_group_key", "v2|other", "stable group key"),
            ("triage_level", "unsupported", "alert identity"),
        )
        for column, value, message in mutations:
            with self.subTest(column=column):
                connection.execute(
                    f"UPDATE alerts SET {column} = ? WHERE alert_id = 'alert-1'",
                    (value,),
                )
                connection.commit()
                with self.assertRaisesRegex(RuntimeError, message):
                    self.load()
                connection.execute(
                    f"UPDATE alerts SET {column} = ? WHERE alert_id = 'alert-1'",
                    (
                        {
                            "stable_group_id": "group-1",
                            "stable_group_key": "v2|group-1",
                            "triage_level": "high",
                        }[column],
                    ),
                )
                connection.commit()
        connection.close()

    def test_unavailable_database_is_reported_as_verification_failure(self) -> None:
        missing = Path(self.temporary.name) / "missing.sqlite3"
        with self.assertRaisesRegex(RuntimeError, "verification failed"):
            self.load(database=missing)


if __name__ == "__main__":
    unittest.main()
