"""Characterization for deterministic agent-memory promotion ordering."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


def load_promotion():
    sys.modules.pop("agent_memory_promotion", None)
    return importlib.import_module("agent_memory_promotion")


class AgentMemoryPromotionOrderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_promotion()
        self.now = dt.datetime(2026, 8, 12, tzinfo=dt.timezone.utc)

    @staticmethod
    def record(
        record_id: str,
        analysis_id: str,
        reinforced_at: str,
        *,
        status: str = "model-observed",
        expired: bool = False,
    ) -> dict[str, object]:
        return {
            "id": record_id,
            "source_analysis_id": analysis_id,
            "last_reinforced_at": reinforced_at,
            "created_at": reinforced_at,
            "status": status,
            "expired": expired,
        }

    def test_namespace_and_ordered_records_signature_are_exact(self) -> None:
        names = sorted(
            name for name in dir(self.module) if not name.startswith("__")
        )
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (36, "ad3e7d4c5b9179fce2b1e292bc672e08e6ce66b62312ceadf6be85d01ad88bbc"),
        )
        self.assertEqual(
            str(inspect.signature(self.module._ordered_records)),
            "(existing_records: 'list[dict[str, Any]]', incoming: "
            "'list[dict[str, Any]]', *, now: 'dt.datetime', record_limit: "
            "'int') -> 'tuple[list[dict[str, Any]], dict[str, int]]'",
        )

    def test_expiration_add_replay_reinforce_order_limit_and_stats_are_exact(self) -> None:
        existing = [
            self.record("expired", "old", "2026-08-01T00:00:00Z", expired=True),
            self.record("replay", "same", "2026-08-02T00:00:00Z"),
            self.record("reinforce", "old", "2026-08-03T00:00:00Z"),
            self.record(
                "confirmed",
                "operator",
                "2026-01-01T00:00:00Z",
                status="operator-confirmed",
            ),
        ]
        incoming = [
            self.record("added", "new", "2026-08-05T00:00:00Z"),
            self.record("replay", "same", "2026-08-06T00:00:00Z"),
            self.record("reinforce", "new", "2026-08-07T00:00:00Z"),
        ]
        merged = self.record("reinforce", "new", "2026-08-07T00:00:00Z")
        with mock.patch.object(
            self.module,
            "_record_is_expired",
            side_effect=lambda record, now: record.get("expired", False),
        ), mock.patch.object(
            self.module,
            "_merge_record",
            return_value=merged,
        ) as merge:
            records, stats = self.module._ordered_records(
                existing,
                incoming,
                now=self.now,
                record_limit=3,
            )
        merge.assert_called_once_with(existing[2], incoming[2])
        self.assertEqual(
            [record["id"] for record in records],
            ["confirmed", "reinforce", "added"],
        )
        self.assertEqual(
            stats,
            {
                "added": 1,
                "reinforced": 1,
                "replayed": 1,
                "expired_removed": 1,
                "retained": 3,
            },
        )
        self.assertIs(records[0], existing[3])
        self.assertIs(records[1], merged)
        self.assertIs(records[2], incoming[0])


if __name__ == "__main__":
    unittest.main()
