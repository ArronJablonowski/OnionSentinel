"""Durability checks for the Raspberry Pi alert delivery outbox."""
from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module():
    path = ROOT / "relay" / "app" / "alert_outbox.py"
    spec = importlib.util.spec_from_file_location("relay_alert_outbox", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


class RelayAlertOutboxTest(unittest.TestCase):
    def setUp(self) -> None:
        self.outbox = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.conn = sqlite3.connect(Path(self.temp.name) / "relay.sqlite3")
        self.outbox.initialize(self.conn)

    def tearDown(self) -> None:
        self.conn.close()
        self.temp.cleanup()

    def test_pending_delivery_survives_reopen(self) -> None:
        alert = {"alert_id": "alert-1", "rule_name": "test"}
        self.assertEqual(self.outbox.enqueue(self.conn, [alert]), 1)
        self.assertEqual(self.outbox.enqueue(self.conn, [alert]), 0)
        self.conn.close()
        self.conn = sqlite3.connect(Path(self.temp.name) / "relay.sqlite3")
        self.outbox.initialize(self.conn)
        self.assertEqual(self.outbox.pending(self.conn)[0]["payload"], alert)

    def test_interrupted_claim_is_requeued_on_initialize(self) -> None:
        self.outbox.enqueue(self.conn, [{"alert_id": "alert-2"}])
        self.assertTrue(self.outbox.claim(self.conn, "alert-2"))
        self.outbox.initialize(self.conn)
        self.assertEqual(self.outbox.counts(self.conn)["pending"], 1)

    def test_delivered_alert_is_not_queued_again(self) -> None:
        alert = {"alert_id": "alert-3"}
        self.outbox.enqueue(self.conn, [alert])
        self.outbox.mark_delivered(self.conn, "alert-3")
        self.assertEqual(self.outbox.enqueue(self.conn, [alert]), 0)
        self.assertEqual(self.outbox.counts(self.conn)["delivered"], 1)

    def test_large_burst_is_deduplicated_without_loss(self) -> None:
        alerts = [{"alert_id": f"burst-{index}", "message": "synthetic"} for index in range(5000)]
        self.assertEqual(self.outbox.enqueue(self.conn, alerts), 5000)
        self.assertEqual(self.outbox.enqueue(self.conn, alerts), 0)
        self.assertEqual(len(self.outbox.pending(self.conn, 10000)), 5000)


if __name__ == "__main__":
    unittest.main()
