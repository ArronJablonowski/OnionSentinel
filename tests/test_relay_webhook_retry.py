#!/usr/bin/env python3
"""Regression checks for relay webhook retry and partial-batch progress."""
from __future__ import annotations

import importlib.util
import sqlite3
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
RELAY_PATH = REPO_ROOT / "relay" / "app" / "relay.py"


def load_relay():
    spec = importlib.util.spec_from_file_location("relay", RELAY_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class RelayWebhookRetryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.relay = load_relay()

    def test_transient_http_500_retries_before_success(self) -> None:
        config = {
            "webhook": {
                "url": "http://example.invalid/webhook",
                "timeout_seconds": 1,
                "retry_attempts": 2,
                "retry_backoff_seconds": 0.01,
            }
        }
        transient = self.relay.WebhookPostError(
            "Webhook returned HTTP 500: Internal Server Error",
            retryable=True,
            status_code=500,
        )

        with mock.patch.object(self.relay, "post_json_to_webhook_once", side_effect=[transient, None]) as post_once:
            with mock.patch.object(self.relay.time, "sleep") as sleep:
                with mock.patch("sys.stderr"):
                    self.relay.post_json_to_webhook(config, {"alert_id": "example-alert"})

        self.assertEqual(post_once.call_count, 2)
        sleep.assert_called_once()

    def test_partial_batch_marks_successfully_posted_alerts_seen(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.execute(
            """
            CREATE TABLE seen_alerts (
                alert_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                seen_count INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        alerts = [{"alert_id": "posted-alert"}, {"alert_id": "failed-alert"}]
        config = {"webhook": {"enabled": True, "url": "http://example.invalid/webhook"}}

        with mock.patch.object(
            self.relay,
            "post_json_to_webhook",
            side_effect=[None, RuntimeError("webhook failed")],
        ):
            with self.assertRaises(RuntimeError):
                self.relay.post_alerts_to_webhook(config, alerts, conn)

        posted = conn.execute(
            "SELECT seen_count FROM seen_alerts WHERE alert_id = ?",
            ("posted-alert",),
        ).fetchone()
        failed = conn.execute(
            "SELECT seen_count FROM seen_alerts WHERE alert_id = ?",
            ("failed-alert",),
        ).fetchone()
        self.assertEqual(posted, (1,))
        self.assertIsNone(failed)
        conn.close()


if __name__ == "__main__":
    unittest.main()
