#!/usr/bin/env python3
"""Regression checks for quiet-cycle relay heartbeat telemetry."""
from __future__ import annotations

import importlib.util
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


class RelayHeartbeatTest(unittest.TestCase):
    def setUp(self) -> None:
        self.relay = load_relay()

    def test_heartbeat_payload_marks_quiet_cycle_without_alert_id(self) -> None:
        payload = self.relay.build_relay_heartbeat(
            {"source": "security-onion", "exported_at": "2026-07-04  20:00:00Z"},
            alert_count=0,
            dropped_count=0,
            filtered_count=0,
            new_count=0,
            duplicate_count=0,
            posted_count=0,
            first_rule="none",
        )

        self.assertEqual(payload["message_type"], "relay_heartbeat")
        self.assertEqual(payload["source"], "security-onion")
        self.assertEqual(payload["new_alert_count"], 0)
        self.assertEqual(payload["posted_webhook_alerts"], 0)
        self.assertEqual(payload["first_rule"], "none")
        self.assertNotIn("alert_id", payload)

    def test_disabled_webhook_does_not_post_heartbeat(self) -> None:
        with mock.patch.object(self.relay, "post_json_to_webhook") as post_json:
            posted = self.relay.post_relay_heartbeat(
                {"webhook": {"enabled": False}},
                {"message_type": "relay_heartbeat"},
            )

        self.assertFalse(posted)
        post_json.assert_not_called()

    def test_enabled_webhook_posts_heartbeat_once(self) -> None:
        heartbeat = {"message_type": "relay_heartbeat"}
        config = {"webhook": {"enabled": True, "url": "http://example.invalid/webhook"}}

        with mock.patch.object(self.relay, "post_json_to_webhook") as post_json:
            posted = self.relay.post_relay_heartbeat(config, heartbeat)

        self.assertTrue(posted)
        post_json.assert_called_once_with(config, heartbeat)


if __name__ == "__main__":
    unittest.main()
