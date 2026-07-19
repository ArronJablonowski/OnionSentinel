#!/usr/bin/env python3
"""Regression coverage for the direct relay-to-alert-store SSH boundary."""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class AlertDeliveryTransportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.delivery = load_module(
            "alert_delivery_test",
            REPO_ROOT / "relay" / "app" / "alert_delivery.py",
        )
        self.temp_dir = tempfile.TemporaryDirectory()
        self.ssh_key = Path(self.temp_dir.name) / "alert-intake-key"
        self.known_hosts = Path(self.temp_dir.name) / "known_hosts"
        self.ssh_key.write_text("synthetic private key placeholder\n", encoding="utf-8")
        self.known_hosts.write_text("synthetic pinned host key placeholder\n", encoding="utf-8")
        self.config = {
            "alert_ingest": {
                "enabled": True,
                "mode": "ssh_batch",
                "host": "10.77.7.225",
                "user": "operator",
                "ssh_key": str(self.ssh_key),
                "known_hosts": str(self.known_hosts),
                "batch_max_items": 2,
                "batch_max_bytes": 4096,
            }
        }

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_split_batches_bounds_item_count(self) -> None:
        messages = [
            {"delivery_id": f"alert-{index}", "payload": {"alert_id": f"alert-{index}"}}
            for index in range(5)
        ]
        batches = self.delivery.split_batches(self.config, messages)
        self.assertEqual([len(batch) for batch in batches], [2, 2, 1])

    def test_ssh_acknowledgements_are_validated(self) -> None:
        messages = [{"delivery_id": "alert-1", "payload": {"alert_id": "alert-1"}}]
        response = {
            "ok": True,
            "protocol": self.delivery.PROTOCOL,
            "results": [{"delivery_id": "alert-1", "ok": True}],
        }
        completed = self.delivery.process_io.subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout=(json.dumps(response) + "\n").encode(),
            stderr=b"",
        )
        with mock.patch.object(
            self.delivery.process_io, "run_bounded_command", return_value=completed
        ) as runner:
            result = self.delivery.deliver_ssh_batch(self.config, messages)
        self.assertTrue(result["results"][0]["ok"])
        self.assertIn(b"onion-sentinel-alert-batch/v1", runner.call_args.kwargs["input_bytes"])
        command = runner.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn(f"UserKnownHostsFile={self.known_hosts}", command)
        self.assertIn("GlobalKnownHostsFile=/dev/null", command)

    def test_missing_acknowledgement_retries_entire_batch(self) -> None:
        completed = self.delivery.process_io.subprocess.CompletedProcess(
            args=["ssh"],
            returncode=0,
            stdout=json.dumps({"protocol": self.delivery.PROTOCOL, "results": []}).encode(),
            stderr=b"",
        )
        with mock.patch.object(self.delivery.process_io, "run_bounded_command", return_value=completed):
            with self.assertRaisesRegex(self.delivery.AlertDeliveryError, "omitted"):
                self.delivery.deliver_ssh_batch(
                    self.config,
                    [{"delivery_id": "alert-1", "payload": {"alert_id": "alert-1"}}],
                )

    def test_missing_ssh_key_is_rejected_before_invoking_ssh(self) -> None:
        self.config["alert_ingest"]["ssh_key"] = ""
        with self.assertRaisesRegex(self.delivery.AlertDeliveryError, "requires host, user, and ssh_key"):
            self.delivery.deliver_ssh_batch(self.config, [])

    def test_missing_ssh_key_file_is_rejected_before_invoking_ssh(self) -> None:
        self.ssh_key.unlink()
        with mock.patch.object(self.delivery.process_io, "run_bounded_command") as runner:
            with self.assertRaisesRegex(self.delivery.AlertDeliveryError, "key does not exist"):
                self.delivery.deliver_ssh_batch(self.config, [])
        runner.assert_not_called()

    def test_missing_known_hosts_file_is_rejected_before_invoking_ssh(self) -> None:
        self.known_hosts.unlink()
        with mock.patch.object(self.delivery.process_io, "run_bounded_command") as runner:
            with self.assertRaisesRegex(self.delivery.AlertDeliveryError, "known_hosts file does not exist"):
                self.delivery.deliver_ssh_batch(self.config, [])
        runner.assert_not_called()

    def test_split_batches_uses_exact_encoded_byte_ceiling(self) -> None:
        message = {"delivery_id": "alert-1", "payload": {"text": "x" * 128}}
        exact_size = len(self.delivery._encoded_batch([message]))
        self.config["alert_ingest"]["batch_max_bytes"] = exact_size
        self.assertEqual(self.delivery.split_batches(self.config, [message]), [[message]])
        self.config["alert_ingest"]["batch_max_bytes"] = exact_size - 1
        with self.assertRaisesRegex(self.delivery.AlertDeliveryError, "exceeds"):
            self.delivery.split_batches(self.config, [message])


class AlertOutboxDeadLetterTest(unittest.TestCase):
    def setUp(self) -> None:
        self.outbox = load_module(
            "alert_outbox_test",
            REPO_ROOT / "relay" / "app" / "alert_outbox.py",
        )
        self.conn = sqlite3.connect(":memory:")
        self.outbox.initialize(self.conn)

    def tearDown(self) -> None:
        self.conn.close()

    def test_permanent_failure_moves_to_dead_letter(self) -> None:
        self.outbox.enqueue(self.conn, [{"alert_id": "alert-1", "rule_name": "synthetic"}])
        self.assertTrue(self.outbox.claim(self.conn, "alert-1"))
        self.assertTrue(self.outbox.move_to_dead_letter(self.conn, "alert-1", "invalid alert"))
        counts = self.outbox.counts(self.conn)
        self.assertEqual(counts["pending"], 0)
        self.assertEqual(counts["dead_letter"], 1)


if __name__ == "__main__":
    unittest.main()
