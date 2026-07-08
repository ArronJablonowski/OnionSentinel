#!/usr/bin/env python3
"""Regression checks for relay wrapper isolation between alert and PCAP paths."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
WRAPPER_PATH = REPO_ROOT / "relay" / "app" / "relay_health_wrapper.py"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("relay_health_wrapper", WRAPPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def completed(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess("unit-test", returncode, stdout, stderr)


class RelayHealthWrapperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.wrapper = load_wrapper()

    def run_main_with(self, relay_result: subprocess.CompletedProcess, pcap_result: subprocess.CompletedProcess):
        stdout = io.StringIO()
        stderr = io.StringIO()
        saved_states: list[dict] = []
        with (
            mock.patch.object(self.wrapper, "run_relay", return_value=relay_result) as run_relay,
            mock.patch.object(self.wrapper, "run_pcap_broker", return_value=pcap_result) as run_pcap,
            mock.patch.object(self.wrapper, "validate_webhook_token_sources", return_value=None),
            mock.patch.object(self.wrapper, "load_state", return_value={"status": "unknown", "consecutive_failures": 0}),
            mock.patch.object(self.wrapper, "save_state", side_effect=lambda state: saved_states.append(dict(state))),
            mock.patch.object(self.wrapper, "send_telegram", return_value={"ok": True, "status": 200}),
            mock.patch.object(self.wrapper, "send_relay_health_event", return_value={"ok": True, "status": 200}),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()
        run_relay.assert_called_once()
        run_pcap.assert_called_once()
        return rc, stdout.getvalue(), stderr.getvalue(), saved_states

    def test_pcap_broker_runs_even_when_alert_relay_fails(self) -> None:
        rc, stdout, stderr, states = self.run_main_with(
            completed(1, stderr="Webhook returned HTTP 500: Internal Server Error\n"),
            completed(0, stdout='{"ok": true, "enabled": true, "processed": 1, "fulfilled": 1, "failed": 0}\n'),
        )

        self.assertEqual(rc, 1)
        self.assertIn('"processed": 1', stdout)
        self.assertIn("alert_relay=failed(1) pcap_broker=ok", states[-1]["last_summary"])
        self.assertIn("Webhook returned HTTP 500", stderr)

    def test_alert_relay_runs_even_when_pcap_broker_fails(self) -> None:
        rc, stdout, _stderr, states = self.run_main_with(
            completed(0, stdout='{"alert_count": 0, "dropped_alert_count": 0, "new_alert_count": 0, "posted_webhook_alerts": 0}\n'),
            completed(2, stderr="PCAP broker request failed\n"),
        )

        self.assertEqual(rc, 2)
        self.assertIn('"alert_count": 0', stdout)
        self.assertIn("alert_relay=ok pcap_broker=failed(2)", states[-1]["last_summary"])

    def test_success_summary_reports_both_components(self) -> None:
        rc, stdout, _stderr, states = self.run_main_with(
            completed(0, stdout='{"alert_count": 0, "dropped_alert_count": 0, "new_alert_count": 0, "posted_webhook_alerts": 0}\n'),
            completed(0, stdout='{"ok": true, "enabled": true, "processed": 0}\n'),
        )

        self.assertEqual(rc, 0)
        self.assertIn('"health_status": "ok"', stdout)
        self.assertIn("alert_relay=ok pcap_broker=ok", states[-1]["last_summary"])

    def test_webhook_token_drift_fails_before_alert_relay(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        saved_states: list[dict] = []
        with (
            mock.patch.object(self.wrapper, "validate_webhook_token_sources", return_value="relay webhook token mismatch between config.json and relay.env"),
            mock.patch.object(self.wrapper, "run_relay") as run_relay,
            mock.patch.object(self.wrapper, "run_pcap_broker", return_value=completed(0, stdout='{"ok": true, "enabled": true, "processed": 0}\n')) as run_pcap,
            mock.patch.object(self.wrapper, "load_state", return_value={"status": "unknown", "consecutive_failures": 0}),
            mock.patch.object(self.wrapper, "save_state", side_effect=lambda state: saved_states.append(dict(state))),
            mock.patch.object(self.wrapper, "send_telegram", return_value={"ok": True, "status": 200}),
            mock.patch.object(self.wrapper, "send_relay_health_event", return_value={"ok": True, "status": 200}),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()

        self.assertEqual(rc, 1)
        run_relay.assert_not_called()
        run_pcap.assert_called_once()
        self.assertIn("relay webhook token mismatch", stderr.getvalue())
        self.assertIn("alert_relay=failed(1) pcap_broker=ok", saved_states[-1]["last_summary"])


if __name__ == "__main__":
    unittest.main()
