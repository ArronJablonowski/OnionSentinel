#!/usr/bin/env python3
"""Regression checks for relay wrapper isolation between alert and PCAP paths."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
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

    def run_component_with_state(
        self,
        component: str,
        state: dict,
        *,
        relay_result: subprocess.CompletedProcess | None = None,
        pcap_result: subprocess.CompletedProcess | None = None,
    ):
        stdout = io.StringIO()
        stderr = io.StringIO()
        persisted: list[dict] = []
        relay_result = relay_result or completed(
            0,
            stdout=(
                '{"alert_count":0,"dropped_alert_count":0,'
                '"new_alert_count":0,"posted_webhook_alerts":0}\n'
            ),
        )
        pcap_result = pcap_result or completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":0}\n'
            ),
        )
        with (
            mock.patch.object(
                self.wrapper,
                "run_relay",
                return_value=relay_result,
            ),
            mock.patch.object(
                self.wrapper,
                "run_pcap_broker",
                return_value=pcap_result,
            ),
            mock.patch.object(
                self.wrapper,
                "validate_webhook_token_sources",
                return_value=None,
            ),
            mock.patch.object(
                self.wrapper,
                "load_state",
                return_value=state,
            ),
            mock.patch.object(
                self.wrapper,
                "persist_component_state",
                side_effect=lambda value, _component, _path: persisted.append(
                    dict(value)
                ),
            ),
            mock.patch.object(
                self.wrapper,
                "send_telegram",
                return_value={"ok": True, "status": 200},
            ) as send_telegram,
            mock.patch.object(
                self.wrapper,
                "send_relay_health_event",
                return_value={"ok": True, "status": 200},
            ),
            mock.patch.object(
                sys,
                "argv",
                ["relay_health_wrapper.py", "--component", component],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()
        return rc, stdout.getvalue(), persisted, send_telegram

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

    def run_component_with_sinks(
        self,
        component: str,
        state: dict,
        *,
        relay_result: subprocess.CompletedProcess | None = None,
        pcap_result: subprocess.CompletedProcess | None = None,
        storage_result: subprocess.CompletedProcess | None = None,
        failure_threshold: int = 1,
    ) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        persisted: list[dict] = []
        telegram_messages: list[str] = []
        webhook_events: list[dict] = []
        relay_result = relay_result or completed(
            0,
            stdout=(
                '{"alert_count":0,"dropped_alert_count":0,'
                '"new_alert_count":0,"posted_webhook_alerts":0}\n'
            ),
        )
        pcap_result = pcap_result or completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":0}\n'
            ),
        )
        storage_result = storage_result or completed(
            0,
            stdout='{"ok":true,"failures":[]}\n',
        )

        def record_telegram(message: str) -> dict:
            telegram_messages.append(message)
            return {"ok": True, "status": 200}

        def record_event(event: dict) -> dict:
            webhook_events.append(event)
            return {"ok": True, "status": 200}

        with (
            mock.patch.object(
                self.wrapper,
                "run_relay",
                return_value=relay_result,
            ),
            mock.patch.object(
                self.wrapper,
                "run_pcap_broker",
                return_value=pcap_result,
            ),
            mock.patch.object(
                self.wrapper,
                "run_storage_health",
                return_value=storage_result,
            ),
            mock.patch.object(
                self.wrapper,
                "validate_webhook_token_sources",
                return_value=None,
            ),
            mock.patch.object(
                self.wrapper,
                "load_state",
                return_value=state,
            ),
            mock.patch.object(
                self.wrapper,
                "persist_component_state",
                side_effect=lambda value, _component, _path: persisted.append(
                    dict(value)
                ),
            ),
            mock.patch.object(
                self.wrapper,
                "send_telegram",
                side_effect=record_telegram,
            ),
            mock.patch.object(
                self.wrapper,
                "send_relay_health_event",
                side_effect=record_event,
            ),
            mock.patch.object(
                self.wrapper,
                "FAILURE_NOTIFY_THRESHOLD",
                failure_threshold,
            ),
            mock.patch.object(
                sys,
                "argv",
                ["relay_health_wrapper.py", "--component", component],
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            rc = self.wrapper.main()
        return {
            "returncode": rc,
            "stdout": stdout.getvalue(),
            "stderr": stderr.getvalue(),
            "persisted": persisted,
            "telegram_messages": telegram_messages,
            "webhook_events": webhook_events,
        }

    def test_pcap_broker_runs_even_when_alert_relay_fails(self) -> None:
        rc, stdout, stderr, states = self.run_main_with(
            completed(1, stderr="Webhook returned HTTP 500: Internal Server Error\n"),
            completed(0, stdout='{"ok": true, "enabled": true, "processed": 1, "fulfilled": 1, "failed": 0}\n'),
        )

        self.assertEqual(rc, 1)
        self.assertIn('"processed": 1', stdout)
        self.assertIn("alert_relay=failed(1) pcap_broker=ok", states[-1]["last_summary"])
        self.assertIn('"category": "http_error"', stderr)
        self.assertIn('"http_status": 500', stderr)

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
        self.assertIn('"category": "configuration_error"', stderr.getvalue())
        self.assertIn("alert_relay=failed(1) pcap_broker=ok", saved_states[-1]["last_summary"])

    def test_pcap_operational_failure_changes_component_exit_status(self) -> None:
        with mock.patch.object(
            self.wrapper,
            "run_shell_command",
            return_value=completed(
                0,
                stdout='{"ok": true, "processed": 1, "failed": 1, "operational_failures": 1}\n',
            ),
        ):
            result = self.wrapper.run_pcap_broker()

        self.assertEqual(result.returncode, 2)
        self.assertIn('"operational_failures": 1', result.stderr)

    def test_pcap_operational_failure_preserves_root_cause(self) -> None:
        error = '{"event":"pcap_artifact_upload_failed","error":"rsync connection reset"}\n'
        with mock.patch.object(
            self.wrapper,
            "run_shell_command",
            return_value=completed(
                0,
                stdout='{"ok": true, "processed": 1, "operational_failures": 1}\n',
                stderr=error,
            ),
        ):
            result = self.wrapper.run_pcap_broker()

        self.assertEqual(result.returncode, 2)
        self.assertIn('"category": "connection_reset"', result.stderr)

    def test_expected_no_packet_outcome_does_not_fail_component(self) -> None:
        with mock.patch.object(
            self.wrapper,
            "run_shell_command",
            return_value=completed(
                0,
                stdout='{"ok": true, "processed": 1, "failed": 1, "operational_failures": 0, "outcomes": {"no_packets_available": 1}}\n',
            ),
        ):
            result = self.wrapper.run_pcap_broker()

        self.assertEqual(result.returncode, 0)

    def test_disabled_and_lock_skip_are_valid_but_do_not_prove_recovery(self) -> None:
        outputs = (
            '{"ok":true,"enabled":false,"processed":0,'
            '"operational_failures":0}\n',
            '{"ok":true,"enabled":true,"locked":true,"processed":0,'
            '"operational_failures":0}\n',
        )
        for output in outputs:
            with self.subTest(output=output):
                raw = completed(0, stdout=output)
                with mock.patch.object(
                    self.wrapper,
                    "run_shell_command",
                    return_value=raw,
                ):
                    validated = self.wrapper.run_pcap_broker()
                self.assertEqual(validated.returncode, 0)
                self.assertFalse(
                    self.wrapper.pcap_result_proves_broker_recovery(validated)
                )

    def test_pcap_summary_is_informative(self) -> None:
        summary = self.wrapper.summarize_output(
            (
                '{"ok":true,"enabled":true,"processed":0,"fulfilled":0,'
                '"failed":0,"operational_failures":0,"deferred":true}\n'
            ),
            "",
        )

        self.assertEqual(
            summary,
            "processed=0 fulfilled=0 failed=0 operational_failures=0 "
            "deferred=true broker_contacted=false",
        )

    def test_capture_protection_hold_is_reported_as_safe_degraded_state(self) -> None:
        result = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"processed":0,'
                '"operational_failures":0,"deferred":true,'
                '"defer_reason":"Zeek capture loss 0.5000% exceeds 0.1000%",'
                '"capture_protection":{"observed_percent":0.5,'
                '"threshold_percent":0.1,"age_seconds":12,'
                '"deferred":true}}\n'
            ),
        )

        event = self.wrapper.build_pcap_status_event(result)

        self.assertEqual(event["message_type"], "relay_heartbeat")
        self.assertEqual(event["component"], "pcap_broker")
        self.assertEqual(event["pcap_workflow"]["state"], "capture_protection_hold")
        self.assertTrue(event["pcap_workflow"]["deferred"])
        self.assertEqual(
            event["pcap_workflow"]["reason"],
            "threshold_exceeded",
        )
        self.assertEqual(event["pcap_workflow"]["observed_percent"], 0.5)
        self.assertEqual(event["pcap_workflow"]["operational_failures"], 0)

        once = self.wrapper.sanitized_child_result(result, "pcap")
        twice = self.wrapper.sanitized_child_result(once, "pcap")
        self.assertEqual(
            self.wrapper.build_pcap_status_event(twice)["pcap_workflow"][
                "reason"
            ],
            "threshold_exceeded",
        )

    def test_capture_protection_hold_does_not_claim_broker_recovery(self) -> None:
        hold = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"processed":0,"deferred":true,'
                '"defer_reason":"Zeek capture-loss telemetry is unavailable",'
                '"capture_protection":{"deferred":true}}\n'
            ),
        )
        prior_state = {
            "status": "failed",
            "last_failure": "2026-07-27  11:59:11Z",
            "last_summary": "pcap_broker=failed(1); connection reset",
            "last_returncode": 1,
            "consecutive_failures": 36,
            "failure_notification_sent": True,
        }
        persisted: list[dict] = []
        stdout = io.StringIO()
        with (
            mock.patch.object(self.wrapper, "run_pcap_broker", return_value=hold),
            mock.patch.object(self.wrapper, "load_state", return_value=prior_state),
            mock.patch.object(
                self.wrapper,
                "persist_component_state",
                side_effect=lambda state, _component, _path: persisted.append(dict(state)),
            ),
            mock.patch.object(self.wrapper, "send_telegram") as send_telegram,
            mock.patch.object(
                self.wrapper,
                "send_relay_health_event",
                return_value={"ok": False, "status": "error"},
            ),
            mock.patch.object(sys, "argv", ["relay_health_wrapper.py", "--component", "pcap"]),
            contextlib.redirect_stdout(stdout),
        ):
            rc = self.wrapper.main()

        self.assertEqual(rc, 0)
        send_telegram.assert_not_called()
        self.assertEqual(persisted[-1]["status"], "failed")
        self.assertEqual(persisted[-1]["consecutive_failures"], 36)
        self.assertTrue(persisted[-1]["failure_notification_sent"])
        self.assertIn('"health_status": "pcap_recovery_unproven"', stdout.getvalue())
        self.assertIn('"reason": "capture_protection_hold"', stdout.getvalue())

    def test_unnotified_failure_latch_is_preserved_during_hold(self) -> None:
        state = {
            "status": "failed",
            "last_summary": "pcap_broker=failed(1); unavailable",
            "last_returncode": 1,
            "consecutive_failures": 2,
            "failure_notification_sent": False,
        }
        hold = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"processed":0,"deferred":true,'
                '"capture_protection":{"deferred":true}}\n'
            ),
        )

        rc, _stdout, persisted, send_telegram = (
            self.run_component_with_state(
                "pcap",
                state,
                pcap_result=hold,
            )
        )

        self.assertEqual(rc, 0)
        self.assertEqual(persisted[-1]["status"], "failed")
        self.assertEqual(persisted[-1]["consecutive_failures"], 2)
        self.assertFalse(persisted[-1]["failure_notification_sent"])
        send_telegram.assert_not_called()

    def test_only_successful_broker_contact_clears_pcap_failure(self) -> None:
        prior_state = {
            "status": "failed",
            "last_failure": "2026-07-27  11:59:11Z",
            "last_summary": "pcap_broker=failed(1); connection reset",
            "last_returncode": 1,
            "consecutive_failures": 36,
            "failure_notification_sent": True,
        }
        healthy = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":0}\n'
            ),
        )

        rc, stdout, persisted, send_telegram = self.run_component_with_state(
            "pcap",
            prior_state,
            pcap_result=healthy,
        )

        self.assertEqual(rc, 0)
        self.assertEqual(persisted[-1]["status"], "ok")
        self.assertEqual(persisted[-1]["consecutive_failures"], 0)
        send_telegram.assert_called_once()
        self.assertIn('"health_status": "recovered"', stdout)

    def test_unproven_pcap_success_shapes_cannot_clear_failure(self) -> None:
        outputs = {
            "missing_summary": "",
            "disabled": '{"ok":true,"enabled":false,"processed":0}\n',
            "lock_skip": (
                '{"ok":true,"enabled":true,"locked":true,"processed":0}\n'
            ),
            "legacy_no_contact_proof": (
                '{"ok":true,"enabled":true,"processed":0,'
                '"operational_failures":0}\n'
            ),
            "string_deferred": (
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"deferred":"false","capture_protection":{},"processed":0,'
                '"operational_failures":0}\n'
            ),
            "numeric_locked": (
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"locked":1,"processed":0,"operational_failures":0}\n'
            ),
            "malformed_operational_failures": (
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":"not-an-int"}\n'
            ),
            "malformed_processed": (
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":[],"operational_failures":0}\n'
            ),
        }
        for label, output in outputs.items():
            with self.subTest(label=label):
                state = {
                    "status": "failed",
                    "last_summary": "pcap_broker=failed(1); unavailable",
                    "last_returncode": 1,
                    "consecutive_failures": 3,
                    "failure_notification_sent": True,
                }
                rc, stdout, persisted, send_telegram = (
                    self.run_component_with_state(
                        "pcap",
                        state,
                        pcap_result=completed(0, stdout=output),
                    )
                )
                self.assertEqual(rc, 0)
                self.assertEqual(persisted[-1]["status"], "failed")
                self.assertEqual(persisted[-1]["consecutive_failures"], 3)
                send_telegram.assert_not_called()
                self.assertIn('"reason": "broker_contact_not_proven"', stdout)

        malformed_hold = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"deferred":"false",'
                '"capture_protection":{}}\n'
            ),
        )
        self.assertFalse(
            self.wrapper.pcap_result_is_capture_protection_hold(
                malformed_hold
            )
        )

        raw = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"deferred":"false","processed":0,'
                '"operational_failures":0}\n'
            ),
        )
        once = self.wrapper.sanitized_child_result(raw, "pcap")
        twice = self.wrapper.sanitized_child_result(once, "pcap")
        self.assertIn("deferred", json.loads(twice.stdout)["invalid_fields"])
        self.assertFalse(
            self.wrapper.pcap_result_proves_broker_recovery(twice)
        )

    def test_final_malformed_output_invalidates_earlier_pcap_summary(self) -> None:
        result = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"broker_contacted":true,'
                '"processed":0,"operational_failures":0}\n'
                "truncated-final-output\n"
            ),
        )
        self.assertIsNone(self.wrapper.parse_pcap_summary(result.stdout))
        with mock.patch.object(
            self.wrapper,
            "run_shell_command",
            return_value=result,
        ):
            validated = self.wrapper.run_pcap_broker()
        self.assertEqual(validated.returncode, 2)
        self.assertIn('"category": "invalid_output"', validated.stderr)

    def test_component_all_hold_does_not_freeze_alert_only_recovery(self) -> None:
        state = {
            "status": "failed",
            "last_summary": (
                "alert_relay=failed(1) pcap_broker=ok; connection refused"
            ),
            "last_returncode": 1,
            "consecutive_failures": 3,
            "failure_notification_sent": True,
        }
        hold = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"processed":0,"deferred":true,'
                '"capture_protection":{"deferred":true}}\n'
            ),
        )

        rc, stdout, persisted, send_telegram = self.run_component_with_state(
            "all",
            state,
            pcap_result=hold,
        )

        self.assertEqual(rc, 0)
        self.assertEqual(persisted[-1]["status"], "ok")
        send_telegram.assert_called_once()
        self.assertIn('"health_status": "recovered"', stdout)

    def test_component_all_hold_preserves_prior_pcap_failure(self) -> None:
        state = {
            "status": "failed",
            "last_summary": (
                "alert_relay=ok pcap_broker=failed(1); connection reset"
            ),
            "last_returncode": 1,
            "consecutive_failures": 3,
            "failure_notification_sent": True,
        }
        hold = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"processed":0,"deferred":true,'
                '"capture_protection":{"deferred":true}}\n'
            ),
        )

        rc, stdout, persisted, send_telegram = (
            self.run_component_with_state(
                "all",
                state,
                pcap_result=hold,
            )
        )

        self.assertEqual(rc, 0)
        self.assertEqual(persisted[-1]["status"], "failed")
        send_telegram.assert_not_called()
        self.assertIn('"health_status": "pcap_recovery_unproven"', stdout)

    def test_component_all_keeps_pcap_failure_across_alert_failure_cycle(
        self,
    ) -> None:
        state = {
            "status": "failed",
            "last_summary": (
                "alert_relay=failed(1) pcap_broker=failed(1); unavailable"
            ),
            "last_returncode": 1,
            "consecutive_failures": 3,
            "failure_notification_sent": True,
        }
        hold = completed(
            0,
            stdout=(
                '{"ok":true,"enabled":true,"processed":0,'
                '"operational_failures":0,"deferred":true,'
                '"capture_protection":{"deferred":true}}\n'
            ),
        )
        alert_failed = completed(1, stderr="alert intake unavailable\n")

        first_rc, _first_stdout, first_persisted, first_telegram = (
            self.run_component_with_state(
                "all",
                state,
                relay_result=alert_failed,
                pcap_result=hold,
            )
        )
        self.assertEqual(first_rc, 1)
        self.assertTrue(
            first_persisted[-1]["pcap_failure_unresolved"]
        )
        first_telegram.assert_not_called()

        second_rc, second_stdout, second_persisted, second_telegram = (
            self.run_component_with_state(
                "all",
                first_persisted[-1],
                pcap_result=hold,
            )
        )
        self.assertEqual(second_rc, 0)
        self.assertEqual(second_persisted[-1]["status"], "failed")
        self.assertTrue(
            second_persisted[-1]["pcap_failure_unresolved"]
        )
        second_telegram.assert_not_called()
        self.assertIn(
            '"health_status": "pcap_recovery_unproven"',
            second_stdout,
        )

    def test_real_pcap_failure_is_not_misclassified_as_hold(self) -> None:
        event = self.wrapper.build_pcap_status_event(completed(2, stdout="malformed\n"))

        self.assertEqual(event["pcap_workflow"]["state"], "operational_failure")
        self.assertFalse(event["pcap_workflow"]["deferred"])
        self.assertEqual(event["pcap_workflow"]["operational_failures"], 1)

    def test_malformed_pcap_counters_do_not_crash_health_wrapper(self) -> None:
        event = self.wrapper.build_pcap_status_event(completed(
            0,
            stdout='{"ok":true,"enabled":true,"processed":"bad","operational_failures":"bad"}\n',
        ))

        self.assertEqual(event["pcap_workflow"]["state"], "operational_failure")
        self.assertEqual(event["pcap_workflow"]["processed"], 0)
        self.assertEqual(event["pcap_workflow"]["operational_failures"], 0)

    def test_pcap_failure_output_is_rebuilt_from_strict_allowlists(self) -> None:
        sentinel = "PCAP_OUTPUT_LEAK_SENTINEL_7f9c2e"
        raw_summary = {
            "ok": False,
            "enabled": True,
            "processed": 3,
            "fulfilled": True,
            "operational_failures": 1,
            "outcomes": {
                "timeout": 2,
                "transport_failed": sentinel,
                "failed": self.wrapper.MAX_COUNTER + 1,
                sentinel: 9,
            },
            "spool": {
                "available": False,
                "path": f"/secret/{sentinel}",
                "reason": sentinel,
                "free_bytes": 4096,
                "total_bytes": sentinel,
                "used_percent": float("inf"),
            },
            "deferred": True,
            "defer_reason": sentinel,
            "capture_protection": {
                "deferred": True,
                "reason": sentinel,
                "metric": sentinel,
                "observed_percent": sentinel,
                "threshold_percent": 0.1,
                "age_seconds": True,
            },
            "error": sentinel,
            "security_onion_storage": {"error": sentinel},
        }
        raw_result = completed(
            0,
            stdout=json.dumps(raw_summary) + "\n",
            stderr=json.dumps({
                "event": sentinel,
                "error": f"rsync connection reset {sentinel}",
            }) + "\n",
        )

        with mock.patch.object(
            self.wrapper,
            "run_shell_command",
            return_value=raw_result,
        ):
            result = self.wrapper.run_pcap_broker()

        emitted = result.stdout + result.stderr
        self.assertNotIn(sentinel, emitted)
        self.assertEqual(result.returncode, 2)
        safe_summary = json.loads(result.stdout)
        self.assertEqual(safe_summary["outcomes"], {"timeout": 2})
        self.assertEqual(
            safe_summary["spool"],
            {"available": False, "free_bytes": 4096},
        )
        self.assertEqual(
            safe_summary["capture_protection"]["metric"],
            "zeek_capture_loss",
        )
        self.assertEqual(
            safe_summary["capture_protection"]["reason_category"],
            "capture_protection_hold",
        )
        self.assertNotIn(
            "observed_percent",
            safe_summary["capture_protection"],
        )
        self.assertNotIn(
            "age_seconds",
            safe_summary["capture_protection"],
        )
        self.assertIn('"category": "connection_reset"', result.stderr)
        self.assertIn('"operational_failures": 1', result.stderr)

    def test_known_diagnostics_survive_without_raw_child_text(self) -> None:
        sentinel = "DIAGNOSTIC_LEAK_SENTINEL_d147af"
        cases = (
            ("socket connection reset by peer", "connection_reset", None),
            ("connect: connection refused", "connection_refused", None),
            ("request timed out after secret", "timeout", None),
            ("Webhook returned HTTP 429: secret", "http_error", 429),
        )
        for raw_error, category, http_status in cases:
            with self.subTest(category=category):
                result = self.wrapper.sanitized_child_result(
                    completed(
                        1,
                        stdout=(
                            '{"alert_count":0,"dropped_alert_count":0,'
                            '"new_alert_count":0,"posted_webhook_alerts":0,'
                            f'"secret":"{sentinel}"}}\n'
                        ),
                        stderr=f"{raw_error} {sentinel}\n",
                    ),
                    "alert",
                )
                emitted = result.stdout + result.stderr
                self.assertNotIn(sentinel, emitted)
                diagnostic = json.loads(result.stderr)["child_diagnostic"]
                self.assertEqual(diagnostic["category"], category)
                if http_status is None:
                    self.assertNotIn("http_status", diagnostic)
                else:
                    self.assertEqual(
                        diagnostic["http_status"],
                        http_status,
                    )

    def test_sentinel_never_reaches_state_notifications_events_or_journal(
        self,
    ) -> None:
        sentinel = "ALL_SINKS_LEAK_SENTINEL_1c850d"
        relay_summary = {
            "alert_count": 4,
            "dropped_alert_count": 1,
            "new_alert_count": 2,
            "posted_webhook_alerts": 1,
            "saved": f"/secret/{sentinel}",
            "first_rule": sentinel,
        }
        pcap_summary = {
            "ok": False,
            "enabled": True,
            "processed": 1,
            "operational_failures": 1,
            "outcomes": {"timeout": 1, sentinel: 5},
            "spool": {
                "available": False,
                "path": sentinel,
                "reason": sentinel,
                "free_bytes": 2048,
            },
            "deferred": True,
            "defer_reason": sentinel,
            "capture_protection": {
                "deferred": True,
                "reason": sentinel,
                "metric": sentinel,
                "observed_percent": sentinel,
                "threshold_percent": 0.1,
                "age_seconds": sentinel,
            },
            "error": sentinel,
        }
        outcome = self.run_component_with_sinks(
            "all",
            {
                "status": "unknown",
                "consecutive_failures": 0,
                "untrusted_state_field": sentinel,
            },
            relay_result=completed(
                1,
                stdout=sentinel + "\n" + json.dumps(relay_summary) + "\n",
                stderr=(
                    f"Webhook returned HTTP 503: {sentinel}\n"
                ),
            ),
            pcap_result=completed(
                2,
                stdout=sentinel + "\n" + json.dumps(pcap_summary) + "\n",
                stderr=(
                    '{"error":"connection refused '
                    + sentinel
                    + '"}\n'
                ),
            ),
        )

        surfaces = (
            outcome["stdout"],
            outcome["stderr"],
            json.dumps(outcome["persisted"], sort_keys=True),
            json.dumps(outcome["telegram_messages"], sort_keys=True),
            json.dumps(outcome["webhook_events"], sort_keys=True),
        )
        for surface in surfaces:
            self.assertNotIn(sentinel, surface)
        self.assertNotEqual(outcome["returncode"], 0)
        self.assertIn('"category": "http_error"', outcome["stderr"])
        self.assertIn('"http_status": 503', outcome["stderr"])
        self.assertIn(
            '"category": "connection_refused"',
            outcome["stderr"],
        )
        self.assertEqual(
            outcome["persisted"][-1]["last_http_status"],
            503,
        )
        self.assertEqual(len(outcome["telegram_messages"]), 1)
        self.assertEqual(len(outcome["webhook_events"]), 1)
        workflow = outcome["webhook_events"][0]["pcap_workflow"]
        self.assertEqual(workflow["metric"], "zeek_capture_loss")
        self.assertIn(
            workflow["reason"],
            self.wrapper.CAPTURE_REASON_CATEGORIES,
        )
        self.assertIsNone(workflow["observed_percent"])
        self.assertIsNone(workflow["telemetry_age_seconds"])

    def test_tainted_legacy_failure_is_sanitized_in_recovery_payload(self) -> None:
        sentinel = "RECOVERY_LEAK_SENTINEL_2d4810"
        healthy_summary = {
            "ok": True,
            "enabled": True,
            "broker_contacted": True,
            "processed": 0,
            "operational_failures": 0,
            "unknown": sentinel,
        }
        outcome = self.run_component_with_sinks(
            "pcap",
            {
                "status": "failed",
                "last_failure": "2026-07-27  11:59:11Z",
                "last_summary": (
                    "pcap_broker=failed(7); connection reset "
                    f"{sentinel}; HTTP 502"
                ),
                "last_returncode": 7,
                "last_http_status": f"502{sentinel}",
                "consecutive_failures": 4,
                "failure_notification_sent": True,
                "legacy_secret": sentinel,
            },
            pcap_result=completed(
                0,
                stdout=sentinel + "\n" + json.dumps(healthy_summary) + "\n",
                stderr=sentinel + "\n",
            ),
        )

        surfaces = (
            outcome["stdout"],
            outcome["stderr"],
            json.dumps(outcome["persisted"], sort_keys=True),
            json.dumps(outcome["telegram_messages"], sort_keys=True),
            json.dumps(outcome["webhook_events"], sort_keys=True),
        )
        for surface in surfaces:
            self.assertNotIn(sentinel, surface)
        self.assertEqual(outcome["returncode"], 0)
        recovery_events = [
            event for event in outcome["webhook_events"]
            if event.get("message_type") == "relay_health_recovery"
        ]
        self.assertEqual(len(recovery_events), 1)
        previous = recovery_events[0]["relay_previous_failure"]
        self.assertIn("diagnostic=connection_reset", previous["summary"])
        self.assertEqual(previous["http_status"], 502)
        self.assertEqual(previous["returncode"], 7)
        self.assertEqual(previous["consecutive_failures"], 4)
        self.assertEqual(len(outcome["telegram_messages"]), 1)

    def test_storage_output_paths_and_failures_are_sanitized(self) -> None:
        sentinel = "STORAGE_LEAK_SENTINEL_f67d91"
        storage_summary = {
            "ok": False,
            "mount": f"/secret/{sentinel}",
            "root_mount": sentinel,
            "device": sentinel,
            "mount_source": sentinel,
            "root_storage": {
                "free_bytes": 100,
                "total_bytes": True,
                "used_percent": sentinel,
            },
            "smart": {
                "passed": False,
                "temperature_c": sentinel,
                "media_errors": 2,
            },
            "failures": [
                f"relay SSD mount is unavailable {sentinel}",
                sentinel,
            ],
            "error": sentinel,
        }
        outcome = self.run_component_with_sinks(
            "storage",
            {"status": "unknown", "consecutive_failures": 0},
            storage_result=completed(
                1,
                stdout=sentinel + "\n" + json.dumps(storage_summary) + "\n",
                stderr=f"connection refused {sentinel}\n",
            ),
        )

        surfaces = (
            outcome["stdout"],
            outcome["stderr"],
            json.dumps(outcome["persisted"], sort_keys=True),
            json.dumps(outcome["telegram_messages"], sort_keys=True),
        )
        for surface in surfaces:
            self.assertNotIn(sentinel, surface)
        safe_summary = json.loads(outcome["stdout"].splitlines()[0])
        self.assertEqual(
            safe_summary["failure_categories"],
            ["health_check_failed", "mount_unavailable"],
        )
        self.assertEqual(
            safe_summary["root_storage"],
            {"free_bytes": 100},
        )
        self.assertEqual(
            safe_summary["smart"],
            {"media_errors": 2, "passed": False},
        )
        self.assertIn(
            '"category": "connection_refused"',
            outcome["stderr"],
        )
        self.assertEqual(len(outcome["telegram_messages"]), 1)

    def test_storage_component_uses_independent_state_and_command(self) -> None:
        stdout = io.StringIO()
        with (
            mock.patch.object(self.wrapper, "run_storage_health", return_value=completed(0, stdout='{"ok": true}\n')) as run_storage,
            mock.patch.object(self.wrapper, "load_state", return_value={"status": "unknown", "consecutive_failures": 0}),
            mock.patch.object(self.wrapper, "persist_component_state") as persist,
            mock.patch.object(self.wrapper, "send_relay_health_event", return_value={"ok": True}),
            mock.patch.object(sys, "argv", ["relay_health_wrapper.py", "--component", "storage"]),
            contextlib.redirect_stdout(stdout),
        ):
            rc = self.wrapper.main()

        self.assertEqual(rc, 0)
        run_storage.assert_called_once()
        self.assertIn("storage_health=ok", persist.call_args.args[0]["last_summary"])


if __name__ == "__main__":
    unittest.main()
