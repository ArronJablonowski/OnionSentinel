from __future__ import annotations

from relay_health_wrapper_fixtures import (
    Path,
    REPO_ROOT,
    WRAPPER_PATH,
    completed,
    contextlib,
    importlib,
    io,
    json,
    load_wrapper,
    mock,
    subprocess,
    sys,
    unittest,
)

class RelayHealthWrapperTestPcapFailureOutputIsRebuiltFromStrictAllowlistsCases:
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


    def test_child_diagnostic_classification_preserves_precedence(self) -> None:
        cases = (
            ("connection reset and HTTP 503", "connection_reset", 503),
            ("connection refused after timeout", "connection_refused", None),
            ("relay webhook token mismatch timeout", "configuration_error", None),
            ("request timed_out with HTTP 504", "timeout", 504),
            ("HTTP Error: 429 name or service not known", "http_error", 429),
            ("temporary failure in name resolution", "name_resolution_failure", None),
            ("sha256 did not match", "checksum_failure", None),
            ("relay spool is full", "storage_unavailable", None),
            ("artifact upload failed", "transport_error", None),
            ("upstream unavailable", "service_unavailable", None),
            ("emitted no valid final json summary", "invalid_output", None),
        )
        for text, category, http_status in cases:
            with self.subTest(category=category):
                diagnostic = self.wrapper.classify_child_diagnostic(text)
                self.assertEqual(diagnostic["category"], category)
                if http_status is None:
                    self.assertNotIn("http_status", diagnostic)
                else:
                    self.assertEqual(diagnostic["http_status"], http_status)


    def test_valid_nested_child_diagnostic_precedes_text_classification(self) -> None:
        nested = json.dumps({
            "child_diagnostic": {
                "category": "operational_failure",
                "http_status": 418,
            },
        })
        diagnostic = self.wrapper.classify_child_diagnostic(
            "connection reset",
            nested,
            fallback="child_failure",
        )
        self.assertEqual(
            diagnostic,
            {"category": "operational_failure", "http_status": 418},
        )
        bool_status = json.dumps({
            "child_diagnostic": {
                "category": "child_failure",
                "http_status": True,
            },
        })
        self.assertEqual(
            self.wrapper.classify_child_diagnostic(bool_status),
            {"category": "child_failure"},
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


    def test_health_state_sanitizer_preserves_bounded_projection_order(self) -> None:
        sentinel = "STATE_LEAK_SENTINEL_5f2a1b"
        raw = {
            "status": "failed",
            "last_failure": "2026-08-14  09:00:00Z",
            "last_success": "invalid",
            "consecutive_failures": True,
            "failure_notification_sent": 1,
            "last_started_at": "2026-08-14  09:01:00Z",
            "last_pcap_unproven_at": "invalid",
            "last_summary": (
                "pcap_broker=failed(7); connection reset "
                f"{sentinel}; HTTP 502"
            ),
            "last_pcap_unproven_summary": f"pcap_broker=ok; {sentinel}",
            "last_returncode": 256,
            "last_http_status": f"502{sentinel}",
            "pcap_failure_unresolved": True,
            "last_pcap_unproven_reason": "capture_protection_hold",
            "unknown": sentinel,
        }
        before = dict(raw)

        state = self.wrapper.sanitize_health_state(raw)

        self.assertEqual(raw, before)
        self.assertEqual(state, {
            "status": "failed",
            "last_failure": "2026-08-14  09:00:00Z",
            "last_success": None,
            "consecutive_failures": 0,
            "failure_notification_sent": False,
            "last_started_at": "2026-08-14  09:01:00Z",
            "last_summary": (
                "pcap_broker=failed(7); diagnostic=connection_reset; "
                "http_status=502"
            ),
            "last_pcap_unproven_summary": "pcap_broker=ok",
            "last_http_status": 502,
            "pcap_failure_unresolved": True,
            "last_pcap_unproven_reason": "capture_protection_hold",
        })
        self.assertNotIn(sentinel, json.dumps(state, sort_keys=True))
        self.assertEqual(
            self.wrapper.sanitize_health_state(None),
            {
                "status": "unknown",
                "last_failure": None,
                "last_success": None,
                "consecutive_failures": 0,
                "failure_notification_sent": False,
            },
        )


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
