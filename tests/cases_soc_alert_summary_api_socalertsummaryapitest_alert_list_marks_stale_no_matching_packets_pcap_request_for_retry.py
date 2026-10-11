from __future__ import annotations

from soc_alert_summary_api_fixtures import (
    PORTAL_PATH,
    Path,
    REPO_ROOT,
    ThreadPoolExecutor,
    dt,
    importlib,
    json,
    load_portal,
    mock,
    sqlite3,
    sys,
    tempfile,
    time,
    unittest,
)

class SocAlertSummaryApiTestAlertListMarksStaleNoMatchingPacketsPcapRequestForRetryCases:
    def test_alert_list_marks_stale_no_matching_packets_pcap_request_for_retry(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "unit test stale no packets"})
        self.conn.execute(
            "UPDATE pcap_requests SET status = 'failed', error = 'no matching packets found for requested window', request_json = ?, completed_at = updated_at WHERE group_id = ?",
            (json.dumps({"destination_ip": "198.51.100.10", "destination_port": 443}), newest_group_id),
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "empty-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"group_id": newest_group_id, "alert_id": "newest-alert"},
                    "pcap_files": [],
                    "artifact_state": "artifact-not-copied-to-mac",
                    "zeek": {"available": False},
                    "tshark": {"available": False},
                }
            ),
            encoding="utf-8",
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "error")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "Retry")


    def test_alert_list_uses_static_ai_status_when_available(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        (self.portal.SOC_ALERT_AI_ANALYSIS_DIR / "unit-local-ai-analysis.json").write_text(
            json.dumps({"alert_id": "newest-alert", "generated_at": "2026-07-03  12:01:00Z"}),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "ok": True,
                    "reports": {
                        newest_group_id: {
                            "ai_status_key": "analyzed",
                            "ai_status_label": "Analyzed",
                            "ai_status_detail": "unit test analysis artifact",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["ai_status_key"], "analyzed")
        self.assertEqual(payload["alerts"][0]["ai_status_label"], "Analyzed")
        self.assertEqual(payload["alerts"][0]["ai_status_detail"], "unit test analysis artifact")


    def test_alert_list_corrects_stale_skipped_ai_status_without_artifact(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "ok": True,
                    "reports": {
                        newest_group_id: {
                            "ai_status_key": "not-queued",
                            "ai_status_label": "Skipped",
                            "ai_status_detail": "stale status from previous build",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["ai_status_key"], "queued")
        self.assertEqual(payload["alerts"][0]["ai_status_label"], "Queued")
        self.assertIn("No AI analysis artifact exists", payload["alerts"][0]["ai_status_detail"])


    def test_ai_analysis_threshold_skips_new_low_alerts_but_retains_history(self) -> None:
        low_group_id = self.insert_summary(
            "low|Below configured floor|192.0.2.40|198.51.100.40|accepted",
            "low-alert",
            "Below configured floor",
            "low",
            "2026-07-03  13:00:00Z",
            1,
            1,
        )
        settings = self.portal.default_soc_ai_settings()
        settings["soc_analyst_analysis_min_severity"] = "medium"
        self.portal.SOC_AI_SETTINGS_FILE.write_text(json.dumps(settings), encoding="utf-8")
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        low_alert = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "low-alert"
        )

        self.assertEqual(status, 200)
        self.assertEqual(low_alert["ai_status_key"], "not-queued")
        self.assertEqual(low_alert["ai_status_label"], "Skipped")
        self.assertIn("Medium automatic AI-analysis minimum", low_alert["ai_status_detail"])

        (self.portal.SOC_ALERT_AI_ANALYSIS_DIR / "low-alert-local-ai-analysis.json").write_text(
            json.dumps(
                {
                    "alert_id": "low-alert",
                    "generated_at": "2026-07-03  13:01:00Z",
                }
            ),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "reports": {
                        low_group_id: {
                            "ai_status_key": "analyzed",
                            "ai_status_label": "Analyzed",
                            "ai_status_detail": "historical analysis artifact",
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        low_alert = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "low-alert"
        )

        self.assertEqual(status, 200)
        self.assertEqual(low_alert["ai_status_key"], "analyzed")
        self.assertEqual(low_alert["ai_status_label"], "Analyzed")


    def test_manual_analyze_queues_fresh_full_group_prompt(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        with (
            mock.patch.object(
                self.portal,
                "alert_store_post_json",
                return_value={"ok": True, "job": {"status": "pending"}},
            ) as post_mock,
        ):
            status, payload = self.portal.soc_alert_queue_analysis_response(group_id, {})

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["ai_status_key"], "queued")
        path, request_payload = post_mock.call_args.args
        self.assertEqual(path, "/ai/request")
        self.assertEqual(request_payload["group_id"], group_id)
        self.assertEqual(request_payload["related_limit"], 250)
        self.assertEqual(request_payload["pcap_analysis_limit"], 8)
        self.assertEqual(post_mock.call_args.kwargs["timeout"], 10.0)


    def test_manual_analyze_forwards_exact_frozen_dispatch_identity(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        identity = {
            "representative_alert_id": "frozen-alert:with:opaque-id",
            "stable_group_id": "abcdef1234567890abcd",
            "stable_group_key": "v2|critical|newest detection|192.0.2.10|198.51.100.10",
            "cohort_id": "newest-20-soc.2026_07_26",
            "dispatch_id": "a" * 64,
            "release_id": "d" * 40,
            "expected_assigned_route": "codex-cli:gpt-5.5:high",
            "expected_reviewer_route": "codex-cli:gpt-5.6-sol:xhigh",
            "reviewer_required": True,
        }
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            return_value={"ok": True, "status": "queued", **identity},
        ) as post_mock:
            status, payload = self.portal.soc_alert_queue_analysis_response(
                group_id,
                identity,
            )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        path, request_payload = post_mock.call_args.args
        self.assertEqual(path, "/ai/request")
        for field, expected in identity.items():
            self.assertEqual(request_payload[field], expected)


    def test_manual_analyze_preserves_alert_store_identity_conflict(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        with mock.patch.object(
            self.portal,
            "alert_store_post_json",
            side_effect=self.portal.AlertStoreRequestError(
                "frozen representative no longer belongs to the group",
                409,
            ),
        ):
            status, payload = self.portal.soc_alert_queue_analysis_response(
                group_id,
                {"representative_alert_id": "stale-alert"},
            )

        self.assertEqual(status, 409)
        self.assertFalse(payload["ok"])
        self.assertIn("no longer belongs", payload["error"])


    def test_top_endpoint_metrics_use_visible_alert_volume(self) -> None:
        self.insert_summary(
            "medium|Noisy visible detection|192.0.2.99|198.51.100.99|accepted",
            "noisy-visible-alert",
            "Noisy visible detection",
            "medium",
            "2026-07-03  10:00:00Z",
            1,
            20,
            source_ip="192.0.2.99",
            destination_ip="198.51.100.99",
            destination_port=8443,
        )
        self.conn.commit()
        status, payload = self.portal.soc_alerts_query_response({"limit": ["2"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["total_matching"], 3)
        self.assertEqual(len(payload["alerts"]), 2)
        self.assertEqual(payload["top_endpoints"]["source_ip"], "192.0.2.99")
        self.assertEqual(payload["top_endpoints"]["destination_ip"], "198.51.100.99")
        self.assertEqual(payload["top_endpoints"]["destination_port"], "8443")


    def test_suppressed_slice_includes_backend_filter_suppressed_groups(self) -> None:
        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["suppressed"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 1)
        self.assertEqual(payload["status_counts"]["total"], 3)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "backend-suppressed-alert")


    def test_metrics_count_backend_suppressed_groups_like_alert_table(self) -> None:
        self.portal.SOC_ALERT_PCAP_ARTIFACT_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ARTIFACT_DIR / "sample.pcap").write_bytes(b"pcap-data")
        status, payload = self.portal.soc_alert_metrics_response({"since": [""]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["grouped_total"], 3)
        self.assertEqual(payload["by_analyst_status"]["open"], 2)
        self.assertEqual(payload["by_analyst_status"]["active"], 2)
        self.assertEqual(payload["by_analyst_status"]["suppressed"], 1)
        self.assertEqual(payload["by_analyst_status"]["acknowledged"], 0)
        self.assertEqual(payload["by_analyst_status"]["total"], 3)
        self.assertEqual(payload["pcap_ingest_size_bytes"], len(b"pcap-data"))


    def test_system_health_includes_pcap_workflow_counts(self) -> None:
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "unit-pcap-analysis.json").write_text(
            json.dumps({"request": {"request_id": "unit"}, "pcap_files": []}),
            encoding="utf-8",
        )
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, group_id, reason, max_window_seconds,
              request_json, created_at, updated_at, completed_at, error
            )
            VALUES (
              'pcap-health-test', 'failed', ?, 'unit test', 120,
              '{}', '2026-07-03  12:00:00Z', '2026-07-03  12:01:00Z',
              '2026-07-03  12:01:00Z', 'no matching packets found'
            )
            """,
            (
                self.portal.soc_alert_group_id(
                    "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
                ),
            ),
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["pcap"]["request_counts"]["failed"], 1)
        self.assertEqual(payload["pcap"]["no_packet_failures"], 1)
        self.assertEqual(payload["pcap"]["analysis_count"], 1)
        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertEqual(payload["pcap"]["recent_requests"][0]["request_id"], "pcap-health-test")
        self.assertEqual(payload["pcap"]["recent_requests"][0]["status"], "failed")


    def test_system_health_derives_legacy_pcap_transfer_duration(self) -> None:
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, claimed_at, completed_at, updated_at
            ) VALUES (
              'pcap-duration-test', 'fulfilled', 'unit test', 120, '{}',
              '2026-07-03  12:00:00Z', '2026-07-03  12:01:00Z',
              '2026-07-03  12:03:05Z', '2026-07-03  12:03:05Z'
            )
            """
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        request = payload["pcap"]["recent_requests"][0]
        self.assertEqual(request["request_id"], "pcap-duration-test")
        self.assertEqual(request["transfer_duration_seconds"], 125)


    def test_system_health_warns_on_stale_or_unexpected_pcap_work(self) -> None:
        fresh_failure_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=30),
            timespec="seconds",
        )
        old_failure_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3),
            timespec="seconds",
        )
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, group_id, reason, max_window_seconds,
              request_json, created_at, updated_at, completed_at, error
            )
            VALUES
              ('pcap-stale-pending', 'pending', ?, 'unit test', 120, '{}',
               '2026-07-03  12:00:00Z', '2026-07-03  12:00:00Z', NULL, NULL),
              ('pcap-unexpected-failure', 'failed', ?, 'unit test', 120, '{}',
               ?, ?, ?, 'artifact upload failed'),
              ('pcap-old-unexpected-failure', 'failed', ?, 'unit test', 120, '{}',
               ?, ?, ?, 'old artifact upload failed'),
              ('pcap-legacy-invalid-json', 'failed', ?, 'unit test', 120, '{}',
               ?, ?, ?, 'PCAP export returned invalid JSON: no JSON object found: line 1 column 1 (char 0); preview=''''')
            """,
            (
                self.portal.soc_alert_group_id(
                    "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
                ),
                self.portal.soc_alert_group_id(
                    "medium|Older detection|192.0.2.20|198.51.100.20|accepted"
                ),
                fresh_failure_at,
                fresh_failure_at,
                fresh_failure_at,
                self.portal.soc_alert_group_id(
                    "low|Old failure|192.0.2.30|198.51.100.30|accepted"
                ),
                old_failure_at,
                old_failure_at,
                old_failure_at,
                self.portal.soc_alert_group_id(
                    "medium|Legacy invalid JSON|192.0.2.40|198.51.100.40|accepted"
                ),
                fresh_failure_at,
                fresh_failure_at,
                fresh_failure_at,
            ),
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 2)
        self.assertTrue(any("pending PCAP request" in item for item in payload["pcap"]["warnings"]))
        self.assertTrue(any("1 PCAP request failure(s) need review" in item for item in payload["pcap"]["warnings"]))


    def test_system_health_does_not_flag_queue_behind_fresh_large_transfer(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
            timespec="seconds",
        )
        fresh_at = self.portal.format_iso_timestamp(dt.datetime.now(dt.timezone.utc), timespec="seconds")
        self.conn.executemany(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, claimed_at, transfer_stage, transfer_bytes,
              transfer_total_bytes, transfer_progress_at, updated_at
            ) VALUES (?, ?, 'unit test', 120, '{}', ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "pcap-active-large", "claimed", old_at, old_at,
                    "security_onion_to_relay", 8 * 1024**3, 24 * 1024**3, fresh_at, fresh_at,
                ),
                (
                    "pcap-queued-behind-large", "pending", old_at, None,
                    None, 0, 0, None, old_at,
                ),
            ],
        )
        self.conn.commit()
        # Broker summaries are emitted between serial transfers and may be
        # older than their three-minute freshness window during a large copy.
        # The request's fresh byte-progress heartbeat must take precedence.
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE.write_text(json.dumps({
            "generated_at": old_at,
            "component": "pcap_broker",
            "pcap_workflow": {"state": "healthy", "processed": 0},
        }), encoding="utf-8")

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertEqual(payload["pcap"]["active_transfers"][0]["request_id"], "pcap-active-large")
        self.assertFalse(any("telemetry is stale" in item for item in payload["pcap"]["warnings"]))


    def test_system_health_preserves_bounded_progress_between_serial_pcap_jobs(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1),
            timespec="seconds",
        )
        fresh_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1),
            timespec="seconds",
        )
        self.conn.executemany(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, updated_at, completed_at
            ) VALUES (?, ?, 'unit test', 120, '{}', ?, ?, ?)
            """,
            [
                ("pcap-old-pending", "pending", old_at, old_at, None),
                ("pcap-recent-terminal", "fulfilled", old_at, fresh_at, fresh_at),
            ],
        )
        self.conn.commit()

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertTrue(payload["pcap"]["queue_progressing"])
        self.assertLessEqual(payload["pcap"]["last_progress_age_seconds"], 65)
        self.assertEqual(payload["pcap"]["warning_count"], 0)


    def test_system_health_treats_fresh_capture_hold_as_advisory(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2),
            timespec="seconds",
        )
        fresh_at = self.portal.format_iso_timestamp(dt.datetime.now(dt.timezone.utc), timespec="seconds")
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, updated_at
            ) VALUES ('pcap-held', 'pending', 'unit test', 120, '{}', ?, ?)
            """,
            (old_at, old_at),
        )
        self.conn.commit()
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE.write_text(json.dumps({
            "generated_at": fresh_at,
            "component": "pcap_broker",
            "relay_host": "relay-test",
            "pcap_workflow": {
                "state": "capture_protection_hold",
                "deferred": True,
                "reason": "Zeek capture loss exceeds threshold",
                "processed": 0,
                "operational_failures": 0,
            },
        }), encoding="utf-8")

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertEqual(payload["pcap"]["warning_count"], 0)
        self.assertTrue(payload["pcap"]["capture_protection"]["active"])
        self.assertTrue(payload["pcap"]["advisories"])


    def test_system_health_rejects_stale_capture_hold_exemption(self) -> None:
        old_at = self.portal.format_iso_timestamp(
            dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2),
            timespec="seconds",
        )
        self.conn.execute(
            """
            INSERT INTO pcap_requests (
              request_id, status, reason, max_window_seconds, request_json,
              created_at, updated_at
            ) VALUES ('pcap-stale-hold', 'pending', 'unit test', 120, '{}', ?, ?)
            """,
            (old_at, old_at),
        )
        self.conn.commit()
        self.portal.SOC_ALERT_PCAP_WORKFLOW_STATE_FILE.write_text(json.dumps({
            "generated_at": old_at,
            "component": "pcap_broker",
            "pcap_workflow": {
                "state": "capture_protection_hold",
                "deferred": True,
                "reason": "stale hold",
            },
        }), encoding="utf-8")

        payload = self.portal.n8n_beacon_history_response({"hours": ["24"]})

        self.assertFalse(payload["pcap"]["capture_protection"]["active"])
        self.assertTrue(any("pending PCAP request" in item for item in payload["pcap"]["warnings"]))
        self.assertTrue(any("telemetry is stale" in item for item in payload["pcap"]["warnings"]))


    def test_event_snapshot_uses_consistent_status_and_metrics_counts(self) -> None:
        payload = self.portal.soc_alert_events_snapshot()

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["counts"]["open"], 2)
        self.assertEqual(payload["counts"]["suppressed"], 0)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["open"], 2)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["suppressed"], 1)
        self.assertEqual(payload["metrics"]["by_analyst_status"]["total"], payload["counts"]["total"])
        self.assertEqual(
            set(payload["revisions"]),
            {
                "incidents",
                "asset_inventory",
                "dhcp_asset_discovery",
                "software_inventory",
                "ac_hunter",
            },
        )
        self.assertTrue(all(len(value) == 64 for value in payload["revisions"].values()))


    def test_live_revisions_do_not_expose_incident_or_asset_records(self) -> None:
        revisions = self.portal.dashboard_live_revisions()
        encoded = json.dumps(revisions)

        self.assertEqual(
            set(revisions),
            {
                "incidents",
                "asset_inventory",
                "dhcp_asset_discovery",
                "software_inventory",
                "ac_hunter",
            },
        )
        self.assertNotIn("Newest detection", encoded)
        self.assertNotIn("192.0.2.10", encoded)
        for value in revisions.values():
            self.assertRegex(value, r"^[0-9a-f]{64}$")


    def test_incident_revision_changes_when_a_case_is_added(self) -> None:
        initial = self.portal.incident_response_live_revision()
        self.conn.execute(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL,
              representative_alert_id TEXT NOT NULL,
              status TEXT NOT NULL,
              agent_status TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            INSERT INTO incident_response_cases (
              case_id, group_id, dashboard_group_id,
              representative_alert_id, status, agent_status, updated_at
            ) VALUES (?, ?, ?, ?, 'open', 'queued', ?)
            """,
            (
                "ir-revision-unit",
                "stable-revision-unit",
                self.portal.soc_alert_group_id(
                    "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
                ),
                "newest-alert",
                "2026-07-29 12:00:00Z",
            ),
        )
        self.conn.commit()

        changed = self.portal.incident_response_live_revision()

        self.assertNotEqual(changed, initial)


    def test_file_revision_changes_without_exposing_file_contents(self) -> None:
        path = Path(self.tmp.name) / "revision-state.json"
        initial = self.portal._bounded_file_revision(path, 1024)
        path.write_text('{"hostname":"sensitive-host.local"}', encoding="utf-8")

        changed = self.portal._bounded_file_revision(path, 1024)

        self.assertNotEqual(changed, initial)
        self.assertNotIn("sensitive-host", changed)


    def test_live_ai_activity_shows_primary_codex_model_with_effort(self) -> None:
        merged = self.portal.merge_live_llm_activity(
            {
                "active": False,
                "label": "AI Alert Triage",
                "detail": "Idle · Assigned: Ollama · previous-local:latest",
                "model": "Ollama · previous-local:latest",
                "provider": "Ollama",
                "route": "ollama:previous-local:latest",
                "counts": {"analyzing": 0, "queued": 2},
            },
            {
                "status": "running",
                "active_phase": "primary_analysis",
                "active_model": "gpt-5.6-sol",
                "active_model_path": "frontier-codex-cli",
                "active_model_route": "codex-cli:gpt-5.6-sol:xhigh",
                "active_provider": "codex-cli",
            },
        )

        self.assertTrue(merged["active"])
        self.assertEqual(merged["phase"], "primary_analysis")
        self.assertEqual(merged["provider"], "Codex CLI")
        self.assertEqual(merged["route"], "codex-cli:gpt-5.6-sol:xhigh")
        self.assertEqual(merged["model"], "Codex CLI · gpt-5.6-sol (xhigh)")
        self.assertEqual(
            merged["detail"],
            "Analyzing · Running: Codex CLI · gpt-5.6-sol (xhigh)",
        )
        self.assertEqual(merged["counts"]["analyzing"], 1)
        self.assertEqual(merged["counts"]["queued"], 2)


    def test_report_provenance_uses_observed_run_fields_not_current_settings(self) -> None:
        historical = self.portal.decorate_llm_analysis_record(
            {
                "status": "success",
                "agent_role": "incident-responder",
                "mode": "codex-cli",
                "model": "gpt-5.6-sol",
                "model_path": "frontier-codex-cli",
                "model_route": "codex-cli:gpt-5.6-sol:high",
            },
            live=False,
        )
        idle = self.portal.decorate_llm_analysis_record(
            {
                "status": "success",
                "agent_role": "incident-responder",
                "model": "gpt-5.6-sol",
                "model_route": "codex-cli:gpt-5.6-sol:high",
            },
            live=True,
        )

        self.assertEqual(historical["agent_label"], "Incident Responder")
        self.assertEqual(historical["job_type"], "incident_response_analysis")
        self.assertEqual(historical["job_label"], "Incident response investigation")
        self.assertEqual(
            historical["runtime_model_label"],
            "Codex CLI · gpt-5.6-sol (high)",
        )
        self.assertEqual(idle["runtime_model_label"], "No model running")
        self.assertEqual(idle["phase_label"], "Idle")
