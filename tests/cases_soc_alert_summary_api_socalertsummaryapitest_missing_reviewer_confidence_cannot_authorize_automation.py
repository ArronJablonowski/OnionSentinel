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

class SocAlertSummaryApiTestMissingReviewerConfidenceCannotAuthorizeAutomationCases:
    def test_missing_reviewer_confidence_cannot_authorize_automation(self) -> None:
        authorization = self.portal._soc_reviewer_automation_authorization({
            "reviewer_confidence": "",
            "automation_authorization": {},
        })
        self.assertFalse(authorization["authorized"])
        self.assertTrue(authorization["legacy_confidence_fallback"])


    def test_detail_sections_collapse_by_default(self) -> None:
        detail_html = (
            "<h3>Alert Summary</h3><p>summary context</p>"
            "<h3>Network And Flow Details</h3><p>flow context</p>"
            "<h4>Nested Evidence</h4><p>stays inside</p>"
            "<h3>TShark Corroboration</h3><p>packet parser context</p>"
            "<h3>Threat Context</h3><p>ioc context</p>"
            "<h3>Analyst Notes</h3><p>operator notes</p>"
            "<h3>Other Section</h3><p>remains expanded</p>"
        )

        collapsed = self.portal.soc_alert_collapse_detail_sections(detail_html)

        self.assertEqual(collapsed.count('class="detail-report-section detail-collapsible-section'), 5)
        self.assertNotIn("<details open", collapsed)
        self.assertIn("<summary>Alert Summary</summary>", collapsed)
        self.assertIn("<summary>Network And Flow Details</summary>", collapsed)
        self.assertIn("<summary>TShark Findings</summary>", collapsed)
        self.assertIn("<summary>Threat Context</summary>", collapsed)
        self.assertIn("<summary>Analyst Notes</summary>", collapsed)
        self.assertIn("<h4>Nested Evidence</h4><p>stays inside</p></div></details>", collapsed)
        self.assertIn("<h3>Other Section</h3><p>remains expanded</p>", collapsed)


    def test_alert_list_uses_summary_table_and_orders_newest_first(self) -> None:
        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 2)
        self.assertEqual(payload["status_counts"]["open"], 2)
        self.assertEqual(payload["status_counts"]["suppressed"], 1)
        self.assertEqual(payload["status_counts"]["acknowledged"], 0)
        self.assertEqual(payload["status_counts"]["total"], 3)
        self.assertEqual(payload["active_total"], 2)
        self.assertEqual(payload["active_highest_severity"], "critical")
        self.assertEqual(payload["active_severity_counts"], payload["severity_counts"])
        self.assertEqual(payload["severity_counts"]["critical"], 1)
        self.assertEqual(payload["severity_counts"]["high"], 1)
        self.assertEqual(payload["severity_counts"]["medium"], 0)
        self.assertEqual(payload["severity_counts"]["low"], 0)
        self.assertEqual(payload["severity_counts"]["informational"], 0)
        self.assertEqual(payload["top_endpoints"]["source_ip"], "192.0.2.10")
        self.assertEqual(payload["top_endpoints"]["destination_ip"], "198.51.100.10")
        self.assertEqual(payload["top_endpoints"]["destination_port"], "443")
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["seen_count"], 5)
        self.assertEqual(payload["alerts"][0]["ai_status_key"], "queued")
        self.assertEqual(payload["alerts"][0]["ai_status_label"], "Queued")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "none")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "None")
        self.assertEqual(payload["alerts"][0]["pcap_size_bytes"], 0)
        self.assertEqual(payload["alerts"][0]["detection_outcome"], "")
        self.assertEqual(payload["alerts"][0]["detection_outcome_label"], "n/a")
        self.assertEqual(payload["alerts"][0]["incident_case_id"], "")
        self.assertEqual(payload["alerts"][0]["incident_status"], "not_escalated")
        self.assertEqual(payload["alerts"][0]["incident_agent_status"], "not_queued")
        self.assertNotIn("backend-suppressed-alert", [alert["representative_alert_id"] for alert in payload["alerts"]])


    def test_manual_incident_escalation_removes_every_group_alias_from_soc_alerts(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        older_group_id = self.portal.soc_alert_group_id(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted"
        )
        stable_group_id = "stable-incident-unit"
        self.conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL
            );
            CREATE TABLE incident_response_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              detail_json TEXT NOT NULL
            );
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO incident_response_cases VALUES (?, ?, ?)",
            ("ir-manual-unit", stable_group_id, newest_group_id),
        )
        self.conn.execute(
            """
            INSERT INTO incident_response_events (case_id, event_type, detail_json)
            VALUES (?, 'escalated', ?)
            """,
            (
                "ir-manual-unit",
                json.dumps({"dashboard_group_id": newest_group_id}),
            ),
        )
        self.conn.execute(
            "INSERT INTO alert_group_alias VALUES (?, ?)",
            (older_group_id, stable_group_id),
        )
        self.conn.commit()

        status, open_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        _, all_payload = self.portal.soc_alerts_query_response({"limit": ["10"]})
        metrics_status, metrics = self.portal.soc_alert_metrics_response({"since": [""]})
        status_payload = self.portal.soc_alert_status_response()

        self.assertEqual(status, 200)
        self.assertEqual(metrics_status, 200)
        self.assertEqual(open_payload["total_matching"], 0)
        self.assertEqual(open_payload["active_total"], 0)
        self.assertEqual(open_payload["status_counts"]["total"], 1)
        self.assertEqual(all_payload["total_matching"], 1)
        self.assertEqual(
            [alert["representative_alert_id"] for alert in all_payload["alerts"]],
            ["backend-suppressed-alert"],
        )
        self.assertEqual(metrics["grouped_total"], 1)
        self.assertEqual(metrics["by_analyst_status"]["total"], 1)
        self.assertEqual(status_payload["counts"]["open"], 0)
        self.assertEqual(status_payload["counts"]["escalated"], 2)
        self.assertEqual(status_payload["counts"]["total"], 1)


    def test_automatic_incident_event_does_not_remove_soc_alert_group(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.conn.executescript(
            """
            CREATE TABLE incident_response_cases (
              case_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL UNIQUE,
              dashboard_group_id TEXT NOT NULL
            );
            CREATE TABLE incident_response_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              case_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              detail_json TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO incident_response_cases VALUES (?, ?, ?)",
            ("ir-auto-unit", "stable-auto-unit", newest_group_id),
        )
        self.conn.execute(
            """
            INSERT INTO incident_response_events (case_id, event_type, detail_json)
            VALUES (?, 'auto_escalated', ?)
            """,
            ("ir-auto-unit", json.dumps({"dashboard_group_id": newest_group_id})),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )

        self.assertEqual(status, 200)
        self.assertEqual(payload["total_matching"], 2)
        alerts = {
            alert["representative_alert_id"]: alert
            for alert in payload["alerts"]
        }
        self.assertIn("newest-alert", alerts)
        self.assertEqual(alerts["newest-alert"]["incident_case_id"], "ir-auto-unit")
        self.assertEqual(alerts["newest-alert"]["incident_status"], "open")
        self.assertEqual(alerts["newest-alert"]["incident_agent_status"], "queued")


    def test_active_metrics_are_independent_of_page_size_and_selected_status_bucket(self) -> None:
        _, one_row = self.portal.soc_alerts_query_response({"limit": ["1"], "analyst_status": ["open"]})
        _, all_rows = self.portal.soc_alerts_query_response({"limit": ["100"], "analyst_status": ["open"]})
        _, suppressed_view = self.portal.soc_alerts_query_response({"limit": ["1"], "analyst_status": ["suppressed"]})

        self.assertEqual(one_row["count"], 1)
        self.assertEqual(one_row["total_matching"], 2)
        self.assertEqual(all_rows["count"], 2)
        self.assertEqual(one_row["active_total"], 2)
        self.assertEqual(one_row["active_total"], all_rows["active_total"])
        self.assertEqual(one_row["active_severity_counts"], all_rows["active_severity_counts"])
        self.assertEqual(one_row["active_severity_counts"], {
            "critical": 1,
            "high": 1,
            "medium": 0,
            "low": 0,
            "informational": 0,
        })
        self.assertEqual(suppressed_view["total_matching"], 1)
        self.assertEqual(suppressed_view["active_total"], one_row["active_total"])
        self.assertEqual(suppressed_view["active_severity_counts"], one_row["active_severity_counts"])
        self.assertEqual(suppressed_view["active_highest_severity"], "critical")


    def test_alert_list_marks_groups_with_parsed_pcap_analysis(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "unit-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"group_id": newest_group_id, "alert_id": "newest-alert"},
                    "pcap_files": [{"name": "unit.pcap", "size_bytes": 128}],
                    "zeek": {"available": True},
                    "tshark": {"available": False},
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "analyzed")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "Analyzed")
        self.assertEqual(payload["alerts"][0]["pcap_size_bytes"], 128)


    def test_alert_list_aggregates_group_pcap_size_and_latest_detection_outcome(self) -> None:
        group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        group_id = self.portal.soc_alert_group_id(group_key)
        pcap_values = (
            ("request-one", "sha-one", 1024),
            ("request-one-retry", "sha-one", 1024),
            ("request-two", "sha-two", 2048),
        )
        for request_id, sha256, size_bytes in pcap_values:
            self.conn.execute(
                """
                INSERT INTO pcap_requests (
                  request_id, status, alert_id, group_id, group_key, reason,
                  max_window_seconds, artifact_path, artifact_sha256,
                  artifact_size_bytes, request_json, created_at, updated_at
                ) VALUES (?, 'fulfilled', 'newest-alert', ?, ?, 'unit test',
                          300, ?, ?, ?, '{}', ?, ?)
                """,
                (
                    request_id,
                    group_id,
                    group_key,
                    f"/tmp/{request_id}.pcap",
                    sha256,
                    size_bytes,
                    "2026-07-03  12:01:00Z",
                    "2026-07-03  12:01:00Z",
                ),
            )
        for analysis_id, generated_at, outcome in (
            ("analysis-old", "2026-07-03  12:01:00Z", "true_positive_suspicious"),
            ("analysis-new", "2026-07-03  12:02:00Z", "false_positive_logic_rule"),
        ):
            self.conn.execute(
                """
                INSERT INTO ai_analysis_runs (
                  analysis_id, group_id, alert_id, generated_at,
                  detection_outcome, response_json, created_at
                ) VALUES (?, ?, 'newest-alert', ?, ?, '{}', ?)
                """,
                (analysis_id, group_id, generated_at, outcome, generated_at),
            )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        newest = payload["alerts"][0]
        self.assertEqual(newest["pcap_size_bytes"], 3072)
        self.assertEqual(newest["detection_outcome"], "false_positive_logic_rule")
        self.assertEqual(newest["detection_outcome_label"], "FP - Rule")


    def test_disagreement_freshness_and_adjudication_guard_follow_current_analysis(self) -> None:
        group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        group_id = self.portal.soc_alert_group_id(group_key)
        stable_group_id = "stable-detection-unit"
        self.conn.executescript(
            """
            CREATE TABLE alert_group_alias (
              legacy_group_id TEXT PRIMARY KEY,
              stable_group_id TEXT NOT NULL
            );
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT PRIMARY KEY,
              status TEXT,
              primary_outcome TEXT,
              primary_confidence TEXT,
              reviewer_outcome TEXT,
              reviewer_confidence TEXT,
              agreement TEXT,
              material_disagreement INTEGER,
              disputed_fields_json TEXT,
              generated_at TEXT
            );
            CREATE TABLE analyst_adjudications (
              adjudication_id TEXT PRIMARY KEY,
              dashboard_group_id TEXT NOT NULL,
              stable_group_id TEXT NOT NULL,
              case_id TEXT,
              analysis_id TEXT NOT NULL,
              outcome_override TEXT NOT NULL,
              confidence TEXT NOT NULL,
              rationale TEXT NOT NULL,
              evidence_gap TEXT,
              next_action TEXT,
              reviewer TEXT NOT NULL,
              event_status TEXT,
              detection_validity TEXT,
              activity_disposition TEXT,
              handling TEXT,
              duplicate_of TEXT,
              case_resolution_reason TEXT,
              created_at TEXT NOT NULL
            );
            """
        )
        self.conn.execute(
            "INSERT INTO alert_group_alias VALUES (?, ?)",
            (group_id, stable_group_id),
        )
        self.conn.execute(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, generated_at, model,
              detection_outcome, confidence, evidence_hash, response_json, created_at
            ) VALUES (?, ?, 'newest-alert', ?, 'primary-model', ?, 'high',
                      'evidence-unit', ?, ?)
            """,
            (
                "analysis-disputed",
                stable_group_id,
                "2026-07-03  11:59:00Z",
                "true_positive_suspicious",
                json.dumps({
                    "evidence_used": ["alert", "flow"],
                    "evidence_gaps": ["endpoint process tree unavailable"],
                }),
                "2026-07-03  11:59:00Z",
            ),
        )
        self.conn.execute(
            """
            INSERT INTO ai_second_opinion_runs VALUES (
              'analysis-disputed', 'completed', 'true_positive_suspicious',
              'high', 'false_positive_logic_rule', 'medium', 'disagree',
              1, '["detection_outcome"]', '2026-07-03  11:59:30Z'
            )
            """
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        newest = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )

        self.assertEqual(status, 200)
        self.assertEqual(newest["analysis_id"], "analysis-disputed")
        self.assertEqual(newest["freshness_status"], "stale")
        self.assertEqual(newest["coverage_status"], "gaps")
        self.assertEqual(newest["primary_outcome"], "true_positive_suspicious")
        self.assertEqual(newest["reviewer_outcome"], "false_positive_logic_rule")
        self.assertEqual(newest["final_review_status"], "disputed_pending_human")

        ok, conflict = self.portal.update_soc_alert_status({
            "id": group_id,
            "status": "suppressed",
            "reason": "should require analyst review",
        })
        self.assertFalse(ok)
        self.assertEqual(conflict["status"], 409)

        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET agreement = 'partial_disagreement', material_disagreement = 0
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()
        _status, advisory_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        advisory = next(
            alert for alert in advisory_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            advisory["final_review_status"],
            "review_completed_not_authorized",
        )
        ok, conflict = self.portal.update_soc_alert_status({
            "id": group_id,
            "status": "suppressed",
            "reason": "medium review cannot authorize suppression",
        })
        self.assertFalse(ok)
        self.assertEqual(conflict["status"], 409)

        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET reviewer_confidence = 'high'
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()
        _status, high_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        high_advisory = next(
            alert for alert in high_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            high_advisory["final_review_status"],
            "reviewer_advisory",
        )

        self.conn.execute(
            """
            UPDATE ai_analysis_runs
            SET response_json = ?
            WHERE analysis_id = 'analysis-disputed'
            """,
            (
                json.dumps({
                    "_second_opinion": {
                        "automation_authorization": {
                            "authorized": False,
                            "reason_code": (
                                "reviewer_confidence_below_"
                                "automation_threshold"
                            ),
                        },
                    },
                }),
            ),
        )
        self.conn.commit()
        _status, denied_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        explicitly_denied = next(
            alert for alert in denied_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            explicitly_denied["final_review_status"],
            "review_completed_not_authorized",
        )
        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET status = 'failed', agreement = '', material_disagreement = 0
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()
        _status, failed_payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        failed_review = next(
            alert for alert in failed_payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(
            failed_review["final_review_status"],
            "review_required_failed",
        )
        self.assertEqual(failed_review["reviewer_error"], "")
        self.conn.execute(
            """
            UPDATE ai_second_opinion_runs
            SET status = 'completed', agreement = 'material_disagreement',
                material_disagreement = 1
            WHERE analysis_id = 'analysis-disputed'
            """
        )
        self.conn.commit()

        self.conn.execute(
            """
            INSERT INTO analyst_adjudications (
              adjudication_id, dashboard_group_id, stable_group_id, case_id,
              analysis_id, outcome_override, confidence, rationale,
              evidence_gap, next_action, reviewer, event_status,
              detection_validity, activity_disposition, handling, duplicate_of,
              case_resolution_reason, created_at
            ) VALUES (
              'adj-unit', ?, ?, NULL, 'analysis-disputed',
              'false_positive_logic_rule', 'high',
              'Corroborated by flow evidence.',
              'Endpoint process tree unavailable', 'Acquire endpoint telemetry',
              'unit-analyst', 'observed', 'logic_error', 'benign', 'no_action',
              NULL, NULL, '2026-07-03  12:02:00Z'
            )
            """,
            ("f" * 12, stable_group_id),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response(
            {"limit": ["10"], "analyst_status": ["open"]}
        )
        newest = next(
            alert for alert in payload["alerts"]
            if alert["representative_alert_id"] == "newest-alert"
        )
        self.assertEqual(status, 200)
        self.assertEqual(newest["final_review_status"], "adjudicated")
        self.assertEqual(newest["detection_outcome"], "true_positive_suspicious")
        self.assertEqual(newest["effective_outcome"], "false_positive_logic_rule")
        self.assertEqual(newest["effective_outcome_label"], "FP - Rule")
        self.assertEqual(newest["adjudication"]["reviewer"], "unit-analyst")
        self.assertEqual(newest["adjudication"]["detection_validity"], "logic_error")
        history_status, history = self.portal.soc_adjudication_history_response(group_id)
        self.assertEqual(history_status, 200)
        self.assertEqual(history["history"][0]["adjudication_id"], "adj-unit")

        ok, _payload = self.portal.update_soc_alert_status({
            "id": group_id,
            "status": "suppressed",
            "reason": "adjudicated handling",
        })
        self.assertTrue(ok)


    def test_alert_list_batches_page_enrichment_without_per_group_lookup(self) -> None:
        group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        for alert_id, last_seen, external_intel in (
            (
                "enrichment-errors",
                "2026-07-03  12:02:00Z",
                {"errors": [{"source": "synthetic"}]},
            ),
            (
                "enrichment-records",
                "2026-07-03  12:01:00Z",
                {"records": [{"source": "synthetic"}]},
            ),
        ):
            self.conn.execute(
                """
                INSERT INTO alerts (
                  alert_id, first_seen, last_seen, timestamp, rule_name,
                  source_ip, destination_ip, triage_level, filter_status,
                  enrichment_json, alert_json, raw_event_json
                ) VALUES (?, ?, ?, ?, 'Newest detection', '192.0.2.10',
                          '198.51.100.10', 'critical', 'accepted', ?, '{}', '{}')
                """,
                (
                    alert_id,
                    last_seen,
                    last_seen,
                    last_seen,
                    json.dumps({"external_intel": external_intel}),
                ),
            )
        self.conn.commit()

        with mock.patch.object(
            self.portal,
            "soc_alert_group_enrichment_json",
            side_effect=AssertionError("per-group enrichment lookup must not run"),
        ):
            status, payload = self.portal.soc_alerts_query_response(
                {"limit": ["10"], "analyst_status": ["open"]}
            )

        self.assertEqual(status, 200)
        newest = next(alert for alert in payload["alerts"] if alert["group_key"] == group_key)
        self.assertEqual(newest["enrichment_status_key"], "enriched")
        self.assertEqual(newest["enrichment_record_count"], 1)


    def test_detail_fragment_rejects_legacy_layout_instead_of_appending_pcap(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR.mkdir()
        (self.portal.SOC_ALERT_DETAIL_DIR / f"{newest_group_id}.html").write_text(
            "<h2>AI Model Used</h2><h4>PCAP Analysis Findings</h4><ul><li>n/a</li></ul>",
            encoding="utf-8",
        )
        (self.portal.SOC_ALERT_PCAP_ANALYSIS_DIR / "unit-pcap-analysis.json").write_text(
            json.dumps(
                {
                    "request": {"request_id": "unit", "group_id": newest_group_id, "alert_id": "newest-alert"},
                    "generated_at": "2026-07-03  12:01:00-06:00",
                    "pcap_files": [{"name": "unit.pcap", "size_bytes": 128}],
                    "zeek": {
                        "available": True,
                        "record_counts": {"conn": 1},
                        "top_connections": [{"id.orig_h": "192.0.2.10", "id.resp_h": "198.51.100.10"}],
                    },
                    "tshark": {
                        "available": True,
                        "samples": [{"protocol_hierarchy": "frame\\nip\\ntcp", "conversations": "192.0.2.10 <-> 198.51.100.10"}],
                    },
                }
            ),
            encoding="utf-8",
        )

        status, payload = self.portal.soc_alert_detail_fragment_response(newest_group_id)

        self.assertEqual(status, 200)
        self.assertFalse(payload["layout_valid"])
        self.assertTrue(payload["layout_issues"])
        self.assertIn("Detailed Alert Report layout error", payload["detail_html"])
        self.assertIn("PCAP Analysis Findings", payload["detail_html"])
        self.assertNotIn("Parsed PCAP Evidence", payload["detail_html"])
        self.assertNotIn("Top Connections", payload["detail_html"])
        self.assertNotIn("192.0.2.10", payload["detail_html"])


    def test_pcap_request_endpoint_queues_group_for_broker(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.conn.execute(
            """
            INSERT INTO alerts (
              alert_id, first_seen, last_seen, timestamp, source_ip, source_port,
              destination_ip, destination_port, transport_protocol, alert_json,
              raw_event_json, triage_level, filter_status
            )
            VALUES (
              'newest-alert', '2026-07-03  12:00:01Z', '2026-07-03  12:00:01Z',
              '2026-07-03  12:00:01Z', '192.0.2.10', 5555, '198.51.100.10',
              443, 'tcp', '{}', '{"suricata":{"capture_file":"/nsm/suripcap/1/so-pcap.unit"}}',
              'critical', 'accepted'
            )
            """
        )
        self.conn.commit()

        status, payload = self.portal.soc_alert_pcap_request_response(
            newest_group_id,
            {"reason": "unit test analyst request", "requested_by": "unit-test", "require_source_port": True},
        )

        self.assertEqual(status, 202)
        self.assertTrue(payload["ok"])
        row = self.conn.execute("SELECT * FROM pcap_requests WHERE group_id = ?", (newest_group_id,)).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["reason"], "unit test analyst request")
        self.assertEqual(row["requested_by"], "unit-test")
        self.assertEqual(row["source_ip"], "192.0.2.10")
        self.assertEqual(row["destination_ip"], "198.51.100.10")
        request_json = json.loads(row["request_json"])
        self.assertTrue(request_json["require_source_port"])
        self.assertEqual(request_json["capture_file"], "/nsm/suripcap/1/so-pcap.unit")


    def test_production_pcap_request_uses_alert_store_api(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        response = mock.MagicMock()
        response_body = json.dumps({
            "ok": True,
            "status": "pending",
            "request": {"request_id": "synthetic-request", "group_id": group_id},
        }).encode("utf-8")
        response.read.return_value = response_body
        response.headers = {"Content-Length": str(len(response_body))}
        context = mock.MagicMock()
        context.__enter__.return_value = response
        self.portal.SOC_ALERT_STORE_API_URL = "http://127.0.0.1:8787"

        with mock.patch.object(self.portal.urllib_request, "urlopen", return_value=context) as urlopen:
            status, payload = self.portal.soc_alert_pcap_request_response(
                group_id,
                {"reason": "unit test request"},
            )

        self.assertEqual(status, 202)
        self.assertEqual(payload["status"], "pending")
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8787/pcap/request")
        sent = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent["group_id"], group_id)


    def test_pcap_request_endpoint_requeues_failed_request(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        status, first = self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "first request"})
        self.assertEqual(status, 202)
        request_id = first["request"]["request_id"]
        self.conn.execute(
            "UPDATE pcap_requests SET status = 'failed', error = 'no matching packets found', completed_at = updated_at WHERE request_id = ?",
            (request_id,),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "first request"})

        self.assertEqual(status, 202)
        row = self.conn.execute("SELECT * FROM pcap_requests WHERE request_id = ?", (request_id,)).fetchone()
        self.assertEqual(payload["request"]["request_id"], request_id)
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["reason"], "first request")
        self.assertIsNone(row["error"])


    def test_alert_list_marks_no_matching_packets_pcap_status(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.soc_alert_pcap_request_response(newest_group_id, {"reason": "unit test no packets"})
        self.conn.execute(
            "UPDATE pcap_requests SET status = 'failed', error = 'no matching packets found for requested window', request_json = ?, completed_at = updated_at WHERE group_id = ?",
            (
                json.dumps({"capture_file": "/nsm/suripcap/5/so-pcap.example"}),
                newest_group_id,
            ),
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
        self.assertEqual(payload["alerts"][0]["pcap_status_key"], "no-packets")
        self.assertEqual(payload["alerts"][0]["pcap_status_label"], "No Packets")


