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

class SocAlertSummaryApiTestLlmAnalysisLogIncludesDistinctSecondOpinionRunsCases:
    def test_llm_analysis_log_includes_distinct_second_opinion_runs(self) -> None:
        log_path = Path(self.tmp.name) / "llm-analysis-log.jsonl"
        log_path.write_text(json.dumps({
            "log_id": "analysis-review-unit",
            "status": "success",
            "agent_role": "soc-analyst",
            "started_at": "2026-07-29  10:00:00-06:00",
            "finished_at": "2026-07-29  10:02:00-06:00",
            "runtime_seconds": 120,
            "model": "primary-model",
            "model_path": "ollama",
            "gpu_temperature_celsius_max": 41.25,
            "gpu_utilization_percent_max": 88.5,
            "cpu_temperature_celsius_max": 49.75,
            "soc_temperature_celsius_max": 51.0,
            "memory_used_percent_max": 57.5,
            "power_watts_max": 33.25,
            "cpu_used_percent_max": 62.5,
            "alert": {
                "primary_alert_id": "newest-alert",
                "rule_name": "Reviewer visibility test",
                "alert_count": 3,
                "source_ip": "192.0.2.10",
                "destination_ip": "198.51.100.10",
            },
        }) + "\n", encoding="utf-8")
        self.portal.SOC_ALERT_LLM_ANALYSIS_LOG_INDEX = (
            self.portal.JsonlLogIndex(log_path)
        )
        self.conn.executescript(
            """
            CREATE TABLE ai_second_opinion_runs (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              alert_id TEXT NOT NULL,
              agent_role TEXT NOT NULL,
              trigger TEXT,
              status TEXT NOT NULL,
              reviewer_error TEXT,
              reviewer_model TEXT,
              reviewer_model_path TEXT,
              reviewer_outcome TEXT,
              reviewer_confidence TEXT,
              agreement TEXT,
              material_disagreement INTEGER NOT NULL DEFAULT 0,
              reviewer_runtime_seconds REAL,
              generated_at TEXT NOT NULL
            );
            INSERT INTO ai_second_opinion_runs VALUES (
              'analysis-review-unit', 'group-unit', 'newest-alert',
              'soc-analyst', 'Consequential conclusion', 'completed', NULL,
              'reviewer-model', 'frontier-codex-cli',
              'true_positive_suspicious', 'high', 'material_disagreement', 1,
              45.5, '2026-07-29  10:01:45-06:00'
            );
            CREATE TABLE ai_disagreement_adjudication_runs (
              analysis_id TEXT PRIMARY KEY,
              alert_id TEXT NOT NULL,
              agent_role TEXT NOT NULL,
              status TEXT NOT NULL,
              mode TEXT NOT NULL,
              adjudicator_error TEXT,
              model_route TEXT,
              decision TEXT,
              confidence TEXT,
              confidence_score REAL,
              adjudicator_runtime_seconds REAL,
              human_adjudication_required INTEGER NOT NULL,
              generated_at TEXT NOT NULL
            );
            INSERT INTO ai_disagreement_adjudication_runs VALUES (
              'analysis-review-unit', 'newest-alert', 'soc-analyst',
              'completed', 'shadow', NULL,
              'codex-cli:gpt-5.6-terra:medium', 'unresolved', 'medium',
              0.55, 30.0, 1, '2026-07-29  10:01:55-06:00'
            );
            """
        )
        self.conn.commit()

        payload = self.portal.llm_analysis_logs_response({
            "page": ["1"],
            "limit": ["25"],
        })

        self.assertEqual(payload["primary_total"], 1)
        self.assertEqual(payload["second_opinion_total"], 1)
        self.assertEqual(payload["disagreement_adjudication_total"], 1)
        self.assertEqual(payload["total"], 3)
        reviewer = next(
            item for item in payload["logs"]
            if item.get("run_kind") == "second_opinion"
        )
        self.assertEqual(reviewer["parent_log_id"], "analysis-review-unit")
        self.assertEqual(reviewer["job_label"], "Second-opinion review")
        self.assertEqual(reviewer["status"], "success")
        self.assertEqual(reviewer["runtime_seconds"], 45.5)
        self.assertEqual(
            reviewer["runtime_model_label"],
            "Codex CLI · reviewer-model",
        )
        self.assertEqual(
            reviewer["alert"]["rule_name"],
            "Reviewer visibility test",
        )
        self.assertEqual(reviewer["gpu_temperature_celsius_max"], 41.25)
        self.assertEqual(reviewer["gpu_utilization_percent_max"], 88.5)
        self.assertEqual(reviewer["cpu_temperature_celsius_max"], 49.75)
        self.assertEqual(reviewer["soc_temperature_celsius_max"], 51.0)
        self.assertEqual(reviewer["memory_used_percent_max"], 57.5)
        self.assertEqual(reviewer["power_watts_max"], 33.25)
        self.assertEqual(reviewer["cpu_used_percent_max"], 62.5)
        self.assertIn("material disagreement", reviewer["error"])
        adjudicator = next(
            item for item in payload["logs"]
            if item.get("run_kind") == "disagreement_adjudication"
        )
        self.assertEqual(
            adjudicator["parent_log_id"],
            "analysis-review-unit",
        )
        self.assertEqual(
            adjudicator["job_label"],
            "Disagreement adjudication",
        )
        self.assertEqual(adjudicator["status"], "success")
        self.assertEqual(adjudicator["runtime_seconds"], 30.0)
        self.assertEqual(
            adjudicator["runtime_model_label"],
            "Codex CLI · gpt-5.6-terra (medium)",
        )
        self.assertEqual(adjudicator["gpu_temperature_celsius_max"], 41.25)
        self.assertTrue(adjudicator["human_adjudication_required"])


    def test_llm_activity_reconciles_every_agent_role_from_database(self) -> None:
        log_path = Path(self.tmp.name) / "llm-analysis-log.jsonl"
        log_path.write_text(json.dumps({
            "log_id": "legacy-jsonl-id",
            "status": "success",
            "agent_role": "soc-analyst",
            "started_at": "2026-07-29  09:58:00-06:00",
            "finished_at": "2026-07-29  10:00:00-06:00",
            "model": "primary-model",
            "model_path": "ollama",
            "alert": {
                "primary_alert_id": "newest-alert",
                "rule_name": "Newest detection",
                "alert_count": 5,
            },
        }) + "\n", encoding="utf-8")
        self.portal.SOC_ALERT_LLM_ANALYSIS_LOG_INDEX = (
            self.portal.JsonlLogIndex(log_path)
        )
        self.conn.execute(
            "ALTER TABLE ai_analysis_runs ADD COLUMN "
            "agent_role TEXT NOT NULL DEFAULT 'soc-analyst'"
        )
        self.conn.executemany(
            """
            INSERT INTO ai_analysis_runs (
              analysis_id, group_id, alert_id, generated_at, model,
              model_path, detection_outcome, bluf, summary, confidence,
              artifact_path, evidence_hash, response_json, created_at,
              agent_role
            ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL,
                      NULL, NULL, '{}', ?, ?)
            """,
            [
                (
                    "database-id-for-legacy-run",
                    "legacy-group",
                    "newest-alert",
                    "2026-07-29  10:00:02-06:00",
                    "primary-model",
                    "ollama",
                    "2026-07-29  10:00:02-06:00",
                    "soc-analyst",
                ),
                (
                    "siem-engineer-run",
                    "engineering-group",
                    "older-alert",
                    "2026-07-29  11:00:00-06:00",
                    "engineering-model",
                    "frontier-codex-cli",
                    "2026-07-29  11:00:00-06:00",
                    "siem-engineer",
                ),
            ],
        )
        self.conn.commit()

        payload = self.portal.llm_analysis_logs_response({
            "page": ["1"],
            "limit": ["25"],
        })

        self.assertEqual(payload["telemetry_total"], 1)
        self.assertEqual(payload["database_recovered_total"], 1)
        self.assertEqual(payload["primary_total"], 2)
        self.assertEqual(payload["total"], 2)
        self.assertEqual(payload["agent_totals"]["soc-analyst"], 1)
        self.assertEqual(payload["agent_totals"]["siem-engineer"], 1)
        siem = next(
            item for item in payload["logs"]
            if item.get("agent_role") == "siem-engineer"
        )
        self.assertEqual(siem["agent_label"], "SIEM Engineer")
        self.assertEqual(siem["job_label"], "Detection engineering analysis")
        self.assertEqual(
            siem["runtime_model_label"],
            "Codex CLI · engineering-model",
        )
        self.assertEqual(siem["telemetry_source"], "analysis_run_database")


    def test_failed_report_without_observation_does_not_claim_assigned_model(self) -> None:
        historical = self.portal.decorate_llm_analysis_record(
            {
                "status": "failure",
                "agent_role": "incident-responder",
                "model": "",
                "model_path": "",
                "model_route": "",
                "model_started": False,
                "assigned_model": "gpt-5.6-sol",
                "assigned_model_path": "frontier-codex-cli",
                "assigned_model_route": "codex-cli:gpt-5.6-sol:xhigh",
            },
            live=False,
        )

        self.assertEqual(historical["runtime_model_label"], "No model started")
        self.assertNotIn(
            "gpt-5.6-sol",
            historical["runtime_model_label"],
        )


    def test_saved_response_report_shows_no_model_started(self) -> None:
        historical = self.portal.decorate_llm_analysis_record(
            {
                "status": "success",
                "agent_role": "soc-analyst",
                "input_mode": "saved_response",
                "model": "",
                "model_path": "",
                "model_route": "",
                "model_started": False,
                "assigned_model": "devstral:latest",
                "assigned_model_path": "ollama",
                "assigned_model_route": "ollama:devstral:latest",
            },
            live=False,
        )

        self.assertEqual(historical["runtime_model_label"], "No model started")
        self.assertNotIn(
            "devstral",
            historical["runtime_model_label"],
        )


    def test_live_preparing_phase_claims_no_running_model(self) -> None:
        runtime = self.portal.llm_runtime_model_state(
            {
                "status": "running",
                "active_phase": "preparing",
                "active_model": "",
                "active_model_path": "",
                "active_model_route": "",
                "active_provider": "",
            }
        )

        self.assertEqual(runtime["phase_label"], "Preparing analysis")
        self.assertEqual(runtime["label"], "No model running")
        self.assertEqual(
            runtime["detail"],
            "Preparing analysis · No model running",
        )


    def test_active_run_files_report_both_concurrent_models(self) -> None:
        active_records = [
            {
                "log_id": "codex-run",
                "status": "running",
                "runner_pid": 101,
                "started_at": "2026-07-24  12:00:00-06:00",
                "prompt_package": "/tmp/codex-prompt.json",
                "agent_role": "soc-analyst",
                "active_phase": "primary_analysis",
                "active_model": "gpt-5.6-sol",
                "active_model_path": "frontier-codex-cli",
                "active_model_route": "codex-cli:gpt-5.6-sol:high",
                "active_provider": "codex-cli",
            },
            {
                "log_id": "ollama-run",
                "status": "running",
                "runner_pid": 202,
                "started_at": "2026-07-24  12:00:01-06:00",
                "prompt_package": "/tmp/ollama-prompt.json",
                "agent_role": "incident-responder",
                "active_phase": "second_opinion",
                "active_model": "gemma4:31b",
                "active_model_path": "ollama",
                "active_model_route": "ollama:gemma4:31b",
                "active_provider": "ollama",
            },
        ]
        for record in active_records:
            (
                self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR
                / f"{record['log_id']}.json"
            ).write_text(json.dumps(record), encoding="utf-8")
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps({"ai": {"counts": {"analyzing": 0, "queued": 3}}}),
            encoding="utf-8",
        )

        with mock.patch.object(
            self.portal,
            "llm_analysis_process_commands",
            return_value=[
                "101 python /runtime/run-local-ai-analysis.py",
                "202 python /runtime/run-local-ai-analysis.py",
            ],
        ):
            current = self.portal.read_llm_current_analysis()

        self.assertEqual(current["status"], "running")
        self.assertEqual(current["active_count"], 2)
        self.assertEqual(current["phase_label"], "Concurrent analyses")
        self.assertIn("SOC Analyst", current["agent_label"])
        self.assertIn("Incident Responder", current["agent_label"])
        self.assertIn("SOC alert triage", current["job_label"])
        self.assertIn("Incident response investigation", current["job_label"])
        self.assertEqual(
            [record["log_id"] for record in current["active_runs"]],
            ["codex-run", "ollama-run"],
        )
        merged = self.portal.merge_live_llm_activity(
            {"label": "AI Alert Triage", "counts": {"analyzing": 0, "queued": 3}},
            current,
        )
        self.assertTrue(merged["active"])
        self.assertEqual(merged["phase"], "concurrent")
        self.assertEqual(merged["counts"]["analyzing"], 2)
        self.assertEqual(merged["counts"]["queued"], 3)
        self.assertIn("Codex CLI · gpt-5.6-sol (high)", merged["model"])
        self.assertIn("Ollama · gemma4:31b", merged["model"])
        self.assertIn("2 analyses running", merged["detail"])


    def test_stale_active_run_does_not_hide_last_completed_record(self) -> None:
        self.portal.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE.write_text(
            json.dumps(
                {
                    "log_id": "completed-run",
                    "status": "success",
                    "model": "gpt-5.5",
                }
            ),
            encoding="utf-8",
        )
        (
            self.portal.SOC_ALERT_LLM_ANALYSIS_ACTIVE_DIR
            / "stale-run.json"
        ).write_text(
            json.dumps(
                {
                    "log_id": "stale-run",
                    "status": "running",
                    "runner_pid": 909,
                    "prompt_package": "/tmp/reused-prompt.json",
                }
            ),
            encoding="utf-8",
        )

        with mock.patch.object(
            self.portal,
            "llm_analysis_process_commands",
            return_value=[
                "808 python /runtime/run-local-ai-analysis.py /tmp/reused-prompt.json",
            ],
        ):
            current = self.portal.read_llm_current_analysis()

        self.assertEqual(current["status"], "success")
        self.assertEqual(current["log_id"], "completed-run")
        self.assertNotIn("active_runs", current)


    def test_pid_status_supports_runs_without_prompt_path_in_command(self) -> None:
        commands = ["303 python /runtime/run-local-ai-analysis.py --generate-prompt"]

        self.assertTrue(
            self.portal.llm_analysis_process_active(
                "/tmp/generated-prompt.json",
                commands,
                303,
            )
        )
        self.assertFalse(
            self.portal.llm_analysis_process_active(
                "/tmp/generated-prompt.json",
                commands,
                404,
            )
        )
        self.assertTrue(
            self.portal.llm_analysis_process_active(
                "/tmp/generated-prompt.json",
                [
                    "505 python /runtime/run-local-ai-analysis.py "
                    "/tmp/generated-prompt.json",
                ],
            )
        )


    def test_event_snapshot_overrides_assigned_codex_with_active_ollama_reviewer(self) -> None:
        self.portal.SOC_ALERT_STATIC_STATUS_FILE.write_text(
            json.dumps(
                {
                    "ai": {
                        "active": True,
                        "label": "AI Alert Triage",
                        "detail": "Analyzing · Assigned: Codex CLI · gpt-5.5 (medium)",
                        "model": "Codex CLI · gpt-5.5 (medium)",
                        "provider": "Codex CLI",
                        "route": "codex-cli:gpt-5.5:medium",
                        "counts": {"analyzing": 1, "queued": 0},
                    },
                    "reports": {},
                }
            ),
            encoding="utf-8",
        )
        self.portal.SOC_ALERT_LLM_ANALYSIS_CURRENT_FILE.write_text(
            json.dumps(
                {
                    "status": "running",
                    "prompt_package": "/tmp/runtime-review-prompt.json",
                    "active_phase": "second_opinion",
                    "active_model": "gemma4:31b",
                    "active_model_path": "ollama",
                    "active_model_route": "ollama:gemma4:31b",
                    "active_provider": "ollama",
                    "model": "gpt-5.5",
                    "model_route": "codex-cli:gpt-5.5:medium",
                    "mode": "codex-cli",
                }
            ),
            encoding="utf-8",
        )

        with mock.patch.object(self.portal, "llm_analysis_process_active", return_value=True):
            payload = self.portal.soc_alert_events_snapshot()

        self.assertTrue(payload["ai"]["active"])
        self.assertEqual(payload["ai"]["phase"], "second_opinion")
        self.assertEqual(payload["ai"]["provider"], "Ollama")
        self.assertEqual(payload["ai"]["route"], "ollama:gemma4:31b")
        self.assertEqual(payload["ai"]["model"], "Ollama · gemma4:31b")
        self.assertEqual(
            payload["ai"]["detail"],
            "Second-opinion review · Running: Ollama · gemma4:31b",
        )


    def test_live_ai_activity_post_processing_claims_no_running_model(self) -> None:
        merged = self.portal.merge_live_llm_activity(
            {
                "active": True,
                "label": "AI Alert Triage",
                "model": "Codex CLI · gpt-5.5 (medium)",
                "counts": {"analyzing": 1},
            },
            {
                "status": "running",
                "active_phase": "post_processing",
                "active_model": "",
                "active_model_path": "",
                "active_model_route": "",
                "active_provider": "",
                "model": "gpt-5.5",
                "model_route": "codex-cli:gpt-5.5:medium",
                "mode": "codex-cli",
            },
        )

        self.assertTrue(merged["active"])
        self.assertEqual(merged["phase"], "post_processing")
        self.assertEqual(merged["provider"], "")
        self.assertEqual(merged["route"], "")
        self.assertEqual(merged["model"], "No model running")
        self.assertEqual(merged["detail"], "Finalizing analysis · No model running")


    def test_live_ai_activity_supports_legacy_running_record(self) -> None:
        runtime = self.portal.llm_runtime_model_state(
            {
                "status": "running",
                "mode": "codex-cli",
                "model": "gpt-5.5",
                "model_path": "frontier-codex-cli",
                "model_route": "codex-cli:gpt-5.5:medium",
            }
        )

        self.assertTrue(runtime["running"])
        self.assertEqual(runtime["phase"], "primary_analysis")
        self.assertEqual(runtime["provider"], "Codex CLI")
        self.assertEqual(runtime["route"], "codex-cli:gpt-5.5:medium")
        self.assertEqual(runtime["model"], "gpt-5.5")
        self.assertEqual(runtime["label"], "Codex CLI · gpt-5.5 (medium)")
        self.assertEqual(
            runtime["detail"],
            "Analyzing · Running: Codex CLI · gpt-5.5 (medium)",
        )


    def test_event_snapshot_cache_coalesces_concurrent_browser_clients(self) -> None:
        self.portal.SOC_ALERT_EVENTS_CACHE.clear()
        payload = {"ok": True, "event": "soc-alerts"}

        def slow_snapshot() -> dict:
            time.sleep(0.05)
            return payload

        with mock.patch.object(self.portal, "soc_alert_events_snapshot", side_effect=slow_snapshot) as snapshot:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: self.portal.cached_soc_alert_events_snapshot(), range(16)))

        self.assertEqual(results, [payload] * 16)
        self.assertEqual(snapshot.call_count, 1)


    def test_acknowledged_group_is_hidden_from_open_slice(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
            "repeat_count": 5,
        })

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 1)
        self.assertEqual(payload["active_total"], 1)
        self.assertEqual(payload["active_highest_severity"], "high")
        self.assertEqual(payload["active_severity_counts"]["critical"], 0)
        self.assertEqual(payload["active_severity_counts"]["high"], 1)
        self.assertEqual(payload["severity_counts"]["critical"], 0)
        self.assertEqual(payload["severity_counts"]["high"], 1)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "older-alert")


    def test_legacy_bulk_acknowledged_payload_is_read_only(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        older_group_id = self.portal.soc_alert_group_id(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted"
        )
        self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
            "repeat_count": 5,
        })

        ok, payload = self.portal.update_soc_alert_status({"acknowledged": [older_group_id]})

        self.assertTrue(ok)
        self.assertEqual(payload["statuses"][newest_group_id]["status"], "acknowledged")
        self.assertNotIn(older_group_id, payload["statuses"])


    def test_acknowledge_without_repeat_count_uses_current_group_count(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )

        ok, payload = self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
        })

        self.assertTrue(ok)
        self.assertEqual(payload["statuses"][newest_group_id]["status"], "acknowledged")
        self.assertEqual(payload["statuses"][newest_group_id]["repeat_count"], 5)
        status, open_payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})
        self.assertEqual(status, 200)
        self.assertNotIn("newest-alert", [alert["representative_alert_id"] for alert in open_payload["alerts"]])


    def test_many_individual_status_updates_do_not_replace_each_other(self) -> None:
        group_ids = []
        for index in range(12):
            group_id = self.insert_summary(
                f"medium|Load test {index}|192.0.2.{40 + index}|198.51.100.{40 + index}|accepted",
                f"load-alert-{index}",
                f"Load test {index}",
                "medium",
                f"2026-07-03  10:{index:02d}:00Z",
                1,
                index + 1,
            )
            group_ids.append(group_id)
        self.conn.commit()

        def write_status(item: tuple[int, str]) -> None:
            index, group_id = item
            status = "suppressed" if index % 3 == 0 else "acknowledged"
            self.portal.update_soc_alert_status({
                "id": group_id,
                "status": status,
                "repeat_count": index + 1,
                "reason": f"load test {index}" if status == "suppressed" else "",
            })

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(write_status, enumerate(group_ids)))

        statuses = self.portal.load_soc_alert_statuses()
        self.assertEqual({group_id for group_id in group_ids}, {group_id for group_id in group_ids if group_id in statuses})
        for index, group_id in enumerate(group_ids):
            expected_status = "suppressed" if index % 3 == 0 else "acknowledged"
            self.assertEqual(statuses[group_id]["status"], expected_status)
            self.assertEqual(statuses[group_id]["repeat_count"], index + 1)


    def test_bulk_status_persistence_merges_without_deleting_other_groups(self) -> None:
        newest_group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        older_group_id = self.portal.soc_alert_group_id(
            "high|Older detection|192.0.2.20|198.51.100.20|accepted"
        )
        self.portal.write_soc_alert_status(newest_group_id, {
            "status": "acknowledged",
            "repeat_count": 5,
            "updated_at": "2026-07-03  12:00:00Z",
        })

        self.portal.save_soc_alert_statuses_to_db({
            older_group_id: {
                "status": "suppressed",
                "repeat_count": 1,
                "reason": "unit test suppression",
                "updated_at": "2026-07-03  12:01:00Z",
            }
        })

        statuses = self.portal.load_soc_alert_statuses()
        self.assertEqual(statuses[newest_group_id]["status"], "acknowledged")
        self.assertEqual(statuses[older_group_id]["status"], "suppressed")


    def test_acknowledged_group_reopens_when_repeat_count_increases(self) -> None:
        newest_group_key = "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        newest_group_id = self.portal.soc_alert_group_id(newest_group_key)
        self.portal.update_soc_alert_status({
            "id": newest_group_id,
            "status": "acknowledged",
            "repeat_count": 5,
        })
        self.conn.execute(
            """
            UPDATE alert_group_summary
            SET raw_alert_count = 3, total_seen_count = 6
            WHERE group_id = ?
            """,
            (newest_group_id,),
        )
        self.conn.commit()

        status, payload = self.portal.soc_alerts_query_response({"limit": ["10"], "analyst_status": ["open"]})
        status_payload = self.portal.soc_alert_status_response()

        self.assertEqual(status, 200)
        self.assertEqual(payload["source"], "sqlite-summary")
        self.assertEqual(payload["total_matching"], 2)
        self.assertEqual(payload["alerts"][0]["representative_alert_id"], "newest-alert")
        self.assertNotIn(newest_group_id, status_payload["statuses"])


    def test_production_status_update_uses_alert_store_api(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        response = mock.MagicMock()
        response_body = json.dumps({
            "ok": True,
            "statuses": {group_id: {"status": "acknowledged", "repeat_count": 5}},
        }).encode("utf-8")
        response.read.return_value = response_body
        response.headers = {"Content-Length": str(len(response_body))}
        context = mock.MagicMock()
        context.__enter__.return_value = response
        self.portal.SOC_ALERT_STORE_API_URL = "http://127.0.0.1:8787"

        with mock.patch.object(self.portal.urllib_request, "urlopen", return_value=context) as urlopen:
            with mock.patch.object(self.portal, "write_soc_alert_status", side_effect=AssertionError("direct DB write")):
                ok, payload = self.portal.update_soc_alert_status({
                    "id": group_id,
                    "status": "acknowledged",
                    "repeat_count": 5,
                })

        self.assertTrue(ok)
        self.assertTrue(payload["ok"])
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8787/analyst-status")
        sent = json.loads(request.data.decode("utf-8"))
        self.assertEqual(sent["id"], group_id)
        self.assertEqual(sent["status"], "acknowledged")


    def test_direct_status_write_requires_explicit_offline_dr_mode(self) -> None:
        group_id = self.portal.soc_alert_group_id(
            "critical|Newest detection|192.0.2.10|198.51.100.10|accepted"
        )
        self.portal.SOC_ALERT_STORE_API_URL = ""
        self.portal.SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED = False

        with mock.patch.object(
            self.portal,
            "write_soc_alert_status",
            side_effect=AssertionError("direct DB write"),
        ):
            ok, payload = self.portal.update_soc_alert_status({
                "id": group_id,
                "status": "acknowledged",
                "repeat_count": 5,
            })

        self.assertFalse(ok)
        self.assertEqual(payload["status"], 503)
        self.assertIn("Direct SQLite writes are disabled", payload["error"])


