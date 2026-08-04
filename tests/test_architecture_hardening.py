from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureHardeningTest(unittest.TestCase):
    def test_installer_signals_dashboard_only_after_new_builder_is_installed(self) -> None:
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        builder_copy = installer.index(
            'cp "$REPO_DIR/onion-sentinel-dashboard/scripts/build_soc_alerts_dashboard.py"'
        )
        refresh_load = installer.index(
            'launchctl load "$LAUNCHD_DIR/com.arron.soc.dashboard-refresh.plist"'
        )
        dashboard_wake = installer.index(
            'touch "$STACK_DIR/run/dashboard-refresh.wake"'
        )

        self.assertLess(builder_copy, refresh_load)
        self.assertLess(refresh_load, dashboard_wake)
        self.assertNotIn(
            '"$STACK_DIR/run/pcap-analysis.wake" "$STACK_DIR/run/dashboard-refresh.wake"',
            installer[:builder_copy],
        )

    def test_group_identity_excludes_mutable_workflow_state(self):
        code = (ROOT / "n8n/alert_store/lib/group_identity.js").read_text(encoding="utf-8")
        self.assertIn("'v2'", code)
        self.assertNotIn("triage_level", code)
        self.assertNotIn("filter_status", code)
        self.assertNotIn("suppression_key", code)

    def test_runtime_images_are_digest_pinned(self):
        compose = (ROOT / "n8n/docker-compose.yml").read_text(encoding="utf-8")
        self.assertNotIn("n8nio/n8n:latest", compose)
        self.assertGreaterEqual(compose.count("n8nio/n8n@sha256:"), 2)
        self.assertIn("postgres@sha256:", compose)
        self.assertIn("no-new-privileges:true", compose)

    def test_alert_store_exposes_operational_metrics(self):
        code = (ROOT / "n8n/alert_store/alert_store.js").read_text(encoding="utf-8")
        self.assertIn("async function operationalMetricsSnapshot", code)
        self.assertIn("'/metrics'", code)
        self.assertIn("oldest_pending_job_seconds", code)
        self.assertIn("oldest_pending_jobs", code)
        self.assertIn("latest_completed_jobs", code)
        self.assertIn("oldest_pending_pcap_seconds", code)
        self.assertIn("MIN(COALESCE(updated_at, created_at))", code)
        self.assertIn("ingest_latency_ms_average", code)

    def test_group_alias_is_refreshed_with_each_group_summary(self):
        code = (ROOT / "n8n/alert_store/alert_store.js").read_text(encoding="utf-8")
        summary = code[code.index("async function refreshAlertGroupSummary"):]
        summary = summary[:summary.index("async function rebuildAlertGroupSummariesUnlocked")]
        self.assertIn("INSERT INTO alert_group_alias", summary)
        self.assertIn("DELETE FROM alert_group_alias", summary)

    def test_ai_launch_agent_does_not_override_settings_model(self):
        plist = (ROOT / "n8n/launchd/com.arron.soc.ai-analysis.plist").read_text(encoding="utf-8")
        self.assertNotIn("--model", plist)
        self.assertNotIn("devstral:latest", plist)

    def test_codex_worker_has_a_context_safe_prompt_artifact_ceiling(self):
        plist = (ROOT / "n8n/launchd/com.arron.soc.ai-analysis-cli.plist").read_text(encoding="utf-8")
        self.assertIn("<string>--max-prompt-bytes</string>", plist)
        self.assertIn("<string>1048576</string>", plist)

    def test_installer_runs_locked_alert_store_install_from_package_directory(self):
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        self.assertIn('cd "$STACK_DIR/alert_store"', installer)
        self.assertIn(
            '/opt/homebrew/bin/npm ci --omit=dev',
            installer,
        )
        self.assertNotIn(
            '/opt/homebrew/bin/npm --prefix "$STACK_DIR/alert_store"',
            installer,
        )

    def test_installer_stops_runner_owned_orphan_codex_subprocesses(self):
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")

        self.assertIn('local runtime_codex_pids', installer)
        self.assertGreaterEqual(
            installer.count('index($0, "/onion-sentinel-codex-")'),
            3,
        )
        self.assertGreaterEqual(
            installer.count('index($0, "--ignore-user-config")'),
            3,
        )
        self.assertGreaterEqual(
            installer.count('index($0, "--ignore-rules")'),
            3,
        )
        self.assertIn(
            'kill -TERM "$pid" >/dev/null 2>&1 || true',
            installer,
        )
        self.assertIn(
            '[[ -z "$runtime_ai_pids" && -z "$runtime_codex_pids" ]]',
            installer,
        )

    def test_installer_holds_both_ai_worker_locks_across_deployment(self):
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")

        self.assertIn("start_ai_deployment_guard", installer)
        self.assertIn("release_ai_deployment_guard", installer)
        self.assertIn("ai-analysis-ollama-worker.lock", installer)
        self.assertIn("ai-analysis-cli-worker.lock", installer)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", installer)
        self.assertIn(
            "an Onion Sentinel AI investigation is active",
            installer,
        )
        self.assertLess(
            installer.index("if ! start_ai_deployment_guard"),
            installer.index("critical_launch_agents_down\n"),
        )
        self.assertIn(
            "release_ai_deployment_guard\n  return $exit_code",
            installer,
        )

    def test_local_analysis_workers_are_event_driven_with_timer_fallbacks(self):
        ollama_plist = (ROOT / "n8n/launchd/com.arron.soc.ai-analysis.plist").read_text(encoding="utf-8")
        cli_plist = (ROOT / "n8n/launchd/com.arron.soc.ai-analysis-cli.plist").read_text(encoding="utf-8")
        pcap_plist = (ROOT / "n8n/launchd/com.arron.soc.pcap-analysis.plist").read_text(encoding="utf-8")
        for plist, wake_path, worker_lock, lane in (
            (ollama_plist, "ai-analysis-ollama.wake", "ai-analysis-ollama-worker.lock", "ollama"),
            (cli_plist, "ai-analysis-cli.wake", "ai-analysis-cli-worker.lock", "cli"),
        ):
            self.assertIn("<key>WatchPaths</key>", plist)
            self.assertIn(wake_path, plist)
            self.assertIn(worker_lock, plist)
            self.assertIn("<key>KeepAlive</key>", plist)
            self.assertIn("<key>PathState</key>", plist)
            self.assertIn("<key>StartInterval</key>", plist)
            self.assertIn("<string>--provider-lane</string>", plist)
            self.assertIn(f"<string>{lane}</string>", plist)
        self.assertIn("<key>WatchPaths</key>", pcap_plist)
        self.assertIn("pcap-analysis.wake", pcap_plist)
        self.assertIn("<key>KeepAlive</key>", pcap_plist)
        self.assertIn("<key>PathState</key>", pcap_plist)
        self.assertIn("<key>StartInterval</key>", pcap_plist)

    def test_relay_pcap_broker_uses_single_flight_one_minute_recovery(self):
        timer = (ROOT / "relay/systemd/so-pcap-broker.timer").read_text(encoding="utf-8")
        worker = (ROOT / "relay/app/relay.py").read_text(encoding="utf-8")
        self.assertIn("OnUnitInactiveSec=1min", timer)
        self.assertNotIn("OnUnitActiveSec=", timer)
        self.assertIn("limit = 1", worker)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", worker)

    def test_dashboard_generation_is_decoupled_from_local_inference(self):
        scheduler = (ROOT / "n8n/bin/auto-run-ai-analysis.py").read_text(encoding="utf-8")
        refresher = (ROOT / "n8n/bin/refresh-soc-dashboard.py").read_text(encoding="utf-8")
        plist = (ROOT / "n8n/launchd/com.arron.soc.dashboard-refresh.plist").read_text(encoding="utf-8")
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(encoding="utf-8")
        self.assertIn("signal_dashboard_refresh", scheduler)
        self.assertNotIn("def refresh_portal", scheduler)
        self.assertNotIn("build_soc_alerts_dashboard.py", scheduler)
        self.assertIn("fcntl.LOCK_NB", refresher)
        self.assertIn("subprocess.TimeoutExpired", refresher)
        self.assertIn("<key>WatchPaths</key>", plist)
        self.assertIn("dashboard-refresh.wake", plist)
        self.assertIn("<key>KeepAlive</key>", plist)
        self.assertIn("<key>PathState</key>", plist)
        self.assertIn("<key>StartInterval</key>", plist)
        self.assertIn("com.arron.soc.dashboard-refresh.plist", installer)

    def test_harness_trace_retention_is_installed_and_hourly_bounded(self):
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        plist = (
            ROOT
            / "n8n/launchd/com.arron.onion-sentinel.harness-maintenance.plist"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'cp "$REPO_DIR/n8n/bin/maintain-investigation-harness.py"',
            installer,
        )
        self.assertIn(
            "com.arron.onion-sentinel.harness-maintenance.plist",
            installer,
        )
        self.assertIn("<key>StartInterval</key>", plist)
        self.assertIn("<integer>3600</integer>", plist)
        self.assertIn("<string>--apply</string>", plist)
        self.assertIn("<string>--max-terminal-runs</string>", plist)
        self.assertIn("<string>--max-live-bytes</string>", plist)

    def test_repair_install_preserves_live_scoring_policy(self):
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(encoding="utf-8")
        destination = '$STACK_DIR/alert_store/config/scoring_rules.json'
        guard = f'if [[ ! -f "{destination}" ]]'
        copy = (
            'cp "$REPO_DIR/n8n/alert_store/config/scoring_rules.json" '
            f'"{destination}"'
        )
        self.assertIn(guard, installer)
        self.assertIn(copy, installer)
        self.assertLess(installer.index(guard), installer.index(copy))

    def test_dashboard_documentation_uses_dedicated_service(self):
        dashboard_readme = (ROOT / "onion-sentinel-dashboard/README.md").read_text(encoding="utf-8")
        self.assertIn("onion_sentinel_server.py", dashboard_readme)
        self.assertIn(":8766", dashboard_readme)
        self.assertNotIn("sync-soc-alerts-portal.py", dashboard_readme)
        self.assertNotIn("sync_report_portal.py", dashboard_readme)

    def test_worker_wake_markers_are_consumable_and_batches_rearm(self):
        ai = (ROOT / "n8n/bin/auto-run-ai-analysis.py").read_text(encoding="utf-8")
        pcap = (ROOT / "n8n/bin/process-pcap-evidence.py").read_text(encoding="utf-8")
        dashboard = (ROOT / "n8n/bin/refresh-soc-dashboard.py").read_text(encoding="utf-8")
        self.assertIn("path.unlink(missing_ok=True)", ai)
        self.assertIn("path.unlink(missing_ok=True)", pcap)
        self.assertIn("signal_follow_up(args.wake_file)", pcap)
        self.assertIn("args.wake_file.unlink(missing_ok=True)", dashboard)


if __name__ == "__main__":
    unittest.main()
