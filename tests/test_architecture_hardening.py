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

    def test_dashboard_builder_module_tree_is_fully_installed(self) -> None:
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(
            encoding="utf-8"
        )
        scripts = ROOT / "onion-sentinel-dashboard/scripts"
        for path in sorted(scripts.glob("dashboard_builder_*.py")):
            with self.subTest(path=path.name):
                self.assertIn(
                    f'$REPO_DIR/onion-sentinel-dashboard/scripts/{path.name}',
                    installer,
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
        routes = (
            ROOT / "n8n/alert_store/routes/health_routes.js"
        ).read_text(encoding="utf-8")
        service = (
            ROOT / "n8n/alert_store/services/health_service.js"
        ).read_text(encoding="utf-8")
        repository = (
            ROOT / "n8n/alert_store/repositories/health_repository.js"
        ).read_text(encoding="utf-8")
        self.assertIn("path: '/metrics'", routes)
        self.assertIn("async function metricsSnapshot", service)
        self.assertIn("oldest_pending_job_seconds", service)
        self.assertIn("oldest_pending_jobs", service)
        self.assertIn("latest_completed_jobs", service)
        self.assertIn("oldest_pending_pcap_seconds", service)
        self.assertIn("MIN(COALESCE(updated_at, created_at))", repository)
        self.assertIn("ingest_latency_ms_average", service)

    def test_group_alias_is_refreshed_with_each_group_summary(self):
        code = (
            ROOT / "n8n/alert_store/services/alert_group_service.js"
        ).read_text(encoding="utf-8")
        summary = code[code.index("async function refreshAlertGroupSummary"):]
        summary = summary[:summary.index("async function rebuildAlertGroupSummariesUnlocked")]
        self.assertIn("INSERT INTO alert_group_alias", summary)
        self.assertIn("await removeEmptyGroup(groupId)", summary)
        self.assertIn("DELETE FROM alert_group_alias", code)

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
        self.assertIn(
            '/opt/homebrew/bin/npm run check:install-scripts',
            installer,
        )
        self.assertIn(
            'verify_install_script_policy.js',
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
        self.assertGreaterEqual(
            installer.count('$2 ~ /(^|\\/)codex$/'),
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
        failure_cleanup = installer[
            installer.index("keep_critical_agents_down_on_failure()"):
            installer.index("trap keep_critical_agents_down_on_failure EXIT")
        ]
        self.assertLess(
            failure_cleanup.index("release_ai_deployment_guard"),
            failure_cleanup.index("cleanup_alert_store_stage"),
        )
        self.assertLess(
            failure_cleanup.index("cleanup_alert_store_stage"),
            failure_cleanup.index("return $exit_code"),
        )
        self.assertIn("for attempt in {1..20}", installer)

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
        relay_app = ROOT / "relay" / "app"
        worker = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                relay_app / "relay.py",
                *sorted(relay_app.glob("relay_*.py")),
            )
        )
        self.assertIn("OnUnitInactiveSec=1min", timer)
        self.assertNotIn("OnUnitActiveSec=", timer)
        self.assertIn("limit = 1", worker)
        self.assertIn("fcntl.LOCK_EX | fcntl.LOCK_NB", worker)

    def test_dashboard_generation_is_decoupled_from_local_inference(self):
        scheduler = (ROOT / "n8n/bin/auto-run-ai-analysis.py").read_text(encoding="utf-8")
        scheduler_runtime = (
            ROOT / "n8n/bin/scheduler_runtime_compat.py"
        ).read_text(encoding="utf-8")
        refresher = (ROOT / "n8n/bin/refresh-soc-dashboard.py").read_text(encoding="utf-8")
        plist = (ROOT / "n8n/launchd/com.arron.soc.dashboard-refresh.plist").read_text(encoding="utf-8")
        installer = (ROOT / "n8n/bin/install-macstudio-stack.zsh").read_text(encoding="utf-8")
        self.assertIn("signal_dashboard_refresh", scheduler_runtime)
        self.assertNotIn("def refresh_portal", scheduler + scheduler_runtime)
        self.assertNotIn(
            "build_soc_alerts_dashboard.py",
            scheduler + scheduler_runtime,
        )
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
        for module in (
            "harness_maintenance_contract.py",
            "harness_maintenance_integrity.py",
            "harness_maintenance_recovery.py",
            "harness_maintenance_retention.py",
            "harness_maintenance_reporting.py",
            "harness_maintenance_cli.py",
        ):
            self.assertIn(
                f'cp "$REPO_DIR/n8n/bin/{module}"',
                installer,
            )
            self.assertLess(
                installer.index(f'cp "$REPO_DIR/n8n/bin/{module}"'),
                installer.index(
                    'cp "$REPO_DIR/n8n/bin/maintain-investigation-harness.py"'
                ),
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

    def test_harness_maintenance_load_waits_for_bounded_database_preflight(self):
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        preflight_call = (
            'wait_for_harness_maintenance_readiness\n'
            'launchctl load "$LAUNCHD_DIR/'
            'com.arron.onion-sentinel.harness-maintenance.plist"'
        )

        self.assertIn("wait_for_harness_maintenance_readiness()", installer)
        self.assertIn("for attempt in {1..30}; do", installer)
        self.assertIn('if (( exit_code == 0 || exit_code == 1 )); then', installer)
        self.assertIn('sleep 1', installer)
        self.assertIn(
            '"$STACK_DIR/logs/harness-maintenance-deploy-preflight.json"',
            installer,
        )
        self.assertIn(preflight_call, installer)

    def test_pcap_query_module_tree_is_installed_before_compatibility_module(self):
        installer = (
            ROOT / "n8n/bin/install-macstudio-stack.zsh"
        ).read_text(encoding="utf-8")
        facade_copy = 'cp "$REPO_DIR/n8n/bin/pcap_evidence_query.py"'
        for module in (
            "pcap_evidence_query_policy.py",
            "pcap_evidence_query_validation.py",
            "pcap_evidence_query_matching.py",
            "pcap_evidence_query_selection.py",
            "pcap_evidence_query_projection.py",
            "pcap_evidence_query_response.py",
        ):
            module_copy = f'cp "$REPO_DIR/n8n/bin/{module}"'
            self.assertIn(module_copy, installer)
            self.assertLess(
                installer.index(module_copy),
                installer.index(facade_copy),
            )

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
        ai = (
            ROOT / "n8n/bin/scheduler_runtime_compat.py"
        ).read_text(encoding="utf-8")
        pcap_root = ROOT / "n8n/bin"
        pcap = "\n".join(
            path.read_text(encoding="utf-8")
            for path in (
                pcap_root / "process-pcap-evidence.py",
                *sorted(pcap_root.glob("pcap_processor_*.py")),
            )
        )
        dashboard = (ROOT / "n8n/bin/refresh-soc-dashboard.py").read_text(encoding="utf-8")
        self.assertIn("path.unlink(missing_ok=True)", ai)
        self.assertIn("path.unlink(missing_ok=True)", pcap)
        self.assertIn("signal_follow_up(args.wake_file)", pcap)
        self.assertIn("args.wake_file.unlink(missing_ok=True)", dashboard)


if __name__ == "__main__":
    unittest.main()
