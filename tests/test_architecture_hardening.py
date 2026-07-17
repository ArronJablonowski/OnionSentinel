from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ArchitectureHardeningTest(unittest.TestCase):
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

    def test_local_analysis_workers_are_event_driven_with_timer_fallbacks(self):
        ai_plist = (ROOT / "n8n/launchd/com.arron.soc.ai-analysis.plist").read_text(encoding="utf-8")
        pcap_plist = (ROOT / "n8n/launchd/com.arron.soc.pcap-analysis.plist").read_text(encoding="utf-8")
        self.assertIn("<key>WatchPaths</key>", ai_plist)
        self.assertIn("ai-analysis.wake", ai_plist)
        self.assertIn("<key>KeepAlive</key>", ai_plist)
        self.assertIn("<key>PathState</key>", ai_plist)
        self.assertIn("<key>StartInterval</key>", ai_plist)
        self.assertIn("<key>WatchPaths</key>", pcap_plist)
        self.assertIn("pcap-analysis.wake", pcap_plist)
        self.assertIn("<key>KeepAlive</key>", pcap_plist)
        self.assertIn("<key>PathState</key>", pcap_plist)
        self.assertIn("<key>StartInterval</key>", pcap_plist)

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
