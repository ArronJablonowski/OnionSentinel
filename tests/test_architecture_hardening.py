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


if __name__ == "__main__":
    unittest.main()
