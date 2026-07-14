"""Static regression checks for alert-store PCAP auto-request policy."""
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
COMPOSE = REPO_ROOT / "n8n" / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / "n8n" / ".env.example"
HOST_RUNNER = REPO_ROOT / "n8n" / "bin" / "run-alert-store-host.zsh"
PCAP_WORKFLOW = REPO_ROOT / "n8n" / "workflows" / "onion-sentinel-pcap-broker.workflow.json"


class AlertStorePcapPolicyTest(unittest.TestCase):
    def test_alert_store_auto_queues_pcap_for_configured_levels(self) -> None:
        code = ALERT_STORE.read_text()

        self.assertIn("PCAP_AUTO_REQUEST_LEVELS", code)
        self.assertIn("critical,high,medium,low,informational", code)
        self.assertIn("async function maybeQueueAutomaticPcapRequest", code)
        self.assertIn("const pcap = await maybeQueueAutomaticPcapRequest(alert, row, inserted, suppression);", code)
        self.assertIn("pcap,", code)
        self.assertIn("Automatic PCAP request for ${level} alert", code)

    def test_runtime_templates_expose_auto_pcap_policy(self) -> None:
        env_example = ENV_EXAMPLE.read_text()
        host_runner = HOST_RUNNER.read_text()

        self.assertIn("alert_store_proxy.js", COMPOSE.read_text())
        self.assertIn("PCAP_AUTO_REQUEST_LEVELS", host_runner)
        self.assertIn("PCAP_AUTO_REQUEST_LEVELS=critical,high,medium,low,informational", env_example)

    def test_host_runner_reads_env_literals_without_shell_evaluation(self) -> None:
        host_runner = HOST_RUNNER.read_text(encoding="utf-8")
        self.assertNotIn('eval "$', host_runner)
        self.assertIn("read -r -d $'\\0' assignment", host_runner)
        self.assertIn('export "$assignment"', host_runner)

    def test_pcap_artifact_http_upload_contract_is_removed(self) -> None:
        code = ALERT_STORE.read_text()
        env_example = ENV_EXAMPLE.read_text()
        host_runner = HOST_RUNNER.read_text()
        workflow = PCAP_WORKFLOW.read_text()

        self.assertNotIn("PCAP_ARTIFACT_CHUNK_MAX_BYTES", code)
        self.assertNotIn("CREATE TABLE IF NOT EXISTS pcap_artifact_chunks", code)
        self.assertNotIn("async function ingestPcapArtifactChunk", code)
        self.assertNotIn("parsedUrl.pathname === '/pcap/artifact-chunk'", code)
        self.assertNotIn("PCAP_ARTIFACT_CHUNK_MAX_BYTES", host_runner)
        self.assertNotIn("PCAP_ARTIFACT_CHUNK_MAX_BYTES", env_example)
        self.assertNotIn("pcap-artifact", workflow)

    def test_pcap_broker_prioritizes_newer_higher_severity_work_and_supports_reviewed_requeue(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        self.assertIn("LEFT JOIN alert_group_summary AS g ON g.group_id = p.group_id", code)
        self.assertIn("WHEN 'critical' THEN 4", code)
        self.assertIn("async function requeuePcapRequests(payload)", code)
        self.assertIn("parsedUrl.pathname === '/pcap/requeue'", code)

    def test_pcap_requests_reject_work_outside_configured_capture_retention(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        env_example = ENV_EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("PCAP_CAPTURE_RETENTION_SECONDS", code)
        self.assertIn("async function rejectExpiredPendingPcapRequests", code)
        self.assertIn("PCAP request exceeds configured capture retention", code)
        self.assertIn("PCAP_CAPTURE_RETENTION_SECONDS=345600", env_example)

    def test_pcap_requests_include_suricata_capture_file_when_available(self) -> None:
        code = ALERT_STORE.read_text()

        self.assertIn("nestedField(rawEventJson, 'suricata.capture_file')", code)
        self.assertIn("capture_file: safeString(merged.capture_file, 512) || null", code)
        self.assertIn("capture_file: requestJson.capture_file || null", code)

    def test_pcap_parser_state_is_durable_and_reported_by_worker(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        worker = (REPO_ROOT / "n8n" / "bin" / "process-pcap-evidence.py").read_text(encoding="utf-8")
        self.assertIn("analysis_status", code)
        self.assertIn("parsedUrl.pathname === '/pcap/analysis-status'", code)
        self.assertIn("report_analysis_status", worker)
        self.assertIn('"processing"', worker)
        self.assertIn('"completed"', worker)
        self.assertIn('"failed"', worker)

    def test_automatic_pcap_requests_coalesce_pending_group_work(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        self.assertIn("existingPending", code)
        self.assertIn("status = 'pending'", code)
        self.assertIn("status: 'coalesced'", code)

    def test_pcap_terminal_outcomes_and_storage_metrics_are_durable(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        self.assertIn("ensureColumn('pcap_requests', 'outcome', 'TEXT')", code)
        self.assertIn("function classifyPcapOutcome", code)
        self.assertIn("backfillPcapOutcomes", code)
        self.assertIn("pcap_outcomes", code)
        self.assertIn("pcap_storage", code)
        self.assertIn("datetime(replace(p.last_seen, '  ', 'T'), '+' || ? || ' seconds')", code)


if __name__ == "__main__":
    unittest.main()
