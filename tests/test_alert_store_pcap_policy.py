"""Static regression checks for alert-store PCAP auto-request policy."""
from pathlib import Path
import json
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
HEALTH_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "health_service.js"
PCAP_ROUTES = REPO_ROOT / "n8n" / "alert_store" / "routes" / "pcap_routes.js"
PCAP_POLICY = REPO_ROOT / "n8n" / "alert_store" / "lib" / "pcap_policy.js"
PCAP_TRANSFER_REPOSITORY = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "repositories"
    / "pcap_transfer_repository.js"
)
PCAP_REQUEST_REPOSITORY = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "repositories"
    / "pcap_request_repository.js"
)
SOC_ANALYSIS_POLICY = REPO_ROOT / "n8n" / "alert_store" / "lib" / "soc_analysis_policy.js"
COMPOSE = REPO_ROOT / "n8n" / "docker-compose.yml"
ENV_EXAMPLE = REPO_ROOT / "n8n" / ".env.example"
HOST_RUNNER = REPO_ROOT / "n8n" / "bin" / "run-alert-store-host.zsh"
PCAP_WORKFLOW = REPO_ROOT / "n8n" / "workflows" / "onion-sentinel-pcap-broker.workflow.json"
PCAP_WORKFLOW_SYNC = REPO_ROOT / "n8n" / "bin" / "sync-pcap-broker-workflow.py"


class AlertStorePcapPolicyTest(unittest.TestCase):
    def test_alert_store_auto_queues_pcap_for_configured_levels(self) -> None:
        code = ALERT_STORE.read_text()
        policy = SOC_ANALYSIS_POLICY.read_text()

        self.assertIn("createSocAnalysisPolicy", code)
        self.assertIn("socAnalysisPolicy.matchesPcap(level)", code)
        self.assertIn("soc_analyst_pcap_min_severity", policy)
        self.assertIn("pcap_capture_loss_threshold_percent", policy)
        self.assertIn("capture_loss_threshold_percent", code)
        self.assertIn(
            "SEVERITY_RANK[normalizedSeverity] >= SEVERITY_RANK[normalizedThreshold]",
            policy,
        )
        self.assertIn("async function maybeQueueAutomaticPcapRequest", code)
        self.assertIn("const pcap = await maybeQueueAutomaticPcapRequest(alert, row, inserted, suppression, campaign);", code)
        self.assertIn("status: 'coalesced_campaign'", code)
        self.assertIn("pcap,", code)
        self.assertIn("Automatic PCAP request for ${level} alert", code)

    def test_automatic_incident_routing_failure_rolls_back_for_upstream_retry(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        start = code.index("async function maybeQueueAutomaticIncidentResponse")
        end = code.index("function readJsonBody", start)
        function = code[start:end]

        self.assertIn("queueIncidentResponseForGroup", function)
        self.assertIn("error.statusCode = Number(error.statusCode || 503)", function)
        self.assertIn("throw error", function)
        self.assertNotIn("status: 'failed'", function)

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
        request_repository = PCAP_REQUEST_REPOSITORY.read_text(encoding="utf-8")
        routes = PCAP_ROUTES.read_text(encoding="utf-8")
        self.assertIn(
            "LEFT JOIN alert_group_summary AS g ON g.group_id = p.group_id",
            request_repository,
        )
        self.assertIn("WHEN 'critical' THEN 4", request_repository)
        self.assertIn("async function requeueRequests(payload)", request_repository)
        self.assertIn("post('/pcap/requeue', 'requeue')", routes)

    def test_pcap_requests_reject_work_outside_configured_capture_retention(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        pcap_policy = PCAP_POLICY.read_text(encoding="utf-8")
        request_repository = PCAP_REQUEST_REPOSITORY.read_text(encoding="utf-8")
        env_example = ENV_EXAMPLE.read_text(encoding="utf-8")
        self.assertIn("PCAP_CAPTURE_RETENTION_SECONDS", code)
        self.assertIn("async function rejectExpiredPending", request_repository)
        self.assertIn("PCAP request exceeds configured capture retention", pcap_policy)
        self.assertIn("PCAP_CAPTURE_RETENTION_SECONDS=345600", env_example)

    def test_pcap_requests_include_suricata_capture_file_when_available(self) -> None:
        pcap_policy = PCAP_POLICY.read_text(encoding="utf-8")

        self.assertIn(
            "nestedField(rawEventJson, 'suricata.capture_file')",
            pcap_policy,
        )
        self.assertIn(
            "capture_file: safeString(merged.capture_file, 512) || null",
            pcap_policy,
        )
        self.assertIn(
            "capture_file: requestJson.capture_file || null",
            pcap_policy,
        )

    def test_pcap_parser_state_is_durable_and_reported_by_worker(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        routes = PCAP_ROUTES.read_text(encoding="utf-8")
        worker = (REPO_ROOT / "n8n" / "bin" / "process-pcap-evidence.py").read_text(encoding="utf-8")
        self.assertIn("analysis_status", code)
        self.assertIn("post('/pcap/analysis-status', 'analysisStatus')", routes)
        self.assertIn("report_analysis_status", worker)
        self.assertIn('"processing"', worker)
        self.assertIn('"completed"', worker)
        self.assertIn('"failed"', worker)

    def test_automatic_pcap_requests_coalesce_pending_group_work(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        self.assertIn("existingPending", code)
        self.assertIn("status = 'pending'", code)
        self.assertIn("status: 'coalesced'", code)

    def test_recovered_analysis_leases_reapply_campaign_admission(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        start = code.index("async function recoverExpiredDurableJobs")
        end = code.index("const cohortIdPattern", start)
        recovery = code[start:end]
        self.assertIn("await durableJobs.recoverExpired()", recovery)
        self.assertIn(
            "recovered.authorized_activity = await "
            "reconcileAuthorizedActivityBacklog()",
            recovery,
        )
        self.assertLess(
            recovery.index("reconcileAuthorizedActivityBacklog()"),
            recovery.index("signalAiWorkers('ai-lease-recovered')"),
        )

    def test_pcap_terminal_outcomes_and_storage_metrics_are_durable(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        pcap_policy = PCAP_POLICY.read_text(encoding="utf-8")
        request_repository = PCAP_REQUEST_REPOSITORY.read_text(encoding="utf-8")
        health_service = HEALTH_SERVICE.read_text(encoding="utf-8")
        self.assertIn("ensureColumn('pcap_requests', 'outcome', 'TEXT')", code)
        self.assertIn("function classifyPcapOutcome", pcap_policy)
        self.assertIn("backfillOutcomes", request_repository)
        self.assertIn("pcap_outcomes", health_service)
        self.assertIn("pcap_storage", health_service)
        self.assertIn(
            "datetime(replace(p.last_seen, '  ', 'T'), '+' || ? || ' seconds')",
            request_repository,
        )

    def test_singular_no_matching_packet_errors_are_normalized(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        pcap_policy = PCAP_POLICY.read_text(encoding="utf-8")
        transfer_repository = PCAP_TRANSFER_REPOSITORY.read_text(encoding="utf-8")
        request_repository = PCAP_REQUEST_REPOSITORY.read_text(encoding="utf-8")
        self.assertIn("detail.includes('no matching packet')", pcap_policy)
        self.assertIn("outcome = 'failed'", request_repository)
        self.assertIn("requestedOutcome !== 'failed'", transfer_repository)

    def test_large_transfer_progress_renews_claim_lease(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        transfer_repository = PCAP_TRANSFER_REPOSITORY.read_text(encoding="utf-8")
        routes = PCAP_ROUTES.read_text(encoding="utf-8")
        self.assertIn("ensureColumn('pcap_requests', 'transfer_progress_at', 'TEXT')", code)
        self.assertIn(
            "COALESCE(transfer_progress_at, claimed_at, updated_at, created_at)",
            transfer_repository,
        )
        self.assertIn("post('/pcap/progress', 'progress')", routes)
        workflow = json.loads(PCAP_WORKFLOW.read_text(encoding="utf-8"))
        progress_webhook = next(node for node in workflow["nodes"] if node["name"] == "PCAP Progress Webhook")
        self.assertEqual(progress_webhook["parameters"]["path"], "pcap/progress")

    def test_pcap_transfer_duration_is_persisted_and_backfilled(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        transfer_repository = PCAP_TRANSFER_REPOSITORY.read_text(encoding="utf-8")
        self.assertIn("ensureColumn('pcap_requests', 'transfer_duration_seconds', 'INTEGER')", code)
        self.assertIn("julianday(replace(completed_at, '  ', 'T'))", code)
        self.assertIn("transfer_duration_seconds = CASE", transfer_repository)

    def test_pcap_transfer_retries_are_durable_bounded_and_stage_aware(self) -> None:
        code = ALERT_STORE.read_text(encoding="utf-8")
        transfer_repository = PCAP_TRANSFER_REPOSITORY.read_text(encoding="utf-8")
        request_repository = PCAP_REQUEST_REPOSITORY.read_text(encoding="utf-8")
        routes = PCAP_ROUTES.read_text(encoding="utf-8")
        for column in (
            "transfer_attempt_count",
            "transfer_retry_count",
            "transfer_last_error",
            "transfer_last_failed_stage",
            "next_attempt_at",
        ):
            self.assertIn(f"ensureColumn('pcap_requests', '{column}'", code)
        self.assertIn("PCAP_TRANSFER_MAX_ATTEMPTS", code)
        self.assertIn("async function retryRequest(payload)", transfer_repository)
        self.assertIn("post('/pcap/retry', 'retry')", routes)
        self.assertIn("retry_scheduled: !exhausted", transfer_repository)
        self.assertIn("p.next_attempt_at IS NULL", request_repository)

    def test_pcap_proxy_workflow_includes_generated_retry_route(self) -> None:
        workflow = json.loads(PCAP_WORKFLOW.read_text(encoding="utf-8"))
        retry_webhook = next(node for node in workflow["nodes"] if node["name"] == "PCAP Retry Webhook")
        retry_code = next(node for node in workflow["nodes"] if node["name"] == "Retry PCAP Request")
        self.assertEqual(retry_webhook["parameters"]["path"], "pcap-retry")
        self.assertIn("`/pcap/retry`", retry_code["parameters"]["jsCode"])
        self.assertTrue(PCAP_WORKFLOW_SYNC.is_file())


if __name__ == "__main__":
    unittest.main()
