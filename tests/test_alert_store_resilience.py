#!/usr/bin/env python3
"""Architecture regressions for the alert-store critical path."""
from pathlib import Path
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
ALERT_STORE = REPO_ROOT / "n8n" / "alert_store" / "alert_store.js"
PROVIDER_SCHEDULER = REPO_ROOT / "n8n" / "alert_store" / "lib" / "provider_scheduler.js"
HTTP_RUNTIME = REPO_ROOT / "n8n" / "alert_store" / "lib" / "http_runtime.js"
HTTP_DISPATCH = REPO_ROOT / "n8n" / "alert_store" / "lib" / "http_dispatch.js"
HTTP_JSON_CLIENT = REPO_ROOT / "n8n" / "alert_store" / "lib" / "http_json_client.js"
ENRICHMENT_CACHE = REPO_ROOT / "n8n" / "alert_store" / "lib" / "enrichment_cache.js"
HEALTH_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "health_service.js"
ANALYST_STATE_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "analyst_state_service.js"
ANALYST_STATE_ROUTES = REPO_ROOT / "n8n" / "alert_store" / "routes" / "analyst_state_routes.js"
DURABLE_JOB_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "durable_job_service.js"
DURABLE_JOB_ROUTES = REPO_ROOT / "n8n" / "alert_store" / "routes" / "durable_job_routes.js"
PCAP_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "pcap_service.js"
ENRICHMENT_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "enrichment_service.js"
ALERT_INGEST_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "alert_ingest_service.js"
ALERT_INGEST_ORCHESTRATOR = REPO_ROOT / "n8n" / "alert_store" / "services" / "alert_ingest_orchestrator.js"
NOTIFICATION_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "notification_service.js"
ALERT_GROUP_SERVICE = REPO_ROOT / "n8n" / "alert_store" / "services" / "alert_group_service.js"
ENRICHMENT_PROVIDER_CLIENT = REPO_ROOT / "n8n" / "alert_store" / "services" / "enrichment_provider_client.js"
ENRICHMENT_ORCHESTRATOR = REPO_ROOT / "n8n" / "alert_store" / "services" / "enrichment_orchestrator.js"
ANALYST_REVIEW_POLICY = REPO_ROOT / "n8n" / "alert_store" / "lib" / "analyst_review_policy.js"
SCHEMA_FOUNDATION = REPO_ROOT / "n8n" / "alert_store" / "services" / "alert_store_schema_foundation.js"
AI_REVIEW_SCHEMA = REPO_ROOT / "n8n" / "alert_store" / "services" / "ai_review_schema.js"
NOTIFICATION_ENRICHMENT_SCHEMA = REPO_ROOT / "n8n" / "alert_store" / "services" / "notification_enrichment_schema.js"
ANALYST_REVIEW_PROJECTION = REPO_ROOT / "n8n" / "alert_store" / "services" / "analyst_review_projection.js"
ANALYST_DECISION_PERSISTENCE = REPO_ROOT / "n8n" / "alert_store" / "services" / "analyst_decision_persistence.js"
SUPPRESSION_PERSISTENCE = REPO_ROOT / "n8n" / "alert_store" / "services" / "suppression_persistence.js"
AI_REVIEW_REPOSITORY = REPO_ROOT / "n8n" / "alert_store" / "repositories" / "ai_review_repository.js"
AI_ANALYSIS_ACCEPTANCE = REPO_ROOT / "n8n" / "alert_store" / "services" / "ai_analysis_acceptance.js"
DURABLE_JOB_TRANSITION_EXECUTOR = REPO_ROOT / "n8n" / "alert_store" / "services" / "durable_job_transition_executor.js"
DISK_WRITE_ADMISSION = REPO_ROOT / "n8n" / "alert_store" / "services" / "disk_write_admission.js"
WORKER_WAKE_SIGNALING = REPO_ROOT / "n8n" / "alert_store" / "services" / "worker_wake_signaling.js"
BEACON_PERSISTENCE = REPO_ROOT / "n8n" / "alert_store" / "services" / "beacon_persistence.js"
PROJECT_SERIALIZATION = REPO_ROOT / "n8n" / "alert_store" / "lib" / "project_serialization.js"
ALERT_VALUE_NORMALIZATION = REPO_ROOT / "n8n" / "alert_store" / "lib" / "alert_value_normalization.js"
SQLITE_RUNTIME = REPO_ROOT / "n8n" / "alert_store" / "services" / "sqlite_runtime.js"
RUNTIME_CONFIGURATION = (
    REPO_ROOT / "n8n" / "alert_store" / "lib" / "runtime_configuration.js"
)
DURABLE_BACKGROUND_DRAINS = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "durable_background_drains.js"
)
SERVICE_RUNTIME_LIFECYCLE = (
    REPO_ROOT
    / "n8n"
    / "alert_store"
    / "services"
    / "service_runtime_lifecycle.js"
)


class AlertStoreResilienceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.code = ALERT_STORE.read_text(encoding="utf-8")
        cls.provider_scheduler = PROVIDER_SCHEDULER.read_text(encoding="utf-8")
        cls.http_runtime = HTTP_RUNTIME.read_text(encoding="utf-8")
        cls.http_dispatch = HTTP_DISPATCH.read_text(encoding="utf-8")
        cls.http_json_client = HTTP_JSON_CLIENT.read_text(encoding="utf-8")
        cls.enrichment_cache = ENRICHMENT_CACHE.read_text(encoding="utf-8")
        cls.health_service = HEALTH_SERVICE.read_text(encoding="utf-8")
        cls.analyst_state_service = ANALYST_STATE_SERVICE.read_text(encoding="utf-8")
        cls.analyst_state_routes = ANALYST_STATE_ROUTES.read_text(encoding="utf-8")
        cls.durable_job_service = DURABLE_JOB_SERVICE.read_text(encoding="utf-8")
        cls.durable_job_routes = DURABLE_JOB_ROUTES.read_text(encoding="utf-8")
        cls.pcap_service = PCAP_SERVICE.read_text(encoding="utf-8")
        cls.enrichment_service = ENRICHMENT_SERVICE.read_text(encoding="utf-8")
        cls.alert_ingest_service = ALERT_INGEST_SERVICE.read_text(encoding="utf-8")
        cls.alert_ingest_orchestrator = ALERT_INGEST_ORCHESTRATOR.read_text(encoding="utf-8")
        cls.notification_service = NOTIFICATION_SERVICE.read_text(encoding="utf-8")
        cls.alert_group_service = ALERT_GROUP_SERVICE.read_text(encoding="utf-8")
        cls.enrichment_provider_client = ENRICHMENT_PROVIDER_CLIENT.read_text(encoding="utf-8")
        cls.enrichment_orchestrator = ENRICHMENT_ORCHESTRATOR.read_text(encoding="utf-8")
        cls.analyst_review_policy = ANALYST_REVIEW_POLICY.read_text(encoding="utf-8")
        cls.schema_foundation = SCHEMA_FOUNDATION.read_text(encoding="utf-8")
        cls.ai_review_schema = AI_REVIEW_SCHEMA.read_text(encoding="utf-8")
        cls.notification_enrichment_schema = NOTIFICATION_ENRICHMENT_SCHEMA.read_text(encoding="utf-8")
        cls.analyst_review_projection = ANALYST_REVIEW_PROJECTION.read_text(encoding="utf-8")
        cls.analyst_decision_persistence = ANALYST_DECISION_PERSISTENCE.read_text(encoding="utf-8")
        cls.suppression_persistence = SUPPRESSION_PERSISTENCE.read_text(encoding="utf-8")
        cls.ai_review_repository = AI_REVIEW_REPOSITORY.read_text(encoding="utf-8")
        cls.ai_analysis_acceptance = AI_ANALYSIS_ACCEPTANCE.read_text(encoding="utf-8")
        cls.durable_job_transition_executor = DURABLE_JOB_TRANSITION_EXECUTOR.read_text(encoding="utf-8")
        cls.disk_write_admission = DISK_WRITE_ADMISSION.read_text(encoding="utf-8")
        cls.worker_wake_signaling = WORKER_WAKE_SIGNALING.read_text(encoding="utf-8")
        cls.beacon_persistence = BEACON_PERSISTENCE.read_text(encoding="utf-8")
        cls.project_serialization = PROJECT_SERIALIZATION.read_text(encoding="utf-8")
        cls.alert_value_normalization = ALERT_VALUE_NORMALIZATION.read_text(encoding="utf-8")
        cls.sqlite_runtime = SQLITE_RUNTIME.read_text(encoding="utf-8")
        cls.runtime_configuration = RUNTIME_CONFIGURATION.read_text(encoding="utf-8")
        cls.durable_background_drains = DURABLE_BACKGROUND_DRAINS.read_text(
            encoding="utf-8"
        )
        cls.service_runtime_lifecycle = SERVICE_RUNTIME_LIFECYCLE.read_text(
            encoding="utf-8"
        )

    def test_enrichment_uses_a_separate_gate(self) -> None:
        self.assertIn("require('./lib/provider_scheduler')", self.code)
        self.assertIn("scheduler.run(", self.enrichment_orchestrator)
        self.assertIn("await Promise.all(jobs);", self.enrichment_orchestrator)
        self.assertNotIn("withEnrichmentGate", self.enrichment_orchestrator)

    def test_enrichment_is_durable_and_outside_ingest_latency(self) -> None:
        self.assertIn("require('./lib/durable_job_queue')", self.code)
        self.assertIn("enqueueJob: (...args) => durableJobs.enqueue(...args)", self.code)
        self.assertIn("await enqueueJob('public_enrichment'", self.alert_ingest_orchestrator)
        self.assertIn("async function drainEnrichmentJobs()", self.code)
        store = self.alert_ingest_orchestrator.split("async function store(rawAlert)", 1)[1]
        self.assertNotIn("await enrichAlert(", store)

    def test_enrichment_provider_circuits_are_bounded(self) -> None:
        self.assertIn(
            "ENRICHMENT_CIRCUIT_FAILURE_THRESHOLD", self.runtime_configuration
        )
        self.assertIn("ENRICHMENT_CIRCUIT_RESET_MS", self.runtime_configuration)
        self.assertIn("provider circuit open until", self.provider_scheduler)

    def test_enrichment_cache_and_rate_limits_share_the_sqlite_write_boundary(self) -> None:
        self.assertIn(
            "async function reserveProviderRateLimitSlot(source)",
            self.enrichment_orchestrator,
        )
        self.assertIn(
            "return withSqliteWriteGate(() => withImmediateTransaction(async () =>",
            self.enrichment_orchestrator,
        )
        self.assertIn("withWriteGate: withSqliteWriteGate", self.code)
        self.assertIn("withTransaction: withImmediateTransaction", self.code)
        cached_lookup = self.enrichment_orchestrator.split(
            "async function cachedLookup", 1
        )[1].split(
            "async function runEnrichmentLookup", 1
        )[0]
        self.assertIn("return cache.lookup({", cached_lookup)
        self.assertIn("const waitMs = await reserveProviderRateLimitSlot(source)", cached_lookup)
        self.assertIn("return lookup();", cached_lookup)
        self.assertIn("await withWriteGate(() => withTransaction(() => run(", self.enrichment_cache)
        self.assertIn("withWriteGate(() => get('SELECT * FROM enrichment_cache", self.enrichment_cache)

    def test_enrichment_requests_identify_the_service_and_keep_safe_provider_errors(self) -> None:
        self.assertIn("'User-Agent': 'Onion-Sentinel/1.0'", self.http_json_client)
        self.assertIn(
            "function providerErrorDetail(body)",
            self.enrichment_provider_client,
        )
        self.assertIn(
            "Censys Platform API returned HTTP",
            self.enrichment_provider_client,
        )

    def test_sqlite_gate_only_wraps_storage(self) -> None:
        self.assertIn(
            "withSqliteWriteGate(() => withImmediateTransaction(task))",
            self.code,
        )
        self.assertIn(
            "withWriteTransaction(async () =>", self.durable_background_drains
        )
        store_unlocked = self.code.split("async function storeAlertUnlocked(alert)", 1)[1].split(
            "async function applySuppressionPolicy", 1
        )[0]
        self.assertNotIn("enrichAlert(", store_unlocked)
        self.assertNotIn("maybeNotifyTelegram(", store_unlocked)

    def test_notification_failure_does_not_reject_persisted_alert(self) -> None:
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS notification_outbox",
            self.notification_enrichment_schema,
        )
        self.assertIn(
            "const result = await withWriteGate(() => withTransaction(async () =>",
            self.alert_ingest_orchestrator,
        )
        self.assertIn("void drainNotificationOutbox();", self.alert_ingest_orchestrator)
        store = self.alert_ingest_orchestrator.split("async function store(rawAlert)", 1)[1]
        self.assertNotIn("postTelegramMessage(", store)

    def test_notification_outbox_has_bounded_retry(self) -> None:
        self.assertIn("TELEGRAM_OUTBOX_MAX_ATTEMPTS", self.runtime_configuration)
        self.assertIn("outboxRetryTimestamp", self.notification_service)
        self.assertIn(
            "terminal ? 'failed' : 'pending'",
            self.notification_service,
        )

    def test_analyst_state_is_owned_by_alert_store(self) -> None:
        self.assertIn("createAlertStoreSchemaFoundation", self.code)
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS analyst_alert_group_state",
            self.schema_foundation,
        )
        self.assertIn("path: '/analyst-status'", self.analyst_state_routes)
        self.assertIn("return withWriteGate(async () =>", self.analyst_decision_persistence)

    def test_analyst_adjudication_is_append_only_and_guards_terminal_actions(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS analyst_adjudications", self.ai_review_schema)
        self.assertIn("INSERT INTO analyst_adjudications", self.analyst_decision_persistence)
        self.assertNotIn("UPDATE analyst_adjudications", self.analyst_decision_persistence)
        for column in (
            "event_status",
            "detection_validity",
            "activity_disposition",
            "handling",
            "duplicate_of",
        ):
            self.assertIn(f"'{column}'", self.ai_review_schema)
        self.assertIn(
            "ensureColumn('analyst_adjudications', name, 'TEXT')",
            self.ai_review_schema,
        )
        self.assertIn("resolve_case must be a JSON boolean", self.analyst_decision_persistence)
        self.assertIn(
            "function deriveAnalystLegacyOutcome(factors)",
            self.analyst_review_policy,
        )
        self.assertIn(
            "function analystVerdictContradictions(outcome, explicitFactors)",
            self.analyst_review_policy,
        )
        self.assertIn(
            "const contradictions = verdictContradictions(",
            self.analyst_decision_persistence,
        )
        self.assertIn(
            "outcome_override conflicts with explicit verdict factors",
            self.analyst_decision_persistence,
        )
        self.assertIn("path: '/adjudications'", self.analyst_state_routes)
        self.assertIn("path: '/incidents/status'", self.analyst_state_routes)
        self.assertIn("disputed_pending_human", self.analyst_review_projection)
        self.assertIn("review_completed_not_authorized", self.analyst_review_projection)
        self.assertIn(
            "function reviewerAutomationAuthorization(",
            self.analyst_review_policy,
        )
        self.assertIn(
            "function conservativeReviewerTelemetry(",
            self.analyst_review_policy,
        )
        self.assertGreaterEqual(
            self.analyst_review_projection.count(
                "const reviewer = conservativeReviewerTelemetry("
            ),
            2,
        )
        self.assertIn(
            "embedded.comparison",
            self.analyst_review_policy,
        )
        self.assertIn(
            "embedded.response",
            self.analyst_review_policy,
        )
        self.assertIn(
            "corruptRow || corruptEmbedded || statusConflict",
            self.analyst_review_policy,
        )
        self.assertIn(
            "authorization.authorized === false",
            self.analyst_review_projection,
        )
        self.assertIn(
            "required independent review needs explicit analyst adjudication before suppression",
            self.analyst_decision_persistence,
        )
        self.assertIn(
            "required independent review needs explicit analyst adjudication before resolution",
            self.analyst_decision_persistence,
        )
        self.assertIn("async function stableGroupHasPendingHumanReview", self.code)
        self.assertIn(
            "automatic suppression blocked pending explicit analyst adjudication",
            self.suppression_persistence,
        )
        self.assertIn(
            "recordAdjudication: (payload) => transactionalWrite(\n"
            "      () => recordAnalystAdjudication(payload)",
            self.analyst_state_service,
        )

    def test_pcap_mutations_use_the_sqlite_gate(self) -> None:
        self.assertIn("return gated(() => createRequest(payload))", self.pcap_service)
        self.assertIn("return gated(() => claimRequest(payload))", self.pcap_service)
        self.assertIn("await gated(() => completeRequest(payload))", self.pcap_service)

    def test_ai_job_reconciliation_is_bounded_and_transactional(self) -> None:
        self.assertIn("path: '/jobs/reconcile-completed'", self.durable_job_routes)
        self.assertIn(".slice(0, 2000)", self.durable_job_service)
        self.assertIn("completePendingByDedupeKeys(jobType, dedupeKeys)", self.durable_job_service)

    def test_second_opinion_telemetry_has_an_independent_durable_schema(self) -> None:
        self.assertIn("CREATE TABLE IF NOT EXISTS ai_second_opinion_runs", self.ai_review_schema)
        self.assertIn("INSERT INTO ai_second_opinion_runs", self.ai_review_repository)
        for field in (
            "primary_model",
            "reviewer_model",
            "reviewer_outcome",
            "agreement",
            "material_disagreement",
            "disputed_fields_json",
            "reviewer_runtime_seconds",
            "memory_candidates_promoted",
            "reviewer_error",
        ):
            self.assertIn(field, self.ai_review_schema + self.ai_review_repository)
        self.assertIn(
            "second_opinion_recorded: Boolean(state.secondOpinionRecorded)",
            self.ai_analysis_acceptance,
        )

    def test_ai_status_callback_resolves_legacy_group_alias(self) -> None:
        self.assertIn("async function transition(", self.durable_job_transition_executor)
        self.assertIn(
            "SELECT stable_group_id FROM alert_group_alias WHERE legacy_group_id = ?",
            self.durable_job_transition_executor,
        )
        self.assertIn(
            "transitionJobStatus: durableJobTransitionExecutor.transition",
            self.code,
        )
        for forwarding_function in (
            "controlledJobClaimIdentity",
            "controlledEvaluationLeaseKey",
            "controlledJobTransitionAdmission",
            "applyControlledJobTransition",
            "controlledEvaluationClaimDigest",
            "controlledEvaluationResultAdmission",
            "applyControlledEvaluationResultAdmission",
            "transitionDurableJobStatus",
            "recoverExpiredDurableJobs",
        ):
            self.assertNotIn(f"function {forwarding_function}", self.code)

    def test_summary_rebuild_uses_one_windowed_scan(self) -> None:
        rebuild = self.alert_group_service.split("async function rebuildAlertGroupSummariesUnlocked()", 1)[1].split(
            "async function rebuildAlertGroupSummaries()", 1
        )[0]
        self.assertIn("ROW_NUMBER() OVER", rebuild)
        self.assertNotIn("refreshAlertGroupSummary(", rebuild)

    def test_oversized_payload_returns_413_without_socket_destroy(self) -> None:
        self.assertIn("return readJsonObject(request, {", self.code)
        self.assertIn("maxBytes: maxRequestBytes,", self.code)
        self.assertIn("statusError(`payload exceeds ${limit} byte limit`, 413)", self.http_runtime)
        self.assertNotIn("request.destroy", self.http_runtime)

    def test_http_runtime_has_explicit_request_and_connection_ceilings(self) -> None:
        self.assertIn(
            "configureHttpServer(httpCreateServer((request, response) =>",
            self.service_runtime_lifecycle,
        )
        self.assertIn(
            "httpCreateServer: (listener) => http.createServer(listener)", self.code
        )
        self.assertIn("server.requestTimeout", self.http_runtime)
        self.assertIn("server.headersTimeout", self.http_runtime)
        self.assertIn("server.maxRequestsPerSocket", self.http_runtime)
        self.assertIn("server.maxConnections", self.http_runtime)
        self.assertIn("createRequestDispatcher({", self.code)
        self.assertIn("postRequestAdmission.tryAcquire()", self.http_dispatch)

    def test_controlled_shutdown_uses_the_sqlite_runtime_owner(self) -> None:
        self.assertIn("await waitForSqliteWrites()", self.service_runtime_lifecycle)
        self.assertIn(
            "getActiveSqliteWrites() !== 0", self.service_runtime_lifecycle
        )
        self.assertIn(
            "waitForSqliteWrites: () => sqliteRuntime.waitForWrites()", self.code
        )
        self.assertIn("waitForWrites", self.sqlite_runtime)
        self.assertNotIn("sqliteWriteGate.catch", self.code)

    def test_new_intake_stops_before_the_eighty_percent_disk_ceiling(self) -> None:
        self.assertIn("function assertDiskWriteAdmission", self.code)
        self.assertIn("80, Math.max(2", self.runtime_configuration)
        self.assertIn("createDiskWriteAdmission", self.code)
        self.assertIn("assertDiskWriteAdmission('alert ingestion')", self.alert_ingest_service)
        self.assertIn("assertDiskWriteAdmission('alert enrichment')", self.enrichment_service)
        self.assertIn("error.statusCode = 507", self.disk_write_admission)
        self.assertIn("disk_capacity: state.diskCapacitySnapshot()", self.health_service)

    def test_heartbeats_are_accepted_before_disk_admission_is_checked(self) -> None:
        route = self.alert_ingest_service
        heartbeat_index = route.index("if (isRelayHeartbeat(alert))")
        admission_index = route.index("assertDiskWriteAdmission('alert ingestion')")
        self.assertLess(heartbeat_index, admission_index)

    def test_pipeline_observability_is_bounded_and_outside_network_paths(self) -> None:
        self.assertIn("require('./lib/pipeline_metrics')", self.code)
        self.assertIn("PIPELINE_EVENT_RETENTION_HOURS", self.runtime_configuration)
        self.assertIn("state.pipelineMetrics.snapshot()", self.health_service)
        self.assertIn("pipelineMetrics.captureDiskSample", self.code)

    def test_beacon_artifacts_have_one_atomic_bounded_persistence_owner(self) -> None:
        self.assertIn("createBeaconPersistence", self.code)
        self.assertIn("writeBeacon: writeN8nBeacon", self.code)
        self.assertIn("function writeJsonAtomic", self.beacon_persistence)
        self.assertNotIn("function writeJsonAtomic", self.code)
        self.assertIn("atomic local-only state with no credentials or packet evidence", self.beacon_persistence)

    def test_timestamp_and_json_serialization_have_one_shared_owner(self) -> None:
        self.assertIn("createProjectSerialization", self.code)
        self.assertNotIn("function normalizeTimestampValue", self.code)
        self.assertIn("isoTimestampPattern", self.project_serialization)
        self.assertIn("function normalizeTimestampValue", self.project_serialization)
        self.assertIn("function canonicalJsonText", self.project_serialization)

    def test_alert_value_normalization_has_one_shared_owner(self) -> None:
        self.assertIn("require('./lib/alert_value_normalization')", self.code)
        self.assertIn("alert_json remains the complete source of truth", self.alert_value_normalization)
        self.assertIn("function enrichmentRecord", self.alert_value_normalization)
        self.assertIn("function normalizeTriageLevel", self.alert_value_normalization)
        self.assertIn("function safeFileToken", self.alert_value_normalization)
        for forwarding_function in (
            "isRelayHeartbeat",
            "nestedField",
            "integerField",
            "nonNegativeIntegerField",
            "enrichmentRecord",
            "normalizeTriageLevel",
            "safeString",
            "safeFileToken",
            "parseJsonObject",
        ):
            self.assertNotIn(f"function {forwarding_function}", self.code)

    def test_sqlite_runtime_owns_admission_promises_and_transaction_serialization(self) -> None:
        self.assertIn("createSqliteRuntime", self.code)
        self.assertIn("controlled evaluation refuses database recovery sidecar", self.sqlite_runtime)
        self.assertIn("function run(sql, params = [])", self.sqlite_runtime)
        self.assertIn("function get(sql, params = [])", self.sqlite_runtime)
        self.assertIn("function all(sql, params = [])", self.sqlite_runtime)
        self.assertIn("function withWriteGate", self.sqlite_runtime)
        self.assertIn("async function withImmediateTransaction", self.sqlite_runtime)
        for forwarding_function in (
            "run",
            "get",
            "all",
            "withSqliteWriteGate",
            "withImmediateTransaction",
        ):
            self.assertNotIn(f"function {forwarding_function}", self.code)
        self.assertIn("await run('BEGIN IMMEDIATE')", self.sqlite_runtime)
        self.assertIn("activeSqliteWrites", self.sqlite_runtime)

    def test_n8n_report_work_is_enqueued_inside_commit_and_delivered_afterward(self) -> None:
        store = self.alert_ingest_orchestrator.split("async function store(rawAlert)", 1)[1]
        transaction, after_commit = store.split("if (!result.ok) return result;", 1)
        self.assertIn("await enqueuePostCommit(rawAlert, stored)", transaction)
        self.assertIn(
            "await enqueueJob('n8n_post_commit'",
            self.alert_ingest_orchestrator,
        )
        self.assertIn("enqueueJob: (...args) => durableJobs.enqueue(...args)", self.code)
        self.assertNotIn("requestJson({", transaction)
        self.assertIn("void drainPostCommitJobs();", after_commit)
        self.assertIn("N8N_POST_COMMIT_MAX_ATTEMPTS", self.runtime_configuration)
        self.assertIn(
            "N8N_POST_COMMIT_BASE_RETRY_SECONDS", self.runtime_configuration
        )

    def test_committed_evidence_wakes_local_workers_without_owning_durability(self) -> None:
        self.assertIn("async function signalWorker", self.code)
        self.assertIn("createWorkerWakeSignaling", self.code)
        self.assertIn("AI_ANALYSIS_WAKE_PATH", self.runtime_configuration)
        self.assertIn("PCAP_ANALYSIS_WAKE_PATH", self.runtime_configuration)
        self.assertIn("Wake files are an optimization", self.worker_wake_signaling)
        self.assertIn("interval fallback remain authoritative", self.worker_wake_signaling)
        self.assertIn(
            "void signalAiWorkers('enrichment-completed')",
            self.durable_background_drains,
        )
        self.assertIn("signalPcapWorker: (reason) => signalWorker(pcapAnalysisWakePath, reason)", self.code)
        self.assertIn("void signalPcapWorker('pcap-transfer-completed')", self.pcap_service)
        self.assertIn("void signalAiWorkers('pcap-analysis-completed')", self.pcap_service)


if __name__ == "__main__":
    unittest.main()
