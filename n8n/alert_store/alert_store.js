// alert-store is the policy and persistence layer for Security Onion alerts.
//
// n8n calls POST /alert with one normalized alert at a time. This service then
// scores, deduplicates, applies hard drops and TTL suppressions, stores the
// result in SQLite, and sends Telegram notifications when policy allows.
//
// First troubleshooting checks:
//   1. GET /health from inside the n8n Docker network.
//   2. Inspect /data/alerts.sqlite3 for alert/filter state.
//   3. Inspect /app/config/scoring_rules.json for tuning rules.
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {createEnrichmentCache} = require('./lib/enrichment_cache');
const {createProviderScheduler} = require('./lib/provider_scheduler');
const {createDurableJobQueue} = require('./lib/durable_job_queue');
const {createPostgresShadowOutbox} = require('./lib/postgres_shadow_outbox');
const {createPostgresShadowProjector} = require('./lib/postgres_shadow_projector');
const {createPostgresAssetStore} = require('./lib/postgres_asset_store');
const {createPostgresSoftwareStore} = require('./lib/postgres_software_store');
const {createPostgresAcHunterStore} = require('./lib/postgres_ac_hunter_store');
const {createSecurityLogger} = require('./lib/security_logger');
const {createPipelineMetrics} = require('./lib/pipeline_metrics');
const {createSocAnalysisPolicy} = require('./lib/soc_analysis_policy');
const {createRouteRegistry} = require('./lib/route_registry');
const {createRequestDispatcher} = require('./lib/http_dispatch');
const {createRequestAuthorization} = require('./lib/request_authorization');
const {createControlledJobIdentity} = require('./lib/controlled_job_identity');
const controlledRetirementDefinitions = require('./lib/controlled_retirement_identity');
const {createControlledRetirementProjections} = require('./lib/controlled_retirement_projections');
const {createManualDispatchIdentity} = require('./lib/manual_dispatch_identity');
const {createControlledEvaluationSchema} = require('./lib/controlled_evaluation_schema');
const {
  createAlertStoreSchemaFoundation,
} = require('./services/alert_store_schema_foundation');
const {createIncidentAnalysisSchema} = require('./services/incident_analysis_schema');
const {createAiReviewSchema} = require('./services/ai_review_schema');
const {
  createNotificationEnrichmentSchema,
} = require('./services/notification_enrichment_schema');
const {createPcapSchema} = require('./services/pcap_schema');
const {
  createStartupPersistenceOrchestrator,
} = require('./services/startup_persistence_orchestrator');
const {
  createAuthorizedCampaignPersistence,
} = require('./services/authorized_campaign_persistence');
const analystReviewDefinitions = require('./services/analyst_review_projection');
const {
  createAnalystDecisionPersistence,
} = require('./services/analyst_decision_persistence');
const {createAlertIngestOrchestrator} = require('./services/alert_ingest_orchestrator');
const {createPostCommitPayload} = require('./services/post_commit_payload');
const {createAlertPersistence} = require('./services/alert_persistence');
const {createSuppressionPersistence} = require('./services/suppression_persistence');
const {createRescorePersistence} = require('./services/rescore_persistence');
const {createAutomaticResponseRouting} = require('./services/automatic_response_routing');
const {createManualAnalysisDispatch} = require('./services/manual_analysis_dispatch');
const {createDurableBackgroundDrains} = require('./services/durable_background_drains');
const {createServiceRuntimeLifecycle} = require('./services/service_runtime_lifecycle');
const {createHttpRequestBoundary} = require('./services/http_request_boundary');
const {createDiskWriteAdmission} = require('./services/disk_write_admission');
const {createWorkerWakeSignaling} = require('./services/worker_wake_signaling');
const {createBeaconPersistence} = require('./services/beacon_persistence');
const {
  createPostgresAuxiliaryStoreRuntime,
} = require('./services/postgres_auxiliary_store_runtime');
const {createSqliteRuntime} = require('./services/sqlite_runtime');
const {createInventoryService} = require('./services/inventory_service');
const {createInventoryRoutes} = require('./routes/inventory_routes');
const {createHealthRepository} = require('./repositories/health_repository');
const {createAiCorrelationRepository} = require('./repositories/ai_correlation_repository');
const {createAiReviewRepository} = require('./repositories/ai_review_repository');
const {createPcapRequestRepository} = require('./repositories/pcap_request_repository');
const {createPcapTransferRepository} = require('./repositories/pcap_transfer_repository');
const {createHealthService} = require('./services/health_service');
const {createAiAnalysisAcceptance} = require('./services/ai_analysis_acceptance');
const {createControlledJobTransition} = require('./services/controlled_job_transition');
const {createControlledResultAdmission} = require('./services/controlled_result_admission');
const {createDurableJobRecovery} = require('./services/durable_job_recovery');
const {createDurableJobTransitionExecutor} = require('./services/durable_job_transition_executor');
const {
  createControlledRetirementCompletedMember,
} = require('./services/controlled_retirement_completed_member');
const {
  createControlledRetirementTargetMember,
} = require('./services/controlled_retirement_target_member');
const {
  createControlledRetirementCensus,
} = require('./services/controlled_retirement_census');
const {
  createControlledRetirementReplay,
} = require('./services/controlled_retirement_replay');
const {
  createControlledRetirementCommand,
} = require('./services/controlled_retirement_command');
const {
  createIncidentReanalysisFrozenDispatch,
} = require('./services/incident_reanalysis_frozen_dispatch');
const {
  createAlertGroupAliasResolution,
} = require('./services/alert_group_alias_resolution');
const {
  createIncidentDurableJobPersistence,
} = require('./services/incident_durable_job_persistence');
const {
  createIncidentReanalysisRequest,
} = require('./services/incident_reanalysis_request');
const {
  createIncidentReanalysisJobOwnership,
} = require('./services/incident_reanalysis_job_ownership');
const {
  createIncidentReanalysisAttemptLifecycle,
} = require('./services/incident_reanalysis_attempt_lifecycle');
const {
  createIncidentReanalysisRecovery,
} = require('./services/incident_reanalysis_recovery');
const {
  createIncidentReanalysisRunPersistence,
} = require('./services/incident_reanalysis_run_persistence');
const {createIncidentAnalysisCompletion} = require('./services/incident_analysis_completion');
const {createIncidentReanalysisBindingService} = require('./services/incident_reanalysis_binding');
const {createHealthRoutes} = require('./routes/health_routes');
const {createAnalystStateService} = require('./services/analyst_state_service');
const {createAnalystStateRoutes} = require('./routes/analyst_state_routes');
const {createDurableJobService} = require('./services/durable_job_service');
const {createDurableJobRoutes} = require('./routes/durable_job_routes');
const {createAnalysisRequestService} = require('./services/analysis_request_service');
const {createAnalysisRequestRoutes} = require('./routes/analysis_request_routes');
const {createAnalysisResultService} = require('./services/analysis_result_service');
const {createAnalysisResultRoutes} = require('./routes/analysis_result_routes');
const {createPcapService} = require('./services/pcap_service');
const {createPcapAnalysisCompletion} = require('./services/pcap_analysis_completion');
const {createPcapRoutes} = require('./routes/pcap_routes');
const {createEnrichmentService} = require('./services/enrichment_service');
const {createEnrichmentRoutes} = require('./routes/enrichment_routes');
const {createMaintenanceRoutes} = require('./routes/maintenance_routes');
const {createAlertIngestService} = require('./services/alert_ingest_service');
const {createAlertIngestRoutes} = require('./routes/alert_ingest_routes');
const {createNotificationService} = require('./services/notification_service');
const {createAlertGroupService} = require('./services/alert_group_service');
const {createScoringPolicy} = require('./lib/scoring_policy');
const {createScoringRulesRuntime} = require('./lib/scoring_rules_runtime');
const {createIndicatorExtraction} = require('./lib/indicator_extraction');
const {createEnrichmentPolicy} = require('./lib/enrichment_policy');
const {createPcapPolicy} = require('./lib/pcap_policy');
const {createProjectSerialization} = require('./lib/project_serialization');
const {createRuntimeConfiguration} = require('./lib/runtime_configuration');
const alertValueNormalization = require('./lib/alert_value_normalization');
const {createEnrichmentProviderClient} = require('./services/enrichment_provider_client');
const {createEnrichmentOrchestrator} = require('./services/enrichment_orchestrator');
const {
  analystAdjudicationOutcomes,
  analystAdjudicationConfidences,
  analystEventStatuses,
  analystDetectionValidities,
  analystActivityDispositions,
  analystHandlingValues,
  reviewerFailureStatuses,
  analystVerdictContradictions,
  createReviewerPolicy,
} = require('./lib/analyst_review_policy');
const {
  loadAuthorizedActivityPolicy,
  matchAuthorizedActivity,
} = require('./lib/authorized_activity_policy');
const {
  stableGroupKey,
  stableGroupId,
  validPinnedStableGroupKey,
} = require('./lib/group_identity');
const {buildAlertObservables, compactCorrelationCandidates} = require('./lib/correlation_context');
const {configureHttpServer, createRequestAdmission, readJsonObject} = require('./lib/http_runtime');
const {requestJson: boundedRequestJson} = require('./lib/http_json_client');
let sqlite3;
try {
  // Host-native launchd deployments install sqlite3 beside this script.
  sqlite3 = require('sqlite3');
} catch (error) {
  // The Docker proxy is preferred for n8n reachability, but this fallback keeps
  // older container-based DR deployments bootable.
  sqlite3 = require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3');
}
const {
  projectOffset,
  formatProjectTimestamp,
  parseProjectTimestamp,
  nowUtc,
  normalizeTimestampValue,
  normalizeJsonTimestamps,
  jsonText,
  canonicalJsonText,
} = createProjectSerialization();

// Runtime values come from docker-compose.yml and .env. Keep real tokens in
// .env only; this DR repo stores placeholders and source code.
const runtimeConfiguration = createRuntimeConfiguration({
  env: process.env,
  fs,
  path,
  os,
  dirname: __dirname,
  getuid: typeof process.getuid === 'function' ? () => process.getuid() : null,
  loadAuthorizedActivityPolicy,
});
const {
  dbPath,
  scoringRulesPath,
  authorizedActivityPolicyPath,
  authorizedActivityPolicy,
  beaconPaths,
  beaconHistoryPaths,
  host,
  port,
  postgresShadowEnabled,
  postgresShadowIntervalMs,
  postgresShadowBatchSize,
  assetPostgresEnabled,
  assetPostgresSchemaPath,
  softwarePostgresEnabled,
  softwarePostgresSchemaPath,
  acHunterPostgresEnabled,
  acHunterPostgresSchemaPath,
  assetStoreWriteToken,
  controlledEvaluationMode,
  runtimeReleaseIdValue,
  controlledEvaluationToken,
  applicationLogPath,
  applicationLogMaxBytes,
  applicationLogBackups,
  telegramBotToken,
  telegramChatId,
  maxRequestBytes,
  httpRequestTimeoutMs,
  httpHeadersTimeoutMs,
  httpKeepAliveTimeoutMs,
  httpMaxRequestsPerSocket,
  httpMaxConnections,
  httpMaxActivePosts,
  diskHardMaxUsedPercent,
  diskStartMaxUsedPercent,
  diskMinFreeBytes,
  telegramAlertLevels,
  telegramCooldownSeconds,
  telegramOutboxIntervalMs,
  telegramOutboxBaseRetrySeconds,
  telegramOutboxMaxRetrySeconds,
  telegramOutboxMaxAttempts,
  telegramOutboxAutostart,
  enrichmentCacheDefaultTtlSeconds,
  vulnerabilityCacheDefaultTtlSeconds,
  enrichmentNegativeCacheTtlSeconds,
  enrichmentStaleIfErrorSeconds,
  enrichmentVulnerabilityStaleIfErrorSeconds,
  enrichmentCacheL1MaxEntries,
  enrichmentCacheL1TtlSeconds,
  enrichmentCacheL1MaxBytes,
  enrichmentCacheMaxEntries,
  enrichmentCacheMaxBytes,
  enrichmentCacheRawResponseMaxBytes,
  enrichmentCacheCleanupIntervalMs,
  enrichmentSourceTtlDefaults,
  enrichmentTimeoutMs,
  httpJsonMaxResponseBytes,
  enrichmentCircuitFailureThreshold,
  enrichmentCircuitResetMs,
  enrichmentCircuitMaxResetMs,
  enrichmentWorkerIntervalMs,
  enrichmentWorkerMaxAttempts,
  virustotalMinimumLevel,
  urlscanSubmitEnabled,
  pcapRequestMaxWindowSeconds,
  pcapRequestDefaultWindowSeconds,
  pcapClaimLeaseSeconds,
  pcapCaptureRetentionSeconds,
  pcapPriorityMaxWaitSeconds,
  pcapTransferMaxAttempts,
  pcapTransferMaxRetrySeconds,
  pipelineEventRetentionHours,
  pipelineDiskSampleIntervalMs,
  n8nPostCommitUrl,
  n8nPostCommitToken,
  n8nPostCommitIntervalMs,
  n8nPostCommitTimeoutMs,
  n8nPostCommitMaxAttempts,
  n8nPostCommitBaseRetrySeconds,
  durableJobRecoveryIntervalMs,
  aiAnalysisLeaseSeconds,
  runtimeDir,
  aiAnalysisWakePaths,
  pcapAnalysisWakePath,
  analystStatusReasonMaxLength,
  analystAdjudicationTextMaxLength,
  enrichmentSecrets,
} = runtimeConfiguration;
const requestAuthorization = createRequestAuthorization({
  assetWriteToken: assetStoreWriteToken,
  evaluationToken: controlledEvaluationToken,
  controlledEvaluationMode,
  timingSafeEqual: crypto.timingSafeEqual,
});
// Validate the complete controlled-runtime boundary before creating a log
// directory or any other external state. A malformed evaluation environment
// must fail closed without deriving a path such as /logs from a missing DB.
const applicationLogger = createSecurityLogger({
  file: applicationLogPath,
  service: 'onion-sentinel-alert-store',
  releaseId: runtimeReleaseIdValue || 'unversioned',
  maxBytes: applicationLogMaxBytes,
  backups: applicationLogBackups,
});
applicationLogger.captureConsole();
applicationLogger.log('info', 'process.starting', {
  runtime_mode: controlledEvaluationMode ? 'controlled-evaluation' : 'production',
  database_path: dbPath,
  listen_host: host,
  listen_port: port,
});
const {
  reviewerAutomationAuthorization,
  conservativeReviewerTelemetry,
} = createReviewerPolicy({safeString, parseJsonObject});
const socAnalysisPolicy = createSocAnalysisPolicy({runtimeDir});

const diskWriteAdmission = createDiskWriteAdmission({
  fs,
  path,
  dbPath,
  diskStartMaxUsedPercent,
  diskHardMaxUsedPercent,
  diskMinFreeBytes,
  maxRequestBytes,
});

function diskCapacitySnapshot(additionalBytes = 0) {
  return diskWriteAdmission.diskCapacitySnapshot(additionalBytes);
}

function assertDiskWriteAdmission(label, additionalBytes = maxRequestBytes) {
  return diskWriteAdmission.assertDiskWriteAdmission(label, additionalBytes);
}

const severityRank = {informational: 0, info: 0, low: 1, medium: 2, high: 3, critical: 4};
const supportedAgentRoles = new Set([
  'soc-analyst',
  'incident-responder',
  'siem-engineer',
  'cyber-threat-intel',
  'threat-hunter',
]);
const workerWakeSignaling = createWorkerWakeSignaling({
  fs,
  path,
  nowUtc,
  isControlledEvaluation: () => controlledEvaluationMode,
  aiAnalysisWakePaths,
  logError: (message) => console.error(message),
});

async function signalWorker(wakePath, eventName) {
  return workerWakeSignaling.signalWorker(wakePath, eventName);
}

async function signalAiWorkers(eventName) {
  return workerWakeSignaling.signalAiWorkers(eventName);
}

const scoringRulesRuntime = createScoringRulesRuntime({
  fs,
  scoringRulesPath,
  logError: (message) => console.error(message),
});

function loadScoringRules() {
  return scoringRulesRuntime.load();
}

const scoringRules = loadScoringRules();
const {
  parseIpv4,
  isPrivateIpv4,
  trafficDirection,
  ruleName,
  findDropRule,
  suppressionKey,
  findSuppressRule,
  scoreAlert,
} = createScoringPolicy({rules: scoringRules, nestedField});
const {
  isProbablyPlaceholderSecret,
  isConfiguredSecret,
  publicHostname,
  redactUrlForPublicLookup,
  extractUrlsFromText,
  extractIpv4sFromText,
  extractDomainsFromText,
  extractCvesFromText,
  extractHashesFromText,
  extractAlertIndicators,
  hasUsableExternalIntel,
} = createIndicatorExtraction({parseIpv4, isPrivateIpv4, nestedField});
const enrichmentPolicy = createEnrichmentPolicy({
  normalizeTimestampValue,
  nowUtc,
  isConfiguredSecret,
  enrichmentSecrets,
  defaultTtlSeconds: enrichmentCacheDefaultTtlSeconds,
  vulnerabilityTtlSeconds: vulnerabilityCacheDefaultTtlSeconds,
  sourceTtlDefaults: enrichmentSourceTtlDefaults,
  staleIfErrorSeconds: enrichmentStaleIfErrorSeconds,
  vulnerabilityStaleIfErrorSeconds: enrichmentVulnerabilityStaleIfErrorSeconds,
  severityRank,
  virusTotalMinimumLevel: virustotalMinimumLevel,
  parseIpv4,
  isPrivateIpv4,
  publicHostname,
  redactUrlForPublicLookup,
});
const {
  normalizedEnrichmentRecord,
  notFoundEnrichmentRecord,
  verdictFromStats,
} = enrichmentPolicy;
const enrichmentProviderClient = createEnrichmentProviderClient({
  controlledEvaluationMode,
  boundedRequestJson,
  timeoutMs: enrichmentTimeoutMs,
  maxResponseBytes: httpJsonMaxResponseBytes,
  safeString,
  normalizedEnrichmentRecord,
  notFoundEnrichmentRecord,
  verdictFromStats,
  enrichmentSecrets,
  isConfiguredSecret,
  formatProjectTimestamp,
});
const {requestJson} = enrichmentProviderClient;
const {
  queueTelegramNotification,
  drainTelegramOutbox,
  telegramOutboxSnapshot,
} = createNotificationService({
  nestedField,
  normalizeTimestampValue,
  formatProjectTimestamp,
  nowUtc,
  get,
  run,
  all,
  withSqliteWriteGate,
  withImmediateTransaction,
  botToken: telegramBotToken,
  chatId: telegramChatId,
  alertLevels: telegramAlertLevels,
  cooldownSeconds: telegramCooldownSeconds,
  outboxBaseRetrySeconds: telegramOutboxBaseRetrySeconds,
  outboxMaxRetrySeconds: telegramOutboxMaxRetrySeconds,
  outboxMaxAttempts: telegramOutboxMaxAttempts,
  outboxAutostart: telegramOutboxAutostart,
  controlledEvaluationMode,
});
const beaconPersistence = createBeaconPersistence({
  fs,
  path,
  processId: process.pid,
  beaconPaths,
  beaconHistoryPaths,
  nowUtc,
  dateNow: () => Date.now(),
  parseProjectTimestamp,
  nestedField,
  integerField,
  nonNegativeIntegerField,
  logError: (message) => console.error(message),
});

function writeN8nBeacon(stage, alert = {}, result = null, error = null) {
  return beaconPersistence.writeBeacon(stage, alert, result, error);
}

function isRelayHeartbeat(payload) {
  return alertValueNormalization.isRelayHeartbeat(payload);
}

function nestedField(value, dottedPath) {
  return alertValueNormalization.nestedField(value, dottedPath);
}

function integerField(value) {
  return alertValueNormalization.integerField(value);
}

function nonNegativeIntegerField(value) {
  return alertValueNormalization.nonNegativeIntegerField(value);
}

function enrichmentRecord(alert) {
  return alertValueNormalization.enrichmentRecord(alert);
}

const sqliteBusyTimeoutMs = Number(process.env.ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS || 30000);
const sqliteRuntime = createSqliteRuntime({
  fs,
  path,
  processApi: process,
  sqlite3,
  dbPath,
  controlledEvaluationMode,
  busyTimeoutMs: sqliteBusyTimeoutMs,
});
const db = sqliteRuntime.database;
const sqliteJournalMode = String(process.env.ALERT_STORE_SQLITE_JOURNAL_MODE || 'DELETE').toUpperCase();
const sqliteSynchronous = String(process.env.ALERT_STORE_SQLITE_SYNCHRONOUS || 'FULL').toUpperCase();
const sqliteTempStore = String(process.env.ALERT_STORE_SQLITE_TEMP_STORE || 'DEFAULT').toUpperCase();
const allowedJournalModes = new Set(['DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL', 'OFF']);
const allowedSynchronousModes = new Set(['OFF', 'NORMAL', 'FULL', 'EXTRA']);
const allowedTempStoreModes = new Set(['DEFAULT', 'FILE', 'MEMORY']);
function normalizeTriageLevel(value, fallback = '') {
  return alertValueNormalization.normalizeTriageLevel(value, fallback);
}

const alertGroupKeySql = `
  COALESCE(
    NULLIF(suppression_key, ''),
    (
      CASE lower(COALESCE(triage_level, ''))
        WHEN 'critical' THEN 'critical'
        WHEN 'high' THEN 'high'
        WHEN 'medium' THEN 'medium'
        WHEN 'low' THEN 'low'
        WHEN 'informational' THEN 'informational'
        WHEN 'info' THEN 'informational'
        ELSE CASE lower(COALESCE(severity_label, ''))
          WHEN 'critical' THEN 'critical'
          WHEN 'high' THEN 'high'
          WHEN 'medium' THEN 'medium'
          WHEN 'low' THEN 'low'
          WHEN 'informational' THEN 'informational'
          WHEN 'info' THEN 'informational'
          ELSE 'unknown'
        END
      END
    ) || '|' ||
    COALESCE(rule_name, 'unknown-rule') || '|' ||
    COALESCE(source_ip, 'unknown-source') || '|' ||
    COALESCE(destination_ip, 'unknown-destination') || '|' ||
    COALESCE(filter_status, 'accepted')
  )
`;

const {
  refreshGroupAliases,
  alertGroupKeyFromRow,
  currentAlertGroupKey,
  refreshAlertGroupSummary,
  rebuildAlertGroupSummariesUnlocked,
  rebuildAlertGroupSummaries,
} = createAlertGroupService({
  all,
  get,
  run,
  withImmediateTransaction,
  withSqliteWriteGate,
  nowUtc,
  normalizeTriageLevel,
  alertGroupId,
  alertGroupKeySql,
});

function run(sql, params = []) {
  return sqliteRuntime.run(sql, params);
}

function get(sql, params = []) {
  return sqliteRuntime.get(sql, params);
}

function all(sql, params = []) {
  return sqliteRuntime.all(sql, params);
}

const enrichmentScheduler = createProviderScheduler({
  failureThreshold: enrichmentCircuitFailureThreshold,
  resetMs: enrichmentCircuitResetMs,
  maxResetMs: enrichmentCircuitMaxResetMs,
  formatTimestamp: formatProjectTimestamp,
});
let durableJobs;
let postgresShadowOutbox;
let postgresShadowProjector;
const postgresAuxiliaryStores = createPostgresAuxiliaryStoreRuntime({
  env: process.env,
  controlledEvaluationMode,
  assetPostgresEnabled,
  softwarePostgresEnabled,
  acHunterPostgresEnabled,
  assetSchemaPath: assetPostgresSchemaPath,
  softwareSchemaPath: softwarePostgresSchemaPath,
  acHunterSchemaPath: acHunterPostgresSchemaPath,
  createPool: (config) => {
    const {Pool} = require('pg');
    return new Pool(config);
  },
  createAssetStore: (options) => createPostgresAssetStore(options),
  createSoftwareStore: (options) => createPostgresSoftwareStore(options),
  createAcHunterStore: (options) => createPostgresAcHunterStore(options),
  logger: applicationLogger,
});
let pipelineMetrics;
let pcapTransferRepository;
const serviceMetrics = {
  started_at: nowUtc(),
  ingest_requests: 0,
  ingest_errors: 0,
  ingest_latency_ms_total: 0,
  ingest_latency_ms_max: 0,
};
const postRequestAdmission = createRequestAdmission(httpMaxActivePosts);

function withSqliteWriteGate(task) {
  return sqliteRuntime.withWriteGate(task);
}

async function withImmediateTransaction(task) {
  return sqliteRuntime.withImmediateTransaction(task);
}

const enrichmentCache = createEnrichmentCache({
  run,
  get,
  all,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  formatTimestamp: formatProjectTimestamp,
  l1MaxEntries: enrichmentCacheL1MaxEntries,
  l1TtlSeconds: enrichmentCacheL1TtlSeconds,
  l1MaxBytes: enrichmentCacheL1MaxBytes,
  maxEntries: enrichmentCacheMaxEntries,
  maxBytes: enrichmentCacheMaxBytes,
  rawResponseMaxBytes: enrichmentCacheRawResponseMaxBytes,
  staleIfErrorSeconds: enrichmentStaleIfErrorSeconds,
  vulnerabilityStaleIfErrorSeconds: enrichmentVulnerabilityStaleIfErrorSeconds,
});
const {
  enrichAlert,
  cachedInvestigationEnrichment,
  queryInvestigationEnrichment,
} = createEnrichmentOrchestrator({
  cache: enrichmentCache,
  scheduler: enrichmentScheduler,
  providers: enrichmentProviderClient,
  policy: enrichmentPolicy,
  extractAlertIndicators,
  isRelayHeartbeat,
  nowUtc,
  formatProjectTimestamp,
  withSqliteWriteGate,
  withImmediateTransaction,
  get,
  run,
  defaultTtlSeconds: enrichmentCacheDefaultTtlSeconds,
  vulnerabilityTtlSeconds: vulnerabilityCacheDefaultTtlSeconds,
  negativeTtlSeconds: enrichmentNegativeCacheTtlSeconds,
  virusTotalMinimumLevel: virustotalMinimumLevel,
  urlscanSubmitEnabled,
});

function initializeDurableJobs() {
  durableJobs = createDurableJobQueue({
    run,
    get,
    all,
    now: nowUtc,
    transitionLeaseSeconds: aiAnalysisLeaseSeconds,
  });
}

function initializePostgresShadowOutbox() {
  postgresShadowOutbox = createPostgresShadowOutbox({run, get, all});
}

function initializePostgresShadowProjector() {
  if (!postgresShadowEnabled || controlledEvaluationMode) return;
  const requiredKeys = [
    'ALERT_STORE_POSTGRES_HOST',
    'ALERT_STORE_POSTGRES_DATABASE',
    'ALERT_STORE_POSTGRES_USER',
    'ALERT_STORE_POSTGRES_PASSWORD',
  ];
  const missing = requiredKeys.filter(
    (key) => !String(process.env[key] || '').trim(),
  );
  if (missing.length) {
    throw new Error(
      `PostgreSQL shadow projection is enabled but missing ${missing.join(', ')}`,
    );
  }
  const {Pool} = require('pg');
  const pool = new Pool({
    host: String(process.env.ALERT_STORE_POSTGRES_HOST),
    port: Number(process.env.ALERT_STORE_POSTGRES_PORT || 5433),
    database: String(process.env.ALERT_STORE_POSTGRES_DATABASE),
    user: String(process.env.ALERT_STORE_POSTGRES_USER),
    password: String(process.env.ALERT_STORE_POSTGRES_PASSWORD),
    max: 2,
    connectionTimeoutMillis: 3000,
    idleTimeoutMillis: 10000,
    application_name: 'onion-sentinel-shadow-projector',
  });
  // An idle pg client reports a database restart/outage through the Pool
  // "error" event. Without a listener Node treats it as an uncaught error and
  // exits the authoritative SQLite service. Shadow availability must never
  // control alert-store availability.
  pool.on('error', (error) => {
    console.error(
      `PostgreSQL shadow idle connection failed: ${String(error.message || error).slice(0, 500)}`,
    );
  });
  postgresShadowProjector = createPostgresShadowProjector({
    pool,
    outbox: postgresShadowOutbox,
    withWriteGate: withSqliteWriteGate,
    now: nowUtc,
    batchSize: postgresShadowBatchSize,
  });
}

async function initializePostgresAssetStore() {
  return postgresAuxiliaryStores.initializeAssetStore();
}

async function initializePostgresAcHunterStore() {
  return postgresAuxiliaryStores.initializeAcHunterStore();
}

async function initializePostgresSoftwareStore() {
  return postgresAuxiliaryStores.initializeSoftwareStore();
}

function requirePostgresAssetStore() {
  return postgresAuxiliaryStores.requireAssetStore();
}

function requirePostgresSoftwareStore() {
  return postgresAuxiliaryStores.requireSoftwareStore();
}

function requirePostgresAcHunterStore() {
  return postgresAuxiliaryStores.requireAcHunterStore();
}

function assetStoreWriteAuthorized(request) {
  return requestAuthorization.assetWriteAuthorized(request);
}

function requireAssetStoreWriteAuthorization(request) {
  return requestAuthorization.requireAssetWrite(request);
}

function initializePipelineMetrics() {
  pipelineMetrics = createPipelineMetrics({
    run,
    all,
    now: nowUtc,
    diskSnapshot: diskCapacitySnapshot,
    retentionHours: pipelineEventRetentionHours,
  });
  pcapTransferRepository = createPcapTransferRepository({
    get,
    run,
    safeString,
    nonNegativeIntegerField,
    nowUtc,
    formatProjectTimestamp,
    pcapRequestFromRow,
    classifyPcapOutcome,
    pcapOutcomes,
    pipelineMetrics,
    claimLeaseSeconds: pcapClaimLeaseSeconds,
    maxAttempts: pcapTransferMaxAttempts,
    maxRetrySeconds: pcapTransferMaxRetrySeconds,
  });
}

async function assertControlledEvaluationSchema() {
  return controlledEvaluationSchema.assertSchema();
}
async function initDb() {
  // Schema upgrades are additive. ensureColumn keeps existing SQLite DBs usable
  // after new triage fields are introduced.
  if (await alertStoreSchemaFoundation.configureRuntime()) return;
  await alertStoreSchemaFoundation.installFoundation();
  await incidentAnalysisSchema.install();
  await aiReviewSchema.install();
  await notificationEnrichmentSchema.install();
  await pcapSchema.install();
  await startupPersistenceOrchestrator.initialize();
}

async function tableColumns(tableName) {
  return new Promise((resolve, reject) => {
    db.all(`PRAGMA table_info(${tableName})`, [], (error, rows) => {
      if (error) reject(error);
      else resolve(rows.map((row) => row.name));
    });
  });
}

async function ensureColumn(tableName, columnName, columnType) {
  // Older SQLite builds do not support ADD COLUMN IF NOT EXISTS.
  const columns = await tableColumns(tableName);
  if (!columns.includes(columnName)) {
    await run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`);
  }
}

function alertGroupId(groupKey) {
  return crypto.createHash('sha1').update(String(groupKey || '')).digest('hex').slice(0, 12);
}

async function persistStableIdentity(alertId, row, alert = {}) {
  const identityRow = {...row, rule_id: alert.rule_id || row.rule_id};
  const key = stableGroupKey(identityRow);
  const id = stableGroupId(identityRow);
  await run('UPDATE alerts SET rule_id = COALESCE(?, rule_id), stable_group_key = ?, stable_group_id = ? WHERE alert_id = ?',
    [alert.rule_id || null, key, id, alertId]);
  return {stable_group_key: key, stable_group_id: id};
}

async function backfillStableGroupIdentity() {
  const pending = await all("SELECT * FROM alerts WHERE stable_group_id IS NULL OR stable_group_id = ''");
  if (!pending.length) return 0;
  // A restart must never expose a partially migrated identity index. Keeping
  // the startup backfill in one transaction also avoids one fsync per row when
  // DELETE/FULL durability is intentionally enabled.
  await withImmediateTransaction(async () => {
    for (const item of pending) {
      const alert = parseJsonObject(item.alert_json);
      await persistStableIdentity(item.alert_id, item, alert);
    }
  });
  return pending.length;
}

async function recordAuthorizedActivityCampaign(alert, row, inserted = true) {
  return authorizedCampaignPersistence.recordCampaign(alert, row, inserted);
}

async function backfillAuthorizedActivityCampaigns() {
  return authorizedCampaignPersistence.backfillCampaigns();
}

async function authorizedCampaignForAlertId(alertId) {
  return authorizedCampaignPersistence.campaignForAlertId(alertId);
}

async function reconcileAuthorizedActivityBacklog() {
  return authorizedCampaignPersistence.reconcileBacklog();
}

async function indexAlertObservables(alert, row) {
  return authorizedCampaignPersistence.indexObservables(alert, row);
}

async function backfillAlertObservables() {
  return authorizedCampaignPersistence.backfillObservables();
}

async function recordAiAnalysisResult(payload) {
  return aiAnalysisAcceptance.record(payload);
}

function validAnalystGroupId(value) {
  return analystReviewDefinitions.validAnalystGroupId(value);
}

function validIncidentCaseId(value) {
  return analystReviewDefinitions.validIncidentCaseId(value);
}

async function stableGroupHasPendingHumanReview(stableId) {
  return analystReviewProjection.pendingHumanReview(stableId);
}

async function analystReviewState(options = {}) {
  return analystReviewProjection.reviewState(options);
}

async function analystAdjudicationSnapshot(searchParams) {
  return analystReviewProjection.adjudicationSnapshot(searchParams);
}

async function recordAnalystAdjudication(payload) {
  return analystDecisionPersistence.recordAdjudication(payload);
}

async function updateIncidentCaseStatus(payload) {
  return analystDecisionPersistence.updateIncidentCaseStatus(payload);
}

async function analystStatusSnapshot() {
  return analystDecisionPersistence.statusSnapshot();
}

async function updateAnalystStatus(payload) {
  return analystDecisionPersistence.updateStatus(payload);
}

async function storeAlert(rawAlert) {
  return alertIngestOrchestrator.store(rawAlert);
}

function controlledJobClaimIdentity(value) {
  return controlledJobIdentity.parseClaim(value);
}

function controlledEvaluationLeaseKey(jobType, dedupeKey) {
  return controlledJobTransitionAuthority.leaseKey(jobType, dedupeKey);
}

async function controlledJobTransitionAdmission(payload) {
  return controlledJobTransitionAuthority.admit(payload);
}

function applyControlledJobTransition(admission, transition) {
  return controlledJobTransitionAuthority.apply(admission, transition);
}

function controlledEvaluationClaimDigest(identity) {
  return controlledResultAdmissionAuthority.claimDigest(identity);
}

async function controlledEvaluationResultAdmission(payload) {
  return controlledResultAdmissionAuthority.admit(payload);
}

function applyControlledEvaluationResultAdmission(admission) {
  return controlledResultAdmissionAuthority.apply(admission);
}

async function transitionDurableJobStatus(
  jobType,
  dedupeKey,
  status,
  error = '',
  leaseToken = '',
  retryable = true,
  requestedClaimIdentity = null,
) {
  return durableJobTransitionExecutor.transition(
    jobType,
    dedupeKey,
    status,
    error,
    leaseToken,
    retryable,
    requestedClaimIdentity,
  );
}

async function recoverExpiredDurableJobs() {
  return durableJobRecovery.recover();
}

const cohortIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const stableGroupIdPattern = /^[a-f0-9]{20}$/;
const dispatchIdPattern = /^[a-f0-9]{64}$/;
const releaseIdPattern = /^[a-f0-9]{40}$/;
const representativeAlertIdPattern = /^[A-Za-z0-9._:@=-]{1,256}$/;
const controlledRoutePattern = /^codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):(?:low|medium|high|xhigh)$/;
function controlledRouteModelIdentity(route) {
  return String(route || '').split(':').slice(0, -1).join(':');
}
const controlledRetirementSchema = controlledRetirementDefinitions.RETIREMENT_SCHEMA;
const controlledRetirementReceiptSchema = controlledRetirementDefinitions.RECEIPT_SCHEMA;
const controlledRetirementEventType = controlledRetirementDefinitions.EVENT_TYPE;
const controlledRetirementReceiptFields = controlledRetirementDefinitions.RECEIPT_FIELDS;
const controlledRetirementRequestFields = controlledRetirementDefinitions.REQUEST_FIELDS;

function requestHasOwnField(payload, field) {
  return Boolean(
    payload
    && typeof payload === 'object'
    && Object.prototype.hasOwnProperty.call(payload, field)
  );
}

function incidentIdentityConflict(message) {
  const error = new Error(message);
  error.statusCode = 409;
  return error;
}

function controlledRuntimeReleaseId() {
  const releaseId = process.env.ONION_SENTINEL_RELEASE_ID;
  return (
    typeof releaseId === 'string'
    && releaseIdPattern.test(releaseId)
  ) ? releaseId : '';
}

function manualDispatchIdentity(payload) {
  return manualDispatchIdentityOwner.normalize(payload);
}
async function resolveDashboardAlertGroup(dashboardGroupId, identity = {}) {
  return manualAnalysisDispatch.resolveDashboardAlertGroup(dashboardGroupId, identity);
}

async function requestAiReanalysis(payload) {
  return manualAnalysisDispatch.requestAiReanalysis(payload);
}

async function requestIncidentEscalation(payload) {
  return manualAnalysisDispatch.requestIncidentEscalation(payload);
}

async function queueIncidentResponseForGroup(options) {
  return manualAnalysisDispatch.queueIncidentResponseForGroup(options);
}

function incidentReanalysisReleaseId() {
  const candidate = safeString(
    process.env.ONION_SENTINEL_RELEASE_ID || 'unversioned',
    100,
  ).replace(/[^A-Za-z0-9._:-]+/g, '-').replace(/^-+|-+$/g, '');
  return candidate || 'unversioned';
}

const incidentReanalysisRunPersistence = createIncidentReanalysisRunPersistence({
  get,
  all,
  run,
  nowUtc,
});

async function incidentReanalysisRunSnapshot(runId) {
  return incidentReanalysisRunPersistence.snapshot(runId);
}

async function refreshIncidentReanalysisRun(runId) {
  return incidentReanalysisRunPersistence.refresh(runId);
}

async function supersedeIncidentReanalysisCase(caseId, replacementRunId, updatedAt) {
  return incidentReanalysisRunPersistence.supersedeCase(
    caseId, replacementRunId, updatedAt,
  );
}

async function requestIncidentReanalysis(payload, requestedCaseId = '') {
  return incidentReanalysisRequestOwner.request(payload, requestedCaseId);
}
function incidentReanalysisJobPayload(job) {
  return incidentReanalysisJobOwnership.jobPayload(job);
}

async function retireCompletedIncidentReanalysisJob(job) {
  return incidentReanalysisJobOwnership.retireCompleted(job);
}

async function retireSupersededIncidentReanalysisJob(job) {
  return incidentReanalysisJobOwnership.retireSuperseded(job);
}

function incidentReanalysisAttemptId(leaseToken) {
  return incidentReanalysisJobOwnership.attemptId(leaseToken);
}

function incidentAnalysisProvider(modelPath, observedProvider = '') {
  return incidentReanalysisJobOwnership.analysisProvider(modelPath, observedProvider);
}

async function closeStaleIncidentReanalysisAttempts(
  groupId,
  currentRunId,
  currentCaseId,
  updatedAt,
) {
  return incidentReanalysisJobOwnership.closeStale(
    groupId, currentRunId, currentCaseId, updatedAt,
  );
}
async function beginIncidentReanalysisAttempt(job, leaseToken, groupId) {
  return incidentReanalysisAttemptLifecycle.begin(job, leaseToken, groupId);
}

async function heartbeatIncidentReanalysisAttempt(leaseToken) {
  return incidentReanalysisAttemptLifecycle.heartbeat(leaseToken);
}

async function finishIncidentReanalysisAttempt(job, requestedStatus, error, leaseToken) {
  return incidentReanalysisAttemptLifecycle.finish(job, requestedStatus, error, leaseToken);
}

async function queueCurrentIncidentReanalysisRun(job) {
  return incidentReanalysisAttemptLifecycle.queue(job);
}
async function reconcileRecoveredIncidentReanalysisAttempts() {
  return incidentReanalysisRecovery.reconcile();
}
async function updateIncidentReanalysisProgress(options) {
  return incidentReanalysisAttemptLifecycle.update(options);
}
async function incidentReanalysisBindingAuthority(attempt) {
  return incidentReanalysisBindingService.bindingAuthority(attempt);
}

async function bindIncidentReanalysisResult({
  groupId,
  analysisId,
  model,
  modelPath,
  provider,
  expectedAttemptId,
  allowLegacyFallback,
  analysisStartedAt,
  generatedAt,
}) {
  return incidentReanalysisBindingService.bindResult({
    groupId,
    analysisId,
    model,
    modelPath,
    provider,
    expectedAttemptId,
    allowLegacyFallback,
    analysisStartedAt,
    generatedAt,
  });
}

async function drainEnrichmentJobs() {
  return durableBackgroundDrains.drainEnrichment();
}

function n8nPostCommitResult(body) {
  return durableBackgroundDrains.postCommitResult(body);
}

async function drainN8nPostCommitJobs() {
  return durableBackgroundDrains.drainPostCommit();
}

async function storeAlertUnlocked(alert) {
  return alertPersistence.store(alert);
}

async function applySuppressionPolicy(alert, now) {
  return suppressionPersistence.apply(alert, now);
}

async function rescoreAlertsUnlocked() {
  return rescorePersistence.rescore();
}

async function rescoreAlerts() {
  // Maintenance writes must not interleave with multi-statement ingestion.
  return withSqliteWriteGate(rescoreAlertsUnlocked);
}

function safeString(value, maxLength = 240) {
  return alertValueNormalization.safeString(value, maxLength);
}

function safeFileToken(value, fallback = 'artifact') {
  return alertValueNormalization.safeFileToken(value, fallback);
}

function parseJsonObject(value) {
  return alertValueNormalization.parseJsonObject(value);
}

const {
  pcapOutcomes,
  pcapCandidateFromRow,
  normalizePcapRequest,
  pcapRetentionError,
  pcapRequestFromRow,
  classifyPcapOutcome,
} = createPcapPolicy({
  safeString,
  parseJsonObject,
  nestedField,
  integerField,
  normalizeTimestampValue,
  defaultWindowSeconds: pcapRequestDefaultWindowSeconds,
  maxWindowSeconds: pcapRequestMaxWindowSeconds,
  captureRetentionSeconds: pcapCaptureRetentionSeconds,
});
const pcapRequestRepository = createPcapRequestRepository({
  get,
  all,
  run,
  safeString,
  parseJsonObject,
  jsonText,
  nowUtc,
  pcapCandidateFromRow,
  normalizePcapRequest,
  pcapRetentionError,
  pcapRequestFromRow,
  classifyPcapOutcome,
  recordMetric: (...args) => pipelineMetrics.record(...args),
  readCaptureLossThreshold: () => (
    socAnalysisPolicy.read().pcap_capture_loss_threshold_percent
  ),
  requeueStaleClaims: (...args) => (
    pcapTransferRepository.requeueStaleClaims(...args)
  ),
  priorityMaxWaitSeconds: pcapPriorityMaxWaitSeconds,
  captureRetentionSeconds: pcapCaptureRetentionSeconds,
});
const pcapAnalysisCompletion = createPcapAnalysisCompletion({
  run,
  get,
  safeString,
  nowUtc,
  recordMetric: (...args) => pipelineMetrics.record(...args),
  matchesAnalysis: (level) => socAnalysisPolicy.matchesAnalysis(level),
  authorizedCampaignForAlertId,
  enqueueAiJob: (...args) => durableJobs.enqueue('ai_analysis', ...args),
  severityRank,
});
const aiReviewRepository = createAiReviewRepository({
  run,
  safeString,
  jsonText,
  nowUtc,
});
const aiCorrelationRepository = createAiCorrelationRepository({
  get,
  run,
  safeString,
  jsonText,
  nowUtc,
  compactCorrelationCandidates,
});
const incidentReanalysisBindingService = createIncidentReanalysisBindingService({
  get,
  run,
  safeString,
  parseProjectTimestamp,
  formatProjectTimestamp,
  nowUtc,
  incidentAnalysisProvider,
  refreshIncidentReanalysisRun,
});
const incidentAnalysisCompletion = createIncidentAnalysisCompletion({
  get,
  run,
  safeString,
  jsonText,
  nowUtc,
  bindIncidentReanalysisResult,
});
const aiAnalysisAcceptance = createAiAnalysisAcceptance({
  get,
  run,
  safeString,
  jsonText,
  nowUtc,
  parseJsonObject,
  canonicalJsonText,
  normalizeTimestampValue,
  supportedAgentRoles,
  incidentReanalysisBindingAuthority,
  aiReviewRepository,
  incidentAnalysisCompletion,
  aiCorrelationRepository,
});
const controlledJobIdentity = createControlledJobIdentity({
  requestHasOwnField,
  identityConflict: incidentIdentityConflict,
  validPinnedStableGroupKey,
  representativeAlertIdPattern,
  dispatchIdPattern,
  controlledRoutePattern,
  controlledRouteModelIdentity,
});
const controlledJobTransitionAuthority = createControlledJobTransition({
  controlledEvaluationMode,
  safeString,
  identityConflict: incidentIdentityConflict,
  stableGroupIdPattern,
  parseClaimIdentity: controlledJobClaimIdentity,
  all,
  get,
  incidentReanalysisJobPayload,
  validPinnedStableGroupKey,
  cohortIdPattern,
  dispatchIdPattern,
  representativeAlertIdPattern,
  controlledRuntimeReleaseId,
  controlledRoutePattern,
  controlledRouteModelIdentity,
  incidentReanalysisAttemptId,
});
const controlledEvaluationLeases = controlledJobTransitionAuthority.leases;
const controlledResultAdmissionAuthority = createControlledResultAdmission({
  controlledEvaluationMode,
  safeString,
  identityConflict: incidentIdentityConflict,
  claimLeaseKey: controlledEvaluationLeaseKey,
  get,
  incidentReanalysisJobPayload,
  parseJsonObject,
  canonicalJsonText,
  controlledRoutePattern,
  controlledRouteModelIdentity,
  cohortIdPattern,
  dispatchIdPattern,
  representativeAlertIdPattern,
  stableGroupIdPattern,
  validPinnedStableGroupKey,
  releaseIdPattern,
  runtimeReleaseId: runtimeReleaseIdValue,
  incidentReanalysisAttemptId,
  retireLease: controlledJobTransitionAuthority.retireLease,
});
const durableBackgroundDrains = createDurableBackgroundDrains({
  durableJobs: () => durableJobs,
  withWriteTransaction: (task) => (
    withSqliteWriteGate(() => withImmediateTransaction(task))
  ),
  get,
  run,
  enrichAlert,
  enrichmentRecord,
  jsonText,
  indexAlertObservables,
  groupKeyFromRow: alertGroupKeyFromRow,
  groupIdFromKey: alertGroupId,
  authorizedCampaignForAlertId,
  matchesAnalysis: (level) => socAnalysisPolicy.matchesAnalysis(level),
  severityRank,
  recordMetric: (...args) => pipelineMetrics.record(...args),
  signalAiWorkers,
  requestJson,
  safeString,
  enrichmentTimeoutMs,
  n8nPostCommitUrl,
  n8nPostCommitToken,
  n8nPostCommitTimeoutMs,
  n8nPostCommitBaseRetrySeconds,
});
const durableJobRecovery = createDurableJobRecovery({
  durableJobs: () => durableJobs,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  reconcileIncidentAttempts: reconcileRecoveredIncidentReanalysisAttempts,
  reconcileAuthorizedActivity: reconcileAuthorizedActivityBacklog,
  nowUtc,
  warn: (...args) => console.warn(...args),
  signalAiWorkers,
  drainEnrichmentJobs,
  drainPostCommitJobs: drainN8nPostCommitJobs,
});
const durableJobTransitionExecutor = createDurableJobTransitionExecutor({
  controlledEvaluationMode,
  parseClaimIdentity: controlledJobClaimIdentity,
  stableGroupIdPattern,
  identityConflict: incidentIdentityConflict,
  get,
  run,
  safeString,
  incidentReanalysisJobPayload,
  controlledRuntimeReleaseId,
  incidentReanalysisAttemptId,
  aiAnalysisLeaseSeconds,
  nowUtc,
  durableJobs: () => durableJobs,
  pipelineMetrics: () => pipelineMetrics,
  retireCompletedIncidentReanalysisJob,
  retireSupersededIncidentReanalysisJob,
  updateIncidentReanalysisProgress,
  signalAiWorkers,
});
const controlledRetirementIdentityOwner = (
  controlledRetirementDefinitions.createControlledRetirementIdentity({
    controlledEvaluationMode,
    safeString,
    validIncidentCaseId,
    cohortIdPattern,
    dispatchIdPattern,
    releaseIdPattern,
    representativeAlertIdPattern,
    stableGroupIdPattern,
    validPinnedStableGroupKey,
    controlledRuntimeReleaseId,
  })
);
const {
  conflict: controlledRetirementConflict,
  canonicalJsonText: controlledRetirementCanonicalJsonText,
  sha256: controlledRetirementSha256,
  rawSha256: controlledRetirementRawSha256,
  normalize: controlledRetirementIdentity,
} = controlledRetirementIdentityOwner;
const controlledEvaluationSchema = createControlledEvaluationSchema({
  all,
  get,
  initializeDurableJobs,
  initializePipelineMetrics,
});
const alertStoreSchemaFoundation = createAlertStoreSchemaFoundation({
  run,
  ensureColumn,
  assertControlledSchema: assertControlledEvaluationSchema,
  controlledEvaluationMode,
  sqliteBusyTimeoutMs,
  allowedJournalModes,
  sqliteJournalMode,
  allowedSynchronousModes,
  sqliteSynchronous,
  allowedTempStoreModes,
  sqliteTempStore,
  alertGroupKeySql,
});
const incidentAnalysisSchema = createIncidentAnalysisSchema({run, ensureColumn});
const aiReviewSchema = createAiReviewSchema({run, ensureColumn});
const notificationEnrichmentSchema = createNotificationEnrichmentSchema({
  run,
  nowUtc,
  installEnrichmentCache: () => enrichmentCache.install(),
});
const pcapSchema = createPcapSchema({
  run,
  ensureColumn,
  backfillOutcomes: () => pcapRequestRepository.backfillOutcomes(),
});
const authorizedCampaignPersistence = createAuthorizedCampaignPersistence({
  all,
  get,
  run,
  withImmediateTransaction,
  policy: authorizedActivityPolicy,
  matchAuthorizedActivity,
  parseJsonObject,
  normalizeTimestampValue,
  nowUtc,
  jsonText,
  integerField,
  completePendingJobs: (...args) => durableJobs.completePendingByDedupeKeys(...args),
  stableGroupKey,
  stableGroupId,
  buildAlertObservables,
  extractAlertIndicators,
});
const analystReviewProjection = analystReviewDefinitions.createAnalystReviewProjection({
  get,
  all,
  resolveDashboardAlertGroup,
  safeString,
  parseJsonObject,
  conservativeReviewerTelemetry,
  reviewerAutomationAuthorization,
  reviewerFailureStatuses,
});
const analystDecisionPersistence = createAnalystDecisionPersistence({
  get,
  all,
  run,
  withWriteGate: withSqliteWriteGate,
  reviewState: analystReviewState,
  validGroupId: validAnalystGroupId,
  validCaseId: validIncidentCaseId,
  safeString,
  adjudicationOutcomes: analystAdjudicationOutcomes,
  adjudicationConfidences: analystAdjudicationConfidences,
  eventStatuses: analystEventStatuses,
  detectionValidities: analystDetectionValidities,
  activityDispositions: analystActivityDispositions,
  handlingValues: analystHandlingValues,
  verdictContradictions: analystVerdictContradictions,
  adjudicationTextMaxLength: analystAdjudicationTextMaxLength,
  statusReasonMaxLength: analystStatusReasonMaxLength,
  nowUtc,
  randomUUID: crypto.randomUUID,
  jsonText,
});
const suppressionPersistence = createSuppressionPersistence({
  findSuppressRule,
  stableGroupId,
  nestedField,
  pendingHumanReview: stableGroupHasPendingHumanReview,
  suppressionKey,
  ruleName,
  get,
  run,
});
const rescorePersistence = createRescorePersistence({
  all,
  run,
  scoreAlert,
  nestedField,
  integerField,
  jsonText,
  enrichmentRecord,
  rebuildGroupSummaries: rebuildAlertGroupSummariesUnlocked,
  scoringRulesName: path.basename(scoringRulesPath),
});
const automaticResponseRouting = createAutomaticResponseRouting({
  nestedField,
  readPolicy: () => socAnalysisPolicy.read(),
  matchesPcap: (level) => socAnalysisPolicy.matchesPcap(level),
  matchesIncident: (level) => socAnalysisPolicy.matchesIncident(level),
  groupKeyFromRow: alertGroupKeyFromRow,
  groupIdFromKey: alertGroupId,
  get,
  run,
  parseJsonObject,
  jsonText,
  nowUtc,
  createPcapRequest: (...args) => pcapRequestRepository.createRequest(...args),
  pcapRequestDefaultWindowSeconds,
  queueIncidentResponseForGroup,
  severityRank,
});
const alertPersistence = createAlertPersistence({
  currentGroupKey: currentAlertGroupKey,
  nowUtc,
  findDropRule,
  nestedField,
  ruleName,
  normalizeTimestampValue,
  integerField,
  jsonText,
  enrichmentRecord,
  run,
  get,
  applySuppression: applySuppressionPolicy,
  persistStableIdentity,
  indexObservables: indexAlertObservables,
  recordCampaign: recordAuthorizedActivityCampaign,
  groupKeyFromRow: alertGroupKeyFromRow,
  refreshGroupSummary: refreshAlertGroupSummary,
  queueAutomaticPcap: maybeQueueAutomaticPcapRequest,
  queueAutomaticIncident: maybeQueueAutomaticIncidentResponse,
});
const postCommitPayload = createPostCommitPayload({nowUtc, nestedField});
const alertIngestOrchestrator = createAlertIngestOrchestrator({
  scoreAlert,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  storeUnlocked: storeAlertUnlocked,
  queueNotification: queueTelegramNotification,
  nowUtc,
  buildPostCommitPayload: postCommitPayload.build,
  enqueueJob: (...args) => durableJobs.enqueue(...args),
  recordMetric: (...args) => pipelineMetrics.record(...args),
  severityRank,
  postCommitMaxAttempts: n8nPostCommitMaxAttempts,
  hasUsableExternalIntel,
  nestedField,
  enrichmentMaxAttempts: enrichmentWorkerMaxAttempts,
  groupKeyFromRow: alertGroupKeyFromRow,
  groupIdFromKey: alertGroupId,
  matchesAnalysis: (level) => socAnalysisPolicy.matchesAnalysis(level),
  signalAiWorkers,
  drainNotificationOutbox: drainTelegramOutbox,
  drainEnrichmentJobs,
  drainPostCommitJobs: drainN8nPostCommitJobs,
});
const startupPersistenceOrchestrator = createStartupPersistenceOrchestrator({
  initializeDurableJobs,
  installDurableJobs: () => durableJobs.install(),
  initializePostgresShadowOutbox,
  installPostgresShadowOutbox: () => postgresShadowOutbox.install(),
  initializePostgresShadowProjector,
  reconcileRecoveredIncidentAttempts: reconcileRecoveredIncidentReanalysisAttempts,
  initializePipelineMetrics,
  installPipelineMetrics: () => pipelineMetrics.install(),
  backfillStableGroupIdentity,
  backfillAuthorizedActivityCampaigns,
  reconcileAuthorizedActivityBacklog,
  backfillAlertObservables,
  rebuildAlertGroupSummaries,
  refreshGroupAliases,
});
const controlledRetirementProjections = createControlledRetirementProjections({
  rawSha256: controlledRetirementRawSha256,
  sha256: controlledRetirementSha256,
  safeString,
  parseTimestamp: parseProjectTimestamp,
});
const {
  job: controlledRetirementJobProjection,
  orderedDispatches: controlledRetirementOrderedDispatches,
  error: controlledRetirementErrorProjection,
  run: controlledRetirementRunProjection,
  runCase: controlledRetirementRunCaseProjection,
  attempt: controlledRetirementAttemptProjection,
  completedLifecycleValid: controlledRetirementCompletedJobLifecycleValid,
  completed: controlledRetirementCompletedProjection,
} = controlledRetirementProjections;
const controlledRetirementCompletedMemberOwner = createControlledRetirementCompletedMember({
  all,
  get,
  parseJsonObject,
  incidentAnalysisProvider,
  completedJobLifecycleValid: controlledRetirementCompletedJobLifecycleValid,
  projectCompleted: controlledRetirementCompletedProjection,
  conflict: controlledRetirementConflict,
});
const controlledRetirementTargetMemberOwner = createControlledRetirementTargetMember({
  all,
  safeString,
  projectJob: controlledRetirementJobProjection,
  projectRun: controlledRetirementRunProjection,
  projectRunCase: controlledRetirementRunCaseProjection,
  projectAttempt: controlledRetirementAttemptProjection,
  projectError: controlledRetirementErrorProjection,
  rawSha256: controlledRetirementRawSha256,
  conflict: controlledRetirementConflict,
});
const controlledRetirementCensusOwner = createControlledRetirementCensus({
  all,
  orderedDispatches: controlledRetirementOrderedDispatches,
  parseJobPayload: incidentReanalysisJobPayload,
  validIncidentCaseId,
  stableGroupIdPattern,
  validPinnedStableGroupKey,
  representativeAlertIdPattern,
  parseJsonObject,
  projectCompleted: controlledRetirementCompletedMemberOwner.project,
  projectTarget: controlledRetirementTargetMemberOwner.project,
  conflict: controlledRetirementConflict,
});
const controlledRetirementReplayOwner = createControlledRetirementReplay({
  all,
  get,
  eventType: controlledRetirementEventType,
  receiptFields: controlledRetirementReceiptFields,
  receiptSchema: controlledRetirementReceiptSchema,
  dispatchIdPattern,
  parseJsonObject,
  canonicalJsonText: controlledRetirementCanonicalJsonText,
  sha256: controlledRetirementSha256,
  projectJob: controlledRetirementJobProjection,
  projectCensus: controlledRetirementCensusOwner.project,
  conflict: controlledRetirementConflict,
});
const controlledRetirementCommandOwner = createControlledRetirementCommand({
  normalizeIdentity: controlledRetirementIdentity,
  sha256: controlledRetirementSha256,
  replay: controlledRetirementReplayOwner.replay,
  validatePostState: controlledRetirementReplayOwner.validatePostState,
  projectCensus: controlledRetirementCensusOwner.project,
  get,
  all,
  run,
  parseJobPayload: incidentReanalysisJobPayload,
  projectJob: controlledRetirementJobProjection,
  parseJsonObject,
  leaseKey: controlledEvaluationLeaseKey,
  hasLease: (key) => controlledEvaluationLeases.has(key),
  nowUtc,
  retirePendingExact: (options) => durableJobs.retirePendingExact(options),
  refreshRun: refreshIncidentReanalysisRun,
  receiptSchema: controlledRetirementReceiptSchema,
  eventType: controlledRetirementEventType,
  canonicalJsonText: controlledRetirementCanonicalJsonText,
  validateReceipt: controlledRetirementReplayOwner.validateReceipt,
  conflict: controlledRetirementConflict,
});
const manualDispatchIdentityOwner = createManualDispatchIdentity({
  hasOwnField: requestHasOwnField,
  stableGroupIdPattern,
  validPinnedStableGroupKey,
  cohortIdPattern,
  dispatchIdPattern,
  releaseIdPattern,
  controlledRoutePattern,
  controlledRouteModelIdentity,
  representativeAlertIdPattern,
  runtimeReleaseId: controlledRuntimeReleaseId,
  conflict: incidentIdentityConflict,
});
const incidentDurableJobPersistence = createIncidentDurableJobPersistence({
  get,
  run,
  conflict: incidentIdentityConflict,
});
const manualAnalysisDispatch = createManualAnalysisDispatch({
  get,
  run,
  safeString,
  normalizeIdentity: manualDispatchIdentity,
  conflict: incidentIdentityConflict,
  rejectProcessingJob: incidentDurableJobPersistence.rejectProcessing,
  enqueueJob: (...args) => durableJobs.enqueue(...args),
  recordMetric: (...args) => pipelineMetrics.record(...args),
  nowUtc,
  jsonText,
  sha256Text: (value) => crypto.createHash('sha256').update(value).digest('hex'),
});
const alertGroupAliasResolution = createAlertGroupAliasResolution({
  all,
  conflict: incidentIdentityConflict,
});
const incidentReanalysisFrozenDispatchOwner = createIncidentReanalysisFrozenDispatch({
  get,
  all,
  run,
  parseJsonObject,
  loadAliases: alertGroupAliasResolution.loadSnapshot,
  resolveCanonicalIdentity: alertGroupAliasResolution.resolve,
  rejectProcessingJob: incidentDurableJobPersistence.rejectProcessing,
  jsonText,
  conflict: incidentIdentityConflict,
});
const incidentReanalysisRequestOwner = createIncidentReanalysisRequest({
  validCaseId: validIncidentCaseId,
  normalizeIdentity: manualDispatchIdentity,
  controlledEvaluationMode,
  safeString,
  replayFrozen: (...args) => incidentReanalysisFrozenDispatchOwner.replay(...args),
  bindFrozen: (...args) => incidentReanalysisFrozenDispatchOwner.bind(...args),
  releaseId: incidentReanalysisReleaseId,
  nowUtc,
  randomUuid: () => crypto.randomUUID(),
  all,
  get,
  run,
  supersedeCase: supersedeIncidentReanalysisCase,
  retirePendingJobs: incidentDurableJobPersistence.retirePendingIncident,
  enqueueJob: (...args) => durableJobs.enqueue(...args),
  jsonText,
  recordMetric: (...args) => pipelineMetrics.record(...args),
  refreshRun: refreshIncidentReanalysisRun,
  conflict: incidentIdentityConflict,
});
const incidentReanalysisJobOwnership = createIncidentReanalysisJobOwnership({
  safeString,
  validCaseId: validIncidentCaseId,
  get,
  all,
  run,
  nowUtc,
  sha256Text: (value) => crypto.createHash('sha256').update(value).digest('hex'),
  refreshRun: refreshIncidentReanalysisRun,
});
const incidentReanalysisAttemptLifecycle = createIncidentReanalysisAttemptLifecycle({
  jobPayload: incidentReanalysisJobPayload,
  safeString,
  validCaseId: validIncidentCaseId,
  attemptId: incidentReanalysisAttemptId,
  closeStale: closeStaleIncidentReanalysisAttempts,
  get,
  run,
  nowUtc,
  refreshRun: refreshIncidentReanalysisRun,
});
const incidentReanalysisRecovery = createIncidentReanalysisRecovery({
  durableJobsAvailable: () => Boolean(durableJobs),
  all,
  get,
  run,
  retireCompleted: retireCompletedIncidentReanalysisJob,
  retireSuperseded: retireSupersededIncidentReanalysisJob,
  attemptId: incidentReanalysisAttemptId,
  beginAttempt: beginIncidentReanalysisAttempt,
  safeString,
  jobPayload: incidentReanalysisJobPayload,
  validCaseId: validIncidentCaseId,
  nowUtc,
  refreshRun: refreshIncidentReanalysisRun,
});

async function maybeQueueAutomaticPcapRequest(alert, storedRow, inserted, suppression, campaign = null) {
  return automaticResponseRouting.queuePcap(
    alert, storedRow, inserted, suppression, campaign,
  );
}

async function maybeQueueAutomaticIncidentResponse(alert, storedRow, inserted, suppression, campaign = null) {
  return automaticResponseRouting.queueIncident(
    alert, storedRow, inserted, suppression, campaign,
  );
}

function readJsonBody(request, includeBodySha256 = false) {
  return readJsonObject(request, {
    maxBytes: maxRequestBytes,
    includeBodySha256,
  });
}

function sendJson(response, code, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  response.end(body);
}

async function capturePipelineDiskSample() {
  if (!pipelineMetrics) return;
  const pageCount = await get('PRAGMA page_count');
  const pageSize = await get('PRAGMA page_size');
  const sqliteBytes = Number(pageCount?.page_count || 0) * Number(pageSize?.page_size || 0);
  await withSqliteWriteGate(() => pipelineMetrics.captureDiskSample(sqliteBytes));
}

const controlledEvaluationRequests = new Set([
  'GET /health',
  'POST /ai/request',
  'POST /analysis/result',
  'POST /controlled-evaluations/retire',
  'POST /incidents/reanalyze',
  'POST /jobs/status',
]);

const inventoryService = createInventoryService({
  requireAcHunterStore: requirePostgresAcHunterStore,
  requireSoftwareStore: requirePostgresSoftwareStore,
  requireAssetStore: requirePostgresAssetStore,
});
const modularRoutes = createRouteRegistry(createInventoryRoutes({
  service: inventoryService,
  authorizeWrite: requireAssetStoreWriteAuthorization,
  readJsonBody,
  sendJson,
}));
const healthRepository = createHealthRepository({get, all});
const healthService = createHealthService({
  repository: healthRepository,
  runtime: () => ({
    controlledEvaluationMode,
    controlledEvaluationLeases,
    controlledRoutes: controlledEvaluationRequests,
    runtimeReleaseId: runtimeReleaseIdValue,
    host,
    port,
    activeSqliteWrites: sqliteRuntime.activeWrites(),
    telegramOutboxSnapshot,
    enrichmentScheduler,
    enrichmentCache,
    authorizedActivityPolicyPath,
    authorizedActivityPolicyCount: authorizedActivityPolicy.policies.length,
    authorizedCampaignReconciliation: authorizedCampaignPersistence.reconciliationState(),
    diskCapacitySnapshot,
    postgresShadowOutbox,
    postgresShadowProjector,
    postgresShadowEnabled,
    ...postgresAuxiliaryStores.state(),
    durableJobs,
    serviceMetrics,
    postRequestAdmission,
    pipelineMetrics,
    nowUtc,
  }),
});
modularRoutes.registerAll(createHealthRoutes({service: healthService, sendJson}));
const analystStateService = createAnalystStateService({
  analystStatusSnapshot,
  updateAnalystStatus,
  analystAdjudicationSnapshot,
  recordAnalystAdjudication,
  updateIncidentCaseStatus,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
});
modularRoutes.registerAll(createAnalystStateRoutes({
  service: analystStateService,
  readJsonBody,
  sendJson,
}));
const durableJobService = createDurableJobService({
  safeString,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  controlledTransitionAdmission: controlledJobTransitionAdmission,
  transitionJobStatus: transitionDurableJobStatus,
  applyControlledTransition: applyControlledJobTransition,
  completePendingByDedupeKeys: (...args) => (
    durableJobs.completePendingByDedupeKeys(...args)
  ),
});
modularRoutes.registerAll(createDurableJobRoutes({
  service: durableJobService,
  readJsonBody,
  sendJson,
}));
const analysisRequestService = createAnalysisRequestService({
  controlledEvaluationMode: () => controlledEvaluationMode,
  identityConflict: incidentIdentityConflict,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  requestAiReanalysis,
  requestIncidentEscalation,
  requestIncidentReanalysis,
  retireControlledEvaluation: controlledRetirementCommandOwner.retire,
  signalAiWorkers,
});
modularRoutes.registerAll(createAnalysisRequestRoutes({
  service: analysisRequestService,
  readJsonBody,
  sendJson,
}));
const analysisResultService = createAnalysisResultService({
  controlledEvaluationMode: () => controlledEvaluationMode,
  requestHasOwnField,
  identityConflict: incidentIdentityConflict,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  controlledResultAdmission: controlledEvaluationResultAdmission,
  recordAnalysisResult: recordAiAnalysisResult,
  transitionJobStatus: transitionDurableJobStatus,
  applyControlledResultAdmission: applyControlledEvaluationResultAdmission,
});
modularRoutes.registerAll(createAnalysisResultRoutes({
  service: analysisResultService,
  readJsonBody,
  sendJson,
}));
const pcapService = createPcapService({
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  createRequest: (...args) => pcapRequestRepository.createRequest(...args),
  listRequests: (...args) => pcapRequestRepository.listRequests(...args),
  claimRequest: (...args) => pcapTransferRepository.claimRequest(...args),
  completeRequest: (...args) => pcapTransferRepository.completeRequest(...args),
  updateTransferProgress: (...args) => pcapTransferRepository.updateTransferProgress(...args),
  retryRequest: (...args) => pcapTransferRepository.retryRequest(...args),
  completeAnalysis: (...args) => pcapAnalysisCompletion.complete(...args),
  requeueRequests: (...args) => pcapRequestRepository.requeueRequests(...args),
  signalPcapWorker: (reason) => signalWorker(pcapAnalysisWakePath, reason),
  signalAiWorkers,
});
modularRoutes.registerAll(createPcapRoutes({
  service: pcapService,
  readJsonBody,
  sendJson,
}));
const enrichmentService = createEnrichmentService({
  assertDiskWriteAdmission,
  enrichAlert,
  cachedInvestigationEnrichment,
  queryInvestigationEnrichment,
});
modularRoutes.registerAll(createEnrichmentRoutes({
  service: enrichmentService,
  authorizeInvestigation: requireAssetStoreWriteAuthorization,
  readJsonBody,
  sendJson,
}));
modularRoutes.registerAll(createMaintenanceRoutes({
  service: {
    rescore: rescoreAlerts,
    refreshGroups: rebuildAlertGroupSummaries,
  },
  sendJson,
}));
const alertIngestService = createAlertIngestService({
  metrics: serviceMetrics,
  now: Date.now,
  readJsonBody,
  writeBeacon: writeN8nBeacon,
  isRelayHeartbeat,
  assertDiskWriteAdmission,
  storeAlert,
});
modularRoutes.registerAll(createAlertIngestRoutes({
  service: alertIngestService,
  sendJson,
}));

function controlledEvaluationRequestAuthorized(request) {
  return requestAuthorization.controlledEvaluationAuthorized(request);
}

const httpRequestBoundary = createHttpRequestBoundary({
  controlledEvaluationMode,
  controlledRequests: controlledEvaluationRequests,
  isShutdownStarted: () => serviceRuntimeLifecycle.isShutdownStarted(),
  controlledRequestAuthorized: controlledEvaluationRequestAuthorized,
  routeRegistry: modularRoutes,
  sendJson,
  serviceMetrics,
  writeBeacon: writeN8nBeacon,
});

async function handleRequest(request, response) {
  return httpRequestBoundary.handle(request, response);
}

const dispatchRequest = createRequestDispatcher({
  handleRequest,
  postRequestAdmission,
  logger: applicationLogger,
  sendJson,
  randomUUID: crypto.randomUUID,
  monotonicNow: process.hrtime.bigint,
});

const serviceRuntimeLifecycle = createServiceRuntimeLifecycle({
  initDb,
  initializePostgresAssetStore,
  initializePostgresSoftwareStore,
  initializePostgresAcHunterStore,
  getPostgresStoreState: () => postgresAuxiliaryStores.state(),
  applicationLogger,
  databaseLogFields: {
    database_path: dbPath,
    postgres_shadow_enabled: postgresShadowEnabled,
    asset_postgres_enabled: assetPostgresEnabled,
    software_postgres_enabled: softwarePostgresEnabled,
    ac_hunter_postgres_enabled: acHunterPostgresEnabled,
  },
  httpCreateServer: (listener) => http.createServer(listener),
  configureHttpServer,
  dispatchRequest,
  sendJson,
  httpConfiguration: {
    requestTimeoutMs: httpRequestTimeoutMs,
    headersTimeoutMs: httpHeadersTimeoutMs,
    keepAliveTimeoutMs: httpKeepAliveTimeoutMs,
    maxRequestsPerSocket: httpMaxRequestsPerSocket,
    maxConnections: httpMaxConnections,
  },
  host,
  port,
  dbPath,
  controlledEvaluationMode,
  processLike: process,
  consoleLike: console,
  database: db,
  waitForSqliteWrites: () => sqliteRuntime.waitForWrites(),
  getActiveSqliteWrites: () => sqliteRuntime.activeWrites(),
  setIntervalFn: setInterval,
  setTimeoutFn: setTimeout,
  workers: {
    telegram: {
      enabled: telegramOutboxAutostart,
      intervalMs: telegramOutboxIntervalMs,
      drain: drainTelegramOutbox,
    },
    enrichment: {intervalMs: enrichmentWorkerIntervalMs, drain: drainEnrichmentJobs},
    enrichmentCache: {intervalMs: enrichmentCacheCleanupIntervalMs, prune: () => enrichmentCache.prune()},
    n8nPostCommit: {intervalMs: n8nPostCommitIntervalMs, drain: drainN8nPostCommitJobs},
    durableRecovery: {intervalMs: durableJobRecoveryIntervalMs, recover: recoverExpiredDurableJobs},
    pipelineDisk: {intervalMs: pipelineDiskSampleIntervalMs, capture: capturePipelineDiskSample},
    postgresShadow: {
      enabled: () => Boolean(postgresShadowProjector),
      intervalMs: postgresShadowIntervalMs,
      drain: () => postgresShadowProjector.drain(),
    },
    pipelineMetrics: {
      intervalMs: 60 * 60 * 1000,
      prune: () => pipelineMetrics.prune(),
      withWriteGate: withSqliteWriteGate,
    },
  },
});

serviceRuntimeLifecycle.run();
