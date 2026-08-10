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
const {createRequestDispatcher} = require('./lib/http_dispatch');
const {createRequestAuthorization} = require('./lib/request_authorization');
const analystReviewDefinitions = require('./services/analyst_review_projection');
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
const {createAiCorrelationRepository} = require('./repositories/ai_correlation_repository');
const {createAiReviewRepository} = require('./repositories/ai_review_repository');
const {createPcapRequestRepository} = require('./repositories/pcap_request_repository');
const {createPcapTransferRepository} = require('./repositories/pcap_transfer_repository');
const {createAiAnalysisAcceptance} = require('./services/ai_analysis_acceptance');
const {createPcapAnalysisCompletion} = require('./services/pcap_analysis_completion');
const {createRouteComposition} = require('./composition/route_composition');
const {
  createControlledIncidentComposition,
} = require('./composition/controlled_incident_composition');
const {createApplicationComposition} = require('./composition/application_composition');
const {createNotificationService} = require('./services/notification_service');
const {createAlertGroupService} = require('./services/alert_group_service');
const {createScoringPolicy} = require('./lib/scoring_policy');
const {createScoringRulesRuntime} = require('./lib/scoring_rules_runtime');
const {createIndicatorExtraction} = require('./lib/indicator_extraction');
const {createEnrichmentPolicy} = require('./lib/enrichment_policy');
const {createPcapPolicy} = require('./lib/pcap_policy');
const {createProjectSerialization} = require('./lib/project_serialization');
const {createRuntimeConfiguration} = require('./lib/runtime_configuration');
const {
  isRelayHeartbeat,
  nestedField,
  integerField,
  nonNegativeIntegerField,
  enrichmentRecord,
  normalizeTriageLevel,
  safeString,
  parseJsonObject,
} = require('./lib/alert_value_normalization');
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
const {
  database: db,
  run,
  get,
  all,
  withWriteGate: withSqliteWriteGate,
  withImmediateTransaction,
} = sqliteRuntime;
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

const sqliteJournalMode = String(process.env.ALERT_STORE_SQLITE_JOURNAL_MODE || 'DELETE').toUpperCase();
const sqliteSynchronous = String(process.env.ALERT_STORE_SQLITE_SYNCHRONOUS || 'FULL').toUpperCase();
const sqliteTempStore = String(process.env.ALERT_STORE_SQLITE_TEMP_STORE || 'DEFAULT').toUpperCase();
const allowedJournalModes = new Set(['DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL', 'OFF']);
const allowedSynchronousModes = new Set(['OFF', 'NORMAL', 'FULL', 'EXTRA']);
const allowedTempStoreModes = new Set(['DEFAULT', 'FILE', 'MEMORY']);
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

const cohortIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const stableGroupIdPattern = /^[a-f0-9]{20}$/;
const dispatchIdPattern = /^[a-f0-9]{64}$/;
const releaseIdPattern = /^[a-f0-9]{40}$/;
const representativeAlertIdPattern = /^[A-Za-z0-9._:@=-]{1,256}$/;
const controlledRoutePattern = /^codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):(?:low|medium|high|xhigh)$/;
function controlledRouteModelIdentity(route) {
  return String(route || '').split(':').slice(0, -1).join(':');
}
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
const {
  controlledEvaluationLeases,
  controlledJobTransitionAuthority,
  controlledResultAdmissionAuthority,
  controlledRetirementCommandOwner,
  durableJobRecovery,
  durableJobTransitionExecutor,
  incidentAnalysisCompletion,
  incidentReanalysisBindingService,
  incidentReanalysisJobOwnership,
  incidentReanalysisRecovery,
  incidentReanalysisRequestOwner,
  manualAnalysisDispatch,
  manualDispatchIdentityOwner,
} = createControlledIncidentComposition({
  persistence: {get, all, run},
  identity: {
    safeString,
    validCaseId: validIncidentCaseId,
    validPinnedStableGroupKey,
    stableGroupIdPattern,
    representativeAlertIdPattern,
    dispatchIdPattern,
    cohortIdPattern,
    releaseIdPattern,
    controlledRoutePattern,
    controlledRouteModelIdentity,
    requestHasOwnField,
    identityConflict: incidentIdentityConflict,
  },
  runtime: {
    controlledEvaluationMode,
    runtimeReleaseId: runtimeReleaseIdValue,
    controlledRuntimeReleaseId,
    incidentReanalysisReleaseId,
    aiAnalysisLeaseSeconds,
    nowUtc,
    randomUuid: () => crypto.randomUUID(),
    sha256Text: (value) => crypto.createHash('sha256').update(value).digest('hex'),
    warn: (...args) => console.warn(...args),
  },
  durable: {
    available: () => Boolean(durableJobs),
    owner: () => durableJobs,
    pipelineMetrics: () => pipelineMetrics,
    enqueue: (...args) => durableJobs.enqueue(...args),
    retirePendingExact: (options) => durableJobs.retirePendingExact(options),
    reconcileAuthorizedActivity: reconcileAuthorizedActivityBacklog,
    recordMetric: (...args) => pipelineMetrics.record(...args),
    signalAiWorkers,
  },
  transaction: {
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
  },
  drains: {
    drainEnrichmentJobs: durableBackgroundDrains.drainEnrichment,
    drainPostCommitJobs: durableBackgroundDrains.drainPostCommit,
  },
  serialization: {
    parseJsonObject,
    jsonText,
    canonicalJsonText,
    parseProjectTimestamp,
    formatProjectTimestamp,
  },
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
  incidentReanalysisBindingAuthority: incidentReanalysisBindingService.bindingAuthority,
  aiReviewRepository,
  incidentAnalysisCompletion,
  aiCorrelationRepository,
});
const {
  aiReviewSchema,
  alertIngestOrchestrator,
  alertPersistence,
  alertStoreSchemaFoundation,
  analystDecisionPersistence,
  analystReviewProjection,
  authorizedCampaignPersistence,
  automaticResponseRouting,
  controlledEvaluationSchema,
  incidentAnalysisSchema,
  notificationEnrichmentSchema,
  pcapSchema,
  rescorePersistence,
  startupPersistenceOrchestrator,
  suppressionPersistence,
} = createApplicationComposition({
  database: {
    get,
    all,
    run,
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
    ensureColumn,
  },
  schema: {
    controlledEvaluationMode,
    sqliteBusyTimeoutMs,
    allowedJournalModes,
    sqliteJournalMode,
    allowedSynchronousModes,
    sqliteSynchronous,
    allowedTempStoreModes,
    sqliteTempStore,
    alertGroupKeySql,
  },
  policy: {
    authorizedActivityPolicy,
    matchAuthorizedActivity,
    integerField,
    stableGroupKey,
    stableGroupId,
    buildAlertObservables,
    extractAlertIndicators,
    createAnalystReviewProjection: analystReviewDefinitions.createAnalystReviewProjection,
    safeString,
    conservativeReviewerTelemetry,
    reviewerAutomationAuthorization,
    reviewerFailureStatuses,
    validAnalystGroupId,
    validIncidentCaseId,
    analystAdjudicationOutcomes,
    analystAdjudicationConfidences,
    analystEventStatuses,
    analystDetectionValidities,
    analystActivityDispositions,
    analystHandlingValues,
    analystVerdictContradictions,
    analystAdjudicationTextMaxLength,
    analystStatusReasonMaxLength,
    findSuppressRule,
    nestedField,
    suppressionKey,
    ruleName,
    scoreAlert,
    enrichmentRecord,
    scoringRulesName: path.basename(scoringRulesPath),
    readSocAnalysisPolicy: () => socAnalysisPolicy.read(),
    matchesPcap: (level) => socAnalysisPolicy.matchesPcap(level),
    matchesIncident: (level) => socAnalysisPolicy.matchesIncident(level),
    matchesAnalysis: (level) => socAnalysisPolicy.matchesAnalysis(level),
    groupKeyFromRow: alertGroupKeyFromRow,
    groupIdFromKey: alertGroupId,
    currentGroupKey: currentAlertGroupKey,
    findDropRule,
    pcapRequestDefaultWindowSeconds,
    severityRank,
    postCommitMaxAttempts: n8nPostCommitMaxAttempts,
    hasUsableExternalIntel,
    enrichmentMaxAttempts: enrichmentWorkerMaxAttempts,
  },
  services: {
    installEnrichmentCache: () => enrichmentCache.install(),
    backfillPcapOutcomes: () => pcapRequestRepository.backfillOutcomes(),
    completePendingJobs: (...args) => durableJobs.completePendingByDedupeKeys(...args),
    resolveDashboardAlertGroup,
    randomUUID: crypto.randomUUID,
    rebuildGroupSummaries: rebuildAlertGroupSummariesUnlocked,
    createPcapRequest: (...args) => pcapRequestRepository.createRequest(...args),
    queueIncidentResponseForGroup,
    persistStableIdentity,
    refreshGroupSummary: refreshAlertGroupSummary,
    queueNotification: queueTelegramNotification,
    enqueueJob: (...args) => durableJobs.enqueue(...args),
    recordMetric: (...args) => pipelineMetrics.record(...args),
    signalAiWorkers,
    drainNotificationOutbox: drainTelegramOutbox,
    drainEnrichmentJobs,
    drainPostCommitJobs: drainN8nPostCommitJobs,
  },
  lifecycle: {
    initializeDurableJobs,
    installDurableJobs: () => durableJobs.install(),
    initializePostgresShadowOutbox,
    installPostgresShadowOutbox: () => postgresShadowOutbox.install(),
    initializePostgresShadowProjector,
    reconcileRecoveredIncidentAttempts: incidentReanalysisRecovery.reconcile,
    initializePipelineMetrics,
    installPipelineMetrics: () => pipelineMetrics.install(),
    backfillStableGroupIdentity,
    rebuildAlertGroupSummaries,
    refreshGroupAliases,
  },
  serialization: {nowUtc, parseJsonObject, jsonText, normalizeTimestampValue},
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

const modularRoutes = createRouteComposition({
  http: {readJsonBody, sendJson},
  transaction: {
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
  },
  inventory: {
    requireAcHunterStore: postgresAuxiliaryStores.requireAcHunterStore,
    requireSoftwareStore: postgresAuxiliaryStores.requireSoftwareStore,
    requireAssetStore: postgresAuxiliaryStores.requireAssetStore,
    authorizeWrite: requestAuthorization.requireAssetWrite,
  },
  health: {
    get,
    all,
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
  },
  analystState: {
    analystStatusSnapshot,
    updateAnalystStatus,
    analystAdjudicationSnapshot,
    recordAnalystAdjudication,
    updateIncidentCaseStatus,
  },
  durableJob: {
    safeString,
    controlledTransitionAdmission: controlledJobTransitionAuthority.admit,
    transitionJobStatus: durableJobTransitionExecutor.transition,
    applyControlledTransition: controlledJobTransitionAuthority.apply,
    completePendingByDedupeKeys: (...args) => durableJobs.completePendingByDedupeKeys(...args),
  },
  analysisRequest: {
    controlledEvaluationMode: () => controlledEvaluationMode,
    identityConflict: incidentIdentityConflict,
    requestAiReanalysis,
    requestIncidentEscalation,
    requestIncidentReanalysis: incidentReanalysisRequestOwner.request,
    retireControlledEvaluation: controlledRetirementCommandOwner.retire,
    signalAiWorkers,
  },
  analysisResult: {
    controlledEvaluationMode: () => controlledEvaluationMode,
    requestHasOwnField,
    identityConflict: incidentIdentityConflict,
    controlledResultAdmission: controlledResultAdmissionAuthority.admit,
    recordAnalysisResult: recordAiAnalysisResult,
    transitionJobStatus: durableJobTransitionExecutor.transition,
    applyControlledResultAdmission: controlledResultAdmissionAuthority.apply,
  },
  pcap: {
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
  },
  enrichment: {
    assertDiskWriteAdmission,
    enrichAlert,
    cachedInvestigationEnrichment,
    queryInvestigationEnrichment,
    authorizeInvestigation: requestAuthorization.requireAssetWrite,
  },
  maintenance: {rescore: rescoreAlerts, refreshGroups: rebuildAlertGroupSummaries},
  alertIngest: {
    metrics: serviceMetrics,
    now: Date.now,
    readJsonBody,
    writeBeacon: writeN8nBeacon,
    isRelayHeartbeat,
    assertDiskWriteAdmission,
    storeAlert,
  },
});

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
  initializePostgresAssetStore: postgresAuxiliaryStores.initializeAssetStore,
  initializePostgresSoftwareStore: postgresAuxiliaryStores.initializeSoftwareStore,
  initializePostgresAcHunterStore: postgresAuxiliaryStores.initializeAcHunterStore,
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
    durableRecovery: {intervalMs: durableJobRecoveryIntervalMs, recover: durableJobRecovery.recover},
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
