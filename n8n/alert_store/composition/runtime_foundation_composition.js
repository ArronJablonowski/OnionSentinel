'use strict';

const {createEnrichmentCache} = require('../lib/enrichment_cache');
const {createProviderScheduler} = require('../lib/provider_scheduler');
const {createPostgresAssetStore} = require('../lib/postgres_asset_store');
const {createPostgresSoftwareStore} = require('../lib/postgres_software_store');
const {createPostgresAcHunterStore} = require('../lib/postgres_ac_hunter_store');
const {createSecurityLogger} = require('../lib/security_logger');
const {createSocAnalysisPolicy} = require('../lib/soc_analysis_policy');
const {createRequestAuthorization} = require('../lib/request_authorization');
const {createScoringPolicy} = require('../lib/scoring_policy');
const {createScoringRulesRuntime} = require('../lib/scoring_rules_runtime');
const {createIndicatorExtraction} = require('../lib/indicator_extraction');
const {createEnrichmentPolicy} = require('../lib/enrichment_policy');
const {createRequestAdmission} = require('../lib/http_runtime');
const {createReviewerPolicy} = require('../lib/analyst_review_policy');
const {createNotificationService} = require('../services/notification_service');
const {createAlertGroupService} = require('../services/alert_group_service');
const {createEnrichmentProviderClient} = require('../services/enrichment_provider_client');
const {createEnrichmentOrchestrator} = require('../services/enrichment_orchestrator');
const {createDiskWriteAdmission} = require('../services/disk_write_admission');
const {createWorkerWakeSignaling} = require('../services/worker_wake_signaling');
const {createBeaconPersistence} = require('../services/beacon_persistence');
const {
  createPostgresAuxiliaryStoreRuntime,
} = require('../services/postgres_auxiliary_store_runtime');
const {createSqliteRuntime} = require('../services/sqlite_runtime');

const severityRank = {
  informational: 0,
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};
const supportedAgentRoles = new Set([
  'soc-analyst',
  'incident-responder',
  'siem-engineer',
  'cyber-threat-intel',
  'threat-hunter',
]);
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

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} runtime foundation composition section is required`);
  }
  return section;
}

function alertGroupId(groupKey, crypto) {
  return crypto.createHash('sha1').update(String(groupKey || '')).digest('hex').slice(0, 12);
}

function createPolicyOwners({runtime, platform, serialization, normalization, network}) {
  const {fs, path, processApi, crypto} = platform;
  const {nowUtc, normalizeTimestampValue, formatProjectTimestamp} = serialization;
  const {nestedField, safeString, parseJsonObject} = normalization;
  const requestAuthorization = createRequestAuthorization({
    assetWriteToken: runtime.assetStoreWriteToken,
    evaluationToken: runtime.controlledEvaluationToken,
    controlledEvaluationMode: runtime.controlledEvaluationMode,
    timingSafeEqual: crypto.timingSafeEqual,
  });
  const applicationLogger = createSecurityLogger({
    file: runtime.applicationLogPath,
    service: 'onion-sentinel-alert-store',
    releaseId: runtime.runtimeReleaseIdValue || 'unversioned',
    maxBytes: runtime.applicationLogMaxBytes,
    backups: runtime.applicationLogBackups,
  });
  applicationLogger.captureConsole();
  applicationLogger.log('info', 'process.starting', {
    runtime_mode: runtime.controlledEvaluationMode ? 'controlled-evaluation' : 'production',
    database_path: runtime.dbPath,
    listen_host: runtime.host,
    listen_port: runtime.port,
  });
  const reviewerPolicy = createReviewerPolicy({safeString, parseJsonObject});
  const socAnalysisPolicy = createSocAnalysisPolicy({runtimeDir: runtime.runtimeDir});
  const diskWriteAdmission = createDiskWriteAdmission({
    fs,
    path,
    dbPath: runtime.dbPath,
    diskStartMaxUsedPercent: runtime.diskStartMaxUsedPercent,
    diskHardMaxUsedPercent: runtime.diskHardMaxUsedPercent,
    diskMinFreeBytes: runtime.diskMinFreeBytes,
    maxRequestBytes: runtime.maxRequestBytes,
  });
  const workerWakeSignaling = createWorkerWakeSignaling({
    fs,
    path,
    nowUtc,
    isControlledEvaluation: () => runtime.controlledEvaluationMode,
    aiAnalysisWakePaths: runtime.aiAnalysisWakePaths,
    logError: (message) => console.error(message),
  });
  const scoringRulesRuntime = createScoringRulesRuntime({
    fs,
    scoringRulesPath: runtime.scoringRulesPath,
    logError: (message) => console.error(message),
  });
  const scoringPolicy = createScoringPolicy({
    rules: scoringRulesRuntime.load(),
    nestedField,
  });
  const indicatorExtraction = createIndicatorExtraction({
    parseIpv4: scoringPolicy.parseIpv4,
    isPrivateIpv4: scoringPolicy.isPrivateIpv4,
    nestedField,
  });
  const enrichmentPolicy = createEnrichmentPolicy({
    normalizeTimestampValue,
    nowUtc,
    isConfiguredSecret: indicatorExtraction.isConfiguredSecret,
    enrichmentSecrets: runtime.enrichmentSecrets,
    defaultTtlSeconds: runtime.enrichmentCacheDefaultTtlSeconds,
    vulnerabilityTtlSeconds: runtime.vulnerabilityCacheDefaultTtlSeconds,
    sourceTtlDefaults: runtime.enrichmentSourceTtlDefaults,
    staleIfErrorSeconds: runtime.enrichmentStaleIfErrorSeconds,
    vulnerabilityStaleIfErrorSeconds: runtime.enrichmentVulnerabilityStaleIfErrorSeconds,
    severityRank,
    virusTotalMinimumLevel: runtime.virustotalMinimumLevel,
    parseIpv4: scoringPolicy.parseIpv4,
    isPrivateIpv4: scoringPolicy.isPrivateIpv4,
    publicHostname: indicatorExtraction.publicHostname,
    redactUrlForPublicLookup: indicatorExtraction.redactUrlForPublicLookup,
  });
  const enrichmentProviderClient = createEnrichmentProviderClient({
    controlledEvaluationMode: runtime.controlledEvaluationMode,
    boundedRequestJson: network.boundedRequestJson,
    timeoutMs: runtime.enrichmentTimeoutMs,
    maxResponseBytes: runtime.httpJsonMaxResponseBytes,
    safeString,
    normalizedEnrichmentRecord: enrichmentPolicy.normalizedEnrichmentRecord,
    notFoundEnrichmentRecord: enrichmentPolicy.notFoundEnrichmentRecord,
    verdictFromStats: enrichmentPolicy.verdictFromStats,
    enrichmentSecrets: runtime.enrichmentSecrets,
    isConfiguredSecret: indicatorExtraction.isConfiguredSecret,
    formatProjectTimestamp,
  });
  return {
    applicationLogger,
    diskWriteAdmission,
    enrichmentPolicy,
    enrichmentProviderClient,
    indicatorExtraction,
    requestAuthorization,
    reviewerPolicy,
    scoringPolicy,
    socAnalysisPolicy,
    workerWakeSignaling,
  };
}

function createPersistenceOwners({
  runtime,
  platform,
  serialization,
  normalization,
  network,
  policyOwners,
}) {
  const {fs, path, processApi, sqlite3, createPostgresPool} = platform;
  const {
    nowUtc,
    normalizeTimestampValue,
    formatProjectTimestamp,
    parseProjectTimestamp,
  } = serialization;
  const {nestedField, integerField, nonNegativeIntegerField, normalizeTriageLevel} = normalization;
  const sqliteBusyTimeoutMs = Number(processApi.env.ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS || 30000);
  const sqliteRuntime = createSqliteRuntime({
    fs,
    path,
    processApi,
    sqlite3,
    dbPath: runtime.dbPath,
    controlledEvaluationMode: runtime.controlledEvaluationMode,
    busyTimeoutMs: sqliteBusyTimeoutMs,
  });
  const {get, all, run, withImmediateTransaction} = sqliteRuntime;
  const withSqliteWriteGate = sqliteRuntime.withWriteGate;
  const notificationService = createNotificationService({
    nestedField,
    normalizeTimestampValue,
    formatProjectTimestamp,
    nowUtc,
    get,
    run,
    all,
    withSqliteWriteGate,
    withImmediateTransaction,
    botToken: runtime.telegramBotToken,
    chatId: runtime.telegramChatId,
    alertLevels: runtime.telegramAlertLevels,
    cooldownSeconds: runtime.telegramCooldownSeconds,
    outboxBaseRetrySeconds: runtime.telegramOutboxBaseRetrySeconds,
    outboxMaxRetrySeconds: runtime.telegramOutboxMaxRetrySeconds,
    outboxMaxAttempts: runtime.telegramOutboxMaxAttempts,
    outboxAutostart: runtime.telegramOutboxAutostart,
    controlledEvaluationMode: runtime.controlledEvaluationMode,
  });
  const beaconPersistence = createBeaconPersistence({
    fs,
    path,
    processId: processApi.pid,
    beaconPaths: runtime.beaconPaths,
    beaconHistoryPaths: runtime.beaconHistoryPaths,
    nowUtc,
    dateNow: () => Date.now(),
    parseProjectTimestamp,
    nestedField,
    integerField,
    nonNegativeIntegerField,
    logError: (message) => console.error(message),
  });
  const alertGroupService = createAlertGroupService({
    all,
    get,
    run,
    withImmediateTransaction,
    withSqliteWriteGate,
    nowUtc,
    normalizeTriageLevel,
    alertGroupId: (groupKey) => alertGroupId(groupKey, platform.crypto),
    alertGroupKeySql,
  });
  const enrichmentScheduler = createProviderScheduler({
    failureThreshold: runtime.enrichmentCircuitFailureThreshold,
    resetMs: runtime.enrichmentCircuitResetMs,
    maxResetMs: runtime.enrichmentCircuitMaxResetMs,
    formatTimestamp: formatProjectTimestamp,
  });
  const postgresAuxiliaryStores = createPostgresAuxiliaryStoreRuntime({
    env: processApi.env,
    controlledEvaluationMode: runtime.controlledEvaluationMode,
    assetPostgresEnabled: runtime.assetPostgresEnabled,
    softwarePostgresEnabled: runtime.softwarePostgresEnabled,
    acHunterPostgresEnabled: runtime.acHunterPostgresEnabled,
    assetSchemaPath: runtime.assetPostgresSchemaPath,
    softwareSchemaPath: runtime.softwarePostgresSchemaPath,
    acHunterSchemaPath: runtime.acHunterPostgresSchemaPath,
    createPool: createPostgresPool,
    createAssetStore: (options) => createPostgresAssetStore(options),
    createSoftwareStore: (options) => createPostgresSoftwareStore(options),
    createAcHunterStore: (options) => createPostgresAcHunterStore(options),
    logger: policyOwners.applicationLogger,
  });
  const enrichmentCache = createEnrichmentCache({
    run,
    get,
    all,
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
    formatTimestamp: formatProjectTimestamp,
    l1MaxEntries: runtime.enrichmentCacheL1MaxEntries,
    l1TtlSeconds: runtime.enrichmentCacheL1TtlSeconds,
    l1MaxBytes: runtime.enrichmentCacheL1MaxBytes,
    maxEntries: runtime.enrichmentCacheMaxEntries,
    maxBytes: runtime.enrichmentCacheMaxBytes,
    rawResponseMaxBytes: runtime.enrichmentCacheRawResponseMaxBytes,
    staleIfErrorSeconds: runtime.enrichmentStaleIfErrorSeconds,
    vulnerabilityStaleIfErrorSeconds: runtime.enrichmentVulnerabilityStaleIfErrorSeconds,
  });
  const enrichmentOrchestrator = createEnrichmentOrchestrator({
    cache: enrichmentCache,
    scheduler: enrichmentScheduler,
    providers: policyOwners.enrichmentProviderClient,
    policy: policyOwners.enrichmentPolicy,
    extractAlertIndicators: policyOwners.indicatorExtraction.extractAlertIndicators,
    isRelayHeartbeat: network.isRelayHeartbeat,
    nowUtc,
    formatProjectTimestamp,
    withSqliteWriteGate,
    withImmediateTransaction,
    get,
    run,
    defaultTtlSeconds: runtime.enrichmentCacheDefaultTtlSeconds,
    vulnerabilityTtlSeconds: runtime.vulnerabilityCacheDefaultTtlSeconds,
    negativeTtlSeconds: runtime.enrichmentNegativeCacheTtlSeconds,
    virusTotalMinimumLevel: runtime.virustotalMinimumLevel,
    urlscanSubmitEnabled: runtime.urlscanSubmitEnabled,
  });
  return {
    alertGroupService,
    beaconPersistence,
    enrichmentCache,
    enrichmentOrchestrator,
    enrichmentScheduler,
    notificationService,
    postgresAuxiliaryStores,
    sqliteBusyTimeoutMs,
    sqliteRuntime,
  };
}

function createRuntimeFoundationComposition(options = {}) {
  const runtime = requireSection(options, 'runtime');
  const platform = requireSection(options, 'platform');
  const serialization = requireSection(options, 'serialization');
  const normalization = requireSection(options, 'normalization');
  const network = requireSection(options, 'network');
  const sections = {runtime, platform, serialization, normalization, network};
  const policyOwners = createPolicyOwners(sections);
  const persistenceOwners = createPersistenceOwners({...sections, policyOwners});
  const serviceMetrics = {
    started_at: serialization.nowUtc(),
    ingest_requests: 0,
    ingest_errors: 0,
    ingest_latency_ms_total: 0,
    ingest_latency_ms_max: 0,
  };
  return {
    ...policyOwners,
    ...persistenceOwners,
    alertGroupId: (groupKey) => alertGroupId(groupKey, platform.crypto),
    alertGroupKeySql,
    allowedJournalModes,
    allowedSynchronousModes,
    allowedTempStoreModes,
    postRequestAdmission: createRequestAdmission(runtime.httpMaxActivePosts),
    serviceMetrics,
    severityRank,
    sqliteJournalMode: String(platform.processApi.env.ALERT_STORE_SQLITE_JOURNAL_MODE || 'DELETE').toUpperCase(),
    sqliteSynchronous: String(platform.processApi.env.ALERT_STORE_SQLITE_SYNCHRONOUS || 'FULL').toUpperCase(),
    sqliteTempStore: String(platform.processApi.env.ALERT_STORE_SQLITE_TEMP_STORE || 'DEFAULT').toUpperCase(),
    supportedAgentRoles,
  };
}

module.exports = {createRuntimeFoundationComposition};
