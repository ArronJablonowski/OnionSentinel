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
const {createAlertPersistence} = require('./services/alert_persistence');
const {createSuppressionPersistence} = require('./services/suppression_persistence');
const {createRescorePersistence} = require('./services/rescore_persistence');
const {createAutomaticResponseRouting} = require('./services/automatic_response_routing');
const {createDiskWriteAdmission} = require('./services/disk_write_admission');
const {createWorkerWakeSignaling} = require('./services/worker_wake_signaling');
const {createBeaconPersistence} = require('./services/beacon_persistence');
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
const {createIndicatorExtraction} = require('./lib/indicator_extraction');
const {createEnrichmentPolicy} = require('./lib/enrichment_policy');
const {createPcapPolicy} = require('./lib/pcap_policy');
const {createProjectSerialization} = require('./lib/project_serialization');
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
const projectSerialization = createProjectSerialization();

// Runtime values come from docker-compose.yml and .env. Keep real tokens in
// .env only; this DR repo stores placeholders and source code.
const dbPath = process.env.ALERT_STORE_DB || '/data/alerts.sqlite3';
const scoringRulesPath = process.env.SCORING_RULES_PATH || '/app/config/scoring_rules.json';
const authorizedActivityPolicyPath = process.env.AUTHORIZED_ACTIVITY_POLICY_PATH
  || path.join(__dirname, '..', 'config', 'authorized_activity_campaigns.json');
const authorizedActivityPolicy = loadAuthorizedActivityPolicy(authorizedActivityPolicyPath);
const beaconPaths = (process.env.ALERT_STORE_BEACON_PATHS || '/data/n8n-beacon.json')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const beaconHistoryPaths = (process.env.ALERT_STORE_BEACON_HISTORY_PATHS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const host = process.env.ALERT_STORE_HOST || '127.0.0.1';
const port = Number(process.env.ALERT_STORE_PORT || 8787);
const postgresShadowEnabled = String(
  process.env.ALERT_STORE_POSTGRES_SHADOW_ENABLED || '0',
).trim() === '1';
const postgresShadowIntervalMs = Math.max(
  1000,
  Number(process.env.ALERT_STORE_POSTGRES_SHADOW_INTERVAL_MS || 5000),
);
const postgresShadowBatchSize = Math.max(
  1,
  Math.min(1000, Number(process.env.ALERT_STORE_POSTGRES_SHADOW_BATCH_SIZE || 50)),
);
const assetPostgresEnabled = ['1', 'true', 'yes'].includes(
  String(process.env.ASSET_POSTGRES_ENABLED || '0').trim().toLowerCase(),
);
const assetPostgresSchemaPath = process.env.ASSET_POSTGRES_SCHEMA_PATH
  || path.join(__dirname, '..', 'postgres', 'asset-inventory-schema.sql');
const softwarePostgresEnabled = ['1', 'true', 'yes'].includes(
  String(
    process.env.SOFTWARE_POSTGRES_ENABLED
    ?? process.env.ASSET_POSTGRES_ENABLED
    ?? '0',
  ).trim().toLowerCase(),
);
const softwarePostgresSchemaPath = process.env.SOFTWARE_POSTGRES_SCHEMA_PATH
  || path.join(__dirname, '..', 'postgres', 'software-inventory-schema.sql');
const acHunterPostgresEnabled = ['1', 'true', 'yes'].includes(
  String(
    process.env.AC_HUNTER_POSTGRES_ENABLED
    ?? process.env.ASSET_POSTGRES_ENABLED
    ?? '0',
  ).trim().toLowerCase(),
);
const acHunterPostgresSchemaPath = process.env.AC_HUNTER_POSTGRES_SCHEMA_PATH
  || path.join(__dirname, '..', 'postgres', 'ac-hunter-schema.sql');
const assetStoreWriteToken = String(
  process.env.ASSET_STORE_WRITE_TOKEN
  || process.env.N8N_POST_COMMIT_TOKEN
  || '',
).trim();
const evaluationModeValue = String(
  process.env.ONION_SENTINEL_EVALUATION_MODE || '',
).trim();
if (!['', '0', '1'].includes(evaluationModeValue)) {
  throw new Error(
    'ONION_SENTINEL_EVALUATION_MODE must be unset, 0, or 1',
  );
}
const controlledEvaluationMode = evaluationModeValue === '1';
if (
  (assetPostgresEnabled || softwarePostgresEnabled || acHunterPostgresEnabled)
  && !controlledEvaluationMode
  && assetStoreWriteToken.length < 32
) {
  throw new Error(
    'ASSET_STORE_WRITE_TOKEN must contain at least 32 characters when PostgreSQL assets are enabled',
  );
}
const runtimeReleaseIdValue = String(
  process.env.ONION_SENTINEL_RELEASE_ID || '',
).trim();
const controlledEvaluationToken = String(
  process.env.ONION_SENTINEL_EVALUATION_TOKEN || '',
).trim();
const evaluationCredentialEnvironmentKeys = Object.freeze([
  'TELEGRAM_BOT_TOKEN',
  'TELEGRAM_CHAT_ID',
  'N8N_POST_COMMIT_TOKEN',
  'ASSET_STORE_WRITE_TOKEN',
  'ABUSEIPDB_API_KEY',
  'GREYNOISE_API_KEY',
  'OTX_API_KEY',
  'URLHAUS_AUTH_KEY',
  'VIRUSTOTAL_API_KEY',
  'URLSCAN_API_KEY',
  'GOOGLE_SAFE_BROWSING_API_KEY',
  'PHISHTANK_API_KEY',
  'MALWAREBAZAAR_AUTH_KEY',
  'THREATFOX_AUTH_KEY',
  'SHODAN_API_KEY',
  'CENSYS_API_ID',
  'CENSYS_API_SECRET',
  'CENSYS_API_TOKEN',
  'CENSYS_ORGANIZATION_ID',
  'NVD_API_KEY',
]);
if (controlledEvaluationMode) {
  const configuredCredentialKeys = evaluationCredentialEnvironmentKeys.filter(
    (key) => String(process.env[key] || '').trim(),
  );
  const explicitRuntimeKeys = [
    'ALERT_STORE_DB',
    'ALERT_STORE_HOST',
    'ALERT_STORE_PORT',
    'SCORING_RULES_PATH',
  ];
  if (
    explicitRuntimeKeys.some(
      (key) => (
        !Object.prototype.hasOwnProperty.call(process.env, key)
        || !String(process.env[key] || '').trim()
      ),
    )
    || host !== '127.0.0.1'
    || !Number.isSafeInteger(port)
    || port < 1024
    || port > 65535
    || port === 8787
    || !path.isAbsolute(dbPath)
    || !/^[a-f0-9]{40}$/.test(runtimeReleaseIdValue)
    || !/^[a-f0-9]{64}$/.test(controlledEvaluationToken)
    || configuredCredentialKeys.length
  ) {
    throw new Error(
      'controlled evaluation requires loopback, an explicit existing '
      + 'database, an exact release ID, an ephemeral authorization token, '
      + 'and no configured production credentials',
    );
  }
  const evaluationScoringPath = path.resolve(scoringRulesPath);
  const evaluationScoringMetadata = fs.lstatSync(
    evaluationScoringPath,
  );
  const evaluationOwner = typeof process.getuid === 'function'
    ? process.getuid()
    : evaluationScoringMetadata.uid;
  if (
    evaluationScoringPath !== scoringRulesPath
    || fs.realpathSync(evaluationScoringPath) !== evaluationScoringPath
    || !evaluationScoringMetadata.isFile()
    || evaluationScoringMetadata.isSymbolicLink()
    || evaluationScoringMetadata.uid !== evaluationOwner
    || (evaluationScoringMetadata.mode & 0o022) !== 0
  ) {
    throw new Error(
      'controlled evaluation scoring rules must be an owner-controlled regular file',
    );
  }
}
const requestAuthorization = createRequestAuthorization({
  assetWriteToken: assetStoreWriteToken,
  evaluationToken: controlledEvaluationToken,
  controlledEvaluationMode,
  timingSafeEqual: crypto.timingSafeEqual,
});
// Validate the complete controlled-runtime boundary before creating a log
// directory or any other external state. A malformed evaluation environment
// must fail closed without deriving a path such as /logs from a missing DB.
const applicationLogPath = process.env.ALERT_STORE_APPLICATION_LOG
  || path.join(path.dirname(path.dirname(dbPath)), 'logs', 'alert-store-application.jsonl');
const applicationLogger = createSecurityLogger({
  file: applicationLogPath,
  service: 'onion-sentinel-alert-store',
  releaseId: runtimeReleaseIdValue || 'unversioned',
  maxBytes: Math.max(
    1024 * 1024,
    Number(process.env.ALERT_STORE_APPLICATION_LOG_MAX_BYTES || 10 * 1024 * 1024),
  ),
  backups: Math.max(
    1,
    Math.min(20, Number(process.env.ALERT_STORE_APPLICATION_LOG_BACKUPS || 5)),
  ),
});
applicationLogger.captureConsole();
applicationLogger.log('info', 'process.starting', {
  runtime_mode: controlledEvaluationMode ? 'controlled-evaluation' : 'production',
  database_path: dbPath,
  listen_host: host,
  listen_port: port,
});
const telegramBotToken = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const telegramChatId = (process.env.TELEGRAM_CHAT_ID || '').trim();
const maxRequestBytes = Math.max(1024, Number(process.env.ALERT_STORE_MAX_REQUEST_BYTES || 10 * 1024 * 1024));
const httpRequestTimeoutMs = Math.max(1000, Number(process.env.ALERT_STORE_REQUEST_TIMEOUT_MS || 30000));
const httpHeadersTimeoutMs = Math.max(1000, Number(process.env.ALERT_STORE_HEADERS_TIMEOUT_MS || 10000));
const httpKeepAliveTimeoutMs = Math.max(1000, Number(process.env.ALERT_STORE_KEEPALIVE_TIMEOUT_MS || 5000));
const httpMaxRequestsPerSocket = Math.max(1, Number(process.env.ALERT_STORE_MAX_REQUESTS_PER_SOCKET || 100));
const httpMaxConnections = Math.max(8, Number(process.env.ALERT_STORE_MAX_CONNECTIONS || 256));
const httpMaxActivePosts = Math.max(1, Number(process.env.ALERT_STORE_MAX_ACTIVE_POSTS || 32));
const diskHardMaxUsedPercent = Math.min(80, Math.max(
  2,
  Number(process.env.ALERT_STORE_DISK_HARD_MAX_USED_PERCENT || 80),
));
const diskStartMaxUsedPercent = Math.min(
  diskHardMaxUsedPercent - 0.1,
  Math.max(1, Number(process.env.ALERT_STORE_DISK_START_MAX_USED_PERCENT || 75)),
);
const diskMinFreeBytes = Math.max(
  0,
  Number(process.env.ALERT_STORE_DISK_MIN_FREE_BYTES || 50 * 1024 * 1024 * 1024),
);
const telegramAlertLevels = new Set(
  (process.env.TELEGRAM_ALERT_LEVELS || 'critical,high')
    .split(',')
    .map((level) => level.trim().toLowerCase())
    .filter(Boolean),
);
const telegramCooldownSeconds = Number(process.env.TELEGRAM_COOLDOWN_SECONDS || 900);
const telegramOutboxIntervalMs = Math.max(1000, Number(process.env.TELEGRAM_OUTBOX_INTERVAL_MS || 15000));
const telegramOutboxBaseRetrySeconds = Math.max(5, Number(process.env.TELEGRAM_OUTBOX_BASE_RETRY_SECONDS || 30));
const telegramOutboxMaxRetrySeconds = Math.max(
  telegramOutboxBaseRetrySeconds,
  Number(process.env.TELEGRAM_OUTBOX_MAX_RETRY_SECONDS || 3600),
);
const telegramOutboxMaxAttempts = Math.max(1, Number(process.env.TELEGRAM_OUTBOX_MAX_ATTEMPTS || 8));
const telegramOutboxAutostart = !['0', 'false', 'no'].includes(
  String(process.env.TELEGRAM_OUTBOX_AUTOSTART || '1').toLowerCase(),
);
const enrichmentCacheDefaultTtlSeconds = Number(process.env.ENRICHMENT_CACHE_TTL_SECONDS || 86400);
const vulnerabilityCacheDefaultTtlSeconds = Number(process.env.ENRICHMENT_VULN_CACHE_TTL_SECONDS || 86400);
const enrichmentNegativeCacheTtlSeconds = Math.max(
  300,
  Number(process.env.ENRICHMENT_NEGATIVE_CACHE_TTL_SECONDS || 21600),
);
const enrichmentStaleIfErrorSeconds = Math.max(
  3600,
  Number(process.env.ENRICHMENT_STALE_IF_ERROR_SECONDS || 7 * 86400),
);
const enrichmentVulnerabilityStaleIfErrorSeconds = Math.max(
  enrichmentStaleIfErrorSeconds,
  Number(process.env.ENRICHMENT_VULN_STALE_IF_ERROR_SECONDS || 30 * 86400),
);
const enrichmentCacheL1MaxEntries = Math.max(
  64,
  Number(process.env.ENRICHMENT_CACHE_L1_MAX_ENTRIES || 2048),
);
const enrichmentCacheL1TtlSeconds = Math.max(
  10,
  Number(process.env.ENRICHMENT_CACHE_L1_TTL_SECONDS || 300),
);
const enrichmentCacheL1MaxBytes = Math.max(
  1024 * 1024,
  Number(process.env.ENRICHMENT_CACHE_L1_MAX_BYTES || 64 * 1024 * 1024),
);
const enrichmentCacheMaxEntries = Math.max(
  1000,
  Number(process.env.ENRICHMENT_CACHE_MAX_ENTRIES || 10000),
);
const enrichmentCacheMaxBytes = Math.max(
  16 * 1024 * 1024,
  Number(process.env.ENRICHMENT_CACHE_MAX_BYTES || 256 * 1024 * 1024),
);
const enrichmentCacheRawResponseMaxBytes = Math.max(
  1024,
  // Match the bounded HTTP client. Every provider response accepted by the
  // client is therefore retained intact; responses above this limit fail
  // before parsing instead of being silently reduced to a marker in cache.
  Number(process.env.ENRICHMENT_CACHE_RAW_RESPONSE_MAX_BYTES || 5 * 1024 * 1024),
);
const enrichmentCacheCleanupIntervalMs = Math.max(
  5 * 60 * 1000,
  Number(process.env.ENRICHMENT_CACHE_CLEANUP_INTERVAL_SECONDS || 3600) * 1000,
);
const enrichmentSourceTtlDefaults = Object.freeze({
  abuseipdb: 12 * 3600,
  greynoise: 24 * 3600,
  shodan_internetdb: 24 * 3600,
  otx: 12 * 3600,
  urlhaus: 6 * 3600,
  virustotal: 24 * 3600,
  urlscan: 12 * 3600,
  google_safe_browsing: 6 * 3600,
  phishtank: 6 * 3600,
  malwarebazaar: 24 * 3600,
  threatfox: 6 * 3600,
  shodan: 24 * 3600,
  censys: 24 * 3600,
});
const enrichmentTimeoutMs = Number(process.env.ENRICHMENT_TIMEOUT_MS || 5000);
const httpJsonMaxResponseBytes = Math.max(
  1024,
  Number(process.env.ALERT_STORE_HTTP_JSON_MAX_RESPONSE_BYTES || 5 * 1024 * 1024),
);
const enrichmentCircuitFailureThreshold = Math.max(1, Number(process.env.ENRICHMENT_CIRCUIT_FAILURE_THRESHOLD || 3));
const enrichmentCircuitResetMs = Math.max(10000, Number(process.env.ENRICHMENT_CIRCUIT_RESET_MS || 60000));
const enrichmentCircuitMaxResetMs = Math.max(
  enrichmentCircuitResetMs,
  Number(process.env.ENRICHMENT_CIRCUIT_MAX_RESET_MS || 3600000),
);
// Provider-specific reservations below enforce the actual external rate
// limits. Poll the serial durable queue once per second so a burst does not
// accumulate an avoidable four-second idle gap between completed bundles.
const enrichmentWorkerIntervalMs = Math.max(1000, Number(process.env.ENRICHMENT_WORKER_INTERVAL_MS || 1000));
const enrichmentWorkerMaxAttempts = Math.max(1, Number(process.env.ENRICHMENT_WORKER_MAX_ATTEMPTS || 8));
const virustotalMinimumLevel = String(process.env.VIRUSTOTAL_MINIMUM_LEVEL || 'high').toLowerCase();
const urlscanSubmitEnabled = ['1', 'true', 'yes'].includes(String(process.env.URLSCAN_SUBMIT_ENABLED || '').toLowerCase());
const pcapRequestMaxWindowSeconds = Math.max(30, Number(process.env.PCAP_REQUEST_MAX_WINDOW_SECONDS || 300));
const pcapRequestDefaultWindowSeconds = Math.min(
  pcapRequestMaxWindowSeconds,
  Math.max(30, Number(process.env.PCAP_REQUEST_DEFAULT_WINDOW_SECONDS || 120)),
);
const pcapClaimLeaseSeconds = Math.max(300, Number(process.env.PCAP_CLAIM_LEASE_SECONDS || 1800));
const pcapCaptureRetentionSeconds = Math.max(0, Number(process.env.PCAP_CAPTURE_RETENTION_SECONDS || 0));
const pcapPriorityMaxWaitSeconds = Math.max(
  60,
  Number(process.env.PCAP_PRIORITY_MAX_WAIT_SECONDS || 1200),
);
const pcapTransferMaxAttempts = Math.max(1, Math.min(20, Number(process.env.PCAP_TRANSFER_MAX_ATTEMPTS || 5)));
const pcapTransferMaxRetrySeconds = Math.max(
  30,
  Math.min(6 * 3600, Number(process.env.PCAP_TRANSFER_MAX_RETRY_SECONDS || 1800)),
);
const pipelineEventRetentionHours = Math.max(24, Number(process.env.PIPELINE_EVENT_RETENTION_HOURS || 168));
const pipelineDiskSampleIntervalMs = Math.max(
  60 * 1000,
  Number(process.env.PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS || 300) * 1000,
);
const n8nPostCommitUrl = String(
  process.env.N8N_POST_COMMIT_URL || 'http://127.0.0.1:5678/webhook/onion-sentinel-committed-alert',
).trim();
const n8nPostCommitToken = String(process.env.N8N_POST_COMMIT_TOKEN || '').trim();
const n8nPostCommitIntervalMs = Math.max(
  1000,
  Number(process.env.N8N_POST_COMMIT_INTERVAL_MS || 5000),
);
const n8nPostCommitTimeoutMs = Math.max(
  5000,
  Number(process.env.N8N_POST_COMMIT_TIMEOUT_MS || 30000),
);
const n8nPostCommitMaxAttempts = Math.max(
  1,
  Number(process.env.N8N_POST_COMMIT_MAX_ATTEMPTS || 12),
);
const n8nPostCommitBaseRetrySeconds = Math.max(
  5,
  Number(process.env.N8N_POST_COMMIT_BASE_RETRY_SECONDS || 15),
);
const durableJobRecoveryIntervalMs = Math.max(
  5000,
  Number(process.env.DURABLE_JOB_RECOVERY_INTERVAL_SECONDS || 60) * 1000,
);
const aiAnalysisLeaseSeconds = Math.max(
  120,
  Number(process.env.AI_ANALYSIS_JOB_LEASE_SECONDS || 1800),
);
const runtimeDir = String(
  process.env.ONION_SENTINEL_RUNTIME_DIR || path.join(os.homedir(), 'n8n-local'),
).trim();
const aiAnalysisWakePaths = String(
  process.env.AI_ANALYSIS_WAKE_PATHS
    || [
      process.env.AI_ANALYSIS_WAKE_PATH,
      path.join(runtimeDir, 'run', 'ai-analysis-ollama.wake'),
      path.join(runtimeDir, 'run', 'ai-analysis-cli.wake'),
    ].filter(Boolean).join(','),
)
  .split(',')
  .map((value) => value.trim())
  .filter((value, index, values) => value && values.indexOf(value) === index);
const pcapAnalysisWakePath = String(
  process.env.PCAP_ANALYSIS_WAKE_PATH || path.join(runtimeDir, 'run', 'pcap-analysis.wake'),
).trim();
const analystStatusReasonMaxLength = 140;
const analystAdjudicationTextMaxLength = 4000;
const {
  reviewerAutomationAuthorization,
  conservativeReviewerTelemetry,
} = createReviewerPolicy({safeString, parseJsonObject});
const socAnalysisPolicy = createSocAnalysisPolicy({runtimeDir});

const enrichmentSecrets = {
  abuseipdb: (process.env.ABUSEIPDB_API_KEY || '').trim(),
  greynoise: (process.env.GREYNOISE_API_KEY || '').trim(),
  otx: (process.env.OTX_API_KEY || '').trim(),
  urlhaus: (process.env.URLHAUS_AUTH_KEY || '').trim(),
  virustotal: (process.env.VIRUSTOTAL_API_KEY || '').trim(),
  urlscan: (process.env.URLSCAN_API_KEY || '').trim(),
  googleSafeBrowsing: (process.env.GOOGLE_SAFE_BROWSING_API_KEY || '').trim(),
  phishtank: (process.env.PHISHTANK_API_KEY || '').trim(),
  malwarebazaar: (process.env.MALWAREBAZAAR_AUTH_KEY || '').trim(),
  threatfox: (process.env.THREATFOX_AUTH_KEY || '').trim(),
  shodan: (process.env.SHODAN_API_KEY || '').trim(),
  censysId: (process.env.CENSYS_API_ID || '').trim(),
  censysSecret: (process.env.CENSYS_API_SECRET || '').trim(),
  censysToken: (process.env.CENSYS_API_TOKEN || '').trim(),
  censysOrganizationId: (process.env.CENSYS_ORGANIZATION_ID || '').trim(),
  nvd: (process.env.NVD_API_KEY || '').trim(),
};

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

function loadScoringRules() {
  // Fallbacks keep ingestion alive if scoring_rules.json is missing or invalid.
  // Normal tuning should happen in config/scoring_rules.json.
  const fallback = {
    thresholds: {medium_min: 40, high_min: 70, critical_min: 85},
    severity_base: {
      critical: 85,
      high: 70,
      medium: 45,
      low: 25,
      numeric_4_or_more: 75,
      numeric_3: 60,
      numeric_2: 45,
      numeric_1: 25,
      default: 30,
    },
    infrastructure_ips: ['192.168.1.7', '10.77.7.225'],
    direction_adjustments: {inbound: 15, outbound: 10, internal: 3, external: 0, unknown: 0},
    infrastructure_adjustments: {destination: 15, source: 5},
    keyword_adjustments: [],
    rule_adjustments: [],
    pair_adjustments: [],
    drop_rules: [],
    suppress_rules: [],
  };
  try {
    return {...fallback, ...JSON.parse(fs.readFileSync(scoringRulesPath, 'utf8'))};
  } catch (error) {
    console.error(`Unable to load scoring rules from ${scoringRulesPath}: ${error.message}`);
    return fallback;
  }
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
function projectOffset(date) {
  return projectSerialization.projectOffset(date);
}

function formatProjectTimestamp(date) {
  return projectSerialization.formatProjectTimestamp(date);
}

function parseProjectTimestamp(value) {
  return projectSerialization.parseProjectTimestamp(value);
}

function nowUtc() {
  return projectSerialization.nowUtc();
}

function normalizeTimestampValue(value) {
  return projectSerialization.normalizeTimestampValue(value);
}

function normalizeJsonTimestamps(value) {
  return projectSerialization.normalizeJsonTimestamps(value);
}

function jsonText(value) {
  return projectSerialization.jsonText(value);
}

function canonicalJsonText(value) {
  return projectSerialization.canonicalJsonText(value);
}

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

if (controlledEvaluationMode) {
  const databasePath = path.resolve(dbPath);
  const databaseMetadata = fs.lstatSync(databasePath);
  const databaseOwner = typeof process.getuid === 'function'
    ? process.getuid()
    : databaseMetadata.uid;
  if (
    databasePath !== dbPath
    || fs.realpathSync(databasePath) !== databasePath
    || !databaseMetadata.isFile()
    || databaseMetadata.isSymbolicLink()
    || databaseMetadata.uid !== databaseOwner
    || (databaseMetadata.mode & 0o022) !== 0
  ) {
    throw new Error(
      'controlled evaluation database must be an owner-controlled regular file',
    );
  }
  const recoverySidecar = ['-journal', '-wal', '-shm'].find(
    (suffix) => fs.existsSync(`${databasePath}${suffix}`),
  );
  if (recoverySidecar) {
    throw new Error(
      `controlled evaluation refuses database recovery sidecar ${recoverySidecar}`,
    );
  }
} else {
  fs.mkdirSync(path.dirname(dbPath), {recursive: true});
}
const db = controlledEvaluationMode
  ? new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE)
  : new sqlite3.Database(dbPath);
const sqliteBusyTimeoutMs = Number(process.env.ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS || 30000);
db.configure('busyTimeout', sqliteBusyTimeoutMs);
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
  // Promise wrappers let the HTTP handlers use async/await with sqlite3.
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(error) {
      if (error) reject(error);
      else resolve(this);
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => {
      if (error) reject(error);
      else resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) reject(error);
      else resolve(rows);
    });
  });
}

let sqliteWriteGate = Promise.resolve();
let activeSqliteWrites = 0;
const enrichmentScheduler = createProviderScheduler({
  failureThreshold: enrichmentCircuitFailureThreshold,
  resetMs: enrichmentCircuitResetMs,
  maxResetMs: enrichmentCircuitMaxResetMs,
  formatTimestamp: formatProjectTimestamp,
});
let enrichmentDrainActive = false;
let n8nPostCommitDrainActive = false;
let durableJobs;
let postgresShadowOutbox;
let postgresShadowProjector;
let postgresAssetPool;
let postgresAssetStore;
let postgresAssetStoreError = '';
let postgresSoftwareStore;
let postgresSoftwareStoreError = '';
let postgresAcHunterStore;
let postgresAcHunterStoreError = '';
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
  // sqlite3 serializes individual statements, but HTTP handlers can still
  // interleave multi-statement workflows. Queue alert-ingest write workflows so
  // suppression state, raw alert rows, and group summaries stay coherent during
  // bursts from n8n.
  const next = sqliteWriteGate.catch(() => undefined).then(async () => {
    activeSqliteWrites += 1;
    try {
      return await task();
    } finally {
      activeSqliteWrites -= 1;
    }
  });
  sqliteWriteGate = next.catch(() => undefined);
  return next;
}

async function withImmediateTransaction(task) {
  await run('BEGIN IMMEDIATE');
  try {
    const result = await task();
    await run('COMMIT');
    return result;
  } catch (error) {
    await run('ROLLBACK').catch(() => undefined);
    throw error;
  }
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
  if (
    (!assetPostgresEnabled && !softwarePostgresEnabled && !acHunterPostgresEnabled)
    || controlledEvaluationMode
  ) return;
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
    postgresAssetStoreError = `missing ${missing.join(', ')}`;
    postgresSoftwareStoreError = `missing ${missing.join(', ')}`;
    postgresAcHunterStoreError = `missing ${missing.join(', ')}`;
    return;
  }
  try {
    const {Pool} = require('pg');
    postgresAssetPool = new Pool({
      host: String(process.env.ALERT_STORE_POSTGRES_HOST),
      port: Number(process.env.ALERT_STORE_POSTGRES_PORT || 5433),
      database: String(process.env.ALERT_STORE_POSTGRES_DATABASE),
      user: String(process.env.ALERT_STORE_POSTGRES_USER),
      password: String(process.env.ALERT_STORE_POSTGRES_PASSWORD),
      max: Math.max(2, Math.min(20, Number(process.env.ASSET_POSTGRES_POOL_SIZE || 8))),
      connectionTimeoutMillis: Math.max(
        1000,
        Number(process.env.ASSET_POSTGRES_CONNECT_TIMEOUT_MS || 3000),
      ),
      idleTimeoutMillis: 10000,
      application_name: 'onion-sentinel-postgres-store',
    });
    postgresAssetPool.on('error', (error) => {
      postgresAssetStoreError = String(error.message || error).slice(0, 500);
      postgresSoftwareStoreError = postgresAssetStoreError;
      postgresAcHunterStoreError = postgresAssetStoreError;
      applicationLogger.log('error', 'asset_store.postgres_idle_error', {
        error_message: postgresAssetStoreError,
      });
    });
    if (assetPostgresEnabled) {
      postgresAssetStore = createPostgresAssetStore({
        pool: postgresAssetPool,
        schemaPath: assetPostgresSchemaPath,
        logger: applicationLogger,
      });
      await postgresAssetStore.initialize();
      postgresAssetStoreError = '';
      applicationLogger.log('info', 'asset_store.ready', {
        backend: 'postgresql',
        schema_version: 1,
      });
    }
  } catch (error) {
    postgresAssetStore = null;
    postgresAssetStoreError = String(error.message || error).slice(0, 500);
    postgresSoftwareStoreError = postgresAssetStoreError;
    postgresAcHunterStoreError = postgresAssetStoreError;
    applicationLogger.log('error', 'asset_store.initialization_failed', {
      error_message: postgresAssetStoreError,
    });
  }
}

async function initializePostgresAcHunterStore() {
  if (!acHunterPostgresEnabled || controlledEvaluationMode) return;
  if (!postgresAssetPool) {
    postgresAcHunterStoreError = 'shared PostgreSQL pool is unavailable';
    return;
  }
  try {
    postgresAcHunterStore = createPostgresAcHunterStore({
      pool: postgresAssetPool,
      schemaPath: acHunterPostgresSchemaPath,
      logger: applicationLogger,
    });
    await postgresAcHunterStore.initialize();
    postgresAcHunterStoreError = '';
    applicationLogger.log('info', 'ac_hunter_store.ready', {
      backend: 'postgresql',
      schema_version: 1,
      retention_seconds: 86400,
      scheduled_minute: 35,
    });
  } catch (error) {
    postgresAcHunterStore = null;
    postgresAcHunterStoreError = String(error.message || error).slice(0, 500);
    applicationLogger.log('error', 'ac_hunter_store.initialization_failed', {
      error_message: postgresAcHunterStoreError,
    });
  }
}

async function initializePostgresSoftwareStore() {
  if (!softwarePostgresEnabled || controlledEvaluationMode) return;
  if (!postgresAssetPool) {
    postgresSoftwareStoreError = (
      'shared PostgreSQL pool is unavailable; enable the PostgreSQL asset store'
    );
    return;
  }
  try {
    postgresSoftwareStore = createPostgresSoftwareStore({
      pool: postgresAssetPool,
      schemaPath: softwarePostgresSchemaPath,
      logger: applicationLogger,
    });
    await postgresSoftwareStore.initialize();
    postgresSoftwareStoreError = '';
    applicationLogger.log('info', 'software_inventory_store.ready', {
      backend: 'postgresql',
      schema_version: 1,
    });
  } catch (error) {
    postgresSoftwareStore = null;
    postgresSoftwareStoreError = String(error.message || error).slice(0, 500);
    applicationLogger.log('error', 'software_inventory_store.initialization_failed', {
      error_message: postgresSoftwareStoreError,
    });
  }
}

function requirePostgresAssetStore() {
  if (!assetPostgresEnabled) {
    const error = new Error('PostgreSQL asset inventory is disabled');
    error.statusCode = 503;
    throw error;
  }
  if (!postgresAssetStore) {
    const error = new Error(
      `PostgreSQL asset inventory is unavailable${postgresAssetStoreError ? `: ${postgresAssetStoreError}` : ''}`,
    );
    error.statusCode = 503;
    throw error;
  }
  return postgresAssetStore;
}

function requirePostgresSoftwareStore() {
  if (!softwarePostgresEnabled) {
    const error = new Error('PostgreSQL software inventory is disabled');
    error.statusCode = 503;
    throw error;
  }
  if (!postgresSoftwareStore) {
    const error = new Error(
      `PostgreSQL software inventory is unavailable${
        postgresSoftwareStoreError ? `: ${postgresSoftwareStoreError}` : ''
      }`,
    );
    error.statusCode = 503;
    throw error;
  }
  return postgresSoftwareStore;
}

function requirePostgresAcHunterStore() {
  if (!acHunterPostgresEnabled) {
    const error = new Error('PostgreSQL AC Hunter cache is disabled');
    error.statusCode = 503;
    throw error;
  }
  if (!postgresAcHunterStore) {
    const error = new Error(
      `PostgreSQL AC Hunter cache is unavailable${
        postgresAcHunterStoreError ? `: ${postgresAcHunterStoreError}` : ''
      }`,
    );
    error.statusCode = 503;
    throw error;
  }
  return postgresAcHunterStore;
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

function buildPostCommitPayload(rawAlert, stored) {
  const row = stored.alert || {};
  const triage = stored.triage || {};
  const filter = stored.filter || {status: stored.status || 'unknown'};
  const notification = stored.notification || {status: 'unknown'};
  const routing = stored.status === 'already_seen'
    ? 'duplicate-suppressed'
    : (triage.routing || row.routing || 'unknown');
  const committedAt = nowUtc();
  return {
    ok: true,
    stage: 'alert-store-post-commit',
    status: stored.status,
    stored: Boolean(stored.stored),
    original_alert: rawAlert,
    alert_id: row.alert_id || rawAlert.alert_id,
    rule_name: row.rule_name || rawAlert.rule_name || null,
    event_dataset: row.event_dataset || rawAlert.event_dataset || null,
    severity: row.severity ?? rawAlert.severity ?? null,
    severity_label: row.severity_label || rawAlert.severity_label || null,
    source_ip: row.source_ip || nestedField(rawAlert, 'source.ip'),
    destination_ip: row.destination_ip || nestedField(rawAlert, 'destination.ip'),
    traffic_direction: triage.traffic_direction || row.traffic_direction || null,
    triage_score: triage.score ?? row.triage_score ?? null,
    triage_level: triage.level || row.triage_level || null,
    routing,
    triage_reasons: triage.reasons || [],
    filter_status: filter.status || row.filter_status || null,
    filter_reason: filter.reason || row.filter_reason || null,
    suppression_key: filter.key || row.suppression_key || null,
    suppression_rule: filter.rule || null,
    notification_channel: notification.channel || 'telegram',
    notification_status: notification.status,
    first_seen: row.first_seen || null,
    last_seen: row.last_seen || null,
    seen_count: row.seen_count || null,
    authorized_activity_campaign: stored.campaign || null,
    should_write_report: stored.status === 'accepted' && Boolean(stored.stored),
    report_decision: 'write_markdown_report',
    report_job_id: `alert-report:${row.alert_id || rawAlert.alert_id}`,
    committed_at: committedAt,
  };
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

function controlledRetirementConflict(message, statusCode = 409) {
  return controlledRetirementIdentityOwner.conflict(message, statusCode);
}

function controlledRetirementCanonicalJsonText(value) {
  return controlledRetirementIdentityOwner.canonicalJsonText(value);
}

function controlledRetirementSha256(value) {
  return controlledRetirementIdentityOwner.sha256(value);
}

function controlledRetirementRawSha256(value) {
  return controlledRetirementIdentityOwner.rawSha256(value);
}

function controlledRetirementIdentity(payload) {
  return controlledRetirementIdentityOwner.normalize(payload);
}

function controlledRetirementJobProjection(row) { return controlledRetirementProjections.job(row); }
function controlledRetirementOrderedDispatches(identity) { return controlledRetirementProjections.orderedDispatches(identity); }
function controlledRetirementErrorProjection(value) { return controlledRetirementProjections.error(value); }
function controlledRetirementRunProjection(row, receipt) { return controlledRetirementProjections.run(row, receipt); }
function controlledRetirementRunCaseProjection(row) { return controlledRetirementProjections.runCase(row); }
function controlledRetirementAttemptProjection(row) { return controlledRetirementProjections.attempt(row); }
function controlledRetirementPrimaryProjection(row) { return controlledRetirementProjections.primary(row); }
function controlledRetirementReviewerProjection(row) { return controlledRetirementProjections.reviewer(row); }
function controlledRetirementCompletedJobLifecycleValid(job) { return controlledRetirementProjections.completedLifecycleValid(job); }
function controlledRetirementCompletedProjection(value) { return controlledRetirementProjections.completed(value); }

async function controlledRetirementCompletedMember(
  identity,
  member,
  job,
  jobPayload,
  runRow,
  runReceipt,
) {
  return controlledRetirementCompletedMemberOwner.project(
    identity,
    member,
    job,
    jobPayload,
    runRow,
    runReceipt,
  );
}
async function controlledRetirementTargetMember(
  identity,
  member,
  targetState,
  job,
  jobPayload,
  runRow,
  runReceipt,
) {
  return controlledRetirementTargetMemberOwner.project(
    identity,
    member,
    targetState,
    job,
    jobPayload,
    runRow,
    runReceipt,
  );
}
async function controlledRetirementCensus(identity, targetState) {
  return controlledRetirementCensusOwner.project(identity, targetState);
}
function validateControlledRetirementReceipt(receipt, identity, retirementId) {
  return controlledRetirementReplayOwner.validateReceipt(receipt, identity, retirementId);
}

async function controlledRetirementReplay(identity, retirementId) {
  return controlledRetirementReplayOwner.replay(identity, retirementId);
}

async function validateControlledRetirementPostState(identity, receipt) {
  return controlledRetirementReplayOwner.validatePostState(identity, receipt);
}
async function retireControlledEvaluation(payload) {
  return controlledRetirementCommandOwner.retire(payload);
}
async function rejectProcessingControlledJob(jobType, groupIds) {
  const keys = [...new Set(
    (groupIds || [])
      .map((value) => (typeof value === 'string' ? value.trim().toLowerCase() : ''))
      .filter(Boolean),
  )];
  if (!keys.length) return;
  const placeholders = keys.map(() => '?').join(', ');
  const processing = await get(
    `SELECT id, dedupe_key FROM durable_jobs
     WHERE job_type = ? AND status = 'processing'
       AND dedupe_key IN (${placeholders})
     ORDER BY id ASC LIMIT 1`,
    [jobType, ...keys],
  );
  if (processing) {
    throw incidentIdentityConflict(
      `controlled dispatch conflicts with processing ${jobType} job for ${processing.dedupe_key}`,
    );
  }
}

async function retirePendingIncidentJobs(groupIds, retiredAt) {
  const keys = [...new Set(
    (groupIds || [])
      .map((value) => (typeof value === 'string' ? value.trim().toLowerCase() : ''))
      .filter(Boolean),
  )];
  if (!keys.length) return 0;
  const placeholders = keys.map(() => '?').join(', ');
  const result = await run(
    `UPDATE durable_jobs
     SET status = 'completed', lease_expires_at = NULL, lease_token = NULL,
         last_error = NULL, completed_at = COALESCE(completed_at, ?),
         last_completed_at = COALESCE(last_completed_at, ?),
         processing_started_at = NULL, rerun_requested = 0, updated_at = ?
     WHERE job_type = 'incident_response_analysis'
       AND status = 'pending' AND dedupe_key IN (${placeholders})`,
    [retiredAt, retiredAt, retiredAt, ...keys],
  );
  return Number(result.changes || 0);
}

function resolveCanonicalAlertGroupIdentity(groupId, aliases) {
  let current = typeof groupId === 'string' ? groupId.trim().toLowerCase() : '';
  if (!current || !/^[a-f0-9]{12,64}$/.test(current)) {
    throw incidentIdentityConflict('incident case contains an invalid stable group identity');
  }
  const visited = new Set();
  let canonicalGroupKey = '';
  for (let depth = 0; depth < 64; depth += 1) {
    if (visited.has(current)) {
      throw incidentIdentityConflict('incident case stable group alias cycle detected');
    }
    visited.add(current);
    const alias = aliases.get(current);
    if (!alias) return {stableGroupId: current, stableGroupKey: canonicalGroupKey};
    const next = typeof alias.stable_group_id === 'string'
      ? alias.stable_group_id.trim().toLowerCase()
      : '';
    if (!next || !/^[a-f0-9]{12,64}$/.test(next)) {
      throw incidentIdentityConflict('incident case contains an invalid stable group alias');
    }
    const aliasGroupKey = typeof alias.stable_group_key === 'string'
      ? alias.stable_group_key
      : '';
    if (
      canonicalGroupKey
      && aliasGroupKey
      && canonicalGroupKey !== aliasGroupKey
    ) {
      throw incidentIdentityConflict('incident case stable group alias key is ambiguous');
    }
    if (aliasGroupKey) canonicalGroupKey = aliasGroupKey;
    current = next;
  }
  throw incidentIdentityConflict('incident case stable group alias chain is too deep');
}

async function loadAlertGroupAliasSnapshot() {
  const aliases = new Map();
  const rows = await all(
    `SELECT legacy_group_id, stable_group_id, stable_group_key
     FROM alert_group_alias`,
  );
  for (const row of rows) {
    const legacyGroupId = typeof row.legacy_group_id === 'string'
      ? row.legacy_group_id.trim().toLowerCase()
      : '';
    if (!legacyGroupId || aliases.has(legacyGroupId)) {
      throw incidentIdentityConflict('incident case stable group alias map is ambiguous');
    }
    aliases.set(legacyGroupId, row);
  }
  return aliases;
}

function manualDispatchIdentity(payload) {
  return manualDispatchIdentityOwner.normalize(payload);
}
async function resolveDashboardAlertGroup(dashboardGroupId, identity = {}) {
  let representative = await get(
    `SELECT a.alert_id, a.stable_group_id, a.stable_group_key
     FROM alert_group_summary AS g
     JOIN alerts AS a ON a.alert_id = g.representative_alert_id
     WHERE g.group_id = ?`,
    [dashboardGroupId],
  );
  if (!representative) {
    representative = await get(
      `SELECT a.alert_id, a.stable_group_id, a.stable_group_key
       FROM alert_group_alias AS ga
       JOIN alerts AS a ON a.stable_group_id = ga.stable_group_id
       WHERE ga.legacy_group_id = ?
       ORDER BY replace(replace(COALESCE(NULLIF(a.last_seen, ''), NULLIF(a.timestamp, ''), NULLIF(a.first_seen, '')), 'T', ' '), 'Z', '') DESC,
                a.alert_id DESC LIMIT 1`,
      [dashboardGroupId],
    );
  }
  if (!representative) return null;

  const resolvedStableGroupId = typeof representative.stable_group_id === 'string'
    ? representative.stable_group_id
    : '';
  const resolvedStableGroupKey = typeof representative.stable_group_key === 'string'
    ? representative.stable_group_key
    : '';
  if (
    identity.stableGroupIdSupplied
    && identity.stableGroupId !== resolvedStableGroupId
  ) {
    const error = new Error(
      'requested stable_group_id no longer matches the dashboard group',
    );
    error.statusCode = 409;
    throw error;
  }
  if (
    identity.stableGroupKeySupplied
    && identity.stableGroupKey !== resolvedStableGroupKey
  ) {
    throw incidentIdentityConflict(
      'requested stable_group_key no longer matches the dashboard group',
    );
  }
  if (!identity.representativeAlertIdSupplied) return representative;

  const pinned = await get(
    `SELECT alert_id, stable_group_id, stable_group_key
     FROM alerts WHERE alert_id = ? LIMIT 1`,
    [identity.representativeAlertId],
  );
  const pinnedStableGroupId = typeof pinned?.stable_group_id === 'string'
    ? pinned.stable_group_id
    : '';
  const pinnedStableGroupKey = typeof pinned?.stable_group_key === 'string'
    ? pinned.stable_group_key
    : '';
  if (
    !pinned?.alert_id
    || !resolvedStableGroupId
    || pinnedStableGroupId !== resolvedStableGroupId
    || (
      identity.stableGroupIdSupplied
      && pinnedStableGroupId !== identity.stableGroupId
    )
    || (
      resolvedStableGroupKey
      && pinnedStableGroupKey !== resolvedStableGroupKey
    )
    || (
      identity.stableGroupKeySupplied
      && pinnedStableGroupKey !== identity.stableGroupKey
    )
  ) {
    const error = new Error(
      'requested representative_alert_id no longer belongs to the dashboard group',
    );
    error.statusCode = 409;
    throw error;
  }
  representative = pinned;
  return representative;
}

async function requestAiReanalysis(payload) {
  const dashboardGroupId = safeString(payload?.group_id, 64).toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(dashboardGroupId)) {
    const error = new Error('valid dashboard group_id is required');
    error.statusCode = 400;
    throw error;
  }
  const identity = manualDispatchIdentity(payload);
  const representative = await resolveDashboardAlertGroup(
    dashboardGroupId,
    identity,
  );
  const stableGroupId = safeString(representative?.stable_group_id, 64).toLowerCase();
  if (!representative?.alert_id || !stableGroupId) {
    const error = new Error('SOC alert group was not found');
    error.statusCode = 404;
    throw error;
  }
  const requestedRelatedLimit = Number(payload?.related_limit ?? 250);
  const requestedPcapLimit = Number(payload?.pcap_analysis_limit ?? 8);
  if (!Number.isFinite(requestedRelatedLimit) || !Number.isFinite(requestedPcapLimit)) {
    const error = new Error('AI analysis queue limits must be finite numbers');
    error.statusCode = 400;
    throw error;
  }
  const relatedLimit = Math.max(1, Math.min(500, Math.trunc(requestedRelatedLimit)));
  const pcapAnalysisLimit = Math.max(1, Math.min(25, Math.trunc(requestedPcapLimit)));
  const requestedBy = safeString(payload?.requested_by || 'dashboard', 100);
  const requestedAt = nowUtc();
  if (identity.cohortId) {
    await rejectProcessingControlledJob('ai_analysis', [stableGroupId]);
  }
  await durableJobs.enqueue('ai_analysis', stableGroupId, {
    alert_id: representative.alert_id,
    group_id: stableGroupId,
    dashboard_group_id: dashboardGroupId,
    ...(identity.representativeAlertIdSupplied ? {
      representative_alert_id: representative.alert_id,
    } : {}),
    ...(identity.stableGroupIdSupplied ? {
      stable_group_id: stableGroupId,
    } : {}),
    ...(identity.stableGroupKeySupplied ? {
      stable_group_key: identity.stableGroupKey,
    } : {}),
    ...(identity.cohortId ? {
      cohort_id: identity.cohortId,
      dispatch_id: identity.dispatchId,
      release_id: identity.releaseId,
      expected_assigned_route: identity.expectedAssignedRoute,
      expected_reviewer_route: identity.expectedReviewerRoute,
      reviewer_required: identity.reviewerRequired,
      agent_role: 'soc-analyst',
    } : {}),
    manual_reanalysis: true,
    requested_by: requestedBy,
    requested_at: requestedAt,
    reason: safeString(payload?.reason || 'SOC analyst requested fresh AI analysis', 500),
    related_limit: relatedLimit,
    pcap_analysis_limit: pcapAnalysisLimit,
  }, {priority: 1000, maxAttempts: 12});
  await pipelineMetrics.record('ai_analysis', 'enqueued', stableGroupId, {
    eventKey: `ai_analysis:manual:${stableGroupId}:${requestedAt}`,
  });
  return {
    ok: true,
    status: 'queued',
    group_id: dashboardGroupId,
    queue_group_id: stableGroupId,
    representative_alert_id: representative.alert_id,
    ...(identity.stableGroupIdSupplied ? {
      stable_group_id: stableGroupId,
    } : {}),
    ...(identity.stableGroupKeySupplied ? {
      stable_group_key: identity.stableGroupKey,
    } : {}),
    ...(identity.cohortId ? {
      cohort_id: identity.cohortId,
      dispatch_id: identity.dispatchId,
      release_id: identity.releaseId,
      expected_assigned_route: identity.expectedAssignedRoute,
      expected_reviewer_route: identity.expectedReviewerRoute,
      reviewer_required: identity.reviewerRequired,
    } : {}),
    requested_at: requestedAt,
  };
}

async function requestIncidentEscalation(payload) {
  const dashboardGroupId = safeString(payload?.group_id, 64).toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(dashboardGroupId)) {
    const error = new Error('valid dashboard group_id is required');
    error.statusCode = 400;
    throw error;
  }
  const identity = manualDispatchIdentity(payload);
  const representative = await resolveDashboardAlertGroup(
    dashboardGroupId,
    identity,
  );
  const stableGroupId = safeString(representative?.stable_group_id, 64).toLowerCase();
  if (!representative?.alert_id || !stableGroupId) {
    const error = new Error('SOC alert group was not found');
    error.statusCode = 404;
    throw error;
  }
  return queueIncidentResponseForGroup({
    dashboardGroupId,
    representative,
    requestedBy: payload?.requested_by || 'dashboard',
    reason: payload?.reason || 'Escalated from SOC Alerts for incident response',
    relatedLimit: payload?.related_limit ?? 250,
    pcapAnalysisLimit: payload?.pcap_analysis_limit ?? 25,
    // Escalation creates the case's initial Incident Responder analysis. It is
    // manually requested, but it is not a case-bound reanalysis run and must
    // not be mistaken for one by the immutable attempt-lineage contract.
    manualReanalysis: false,
    eventType: 'escalated',
    priority: 1100,
    cohortId: identity.cohortId,
    dispatchId: identity.dispatchId,
    releaseId: identity.releaseId,
    expectedAssignedRoute: identity.expectedAssignedRoute,
    expectedReviewerRoute: identity.expectedReviewerRoute,
    reviewerRequired: identity.reviewerRequired,
    representativeAlertIdPinned: identity.representativeAlertIdSupplied,
    stableGroupIdPinned: identity.stableGroupIdSupplied,
    stableGroupKey: identity.stableGroupKey,
    stableGroupKeyPinned: identity.stableGroupKeySupplied,
  });
}

async function queueIncidentResponseForGroup({
  dashboardGroupId,
  representative,
  requestedBy = 'dashboard',
  reason = 'Escalated from SOC Alerts for incident response',
  relatedLimit = 250,
  pcapAnalysisLimit = 25,
  manualReanalysis = false,
  eventType = 'escalated',
  priority = 1100,
  cohortId = '',
  dispatchId = '',
  releaseId = '',
  expectedAssignedRoute = '',
  expectedReviewerRoute = '',
  reviewerRequired = false,
  representativeAlertIdPinned = false,
  stableGroupIdPinned = false,
  stableGroupKey = '',
  stableGroupKeyPinned = false,
}) {
  const stableGroupId = safeString(representative?.stable_group_id, 64).toLowerCase();
  if (!representative?.alert_id || !stableGroupId) {
    const error = new Error('resolved SOC alert group is missing its stable identity');
    error.statusCode = 409;
    throw error;
  }
  const requestedRelatedLimit = Number(relatedLimit);
  const requestedPcapLimit = Number(pcapAnalysisLimit);
  if (!Number.isFinite(requestedRelatedLimit) || !Number.isFinite(requestedPcapLimit)) {
    const error = new Error('Incident response queue limits must be finite numbers');
    error.statusCode = 400;
    throw error;
  }
  const requestedAt = nowUtc();
  const actor = safeString(requestedBy, 100);
  const normalizedReason = safeString(reason, 1000);
  const caseId = `ir-${crypto.createHash('sha256').update(stableGroupId).digest('hex').slice(0, 16)}`;
  if (cohortId) {
    await rejectProcessingControlledJob(
      'incident_response_analysis',
      [stableGroupId],
    );
  }
  await run(
    `INSERT INTO incident_response_cases (
       case_id, group_id, dashboard_group_id, representative_alert_id, status,
       agent_status, escalated_at, updated_at, escalated_by, reason
     ) VALUES (?, ?, ?, ?, 'open', 'queued', ?, ?, ?, ?)
     ON CONFLICT(group_id) DO UPDATE SET
       dashboard_group_id = excluded.dashboard_group_id,
       representative_alert_id = excluded.representative_alert_id,
       status = CASE WHEN incident_response_cases.status = 'resolved' THEN 'open' ELSE incident_response_cases.status END,
       agent_status = 'queued',
       updated_at = excluded.updated_at,
       escalated_by = excluded.escalated_by,
       reason = excluded.reason,
       resolution_reason = CASE WHEN incident_response_cases.status = 'resolved' THEN NULL ELSE incident_response_cases.resolution_reason END,
       resolved_at = CASE WHEN incident_response_cases.status = 'resolved' THEN NULL ELSE incident_response_cases.resolved_at END,
       resolved_by = CASE WHEN incident_response_cases.status = 'resolved' THEN NULL ELSE incident_response_cases.resolved_by END,
       latest_error = NULL`,
    [
      caseId,
      stableGroupId,
      dashboardGroupId,
      representative.alert_id,
      requestedAt,
      requestedAt,
      actor,
      normalizedReason,
    ],
  );
  const incident = await get('SELECT case_id, escalated_at FROM incident_response_cases WHERE group_id = ?', [stableGroupId]);
  await run(
    `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
     VALUES (?, ?, ?, ?, ?)`,
    [
      incident.case_id,
      safeString(eventType, 64),
      actor,
      jsonText({
        dashboard_group_id: dashboardGroupId,
        ...(representativeAlertIdPinned ? {
          representative_alert_id: representative.alert_id,
        } : {}),
        ...(stableGroupIdPinned ? {stable_group_id: stableGroupId} : {}),
        ...(stableGroupKeyPinned ? {stable_group_key: stableGroupKey} : {}),
        ...(cohortId ? {
          cohort_id: cohortId,
          dispatch_id: dispatchId,
          release_id: releaseId,
          expected_assigned_route: expectedAssignedRoute,
          expected_reviewer_route: expectedReviewerRoute,
          reviewer_required: reviewerRequired,
        } : {}),
        reason: normalizedReason,
      }),
      requestedAt,
    ],
  );
  await durableJobs.enqueue('incident_response_analysis', stableGroupId, {
    agent_role: 'incident-responder',
    case_id: incident.case_id,
    alert_id: representative.alert_id,
    group_id: stableGroupId,
    dashboard_group_id: dashboardGroupId,
    ...(representativeAlertIdPinned ? {
      representative_alert_id: representative.alert_id,
    } : {}),
    ...(stableGroupIdPinned ? {stable_group_id: stableGroupId} : {}),
    ...(stableGroupKeyPinned ? {stable_group_key: stableGroupKey} : {}),
    ...(cohortId ? {
      cohort_id: cohortId,
      dispatch_id: dispatchId,
      release_id: releaseId,
      expected_assigned_route: expectedAssignedRoute,
      expected_reviewer_route: expectedReviewerRoute,
      reviewer_required: reviewerRequired,
    } : {}),
    manual_reanalysis: Boolean(manualReanalysis),
    requested_by: actor,
    requested_at: requestedAt,
    reason: normalizedReason,
    related_limit: Math.max(1, Math.min(500, Math.trunc(requestedRelatedLimit))),
    pcap_analysis_limit: Math.max(1, Math.min(25, Math.trunc(requestedPcapLimit))),
  }, {priority: Math.max(0, Number(priority) || 0), maxAttempts: 12});
  await pipelineMetrics.record('incident_response_analysis', 'enqueued', stableGroupId, {
    eventKey: `incident_response_analysis:${manualReanalysis ? 'manual' : 'automatic'}:${stableGroupId}:${requestedAt}`,
  });
  return {
    ok: true,
    status: 'queued',
    case_id: incident.case_id,
    group_id: dashboardGroupId,
    queue_group_id: stableGroupId,
    representative_alert_id: representative.alert_id,
    ...(stableGroupIdPinned ? {stable_group_id: stableGroupId} : {}),
    ...(stableGroupKeyPinned ? {stable_group_key: stableGroupKey} : {}),
    ...(cohortId ? {
      cohort_id: cohortId,
      dispatch_id: dispatchId,
      release_id: releaseId,
      expected_assigned_route: expectedAssignedRoute,
      expected_reviewer_route: expectedReviewerRoute,
      reviewer_required: reviewerRequired,
    } : {}),
    escalated_at: incident.escalated_at,
    requested_at: requestedAt,
  };
}

function incidentReanalysisReleaseId() {
  const candidate = safeString(
    process.env.ONION_SENTINEL_RELEASE_ID || 'unversioned',
    100,
  ).replace(/[^A-Za-z0-9._:-]+/g, '-').replace(/^-+|-+$/g, '');
  return candidate || 'unversioned';
}

async function incidentReanalysisRunSnapshot(runId) {
  const runRow = await get(
    `SELECT run_id, release_id, scope, status, requested_by, reason,
            total_count, created_at, updated_at, completed_at
     FROM incident_reanalysis_runs WHERE run_id = ?`,
    [runId],
  );
  if (!runRow) return null;
  const counts = {queued: 0, running: 0, completed: 0, failed: 0, skipped: 0};
  const rows = await all(
    `SELECT status, COUNT(*) AS count
     FROM incident_reanalysis_run_cases WHERE run_id = ? GROUP BY status`,
    [runId],
  );
  for (const row of rows) {
    if (Object.prototype.hasOwnProperty.call(counts, row.status)) {
      counts[row.status] = Number(row.count || 0);
    }
  }
  return {
    ...runRow,
    total_count: Number(runRow.total_count || 0),
    counts,
  };
}

async function refreshIncidentReanalysisRun(runId) {
  if (!runId) return null;
  const snapshot = await incidentReanalysisRunSnapshot(runId);
  if (!snapshot) return null;
  const counts = snapshot.counts;
  const terminal = counts.completed + counts.failed + counts.skipped;
  let status = 'queued';
  if (counts.running > 0) status = 'running';
  else if (counts.queued > 0) status = 'queued';
  else if (snapshot.total_count === 0) status = 'completed';
  else if (counts.failed === snapshot.total_count) status = 'failed';
  else if (terminal >= snapshot.total_count && (counts.failed > 0 || counts.skipped > 0)) status = 'partial';
  else if (terminal >= snapshot.total_count) status = 'completed';
  const updatedAt = nowUtc();
  const completedAt = ['completed', 'partial', 'failed'].includes(status) ? updatedAt : null;
  await run(
    `UPDATE incident_reanalysis_runs
     SET status = ?, updated_at = ?, completed_at = ?
     WHERE run_id = ?`,
    [status, updatedAt, completedAt, runId],
  );
  return incidentReanalysisRunSnapshot(runId);
}

async function supersedeIncidentReanalysisCase(caseId, replacementRunId, updatedAt) {
  const priorRuns = await all(
    `SELECT DISTINCT run_id FROM incident_reanalysis_run_cases
     WHERE case_id = ? AND status = 'queued' AND run_id != ?`,
    [caseId, replacementRunId],
  );
  if (!priorRuns.length) return;
  await run(
    `UPDATE incident_reanalysis_run_cases
     SET status = 'skipped', skip_reason = ?, latest_error = NULL,
         completed_at = ?, updated_at = ?
     WHERE case_id = ? AND status = 'queued' AND run_id != ?`,
    [
      `Superseded by newer reanalysis run ${replacementRunId}`,
      updatedAt,
      updatedAt,
      caseId,
      replacementRunId,
    ],
  );
  for (const item of priorRuns) {
    await refreshIncidentReanalysisRun(String(item.run_id || ''));
  }
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
  if (enrichmentDrainActive || !durableJobs) return;
  enrichmentDrainActive = true;
  try {
    // One provider bundle at a time prevents free-tier bursts. The interval
    // immediately runs again after completion, so ingest never waits on it.
    const job = await withSqliteWriteGate(() => withImmediateTransaction(
      () => durableJobs.claim('public_enrichment', Math.ceil(enrichmentTimeoutMs * 20 / 1000)),
    ));
    if (!job) return;
    let wakeAi = false;
    try {
      const row = await get('SELECT alert_json FROM alerts WHERE alert_id = ?', [job.payload.alert_id]);
      if (!row) throw new Error('alert no longer exists');
      const alert = JSON.parse(row.alert_json);
      const result = await enrichAlert(alert);
      if (!result.ok || !result.alert) throw new Error(result.reason || 'enrichment returned no alert');
      await withSqliteWriteGate(() => withImmediateTransaction(async () => {
        await run(
          'UPDATE alerts SET enrichment_json = ?, alert_json = ? WHERE alert_id = ?',
          [jsonText(enrichmentRecord(result.alert)), jsonText(result.alert), job.payload.alert_id],
        );
        const updatedRow = await get('SELECT * FROM alerts WHERE alert_id = ?', [job.payload.alert_id]);
        if (updatedRow) {
          await indexAlertObservables(result.alert, updatedRow);
          const groupKey = updatedRow.stable_group_key || alertGroupKeyFromRow(updatedRow);
          const groupId = updatedRow.stable_group_id || alertGroupId(groupKey);
          const level = String(updatedRow.triage_level || 'informational').toLowerCase();
          const campaign = await authorizedCampaignForAlertId(updatedRow.alert_id);
          const campaignOwnsIncidentInvestigation = campaign?.investigation_mode
            === 'incident_response_only';
          if (socAnalysisPolicy.matchesAnalysis(level) && !campaignOwnsIncidentInvestigation) {
            await durableJobs.enqueue('ai_analysis', groupId, {
              group_id: groupId,
              group_key: groupKey,
              representative_alert_id: updatedRow.alert_id,
            }, {priority: severityRank[level] ?? 0, maxAttempts: 8});
            await pipelineMetrics.record('ai_analysis', 'enqueued', groupId, {
              eventKey: `ai_analysis:enqueued:${groupId}:enrichment:${job.id}:${job.attempt_count}`,
            });
            wakeAi = true;
          }
        }
        const completed = await durableJobs.complete(job);
        if (completed) {
          await pipelineMetrics.record('public_enrichment', 'completed', job.payload.alert_id, {
            eventKey: `public_enrichment:completed:${job.id}:${job.attempt_count}`,
            sizeBytes: Buffer.byteLength(JSON.stringify(enrichmentRecord(result.alert) || {})),
          });
        }
      }));
      if (wakeAi) void signalAiWorkers('enrichment-completed');
    } catch (error) {
      let enrichmentExhausted = false;
      await withSqliteWriteGate(() => withImmediateTransaction(async () => {
        await durableJobs.fail(job, error.message);
        const failedJob = await get('SELECT status FROM durable_jobs WHERE id = ?', [job.id]);
        enrichmentExhausted = failedJob?.status === 'failed';
        await pipelineMetrics.record('public_enrichment', 'failed', job.payload.alert_id, {
          eventKey: `public_enrichment:failed:${job.id}:${job.attempt_count}`,
        });
      }));
      if (enrichmentExhausted) void signalAiWorkers('enrichment-exhausted');
    }
  } finally {
    enrichmentDrainActive = false;
  }
}

function n8nPostCommitResult(body) {
  const candidates = Array.isArray(body) ? body : [body];
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== 'object') continue;
    const payload = candidate.json && typeof candidate.json === 'object' ? candidate.json : candidate;
    if (payload.ok === false || ['rejected', 'error'].includes(String(payload.status || '').toLowerCase())) {
      return {ok: false, reason: safeString(payload.reason || payload.error || payload.status, 500)};
    }
    if (payload.report_written === true) return {ok: true, payload};
  }
  return {ok: false, reason: 'n8n did not confirm the committed alert report write'};
}

async function drainN8nPostCommitJobs() {
  if (n8nPostCommitDrainActive || !durableJobs || !n8nPostCommitUrl || !n8nPostCommitToken) return;
  n8nPostCommitDrainActive = true;
  try {
    const job = await withSqliteWriteGate(() => withImmediateTransaction(
      () => durableJobs.claim('n8n_post_commit', Math.ceil(n8nPostCommitTimeoutMs * 3 / 1000)),
    ));
    if (!job) return;
    try {
      const response = await requestJson({
        method: 'POST',
        url: n8nPostCommitUrl,
        headers: {'X-Relay-Token': n8nPostCommitToken},
        body: job.payload,
        timeoutMs: n8nPostCommitTimeoutMs,
      });
      const result = n8nPostCommitResult(response.body);
      if (response.statusCode < 200 || response.statusCode >= 300 || !result.ok) {
        throw new Error(result.reason || `n8n returned HTTP ${response.statusCode}`);
      }
      await withSqliteWriteGate(() => withImmediateTransaction(async () => {
        const completed = await durableJobs.complete(job);
        if (completed) {
          await pipelineMetrics.record('n8n_post_commit', 'completed', job.dedupe_key, {
            eventKey: `n8n_post_commit:completed:${job.id}:${job.attempt_count}`,
            sizeBytes: Buffer.byteLength(JSON.stringify(job.payload || {})),
          });
        }
      }));
    } catch (error) {
      await withSqliteWriteGate(() => withImmediateTransaction(async () => {
        await durableJobs.fail(job, error.message, n8nPostCommitBaseRetrySeconds);
        await pipelineMetrics.record('n8n_post_commit', 'failed', job.dedupe_key, {
          eventKey: `n8n_post_commit:failed:${job.id}:${job.attempt_count}`,
        });
      }));
    }
  } finally {
    n8nPostCommitDrainActive = false;
  }
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
const alertIngestOrchestrator = createAlertIngestOrchestrator({
  scoreAlert,
  withWriteGate: withSqliteWriteGate,
  withTransaction: withImmediateTransaction,
  storeUnlocked: storeAlertUnlocked,
  queueNotification: queueTelegramNotification,
  nowUtc,
  buildPostCommitPayload,
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
  projectCompleted: controlledRetirementCompletedMember,
  projectTarget: controlledRetirementTargetMember,
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
  projectCensus: controlledRetirementCensus,
  conflict: controlledRetirementConflict,
});
const controlledRetirementCommandOwner = createControlledRetirementCommand({
  normalizeIdentity: controlledRetirementIdentity,
  sha256: controlledRetirementSha256,
  replay: controlledRetirementReplay,
  validatePostState: validateControlledRetirementPostState,
  projectCensus: controlledRetirementCensus,
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
  validateReceipt: validateControlledRetirementReceipt,
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
const incidentReanalysisFrozenDispatchOwner = createIncidentReanalysisFrozenDispatch({
  get,
  all,
  run,
  parseJsonObject,
  loadAliases: loadAlertGroupAliasSnapshot,
  resolveCanonicalIdentity: resolveCanonicalAlertGroupIdentity,
  rejectProcessingJob: rejectProcessingControlledJob,
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
  retirePendingJobs: retirePendingIncidentJobs,
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
    activeSqliteWrites,
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
    postgresAssetStore,
    assetPostgresEnabled,
    postgresAssetStoreError,
    postgresSoftwareStore,
    softwarePostgresEnabled,
    postgresSoftwareStoreError,
    postgresAcHunterStore,
    acHunterPostgresEnabled,
    postgresAcHunterStoreError,
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
  retireControlledEvaluation,
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

async function handleRequest(request, response) {
  try {
    const parsedUrl = new URL(request.url, 'http://alert-store.local');
    if (controlledEvaluationShutdownStarted) {
      request.resume();
      sendJson(response, 503, {
        ok: false,
        status: 'shutting_down',
      });
      return;
    }
    if (
      controlledEvaluationMode
      && request.method === 'POST'
      && !controlledEvaluationRequestAuthorized(request)
    ) {
      request.resume();
      sendJson(response, 403, {
        ok: false,
        status: 'forbidden',
        reason: 'controlled evaluation authorization failed',
      });
      return;
    }
    if (
      controlledEvaluationMode
      && !controlledEvaluationRequests.has(
        `${String(request.method || '').toUpperCase()} ${request.url}`,
      )
    ) {
      request.resume();
      sendJson(response, 403, {
        ok: false,
        status: 'forbidden',
        reason: 'route is disabled in controlled evaluation mode',
      });
      return;
    }
    if (await modularRoutes.dispatch({request, response, parsedUrl})) return;
    sendJson(response, 404, {ok: false, status: 'not_found'});
  } catch (error) {
    if (request.method === 'POST' && request.url === '/alert') {
      serviceMetrics.ingest_errors += 1;
      writeN8nBeacon('error', {}, null, error);
    }
    sendJson(response, Number(error.statusCode || 400), {
      ok: false,
      status: 'rejected',
      reason: error.message,
    });
  }
}

const dispatchRequest = createRequestDispatcher({
  handleRequest,
  postRequestAdmission,
  logger: applicationLogger,
  sendJson,
  randomUUID: crypto.randomUUID,
  monotonicNow: process.hrtime.bigint,
});

let controlledEvaluationShutdownStarted = false;

function installControlledEvaluationShutdown(server) {
  const shutdown = () => {
    if (controlledEvaluationShutdownStarted) return;
    controlledEvaluationShutdownStarted = true;
    const deadline = setTimeout(() => process.exit(1), 10000);
    deadline.unref();
    server.close(async (serverError) => {
      if (serverError) {
        console.error(`controlled evaluation server shutdown failed: ${serverError.message}`);
        process.exit(1);
        return;
      }
      await sqliteWriteGate.catch(() => undefined);
      if (activeSqliteWrites !== 0) {
        console.error('controlled evaluation shutdown retained active writes');
        process.exit(1);
        return;
      }
      db.close((databaseError) => {
        if (databaseError) {
          console.error(`controlled evaluation database shutdown failed: ${databaseError.message}`);
          process.exit(1);
          return;
        }
        process.exit(0);
      });
    });
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

initDb().then(async () => {
  await initializePostgresAssetStore();
  await initializePostgresSoftwareStore();
  await initializePostgresAcHunterStore();
  applicationLogger.log('info', 'database.initialized', {
    database_path: dbPath,
    postgres_shadow_enabled: postgresShadowEnabled,
    asset_postgres_enabled: assetPostgresEnabled,
    asset_postgres_available: Boolean(postgresAssetStore),
    software_postgres_enabled: softwarePostgresEnabled,
    software_postgres_available: Boolean(postgresSoftwareStore),
    ac_hunter_postgres_enabled: acHunterPostgresEnabled,
    ac_hunter_postgres_available: Boolean(postgresAcHunterStore),
  });
  const server = configureHttpServer(http.createServer((request, response) => {
    void dispatchRequest(request, response).catch((error) => {
      console.error(`unhandled HTTP request failure: ${error.message}`);
      if (!response.headersSent) sendJson(response, 500, {ok: false, status: 'error'});
      else response.destroy(error);
    });
  }), {
    requestTimeoutMs: httpRequestTimeoutMs,
    headersTimeoutMs: httpHeadersTimeoutMs,
    keepAliveTimeoutMs: httpKeepAliveTimeoutMs,
    maxRequestsPerSocket: httpMaxRequestsPerSocket,
    maxConnections: httpMaxConnections,
  });
  server.listen(port, host, () => {
    console.log(`alert-store listening on ${host}:${port}, db=${dbPath}`);
    applicationLogger.log('info', 'service.ready', {
      listen_host: host,
      listen_port: port,
      database_path: dbPath,
    });
  });
  if (controlledEvaluationMode) {
    installControlledEvaluationShutdown(server);
    return;
  }
  if (telegramOutboxAutostart) {
    setInterval(() => void drainTelegramOutbox(), telegramOutboxIntervalMs).unref();
    void drainTelegramOutbox();
  }
  setInterval(() => void drainEnrichmentJobs(), enrichmentWorkerIntervalMs).unref();
  void drainEnrichmentJobs();
  setInterval(() => {
    void enrichmentCache.prune()
      .catch((error) => console.error(`enrichment cache retention failed: ${error.message}`));
  }, enrichmentCacheCleanupIntervalMs).unref();
  void enrichmentCache.prune()
    .catch((error) => console.error(`initial enrichment cache retention failed: ${error.message}`));
  setInterval(() => void drainN8nPostCommitJobs(), n8nPostCommitIntervalMs).unref();
  void drainN8nPostCommitJobs();
  setInterval(() => {
    void recoverExpiredDurableJobs().catch((error) => console.error(`durable job lease recovery failed: ${error.message}`));
  }, durableJobRecoveryIntervalMs).unref();
  void recoverExpiredDurableJobs().catch((error) => console.error(`initial durable job lease recovery failed: ${error.message}`));
  setInterval(() => {
    void capturePipelineDiskSample().catch((error) => console.error(`pipeline disk sample failed: ${error.message}`));
  }, pipelineDiskSampleIntervalMs).unref();
  void capturePipelineDiskSample().catch((error) => console.error(`initial pipeline disk sample failed: ${error.message}`));
  if (postgresShadowProjector) {
    setInterval(() => {
      void postgresShadowProjector.drain()
        .catch((error) => console.error(`PostgreSQL shadow projection failed: ${error.message}`));
    }, postgresShadowIntervalMs).unref();
    void postgresShadowProjector.drain()
      .catch((error) => console.error(`initial PostgreSQL shadow projection failed: ${error.message}`));
  }
  setInterval(() => {
    void withSqliteWriteGate(() => pipelineMetrics.prune())
      .catch((error) => console.error(`pipeline metric retention failed: ${error.message}`));
  }, 60 * 60 * 1000).unref();
}).catch((error) => {
  applicationLogger.log('critical', 'service.start_failed', {
    error_type: error.name,
    error_message: error.message,
  });
  console.error(error);
  process.exit(1);
});
