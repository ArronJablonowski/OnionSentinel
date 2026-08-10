'use strict';

const EVALUATION_CREDENTIAL_ENVIRONMENT_KEYS = Object.freeze([
  'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID', 'N8N_POST_COMMIT_TOKEN',
  'ASSET_STORE_WRITE_TOKEN', 'ABUSEIPDB_API_KEY', 'GREYNOISE_API_KEY',
  'OTX_API_KEY', 'URLHAUS_AUTH_KEY', 'VIRUSTOTAL_API_KEY', 'URLSCAN_API_KEY',
  'GOOGLE_SAFE_BROWSING_API_KEY', 'PHISHTANK_API_KEY',
  'MALWAREBAZAAR_AUTH_KEY', 'THREATFOX_AUTH_KEY', 'SHODAN_API_KEY',
  'CENSYS_API_ID', 'CENSYS_API_SECRET', 'CENSYS_API_TOKEN',
  'CENSYS_ORGANIZATION_ID', 'NVD_API_KEY',
]);

function createCoreConfiguration({env, path, dirname, loadAuthorizedActivityPolicy}) {
  const dbPath = env.ALERT_STORE_DB || '/data/alerts.sqlite3';
  const scoringRulesPath = env.SCORING_RULES_PATH || '/app/config/scoring_rules.json';
  const authorizedActivityPolicyPath = env.AUTHORIZED_ACTIVITY_POLICY_PATH
    || path.join(dirname, '..', 'config', 'authorized_activity_campaigns.json');
  const authorizedActivityPolicy = loadAuthorizedActivityPolicy(
    authorizedActivityPolicyPath,
  );
  const beaconPaths = (env.ALERT_STORE_BEACON_PATHS || '/data/n8n-beacon.json')
    .split(',').map((value) => value.trim()).filter(Boolean);
  const beaconHistoryPaths = (env.ALERT_STORE_BEACON_HISTORY_PATHS || '')
    .split(',').map((value) => value.trim()).filter(Boolean);
  const host = env.ALERT_STORE_HOST || '127.0.0.1';
  const port = Number(env.ALERT_STORE_PORT || 8787);
  const postgresShadowEnabled = String(
    env.ALERT_STORE_POSTGRES_SHADOW_ENABLED || '0',
  ).trim() === '1';
  const postgresShadowIntervalMs = Math.max(
    1000, Number(env.ALERT_STORE_POSTGRES_SHADOW_INTERVAL_MS || 5000),
  );
  const postgresShadowBatchSize = Math.max(
    1, Math.min(1000, Number(env.ALERT_STORE_POSTGRES_SHADOW_BATCH_SIZE || 50)),
  );
  const assetPostgresEnabled = ['1', 'true', 'yes'].includes(
    String(env.ASSET_POSTGRES_ENABLED || '0').trim().toLowerCase(),
  );
  const assetPostgresSchemaPath = env.ASSET_POSTGRES_SCHEMA_PATH
    || path.join(dirname, '..', 'postgres', 'asset-inventory-schema.sql');
  const softwarePostgresEnabled = ['1', 'true', 'yes'].includes(
    String(env.SOFTWARE_POSTGRES_ENABLED ?? env.ASSET_POSTGRES_ENABLED ?? '0')
      .trim().toLowerCase(),
  );
  const softwarePostgresSchemaPath = env.SOFTWARE_POSTGRES_SCHEMA_PATH
    || path.join(dirname, '..', 'postgres', 'software-inventory-schema.sql');
  const acHunterPostgresEnabled = ['1', 'true', 'yes'].includes(
    String(env.AC_HUNTER_POSTGRES_ENABLED ?? env.ASSET_POSTGRES_ENABLED ?? '0')
      .trim().toLowerCase(),
  );
  const acHunterPostgresSchemaPath = env.AC_HUNTER_POSTGRES_SCHEMA_PATH
    || path.join(dirname, '..', 'postgres', 'ac-hunter-schema.sql');
  const assetStoreWriteToken = String(
    env.ASSET_STORE_WRITE_TOKEN || env.N8N_POST_COMMIT_TOKEN || '',
  ).trim();
  const evaluationModeValue = String(env.ONION_SENTINEL_EVALUATION_MODE || '').trim();
  if (!['', '0', '1'].includes(evaluationModeValue)) {
    throw new Error('ONION_SENTINEL_EVALUATION_MODE must be unset, 0, or 1');
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
  const runtimeReleaseIdValue = String(env.ONION_SENTINEL_RELEASE_ID || '').trim();
  const controlledEvaluationToken = String(
    env.ONION_SENTINEL_EVALUATION_TOKEN || '',
  ).trim();

  return {
    dbPath, scoringRulesPath, authorizedActivityPolicyPath, authorizedActivityPolicy,
    beaconPaths, beaconHistoryPaths, host, port, postgresShadowEnabled,
    postgresShadowIntervalMs, postgresShadowBatchSize, assetPostgresEnabled,
    assetPostgresSchemaPath, softwarePostgresEnabled, softwarePostgresSchemaPath,
    acHunterPostgresEnabled, acHunterPostgresSchemaPath, assetStoreWriteToken,
    controlledEvaluationMode, runtimeReleaseIdValue, controlledEvaluationToken,
  };
}

function assertControlledRuntime({env, fs, path, getuid, configuration}) {
  if (!configuration.controlledEvaluationMode) return;
  const configuredCredentialKeys = EVALUATION_CREDENTIAL_ENVIRONMENT_KEYS.filter(
    (key) => String(env[key] || '').trim(),
  );
  const explicitRuntimeKeys = [
    'ALERT_STORE_DB', 'ALERT_STORE_HOST', 'ALERT_STORE_PORT', 'SCORING_RULES_PATH',
  ];
  if (
    explicitRuntimeKeys.some(
      (key) => !Object.prototype.hasOwnProperty.call(env, key)
        || !String(env[key] || '').trim(),
    )
    || configuration.host !== '127.0.0.1'
    || !Number.isSafeInteger(configuration.port)
    || configuration.port < 1024
    || configuration.port > 65535
    || configuration.port === 8787
    || !path.isAbsolute(configuration.dbPath)
    || !/^[a-f0-9]{40}$/.test(configuration.runtimeReleaseIdValue)
    || !/^[a-f0-9]{64}$/.test(configuration.controlledEvaluationToken)
    || configuredCredentialKeys.length
  ) {
    throw new Error(
      'controlled evaluation requires loopback, an explicit existing '
      + 'database, an exact release ID, an ephemeral authorization token, '
      + 'and no configured production credentials',
    );
  }
  const evaluationScoringPath = path.resolve(configuration.scoringRulesPath);
  const evaluationScoringMetadata = fs.lstatSync(evaluationScoringPath);
  const evaluationOwner = typeof getuid === 'function'
    ? getuid()
    : evaluationScoringMetadata.uid;
  if (
    evaluationScoringPath !== configuration.scoringRulesPath
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

function createRequestConfiguration({env, path, dbPath}) {
  const applicationLogPath = env.ALERT_STORE_APPLICATION_LOG
    || path.join(path.dirname(path.dirname(dbPath)), 'logs', 'alert-store-application.jsonl');
  const applicationLogMaxBytes = Math.max(
    1024 * 1024, Number(env.ALERT_STORE_APPLICATION_LOG_MAX_BYTES || 10 * 1024 * 1024),
  );
  const applicationLogBackups = Math.max(
    1, Math.min(20, Number(env.ALERT_STORE_APPLICATION_LOG_BACKUPS || 5)),
  );
  const telegramBotToken = (env.TELEGRAM_BOT_TOKEN || '').trim();
  const telegramChatId = (env.TELEGRAM_CHAT_ID || '').trim();
  const maxRequestBytes = Math.max(
    1024, Number(env.ALERT_STORE_MAX_REQUEST_BYTES || 10 * 1024 * 1024),
  );
  const httpRequestTimeoutMs = Math.max(
    1000, Number(env.ALERT_STORE_REQUEST_TIMEOUT_MS || 30000),
  );
  const httpHeadersTimeoutMs = Math.max(
    1000, Number(env.ALERT_STORE_HEADERS_TIMEOUT_MS || 10000),
  );
  const httpKeepAliveTimeoutMs = Math.max(
    1000, Number(env.ALERT_STORE_KEEPALIVE_TIMEOUT_MS || 5000),
  );
  const httpMaxRequestsPerSocket = Math.max(
    1, Number(env.ALERT_STORE_MAX_REQUESTS_PER_SOCKET || 100),
  );
  const httpMaxConnections = Math.max(
    8, Number(env.ALERT_STORE_MAX_CONNECTIONS || 256),
  );
  const httpMaxActivePosts = Math.max(
    1, Number(env.ALERT_STORE_MAX_ACTIVE_POSTS || 32),
  );
  const diskHardMaxUsedPercent = Math.min(
    80, Math.max(2, Number(env.ALERT_STORE_DISK_HARD_MAX_USED_PERCENT || 80)),
  );
  const diskStartMaxUsedPercent = Math.min(
    diskHardMaxUsedPercent - 0.1,
    Math.max(1, Number(env.ALERT_STORE_DISK_START_MAX_USED_PERCENT || 75)),
  );
  const diskMinFreeBytes = Math.max(
    0, Number(env.ALERT_STORE_DISK_MIN_FREE_BYTES || 50 * 1024 * 1024 * 1024),
  );
  const telegramAlertLevels = new Set(
    (env.TELEGRAM_ALERT_LEVELS || 'critical,high')
      .split(',').map((level) => level.trim().toLowerCase()).filter(Boolean),
  );
  const telegramCooldownSeconds = Number(env.TELEGRAM_COOLDOWN_SECONDS || 900);
  const telegramOutboxIntervalMs = Math.max(
    1000, Number(env.TELEGRAM_OUTBOX_INTERVAL_MS || 15000),
  );
  const telegramOutboxBaseRetrySeconds = Math.max(
    5, Number(env.TELEGRAM_OUTBOX_BASE_RETRY_SECONDS || 30),
  );
  const telegramOutboxMaxRetrySeconds = Math.max(
    telegramOutboxBaseRetrySeconds,
    Number(env.TELEGRAM_OUTBOX_MAX_RETRY_SECONDS || 3600),
  );
  const telegramOutboxMaxAttempts = Math.max(
    1, Number(env.TELEGRAM_OUTBOX_MAX_ATTEMPTS || 8),
  );
  const telegramOutboxAutostart = !['0', 'false', 'no'].includes(
    String(env.TELEGRAM_OUTBOX_AUTOSTART || '1').toLowerCase(),
  );

  return {
    applicationLogPath, applicationLogMaxBytes, applicationLogBackups,
    telegramBotToken, telegramChatId, maxRequestBytes, httpRequestTimeoutMs,
    httpHeadersTimeoutMs, httpKeepAliveTimeoutMs, httpMaxRequestsPerSocket,
    httpMaxConnections, httpMaxActivePosts, diskHardMaxUsedPercent,
    diskStartMaxUsedPercent, diskMinFreeBytes, telegramAlertLevels,
    telegramCooldownSeconds, telegramOutboxIntervalMs,
    telegramOutboxBaseRetrySeconds, telegramOutboxMaxRetrySeconds,
    telegramOutboxMaxAttempts, telegramOutboxAutostart,
  };
}

function createEnrichmentConfiguration(env) {
  const enrichmentCacheDefaultTtlSeconds = Number(
    env.ENRICHMENT_CACHE_TTL_SECONDS || 86400,
  );
  const vulnerabilityCacheDefaultTtlSeconds = Number(
    env.ENRICHMENT_VULN_CACHE_TTL_SECONDS || 86400,
  );
  const enrichmentNegativeCacheTtlSeconds = Math.max(
    300, Number(env.ENRICHMENT_NEGATIVE_CACHE_TTL_SECONDS || 21600),
  );
  const enrichmentStaleIfErrorSeconds = Math.max(
    3600, Number(env.ENRICHMENT_STALE_IF_ERROR_SECONDS || 7 * 86400),
  );
  const enrichmentVulnerabilityStaleIfErrorSeconds = Math.max(
    enrichmentStaleIfErrorSeconds,
    Number(env.ENRICHMENT_VULN_STALE_IF_ERROR_SECONDS || 30 * 86400),
  );
  const enrichmentCacheL1MaxEntries = Math.max(
    64, Number(env.ENRICHMENT_CACHE_L1_MAX_ENTRIES || 2048),
  );
  const enrichmentCacheL1TtlSeconds = Math.max(
    10, Number(env.ENRICHMENT_CACHE_L1_TTL_SECONDS || 300),
  );
  const enrichmentCacheL1MaxBytes = Math.max(
    1024 * 1024, Number(env.ENRICHMENT_CACHE_L1_MAX_BYTES || 64 * 1024 * 1024),
  );
  const enrichmentCacheMaxEntries = Math.max(
    1000, Number(env.ENRICHMENT_CACHE_MAX_ENTRIES || 10000),
  );
  const enrichmentCacheMaxBytes = Math.max(
    16 * 1024 * 1024,
    Number(env.ENRICHMENT_CACHE_MAX_BYTES || 256 * 1024 * 1024),
  );
  const enrichmentCacheRawResponseMaxBytes = Math.max(
    1024, Number(env.ENRICHMENT_CACHE_RAW_RESPONSE_MAX_BYTES || 5 * 1024 * 1024),
  );
  const enrichmentCacheCleanupIntervalMs = Math.max(
    5 * 60 * 1000,
    Number(env.ENRICHMENT_CACHE_CLEANUP_INTERVAL_SECONDS || 3600) * 1000,
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
  const enrichmentTimeoutMs = Number(env.ENRICHMENT_TIMEOUT_MS || 5000);
  const httpJsonMaxResponseBytes = Math.max(
    1024, Number(env.ALERT_STORE_HTTP_JSON_MAX_RESPONSE_BYTES || 5 * 1024 * 1024),
  );
  const enrichmentCircuitFailureThreshold = Math.max(
    1, Number(env.ENRICHMENT_CIRCUIT_FAILURE_THRESHOLD || 3),
  );
  const enrichmentCircuitResetMs = Math.max(
    10000, Number(env.ENRICHMENT_CIRCUIT_RESET_MS || 60000),
  );
  const enrichmentCircuitMaxResetMs = Math.max(
    enrichmentCircuitResetMs,
    Number(env.ENRICHMENT_CIRCUIT_MAX_RESET_MS || 3600000),
  );
  const enrichmentWorkerIntervalMs = Math.max(
    1000, Number(env.ENRICHMENT_WORKER_INTERVAL_MS || 1000),
  );
  const enrichmentWorkerMaxAttempts = Math.max(
    1, Number(env.ENRICHMENT_WORKER_MAX_ATTEMPTS || 8),
  );
  const virustotalMinimumLevel = String(
    env.VIRUSTOTAL_MINIMUM_LEVEL || 'high',
  ).toLowerCase();
  const urlscanSubmitEnabled = ['1', 'true', 'yes'].includes(
    String(env.URLSCAN_SUBMIT_ENABLED || '').toLowerCase(),
  );

  return {
    enrichmentCacheDefaultTtlSeconds, vulnerabilityCacheDefaultTtlSeconds,
    enrichmentNegativeCacheTtlSeconds, enrichmentStaleIfErrorSeconds,
    enrichmentVulnerabilityStaleIfErrorSeconds, enrichmentCacheL1MaxEntries,
    enrichmentCacheL1TtlSeconds, enrichmentCacheL1MaxBytes,
    enrichmentCacheMaxEntries, enrichmentCacheMaxBytes,
    enrichmentCacheRawResponseMaxBytes, enrichmentCacheCleanupIntervalMs,
    enrichmentSourceTtlDefaults, enrichmentTimeoutMs, httpJsonMaxResponseBytes,
    enrichmentCircuitFailureThreshold, enrichmentCircuitResetMs,
    enrichmentCircuitMaxResetMs, enrichmentWorkerIntervalMs,
    enrichmentWorkerMaxAttempts, virustotalMinimumLevel, urlscanSubmitEnabled,
  };
}

function createWorkflowConfiguration({env, path, os}) {
  const pcapRequestMaxWindowSeconds = Math.max(
    30, Number(env.PCAP_REQUEST_MAX_WINDOW_SECONDS || 300),
  );
  const pcapRequestDefaultWindowSeconds = Math.min(
    pcapRequestMaxWindowSeconds,
    Math.max(30, Number(env.PCAP_REQUEST_DEFAULT_WINDOW_SECONDS || 120)),
  );
  const pcapClaimLeaseSeconds = Math.max(
    300, Number(env.PCAP_CLAIM_LEASE_SECONDS || 1800),
  );
  const pcapCaptureRetentionSeconds = Math.max(
    0, Number(env.PCAP_CAPTURE_RETENTION_SECONDS || 0),
  );
  const pcapPriorityMaxWaitSeconds = Math.max(
    60, Number(env.PCAP_PRIORITY_MAX_WAIT_SECONDS || 1200),
  );
  const pcapTransferMaxAttempts = Math.max(
    1, Math.min(20, Number(env.PCAP_TRANSFER_MAX_ATTEMPTS || 5)),
  );
  const pcapTransferMaxRetrySeconds = Math.max(
    30, Math.min(6 * 3600, Number(env.PCAP_TRANSFER_MAX_RETRY_SECONDS || 1800)),
  );
  const pipelineEventRetentionHours = Math.max(
    24, Number(env.PIPELINE_EVENT_RETENTION_HOURS || 168),
  );
  const pipelineDiskSampleIntervalMs = Math.max(
    60 * 1000, Number(env.PIPELINE_DISK_SAMPLE_INTERVAL_SECONDS || 300) * 1000,
  );
  const n8nPostCommitUrl = String(
    env.N8N_POST_COMMIT_URL
      || 'http://127.0.0.1:5678/webhook/onion-sentinel-committed-alert',
  ).trim();
  const n8nPostCommitToken = String(env.N8N_POST_COMMIT_TOKEN || '').trim();
  const n8nPostCommitIntervalMs = Math.max(
    1000, Number(env.N8N_POST_COMMIT_INTERVAL_MS || 5000),
  );
  const n8nPostCommitTimeoutMs = Math.max(
    5000, Number(env.N8N_POST_COMMIT_TIMEOUT_MS || 30000),
  );
  const n8nPostCommitMaxAttempts = Math.max(
    1, Number(env.N8N_POST_COMMIT_MAX_ATTEMPTS || 12),
  );
  const n8nPostCommitBaseRetrySeconds = Math.max(
    5, Number(env.N8N_POST_COMMIT_BASE_RETRY_SECONDS || 15),
  );
  const durableJobRecoveryIntervalMs = Math.max(
    5000, Number(env.DURABLE_JOB_RECOVERY_INTERVAL_SECONDS || 60) * 1000,
  );
  const aiAnalysisLeaseSeconds = Math.max(
    120, Number(env.AI_ANALYSIS_JOB_LEASE_SECONDS || 1800),
  );
  const runtimeDir = String(
    env.ONION_SENTINEL_RUNTIME_DIR || path.join(os.homedir(), 'n8n-local'),
  ).trim();
  const aiAnalysisWakePaths = String(
    env.AI_ANALYSIS_WAKE_PATHS
      || [
        env.AI_ANALYSIS_WAKE_PATH,
        path.join(runtimeDir, 'run', 'ai-analysis-ollama.wake'),
        path.join(runtimeDir, 'run', 'ai-analysis-cli.wake'),
      ].filter(Boolean).join(','),
  ).split(',').map((value) => value.trim())
    .filter((value, index, values) => value && values.indexOf(value) === index);
  const pcapAnalysisWakePath = String(
    env.PCAP_ANALYSIS_WAKE_PATH || path.join(runtimeDir, 'run', 'pcap-analysis.wake'),
  ).trim();
  const analystStatusReasonMaxLength = 140;
  const analystAdjudicationTextMaxLength = 4000;

  return {
    pcapRequestMaxWindowSeconds, pcapRequestDefaultWindowSeconds,
    pcapClaimLeaseSeconds, pcapCaptureRetentionSeconds, pcapPriorityMaxWaitSeconds,
    pcapTransferMaxAttempts, pcapTransferMaxRetrySeconds, pipelineEventRetentionHours,
    pipelineDiskSampleIntervalMs, n8nPostCommitUrl, n8nPostCommitToken,
    n8nPostCommitIntervalMs, n8nPostCommitTimeoutMs, n8nPostCommitMaxAttempts,
    n8nPostCommitBaseRetrySeconds, durableJobRecoveryIntervalMs,
    aiAnalysisLeaseSeconds, runtimeDir, aiAnalysisWakePaths, pcapAnalysisWakePath,
    analystStatusReasonMaxLength, analystAdjudicationTextMaxLength,
  };
}

function createEnrichmentSecrets(env) {
  return {
    abuseipdb: (env.ABUSEIPDB_API_KEY || '').trim(),
    greynoise: (env.GREYNOISE_API_KEY || '').trim(),
    otx: (env.OTX_API_KEY || '').trim(),
    urlhaus: (env.URLHAUS_AUTH_KEY || '').trim(),
    virustotal: (env.VIRUSTOTAL_API_KEY || '').trim(),
    urlscan: (env.URLSCAN_API_KEY || '').trim(),
    googleSafeBrowsing: (env.GOOGLE_SAFE_BROWSING_API_KEY || '').trim(),
    phishtank: (env.PHISHTANK_API_KEY || '').trim(),
    malwarebazaar: (env.MALWAREBAZAAR_AUTH_KEY || '').trim(),
    threatfox: (env.THREATFOX_AUTH_KEY || '').trim(),
    shodan: (env.SHODAN_API_KEY || '').trim(),
    censysId: (env.CENSYS_API_ID || '').trim(),
    censysSecret: (env.CENSYS_API_SECRET || '').trim(),
    censysToken: (env.CENSYS_API_TOKEN || '').trim(),
    censysOrganizationId: (env.CENSYS_ORGANIZATION_ID || '').trim(),
    nvd: (env.NVD_API_KEY || '').trim(),
  };
}

function createRuntimeConfiguration(dependencies) {
  const {env, fs, path, os, dirname, getuid, loadAuthorizedActivityPolicy} = dependencies;
  const core = createCoreConfiguration({
    env, path, dirname, loadAuthorizedActivityPolicy,
  });
  assertControlledRuntime({env, fs, path, getuid, configuration: core});
  return {
    ...core,
    ...createRequestConfiguration({env, path, dbPath: core.dbPath}),
    ...createEnrichmentConfiguration(env),
    ...createWorkflowConfiguration({env, path, os}),
    enrichmentSecrets: createEnrichmentSecrets(env),
  };
}

module.exports = {createRuntimeConfiguration};
