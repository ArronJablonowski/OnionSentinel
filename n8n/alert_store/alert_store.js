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
const {createPipelineMetrics} = require('./lib/pipeline_metrics');
const {createSocAnalysisPolicy} = require('./lib/soc_analysis_policy');
const {stableGroupKey, stableGroupId} = require('./lib/group_identity');
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

// Runtime values come from docker-compose.yml and .env. Keep real tokens in
// .env only; this DR repo stores placeholders and source code.
const dbPath = process.env.ALERT_STORE_DB || '/data/alerts.sqlite3';
const scoringRulesPath = process.env.SCORING_RULES_PATH || '/app/config/scoring_rules.json';
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
  Number(process.env.ENRICHMENT_CACHE_RAW_RESPONSE_MAX_BYTES || 128 * 1024),
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
const enrichmentWorkerIntervalMs = Math.max(1000, Number(process.env.ENRICHMENT_WORKER_INTERVAL_MS || 5000));
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

function existingFilesystemAnchor(targetPath) {
  let candidate = path.resolve(targetPath);
  while (!fs.existsSync(candidate) && candidate !== path.dirname(candidate)) {
    candidate = path.dirname(candidate);
  }
  return candidate;
}

function diskCapacitySnapshot(additionalBytes = 0) {
  const anchor = existingFilesystemAnchor(path.dirname(dbPath));
  const stats = fs.statfsSync(anchor);
  const totalBytes = Number(stats.blocks) * Number(stats.bsize);
  const freeBytes = Number(stats.bavail) * Number(stats.bsize);
  const usedBytes = Math.max(0, totalBytes - freeBytes);
  const additional = Math.max(0, Number(additionalBytes) || 0);
  const usedPercent = totalBytes ? usedBytes / totalBytes * 100 : 100;
  const projectedUsedPercent = totalBytes ? (usedBytes + additional) / totalBytes * 100 : 100;
  return {
    filesystem_anchor: anchor,
    total_bytes: totalBytes,
    used_bytes: usedBytes,
    free_bytes: freeBytes,
    additional_bytes: additional,
    free_after_bytes: freeBytes - additional,
    used_percent: Number(usedPercent.toFixed(2)),
    projected_used_percent: Number(projectedUsedPercent.toFixed(2)),
    start_max_used_percent: diskStartMaxUsedPercent,
    hard_max_used_percent: diskHardMaxUsedPercent,
    min_free_bytes: diskMinFreeBytes,
  };
}

function assertDiskWriteAdmission(label, additionalBytes = maxRequestBytes) {
  const snapshot = diskCapacitySnapshot(additionalBytes);
  let reason = '';
  if (snapshot.used_percent >= diskHardMaxUsedPercent) {
    reason = `disk is ${snapshot.used_percent}% used; hard limit is ${diskHardMaxUsedPercent}%`;
  } else if (snapshot.used_percent >= diskStartMaxUsedPercent) {
    reason = `disk is ${snapshot.used_percent}% used; new-write limit is ${diskStartMaxUsedPercent}%`;
  } else if (snapshot.projected_used_percent >= diskStartMaxUsedPercent) {
    reason = `projected disk use is ${snapshot.projected_used_percent}%; new-write limit is ${diskStartMaxUsedPercent}%`;
  } else if (snapshot.free_after_bytes < diskMinFreeBytes) {
    reason = `projected free space is ${snapshot.free_after_bytes} bytes; reserve is ${diskMinFreeBytes} bytes`;
  }
  if (reason) {
    const error = new Error(`${label} refused: ${reason}`);
    error.statusCode = 507;
    throw error;
  }
  return snapshot;
}

const severityRank = {informational: 0, info: 0, low: 1, medium: 2, high: 3, critical: 4};
const supportedAgentRoles = new Set([
  'soc-analyst',
  'incident-responder',
  'siem-engineer',
  'cyber-threat-intel',
  'threat-hunter',
]);

async function signalWorker(wakePath, eventName) {
  if (!wakePath) return false;
  try {
    await fs.promises.mkdir(path.dirname(wakePath), {recursive: true, mode: 0o700});
    const safeEvent = String(eventName || 'work-available').replace(/[^a-z0-9_-]/gi, '-').slice(0, 64);
    await fs.promises.writeFile(wakePath, `${nowUtc()} ${safeEvent}\n`, {encoding: 'utf8', mode: 0o600});
    return true;
  } catch (error) {
    // Wake files are an optimization. Durable SQLite state and launchd's
    // interval fallback remain authoritative if the filesystem signal fails.
    console.error(`${nowUtc()} worker wake signal failed for ${eventName}: ${error.message}`);
    return false;
  }
}

async function signalAiWorkers(eventName) {
  const results = await Promise.all(
    aiAnalysisWakePaths.map((wakePath) => signalWorker(wakePath, eventName)),
  );
  return results.some(Boolean);
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
const isoTimestampPattern = /\b\d{4}-\d{2}-\d{2}(?:T|\s+)\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/g;

function projectOffset(date) {
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absolute = Math.abs(offsetMinutes);
  const hours = String(Math.floor(absolute / 60)).padStart(2, '0');
  const minutes = String(absolute % 60).padStart(2, '0');
  return `${sign}${hours}:${minutes}`;
}

function formatProjectTimestamp(date) {
  const pad = (value, length = 2) => String(value).padStart(length, '0');
  const milliseconds = date.getMilliseconds();
  const fractional = milliseconds ? `.${pad(milliseconds, 3)}` : '';
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}  ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}${fractional}${projectOffset(date)}`;
}

function parseProjectTimestamp(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  const parseable = text.replace(/(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})/, '$1T');
  const hasOffset = /(?:Z|[+-]\d{2}:?\d{2})$/.test(parseable);
  const parsed = new Date(hasOffset ? parseable : `${parseable}Z`);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function nowUtc() {
  return formatProjectTimestamp(new Date());
}

function normalizeTimestampValue(value) {
  // Keep project-visible timestamps consistent. Accept historical
  // UTC/local ISO strings and store local ISO 8601 with a two-space separator.
  if (value === null || value === undefined || value === '') return null;
  return String(value).trim().replace(isoTimestampPattern, (match) => {
    const parsed = parseProjectTimestamp(match);
    return parsed ? formatProjectTimestamp(parsed) : match.replace(/(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})/g, '$1  ');
  });
}

function normalizeJsonTimestamps(value) {
  if (typeof value === 'string') return normalizeTimestampValue(value);
  if (Array.isArray(value)) return value.map((item) => normalizeJsonTimestamps(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeJsonTimestamps(item)]));
  }
  return value;
}

function jsonText(value) {
  return JSON.stringify(normalizeJsonTimestamps(value ?? null));
}

function writeJsonAtomic(filePath, payload) {
  // The dashboard polls this file directly, so write atomically to avoid
  // partially-read JSON while alert-store is updating the beacon.
  const directory = path.dirname(filePath);
  const tmpPath = path.join(directory, `.${path.basename(filePath)}.${process.pid}.tmp`);
  fs.mkdirSync(directory, {recursive: true});
  fs.writeFileSync(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  fs.renameSync(tmpPath, filePath);
}

function n8nBeaconHistoryPaths() {
  const paths = new Set(beaconHistoryPaths);
  for (const filePath of beaconPaths) {
    paths.add(path.join(path.dirname(filePath), 'n8n-beacon-history.json'));
  }
  return [...paths];
}

function boundedPcapWorkflowState(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const finiteNumber = (value) => {
    if (value === null || value === undefined || value === '') return null;
    return Number.isFinite(Number(value)) ? Number(value) : null;
  };
  return {
    state: String(raw.state || 'unknown').slice(0, 64),
    deferred: Boolean(raw.deferred),
    reason: String(raw.reason || '').slice(0, 300),
    metric: String(raw.metric || '').slice(0, 64),
    observed_percent: finiteNumber(raw.observed_percent),
    threshold_percent: finiteNumber(raw.threshold_percent),
    telemetry_age_seconds: finiteNumber(raw.telemetry_age_seconds),
    processed: nonNegativeIntegerField(raw.processed) || 0,
    operational_failures: nonNegativeIntegerField(raw.operational_failures) || 0,
  };
}

function writePcapWorkflowState(payload) {
  // Keep one latest-state file per beacon output directory. This avoids relying
  // on the bounded general beacon history during alert bursts while retaining
  // atomic local-only state with no credentials or packet evidence.
  const state = boundedPcapWorkflowState(payload?.pcap_workflow);
  if (payload?.component !== 'pcap_broker' || !state) return;
  const paths = new Set();
  for (const filePath of beaconPaths) {
    paths.add(path.join(path.dirname(filePath), 'pcap-workflow-state.json'));
  }
  for (const filePath of paths) {
    try {
      writeJsonAtomic(filePath, {
        generated_at: payload.generated_at,
        component: 'pcap_broker',
        relay_host: payload.relay_host ? String(payload.relay_host).slice(0, 128) : null,
        pcap_workflow: state,
      });
    } catch (writeError) {
      console.error(`Unable to write PCAP workflow state ${filePath}: ${writeError.message}`);
    }
  }
}

function appendN8nBeaconHistory(payload) {
  const generatedAt = parseProjectTimestamp(payload?.generated_at);
  const cutoff = Date.now() - (72 * 60 * 60 * 1000);
  const entry = {
    ...payload,
    history_recorded_at: nowUtc(),
  };
  for (const filePath of n8nBeaconHistoryPaths()) {
    try {
      let history = [];
      try {
        const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8') || '[]');
        history = Array.isArray(parsed) ? parsed : [];
      } catch (_) {
        history = [];
      }
      history = history
        .filter((item) => {
          const itemDate = parseProjectTimestamp(item?.generated_at || item?.history_recorded_at);
          return itemDate && itemDate.getTime() >= cutoff;
        })
        .slice(-1000);
      if (generatedAt || entry.history_recorded_at) {
        history.push(entry);
      }
      writeJsonAtomic(filePath, history);
    } catch (writeError) {
      console.error(`Unable to write n8n beacon history ${filePath}: ${writeError.message}`);
    }
  }
}

function writeN8nBeacon(stage, alert = {}, result = null, error = null) {
  const payload = {
    generated_at: nowUtc(),
    stage,
    ok: result ? Boolean(result.ok) : !error,
    status: result?.status || (error ? 'error' : 'received'),
    message_type: alert?.message_type || null,
    source: alert?.source || null,
    relay_host: alert?.relay_host || null,
    exported_at: alert?.exported_at || null,
    alert_count: Number.isFinite(Number(alert?.alert_count)) ? Number(alert.alert_count) : null,
    dropped_alert_count: Number.isFinite(Number(alert?.dropped_alert_count)) ? Number(alert.dropped_alert_count) : null,
    filtered_alert_count: Number.isFinite(Number(alert?.filtered_alert_count)) ? Number(alert.filtered_alert_count) : null,
    new_alert_count: Number.isFinite(Number(alert?.new_alert_count)) ? Number(alert.new_alert_count) : null,
    duplicate_alert_count: Number.isFinite(Number(alert?.duplicate_alert_count)) ? Number(alert.duplicate_alert_count) : null,
    posted_webhook_alerts: Number.isFinite(Number(alert?.posted_webhook_alerts)) ? Number(alert.posted_webhook_alerts) : null,
    alert_id: alert?.alert_id || result?.alert?.alert_id || null,
    rule_name: alert?.rule_name || result?.alert?.rule_name || alert?.first_rule || null,
    source_ip: nestedField(alert, 'source.ip') || result?.alert?.source_ip || null,
    destination_ip: nestedField(alert, 'destination.ip') || result?.alert?.destination_ip || null,
    destination_port: integerField(nestedField(alert, 'destination.port')) || result?.alert?.destination_port || null,
    triage_level: result?.alert?.triage_level || result?.triage?.level || null,
    filter_status: result?.filter?.status || result?.alert?.filter_status || null,
    notification_status: result?.notification?.status || null,
    error: error ? String(error.message || error) : null,
    relay_previous_failure: alert?.relay_previous_failure || null,
    component: alert?.component || null,
    pcap_workflow: boundedPcapWorkflowState(alert?.pcap_workflow),
  };
  for (const filePath of beaconPaths) {
    try {
      writeJsonAtomic(filePath, payload);
    } catch (writeError) {
      console.error(`Unable to write n8n beacon ${filePath}: ${writeError.message}`);
    }
  }
  if (stage !== 'received') {
    writePcapWorkflowState(payload);
    appendN8nBeaconHistory(payload);
  }
  return payload;
}

function isRelayHeartbeat(payload) {
  return ['relay_heartbeat', 'relay_health_recovery'].includes(payload?.message_type);
}

function nestedField(value, dottedPath) {
  // Minimal "source.ip" lookup helper; avoids a JSONPath dependency.
  return dottedPath.split('.').reduce((current, part) => {
    if (!current || typeof current !== 'object') return null;
    return current[part] ?? null;
  }, value);
}

function integerField(value) {
  // Store ports as INTEGER columns for fast filtering/sorting while keeping the
  // original value in alert_json for evidence. Invalid or absent ports stay NULL.
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) return null;
  return parsed;
}

function nonNegativeIntegerField(value) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

function enrichmentRecord(alert) {
  // alert_json remains the complete source of truth. This companion JSON column
  // keeps the investigation/enrichment bundle easy to query without pulling the
  // whole alert object in dashboard or local-AI tooling.
  return {
    message: alert.message ?? null,
    tags: alert.tags ?? [],
    labels: alert.labels ?? {},
    ecs: alert.ecs ?? {},
    agent: alert.agent ?? {},
    log: alert.log ?? {},
    dns: alert.dns ?? {},
    http: alert.http ?? {},
    url: alert.url ?? {},
    tls: alert.tls ?? {},
    file: alert.file ?? {},
    process: alert.process ?? {},
    user: alert.user ?? {},
    related: alert.related ?? {},
    threat: alert.threat ?? {},
    zeek: alert.zeek ?? {},
    suricata: alert.suricata ?? {},
    security_onion: alert.security_onion ?? {},
    external_intel: alert.enrichment?.external_intel ?? {},
  };
}

function secondsToMs(seconds) {
  return Math.max(0, Number(seconds || 0) * 1000);
}

function epochMs(value = new Date()) {
  return value instanceof Date ? value.getTime() : new Date(value).getTime();
}

function isoFromMs(value) {
  return formatProjectTimestamp(new Date(value));
}

function isProbablyPlaceholderSecret(value) {
  if (!value) return true;
  const text = String(value).trim().toLowerCase();
  return !text || text.includes('replace') || text.includes('placeholder') || text.includes('your-') || text.includes('changeme');
}

function isConfiguredSecret(value) {
  return !isProbablyPlaceholderSecret(value);
}

function publicHostname(value) {
  if (!value || typeof value !== 'string') return null;
  const hostname = value.trim().toLowerCase().replace(/\.$/, '');
  if (!hostname || hostname === 'localhost') return null;
  if (!hostname.includes('.')) return null;
  if (/\.local$|\.lan$|\.home$|\.internal$|\.corp$/.test(hostname)) return null;
  if (/^(tls\.sni|h2\.http|suricata\.alert|document\.packet|ds-logs-suricata\.alerts)$/.test(hostname)) return null;
  if (/^\d+\.json$/.test(hostname)) return null;
  if (parseIpv4(hostname)) return isPrivateIpv4(hostname) ? null : hostname;
  return hostname;
}

function redactUrlForPublicLookup(value) {
  if (!value || typeof value !== 'string') return null;
  try {
    const parsed = new URL(value);
    const hostname = publicHostname(parsed.hostname);
    if (!hostname) return null;
    parsed.username = '';
    parsed.password = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return null;
  }
}

function collectStrings(value, results = []) {
  if (typeof value === 'string') {
    results.push(value);
    return results;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectStrings(item, results);
    return results;
  }
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) collectStrings(item, results);
  }
  return results;
}

function collectValuesByKey(value, keyMatcher, results = []) {
  if (Array.isArray(value)) {
    for (const item of value) collectValuesByKey(item, keyMatcher, results);
    return results;
  }
  if (!value || typeof value !== 'object') return results;
  for (const [key, item] of Object.entries(value)) {
    if (keyMatcher(String(key))) results.push(item);
    collectValuesByKey(item, keyMatcher, results);
  }
  return results;
}

function extractUrlsFromText(value) {
  const urls = [];
  for (const text of collectStrings(value)) {
    for (const match of text.match(/\bhttps?:\/\/[^\s<>"'`]+/gi) || []) {
      const cleaned = match.replace(/[),.;\]]+$/, '');
      const redacted = redactUrlForPublicLookup(cleaned);
      if (redacted) urls.push(redacted);
    }
  }
  return urls;
}

function extractIpv4sFromText(value) {
  const ips = [];
  for (const text of collectStrings(value)) {
    for (const match of text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []) {
      if (parseIpv4(match) && !isPrivateIpv4(match)) ips.push(match);
    }
  }
  return ips;
}

function extractDomainsFromText(value) {
  const domains = [];
  for (const text of collectStrings(value)) {
    const normalizedText = text.replace(/\s+\./g, '.').replace(/\.\s+/g, '.');
    for (const match of normalizedText.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi) || []) {
      const normalized = publicHostname(match);
      if (normalized) domains.push(normalized);
    }
  }
  return domains;
}

function domainTextCandidateFields(alert) {
  return [
    alert.message,
    alert.rule_name,
    nestedField(alert, 'rule.name'),
    nestedField(alert, 'event.reason'),
    nestedField(alert, 'suricata.eve.alert.signature'),
    nestedField(alert, 'security_onion.raw_event.alert.signature'),
  ];
}

function domainCandidateFields(alert) {
  return [
    nestedField(alert, 'url.domain'),
    nestedField(alert, 'dns.question.name'),
    nestedField(alert, 'dns.question.registered_domain'),
    nestedField(alert, 'dns.question.top_level_domain'),
    nestedField(alert, 'dns.answers.data'),
    nestedField(alert, 'dns.answers.name'),
    nestedField(alert, 'tls.client.server_name'),
    nestedField(alert, 'tls.server.x509.subject.common_name'),
    nestedField(alert, 'tls.server.x509.issuer.common_name'),
    nestedField(alert, 'http.request.referrer'),
    nestedField(alert, 'http.request.headers.host'),
    nestedField(alert, 'http.response.headers.location'),
    nestedField(alert, 'suricata.eve.dns.rrname'),
    nestedField(alert, 'suricata.eve.dns.query'),
    nestedField(alert, 'suricata.eve.dns.answers.rrname'),
    nestedField(alert, 'suricata.eve.dns.answers.rdata'),
    nestedField(alert, 'suricata.eve.tls.sni'),
    nestedField(alert, 'suricata.eve.http.hostname'),
    nestedField(alert, 'security_onion.raw_event.dns.rrname'),
    nestedField(alert, 'security_onion.raw_event.dns.query'),
    nestedField(alert, 'security_onion.raw_event.dns.answers.rrname'),
    nestedField(alert, 'security_onion.raw_event.dns.answers.rdata'),
    nestedField(alert, 'security_onion.raw_event.tls.sni'),
    nestedField(alert, 'security_onion.raw_event.http.hostname'),
    ...(alert.related?.hosts || []),
    ...extractDomainsFromText(domainTextCandidateFields(alert)),
  ];
}

function urlCandidateFields(alert) {
  return [
    alert.url?.full,
    alert.url?.original,
    nestedField(alert, 'http.request.referrer'),
    nestedField(alert, 'http.response.headers.location'),
    nestedField(alert, 'suricata.eve.http.url'),
    nestedField(alert, 'suricata.eve.http.http_refer'),
    nestedField(alert, 'security_onion.raw_event.url.full'),
    nestedField(alert, 'security_onion.raw_event.url.original'),
    nestedField(alert, 'security_onion.raw_event.http.url'),
    nestedField(alert, 'security_onion.raw_event.http.http_refer'),
  ];
}

function extractCvesFromText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value || {});
  return [...new Set((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map((cve) => cve.toUpperCase()))];
}

function extractHashesFromText(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value || {});
  const hashes = [];
  for (const match of text.match(/\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g) || []) {
    const length = match.length;
    hashes.push({type: length === 32 ? 'md5' : length === 40 ? 'sha1' : 'sha256', value: match.toLowerCase()});
  }
  return [...new Map(hashes.map((item) => [`${item.type}:${item.value}`, item])).values()];
}

function extractAlertIndicators(alert) {
  // Never mine prior enrichment provider responses for new indicators. The
  // enrichment stage should submit only evidence from the original detection,
  // not URLs/IPs/domains found inside third-party API raw_response payloads.
  const evidenceAlert = {...(alert || {})};
  delete evidenceAlert.enrichment;
  const indicators = {
    public_ips: [],
    domains: [],
    urls: [],
    hashes: [],
    cves: [],
  };
  for (const ip of [
    nestedField(alert, 'source.ip'),
    nestedField(alert, 'destination.ip'),
    nestedField(alert, 'client.ip'),
    nestedField(alert, 'server.ip'),
    nestedField(alert, 'host.ip'),
    ...(alert.related?.ip || []),
    ...collectValuesByKey(evidenceAlert, (key) => /(^|_|\.)ip$/i.test(key)),
    ...extractIpv4sFromText(evidenceAlert),
  ]) {
    if (typeof ip === 'string' && parseIpv4(ip) && !isPrivateIpv4(ip)) indicators.public_ips.push(ip);
    if (Array.isArray(ip)) {
      for (const item of ip) {
        if (typeof item === 'string' && parseIpv4(item) && !isPrivateIpv4(item)) indicators.public_ips.push(item);
      }
    }
  }
  for (const hostname of domainCandidateFields(evidenceAlert)) {
    const values = Array.isArray(hostname) ? hostname : [hostname];
    for (const value of values) {
      const normalized = publicHostname(value);
      if (normalized) indicators.domains.push(normalized);
    }
  }
  for (const candidate of urlCandidateFields(evidenceAlert)) {
    const values = Array.isArray(candidate) ? candidate : [candidate];
    for (const value of values) {
      const redacted = redactUrlForPublicLookup(value);
      if (redacted) indicators.urls.push(redacted);
      try {
        const parsed = new URL(String(value));
        const hostname = publicHostname(parsed.hostname);
        if (hostname) indicators.domains.push(hostname);
      } catch {
        // Non-URL strings are handled by the domain field extraction above.
      }
    }
  }
  indicators.hashes = extractHashesFromText(evidenceAlert);
  indicators.cves = extractCvesFromText(evidenceAlert);
  for (const key of Object.keys(indicators)) {
    indicators[key] = [...new Set(indicators[key].map((item) => typeof item === 'string' ? item : JSON.stringify(item)))]
      .map((item) => {
        try { return item.startsWith('{') ? JSON.parse(item) : item; } catch { return item; }
      });
  }
  return indicators;
}

function hasUsableExternalIntel(alert) {
  const externalIntel = alert?.enrichment?.external_intel;
  if (!externalIntel || typeof externalIntel !== 'object') return false;
  return (
    Array.isArray(externalIntel.records) && externalIntel.records.length > 0
  ) || (
    Array.isArray(externalIntel.skipped) && externalIntel.skipped.length > 0
  ) || (
    Array.isArray(externalIntel.errors) && externalIntel.errors.length > 0
  );
}

function requestJson(options) {
  return boundedRequestJson({
    timeoutMs: enrichmentTimeoutMs,
    maxResponseBytes: httpJsonMaxResponseBytes,
    ...options,
  });
}

function providerErrorDetail(body) {
  if (!body || typeof body !== 'object') return '';
  const errors = Array.isArray(body.errors)
    ? body.errors.map((item) => safeString(item?.message || item, 160)).filter(Boolean)
    : [];
  return safeString(errors.join('; ') || body.detail || body.message || body.error, 240);
}

function normalizedEnrichmentRecord(source, indicator, indicatorType, verdict, confidence, tags, rawResponse, firstSeen = null, lastSeen = null) {
  return {
    source,
    indicator,
    indicator_type: indicatorType,
    verdict,
    confidence,
    tags: Array.isArray(tags) ? tags.filter(Boolean).slice(0, 20) : [],
    first_seen: normalizeTimestampValue(firstSeen),
    last_seen: normalizeTimestampValue(lastSeen),
    raw_response: rawResponse ?? null,
    cached_at: nowUtc(),
  };
}

function notFoundEnrichmentRecord(source, indicator, indicatorType, rawResponse) {
  // A provider having no record is absence of evidence, not evidence that an
  // indicator is benign. Cache this normalized negative result to avoid quota
  // churn while preserving an honest unknown verdict for analysts and models.
  return normalizedEnrichmentRecord(
    source,
    indicator,
    indicatorType,
    'unknown',
    0,
    ['not_found'],
    rawResponse || {status: 'not_found'},
  );
}

function verdictFromStats(stats = {}) {
  const malicious = Number(stats.malicious || 0);
  const suspicious = Number(stats.suspicious || 0);
  const harmless = Number(stats.harmless || 0);
  if (malicious > 0) return {verdict: 'malicious', confidence: Math.min(100, 70 + malicious * 5)};
  if (suspicious > 0) return {verdict: 'suspicious', confidence: Math.min(95, 50 + suspicious * 10)};
  if (harmless > 0) return {verdict: 'benign', confidence: 60};
  return {verdict: 'unknown', confidence: 0};
}

function sourceLimitNote(source) {
  const notes = {
    abuseipdb: 'Free AbuseIPDB accounts are commonly limited to 1,000 checks/day.',
    greynoise: 'GreyNoise Community lookups are low-volume; cache aggressively.',
    shodan_internetdb: 'Shodan InternetDB is keyless, free for non-commercial use, and updated weekly.',
    otx: 'OTX authenticated API limits depend on account tier; 429 responses are cached as skips.',
    urlhaus: 'URLhaus community API uses an abuse.ch Auth-Key and fair-use expectations.',
    virustotal: 'VirusTotal Public API is throttled here to 4 requests/minute and used only for high/critical by default.',
    urlscan: 'urlscan.io quotas vary by account and action; URL submissions are disabled unless explicitly enabled.',
    google_safe_browsing: 'Google Safe Browsing uses API-key quota; public URLs are redacted before lookup.',
    phishtank: 'PhishTank publishes rate-limit headers and returns over-limit responses when exceeded.',
    malwarebazaar: 'MalwareBazaar hash lookups use an abuse.ch Auth-Key; file downloads are not performed.',
    threatfox: 'ThreatFox IOC lookups use an abuse.ch Auth-Key.',
    shodan: 'Shodan host API uses account quota; InternetDB runs separately without a key.',
    censys: 'Censys API quotas depend on account tier; IP lookups are throttled conservatively.',
    cisa_kev: 'CISA KEV is a public JSON catalog and is cached longer than alert IOC lookups.',
    epss: 'FIRST EPSS CVE lookups are public and cached longer than alert IOC lookups.',
    nvd: 'NVD allows 5 requests/30s without a key or 50 requests/30s with a key; this workflow throttles more conservatively.',
  };
  return notes[source] || null;
}

function sourceConfigured(source) {
  switch (source) {
    case 'abuseipdb': return isConfiguredSecret(enrichmentSecrets.abuseipdb);
    case 'greynoise': return isConfiguredSecret(enrichmentSecrets.greynoise);
    case 'otx': return isConfiguredSecret(enrichmentSecrets.otx);
    case 'urlhaus': return isConfiguredSecret(enrichmentSecrets.urlhaus);
    case 'virustotal': return isConfiguredSecret(enrichmentSecrets.virustotal);
    case 'urlscan': return isConfiguredSecret(enrichmentSecrets.urlscan);
    case 'google_safe_browsing': return isConfiguredSecret(enrichmentSecrets.googleSafeBrowsing);
    case 'phishtank': return isConfiguredSecret(enrichmentSecrets.phishtank);
    case 'malwarebazaar': return isConfiguredSecret(enrichmentSecrets.malwarebazaar);
    case 'threatfox': return isConfiguredSecret(enrichmentSecrets.threatfox);
    case 'shodan': return isConfiguredSecret(enrichmentSecrets.shodan);
    case 'censys':
      return isConfiguredSecret(enrichmentSecrets.censysToken) ||
        (isConfiguredSecret(enrichmentSecrets.censysId) && isConfiguredSecret(enrichmentSecrets.censysSecret));
    case 'shodan_internetdb':
    case 'cisa_kev':
    case 'epss':
    case 'nvd':
      return true;
    default:
      return false;
  }
}

function sourceRateLimitMs(source) {
  const limits = {
    abuseipdb: 1000,
    greynoise: 2000,
    shodan_internetdb: 1000,
    otx: 500,
    urlhaus: 1000,
    virustotal: 15000,
    urlscan: 2000,
    google_safe_browsing: 1000,
    phishtank: 2000,
    malwarebazaar: 1000,
    threatfox: 1000,
    shodan: 1200,
    censys: 2500,
    cisa_kev: 60000,
    epss: 3000,
    nvd: isConfiguredSecret(enrichmentSecrets.nvd) ? 1000 : 7000,
  };
  return limits[source] || 1000;
}

function sourceTtlSeconds(source) {
  const normalizedSource = String(source || '').trim().toLowerCase();
  const sourceOverride = Number(
    process.env[`ENRICHMENT_CACHE_${normalizedSource.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TTL_SECONDS`],
  );
  if (Number.isFinite(sourceOverride) && sourceOverride >= 300) return Math.floor(sourceOverride);
  if (['cisa_kev', 'epss', 'nvd'].includes(normalizedSource)) {
    return Math.max(300, vulnerabilityCacheDefaultTtlSeconds);
  }
  return Math.max(300, enrichmentSourceTtlDefaults[normalizedSource] || enrichmentCacheDefaultTtlSeconds);
}

function sourceStaleIfErrorSeconds(source) {
  return ['cisa_kev', 'epss', 'nvd'].includes(String(source || '').toLowerCase())
    ? enrichmentVulnerabilityStaleIfErrorSeconds
    : enrichmentStaleIfErrorSeconds;
}

async function reserveProviderRateLimitSlot(source) {
  const minimumMs = sourceRateLimitMs(source);
  return withSqliteWriteGate(() => withImmediateTransaction(async () => {
    const row = await get('SELECT last_request_at FROM enrichment_rate_limit WHERE source = ?', [source]);
    const currentMs = epochMs();
    const parsedLastMs = row?.last_request_at
      ? epochMs(String(row.last_request_at).replace('  ', 'T'))
      : Number.NaN;

    // Persist the reservation before releasing the gate. Different providers
    // may run concurrently, but no cache/rate-limit statement can become part
    // of an unrelated alert-ingest transaction on this shared connection.
    // Implausibly future timestamps are ignored so clock corrections cannot
    // stall enrichment indefinitely.
    const maximumCredibleFutureMs = currentMs + Math.max(60000, minimumMs * 4);
    const lastMs = Number.isFinite(parsedLastMs) && parsedLastMs <= maximumCredibleFutureMs
      ? parsedLastMs
      : currentMs - minimumMs;
    const reservedMs = Math.max(currentMs, lastMs + minimumMs);
    await run(
      'INSERT INTO enrichment_rate_limit (source, last_request_at) VALUES (?, ?) ON CONFLICT(source) DO UPDATE SET last_request_at = excluded.last_request_at',
      [source, isoFromMs(reservedMs).replace('T', '  ')],
    );
    return Math.max(0, reservedMs - currentMs);
  }));
}

async function cachedLookup(source, indicatorType, indicator, lookup) {
  const ttlSeconds = sourceTtlSeconds(source);
  return enrichmentCache.lookup({
    source,
    indicatorType,
    indicator,
    ttlSeconds,
    negativeTtlSeconds: Math.min(ttlSeconds, enrichmentNegativeCacheTtlSeconds),
    staleIfErrorSeconds: sourceStaleIfErrorSeconds(source),
    loader: () => enrichmentScheduler.run(source, async () => {
      const waitMs = await reserveProviderRateLimitSlot(source);
      if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
      return lookup();
    }),
  });
}

async function lookupAbuseIpdb(ip) {
  const response = await requestJson({
    url: `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
    headers: {Key: enrichmentSecrets.abuseipdb},
  });
  const data = response.body?.data || {};
  const score = Number(data.abuseConfidenceScore || 0);
  const verdict = score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : score > 0 ? 'unknown' : 'benign';
  return normalizedEnrichmentRecord('abuseipdb', ip, 'ip', verdict, score, [data.usageType, data.isp, data.countryCode], response.body, null, data.lastReportedAt || null);
}

async function lookupGreynoise(ip) {
  const response = await requestJson({
    url: `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
    headers: {'key': enrichmentSecrets.greynoise},
    allowedStatusCodes: [404],
  });
  if (response.statusCode === 404) return notFoundEnrichmentRecord('greynoise', ip, 'ip', response.body);
  const body = response.body || {};
  const classification = String(body.classification || '').toLowerCase();
  const verdict = classification === 'malicious' ? 'malicious' : classification === 'benign' ? 'noise/scanner' : body.noise ? 'noise/scanner' : 'unknown';
  return normalizedEnrichmentRecord('greynoise', ip, 'ip', verdict, body.noise ? 80 : 30, [body.classification, body.name, body.link ? 'greynoise-link' : null], body, null, body.last_seen || null);
}

async function lookupShodanInternetDb(ip) {
  const response = await requestJson({
    url: `https://internetdb.shodan.io/${encodeURIComponent(ip)}`,
    allowedStatusCodes: [404],
  });
  const body = response.statusCode === 404 ? {status: 'not_found'} : response.body || {};
  if (response.statusCode === 404) return notFoundEnrichmentRecord('shodan_internetdb', ip, 'ip', body);
  const cves = Array.isArray(body.vulns) ? body.vulns : Object.keys(body.vulns || {});
  const verdict = cves.length ? 'suspicious' : Array.isArray(body.ports) && body.ports.length ? 'unknown' : 'benign';
  return normalizedEnrichmentRecord('shodan_internetdb', ip, 'ip', verdict, cves.length ? 65 : 30, [...(body.tags || []), ...cves.slice(0, 5)], body);
}

async function lookupOtx(indicatorType, indicator) {
  const typeMap = {ip: 'IPv4', domain: 'domain', url: 'url', hash: 'file'};
  const otxType = typeMap[indicatorType];
  const response = await requestJson({
    url: `https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(indicator)}/general`,
    headers: {'X-OTX-API-KEY': enrichmentSecrets.otx},
    allowedStatusCodes: [404],
  });
  if (response.statusCode === 404) return notFoundEnrichmentRecord('otx', indicator, indicatorType, response.body);
  const pulses = response.body?.pulse_info?.count || 0;
  const verdict = pulses > 0 ? 'suspicious' : 'unknown';
  return normalizedEnrichmentRecord('otx', indicator, indicatorType, verdict, pulses > 0 ? 55 : 0, [`pulses:${pulses}`], response.body);
}

async function lookupUrlhaus(urlValue) {
  const body = `url=${encodeURIComponent(urlValue)}`;
  const response = await requestJson({
    method: 'POST',
    url: 'https://urlhaus-api.abuse.ch/v1/url/',
    headers: {'Auth-Key': enrichmentSecrets.urlhaus, 'Content-Type': 'application/x-www-form-urlencoded'},
    body,
  });
  const queryStatus = response.body?.query_status;
  const verdict = queryStatus === 'ok' ? 'malicious' : 'unknown';
  return normalizedEnrichmentRecord('urlhaus', urlValue, 'url', verdict, queryStatus === 'ok' ? 85 : 0, [response.body?.threat, response.body?.url_status], response.body, response.body?.date_added || null, response.body?.last_online || null);
}

async function lookupVirusTotal(indicatorType, indicator) {
  const pathMap = {
    ip: `ip_addresses/${encodeURIComponent(indicator)}`,
    domain: `domains/${encodeURIComponent(indicator)}`,
    hash: `files/${encodeURIComponent(indicator)}`,
    url: `urls/${Buffer.from(indicator).toString('base64url')}`,
  };
  const response = await requestJson({
    url: `https://www.virustotal.com/api/v3/${pathMap[indicatorType]}`,
    headers: {'x-apikey': enrichmentSecrets.virustotal},
    allowedStatusCodes: [404],
  });
  if (response.statusCode === 404) return notFoundEnrichmentRecord('virustotal', indicator, indicatorType, response.body);
  const attrs = response.body?.data?.attributes || {};
  const stats = attrs.last_analysis_stats || attrs.last_http_response_content_sha256 ? attrs.last_analysis_stats : {};
  const verdict = verdictFromStats(stats);
  return normalizedEnrichmentRecord('virustotal', indicator, indicatorType, verdict.verdict, verdict.confidence, Object.keys(stats).map((key) => `${key}:${stats[key]}`), response.body, null, attrs.last_analysis_date ? isoFromMs(Number(attrs.last_analysis_date) * 1000) : null);
}

async function lookupUrlscan(indicatorType, indicator) {
  const query = indicatorType === 'domain' ? `domain:${indicator}` : indicator;
  const response = await requestJson({
    url: `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}&size=10`,
    headers: {'API-Key': enrichmentSecrets.urlscan},
  });
  const results = response.body?.results || [];
  const malicious = results.some((item) => item.verdicts?.overall?.malicious || item.verdicts?.engines?.malicious);
  return normalizedEnrichmentRecord('urlscan', indicator, indicatorType, malicious ? 'malicious' : results.length ? 'unknown' : 'unknown', malicious ? 75 : 15, [`results:${results.length}`], response.body);
}

async function lookupGoogleSafeBrowsing(urlValue) {
  const response = await requestJson({
    method: 'POST',
    url: `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(enrichmentSecrets.googleSafeBrowsing)}`,
    body: {
      client: {clientId: 'onion-sentinel', clientVersion: '1.0'},
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{url: urlValue}],
      },
    },
  });
  const matches = response.body?.matches || [];
  return normalizedEnrichmentRecord('google_safe_browsing', urlValue, 'url', matches.length ? 'malicious' : 'benign', matches.length ? 90 : 65, matches.map((item) => item.threatType), response.body);
}

async function lookupPhishTank(urlValue) {
  const body = `url=${encodeURIComponent(urlValue)}&format=json&app_key=${encodeURIComponent(enrichmentSecrets.phishtank)}`;
  const response = await requestJson({
    method: 'POST',
    url: 'https://checkurl.phishtank.com/checkurl/',
    headers: {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'OnionSentinel/1.0'},
    body,
  });
  const result = response.body?.results || {};
  const phishing = Boolean(result.in_database && result.valid);
  return normalizedEnrichmentRecord('phishtank', urlValue, 'url', phishing ? 'malicious' : 'unknown', phishing ? 85 : 0, [result.verified ? 'verified' : null], response.body);
}

async function lookupMalwareBazaar(hash) {
  const body = `query=get_info&hash=${encodeURIComponent(hash)}`;
  const response = await requestJson({
    method: 'POST',
    url: 'https://mb-api.abuse.ch/api/v1/',
    headers: {'Auth-Key': enrichmentSecrets.malwarebazaar, 'Content-Type': 'application/x-www-form-urlencoded'},
    body,
  });
  const found = response.body?.query_status === 'ok';
  const first = Array.isArray(response.body?.data) ? response.body.data[0] : {};
  return normalizedEnrichmentRecord('malwarebazaar', hash, 'hash', found ? 'malicious' : 'unknown', found ? 85 : 0, [first?.signature, first?.file_type, first?.tags?.slice?.(0, 5)?.join(',')], response.body, first?.first_seen || null, first?.last_seen || null);
}

async function lookupThreatFox(indicatorType, indicator) {
  const response = await requestJson({
    method: 'POST',
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    headers: {'Auth-Key': enrichmentSecrets.threatfox},
    body: {query: 'search_ioc', search_term: indicator},
  });
  const found = response.body?.query_status === 'ok';
  const first = Array.isArray(response.body?.data) ? response.body.data[0] : {};
  return normalizedEnrichmentRecord('threatfox', indicator, indicatorType, found ? 'malicious' : 'unknown', found ? 80 : 0, [first?.malware, first?.ioc_type, first?.threat_type], response.body, first?.first_seen || null, first?.last_seen || null);
}

async function lookupShodan(ip) {
  const response = await requestJson({
    url: `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(enrichmentSecrets.shodan)}`,
    allowedStatusCodes: [404],
  });
  if (response.statusCode === 404) return notFoundEnrichmentRecord('shodan', ip, 'ip', response.body);
  const body = response.body || {};
  const vulns = Array.isArray(body.vulns) ? body.vulns : Object.keys(body.vulns || {});
  return normalizedEnrichmentRecord('shodan', ip, 'ip', vulns.length ? 'suspicious' : 'unknown', vulns.length ? 70 : 25, [...(body.tags || []), ...vulns.slice(0, 5)], body, null, body.last_update || null);
}

async function lookupCensys(ip) {
  if (isConfiguredSecret(enrichmentSecrets.censysToken)) {
    const headers = {
      Authorization: `Bearer ${enrichmentSecrets.censysToken}`,
      Accept: 'application/vnd.censys.api.v3.host.v1+json',
    };
    if (isConfiguredSecret(enrichmentSecrets.censysOrganizationId)) {
      headers['X-Organization-ID'] = enrichmentSecrets.censysOrganizationId;
    }
    const response = await requestJson({
      url: `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(ip)}`,
      headers,
      allowedStatusCodes: [404],
    });
    if (response.statusCode === 404) return notFoundEnrichmentRecord('censys', ip, 'ip', response.body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      const detail = providerErrorDetail(response.body);
      throw new Error(`Censys Platform API returned HTTP ${response.statusCode}${detail ? `: ${detail}` : ''}`);
    }
    const body = response.body || {};
    const services = body.result?.services || body.resource?.services || body.host?.services || [];
    const tags = services.map((service) => service.service_name || service.port || service.transport_protocol).filter(Boolean).slice(0, 10);
    return normalizedEnrichmentRecord('censys', ip, 'ip', 'unknown', services.length ? 35 : 0, tags, body);
  }
  const auth = Buffer.from(`${enrichmentSecrets.censysId}:${enrichmentSecrets.censysSecret}`).toString('base64');
  const headers = {Authorization: `Basic ${auth}`};
  const response = await requestJson({
    url: `https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`,
    headers,
    allowedStatusCodes: [404],
  });
  if (response.statusCode === 404) return notFoundEnrichmentRecord('censys', ip, 'ip', response.body);
  if (response.statusCode < 200 || response.statusCode >= 300) {
    const detail = providerErrorDetail(response.body);
    throw new Error(`Censys Search API returned HTTP ${response.statusCode}${detail ? `: ${detail}` : ''}`);
  }
  const body = response.body || {};
  const services = body.result?.services || [];
  const tags = services.map((service) => service.service_name).filter(Boolean).slice(0, 10);
  return normalizedEnrichmentRecord('censys', ip, 'ip', 'unknown', services.length ? 35 : 0, tags, body);
}

async function lookupCisaKev(cve) {
  const response = await requestJson({url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'});
  const vuln = (response.body?.vulnerabilities || []).find((item) => String(item.cveID || '').toUpperCase() === cve);
  return normalizedEnrichmentRecord('cisa_kev', cve, 'cve', vuln ? 'malicious' : 'unknown', vuln ? 90 : 0, [vuln?.vendorProject, vuln?.product, vuln?.knownRansomwareCampaignUse], vuln || {found: false});
}

async function lookupEpss(cve) {
  const response = await requestJson({url: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`});
  const item = Array.isArray(response.body?.data) ? response.body.data[0] : null;
  const epss = Number(item?.epss || 0);
  return normalizedEnrichmentRecord('epss', cve, 'cve', epss >= 0.7 ? 'suspicious' : 'unknown', Math.round(epss * 100), [`percentile:${item?.percentile || 'n/a'}`], response.body);
}

async function lookupNvd(cve) {
  const headers = isConfiguredSecret(enrichmentSecrets.nvd) ? {apiKey: enrichmentSecrets.nvd} : {};
  const response = await requestJson({url: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cve)}`, headers});
  const vuln = Array.isArray(response.body?.vulnerabilities) ? response.body.vulnerabilities[0]?.cve : null;
  const metrics = vuln?.metrics || {};
  const score = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore || metrics.cvssMetricV30?.[0]?.cvssData?.baseScore || metrics.cvssMetricV2?.[0]?.cvssData?.baseScore || 0;
  return normalizedEnrichmentRecord('nvd', cve, 'cve', Number(score) >= 9 ? 'suspicious' : 'unknown', Math.round(Number(score) * 10), [`cvss:${score || 'n/a'}`], response.body, vuln?.published || null, vuln?.lastModified || null);
}

function shouldUseVirusTotal(alert) {
  const level = String(alert.triage?.level || alert.severity_label || '').toLowerCase();
  return (severityRank[level] ?? 0) >= (severityRank[virustotalMinimumLevel] ?? severityRank.high);
}

async function runEnrichmentLookup(source, indicatorType, indicator, lookup, summary) {
  if (!sourceConfigured(source)) {
    summary.skipped.push({source, indicator, indicator_type: indicatorType, reason: 'missing_api_key', limit_note: sourceLimitNote(source)});
    return;
  }
  try {
    const result = await cachedLookup(source, indicatorType, indicator, lookup);
    summary.records.push(result.record);
    summary.sources[source] = {
      status: result.cache_state === 'stale' ? 'stale_cache' : result.cached ? 'cached' : 'queried',
      cache_state: result.cache_state,
      limit_note: sourceLimitNote(source),
    };
    if (result.fallback_error) {
      summary.warnings.push({
        source,
        indicator,
        indicator_type: indicatorType,
        reason: 'provider_refresh_failed_stale_cache_used',
        detail: result.fallback_error,
      });
    }
  } catch (error) {
    summary.errors.push({source, indicator, indicator_type: indicatorType, reason: error.message, limit_note: sourceLimitNote(source)});
  }
}

async function enrichAlert(alert) {
  if (!alert || typeof alert !== 'object' || isRelayHeartbeat(alert)) {
    return {
      ok: true,
      status: isRelayHeartbeat(alert) ? 'heartbeat_skipped' : 'invalid_skipped',
      alert,
      enrichment: {records: [], skipped: [], errors: [], indicators: {}, sources: {}},
    };
  }
  const indicators = extractAlertIndicators(alert);
  const summary = {
    generated_at: nowUtc(),
    cache_ttl_seconds: enrichmentCacheDefaultTtlSeconds,
    vulnerability_cache_ttl_seconds: vulnerabilityCacheDefaultTtlSeconds,
    indicators,
    sources: {},
    records: [],
    skipped: [],
    warnings: [],
    errors: [],
    privacy: {
      submitted_private_ips: false,
      submitted_internal_urls: false,
      url_query_strings_redacted: true,
      urlscan_submit_enabled: urlscanSubmitEnabled,
    },
  };

  const jobs = [];
  const schedule = (source, indicatorType, indicator, lookup) => {
    jobs.push(runEnrichmentLookup(source, indicatorType, indicator, lookup, summary));
  };

  for (const ip of indicators.public_ips.slice(0, 4)) {
    schedule('abuseipdb', 'ip', ip, () => lookupAbuseIpdb(ip));
    schedule('greynoise', 'ip', ip, () => lookupGreynoise(ip));
    schedule('shodan_internetdb', 'ip', ip, () => lookupShodanInternetDb(ip));
    schedule('otx', 'ip', ip, () => lookupOtx('ip', ip));
    schedule('shodan', 'ip', ip, () => lookupShodan(ip));
    schedule('censys', 'ip', ip, () => lookupCensys(ip));
  }

  for (const domain of indicators.domains.slice(0, 4)) {
    schedule('otx', 'domain', domain, () => lookupOtx('domain', domain));
    schedule('urlscan', 'domain', domain, () => lookupUrlscan('domain', domain));
    schedule('threatfox', 'domain', domain, () => lookupThreatFox('domain', domain));
    if (shouldUseVirusTotal(alert)) {
      schedule('virustotal', 'domain', domain, () => lookupVirusTotal('domain', domain));
    } else {
      summary.skipped.push({source: 'virustotal', indicator: domain, indicator_type: 'domain', reason: `below_${virustotalMinimumLevel}_severity`, limit_note: sourceLimitNote('virustotal')});
    }
  }

  for (const urlValue of indicators.urls.slice(0, 3)) {
    schedule('urlhaus', 'url', urlValue, () => lookupUrlhaus(urlValue));
    schedule('urlscan', 'url', urlValue, () => lookupUrlscan('url', urlValue));
    schedule('google_safe_browsing', 'url', urlValue, () => lookupGoogleSafeBrowsing(urlValue));
    schedule('phishtank', 'url', urlValue, () => lookupPhishTank(urlValue));
    schedule('otx', 'url', urlValue, () => lookupOtx('url', urlValue));
    if (shouldUseVirusTotal(alert)) {
      schedule('virustotal', 'url', urlValue, () => lookupVirusTotal('url', urlValue));
    } else {
      summary.skipped.push({source: 'virustotal', indicator: urlValue, indicator_type: 'url', reason: `below_${virustotalMinimumLevel}_severity`, limit_note: sourceLimitNote('virustotal')});
    }
  }

  for (const hash of indicators.hashes.slice(0, 4)) {
    schedule('malwarebazaar', 'hash', hash.value, () => lookupMalwareBazaar(hash.value));
    schedule('otx', 'hash', hash.value, () => lookupOtx('hash', hash.value));
    schedule('threatfox', 'hash', hash.value, () => lookupThreatFox('hash', hash.value));
    if (shouldUseVirusTotal(alert)) {
      schedule('virustotal', 'hash', hash.value, () => lookupVirusTotal('hash', hash.value));
    } else {
      summary.skipped.push({source: 'virustotal', indicator: hash.value, indicator_type: 'hash', reason: `below_${virustotalMinimumLevel}_severity`, limit_note: sourceLimitNote('virustotal')});
    }
  }

  for (const cve of indicators.cves.slice(0, 6)) {
    schedule('cisa_kev', 'cve', cve, () => lookupCisaKev(cve));
    schedule('epss', 'cve', cve, () => lookupEpss(cve));
    schedule('nvd', 'cve', cve, () => lookupNvd(cve));
  }

  await Promise.all(jobs);
  const stableOrder = (left, right) => (
    `${left.source}|${left.indicator_type}|${left.indicator}`
      .localeCompare(`${right.source}|${right.indicator_type}|${right.indicator}`)
  );
  summary.records.sort(stableOrder);
  summary.skipped.sort(stableOrder);
  summary.errors.sort(stableOrder);

  const enrichedAlert = {
    ...alert,
    enrichment: {
      ...(alert.enrichment || {}),
      external_intel: {
        ...summary,
        verdict_counts: summary.records.reduce((counts, record) => {
          counts[record.verdict] = (counts[record.verdict] || 0) + 1;
          return counts;
        }, {}),
      },
    },
  };
  return {ok: true, status: 'enriched', alert: enrichedAlert, enrichment: enrichedAlert.enrichment.external_intel};
}

function parseIpv4(ip) {
  // The relay VLAN is IPv4-only for this project; IPv6 is blocked upstream.
  if (typeof ip !== 'string') return null;
  const parts = ip.split('.').map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts;
}

function isPrivateIpv4(ip) {
  const parts = parseIpv4(ip);
  if (!parts) return false;
  const [a, b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a === 127;
}

function isInfrastructureIp(ip) {
  return scoringRules.infrastructure_ips.includes(ip);
}

function trafficDirection(sourceIp, destinationIp) {
  // Direction is inferred from public/private addressing. It is explainable and
  // deterministic, but not a full topology model.
  const srcPrivate = isPrivateIpv4(sourceIp);
  const dstPrivate = isPrivateIpv4(destinationIp);
  if (srcPrivate && dstPrivate) return 'internal';
  if (!srcPrivate && dstPrivate) return 'inbound';
  if (srcPrivate && !dstPrivate) return 'outbound';
  if (!srcPrivate && !dstPrivate && sourceIp && destinationIp) return 'external';
  return 'unknown';
}

function severityBase(alert) {
  // Security Onion may provide severity as a label, a number, or both.
  const base = scoringRules.severity_base;
  const label = String(alert.severity_label || '').toLowerCase();
  const severity = Number(alert.severity);
  if (label.includes('critical')) return base.critical;
  if (label.includes('high')) return base.high;
  if (label.includes('medium')) return base.medium;
  if (label.includes('low')) return base.low;
  if (Number.isFinite(severity)) {
    if (severity >= 4) return base.numeric_4_or_more;
    if (severity === 3) return base.numeric_3;
    if (severity === 2) return base.numeric_2;
    if (severity === 1) return base.numeric_1;
  }
  return base.default;
}

function alertText(alert) {
  // Keyword scoring uses rule fields only, not raw packet payloads.
  return [
    alert.rule_name,
    alert.rule_category,
    alert.rule_ruleset,
    JSON.stringify(alert.rule_metadata || {}),
  ].join(' ').toLowerCase();
}

function matchesText(text, keywords = []) {
  return keywords.some((keyword) => text.includes(String(keyword).toLowerCase()));
}

function matchesAdjustment(adjustment, alert, text) {
  // All fields specified by a tuning adjustment must match.
  const sourceIp = nestedField(alert, 'source.ip');
  const destinationIp = nestedField(alert, 'destination.ip');
  if (adjustment.source_ip && adjustment.source_ip !== sourceIp) return false;
  if (adjustment.destination_ip && adjustment.destination_ip !== destinationIp) return false;
  if (adjustment.rule_contains && !String(alert.rule_name || '').toLowerCase().includes(String(adjustment.rule_contains).toLowerCase())) return false;
  if (adjustment.keywords && !matchesText(text, adjustment.keywords)) return false;
  return true;
}

function ruleName(rule) {
  return rule.name || rule.reason || rule.rule_contains || 'unnamed policy rule';
}

function findDropRule(alert) {
  // Hard drops are for explicit, known-noise events that should not generate
  // reports or notifications. Raw Pi batches still preserve source evidence.
  const text = alertText(alert);
  const dropRules = [
    ...(scoringRules.drop_rules || []),
    ...((scoringRules.filter_rules && scoringRules.filter_rules.drop_alerts) || []),
  ];
  return dropRules.find((rule) => matchesAdjustment(rule, alert, text)) || null;
}

function levelAllowed(rule, level) {
  const levels = rule.levels || rule.triage_levels;
  if (!levels || !levels.length) return true;
  return levels.map((item) => String(item).toLowerCase()).includes(String(level || '').toLowerCase());
}

function policyKeyPart(alert, field) {
  if (field === 'rule_name') return alert.rule_name || 'unknown-rule';
  if (field === 'triage.level') return nestedField(alert, 'triage.level') || 'unknown-level';
  return nestedField(alert, field) || `unknown-${field}`;
}

function suppressionKey(rule, alert) {
  const fields = rule.key_fields || ['triage.level', 'rule_name', 'source.ip', 'destination.ip'];
  return fields.map((field) => `${field}=${policyKeyPart(alert, field)}`).join('|');
}

function findSuppressRule(alert) {
  // Suppression rules reduce repeated alerting, not evidence. Matching alerts
  // are still stored so seen_count and report rollups can show the pattern.
  const text = alertText(alert);
  const level = nestedField(alert, 'triage.level');
  return (scoringRules.suppress_rules || []).find((rule) => (
    levelAllowed(rule, level) && matchesAdjustment(rule, alert, text)
  )) || null;
}

function scoreAlert(alert) {
  // Scoring is deterministic; every meaningful score change records a reason
  // for reports, Telegram messages, and analyst notes.
  const sourceIp = nestedField(alert, 'source.ip');
  const destinationIp = nestedField(alert, 'destination.ip');
  const direction = trafficDirection(sourceIp, destinationIp);
  const text = alertText(alert);
  const reasons = [];
  let score = severityBase(alert);
  reasons.push(`base severity score ${score}`);

  const directionDelta = scoringRules.direction_adjustments[direction] || 0;
  if (directionDelta) {
    score += directionDelta;
    const labels = {
      inbound: 'public-to-private inbound traffic',
      outbound: 'private-to-public outbound traffic',
      internal: 'internal private traffic',
      external: 'external-to-external traffic',
    };
    reasons.push(labels[direction] || `${direction} traffic`);
  }

  if (isInfrastructureIp(destinationIp)) {
    score += scoringRules.infrastructure_adjustments.destination || 0;
    reasons.push('destination is monitored infrastructure');
  }
  if (isInfrastructureIp(sourceIp)) {
    score += scoringRules.infrastructure_adjustments.source || 0;
    reasons.push('source is monitored infrastructure');
  }

  for (const adjustment of scoringRules.keyword_adjustments || []) {
    // Broad text nudges, for example malware or command-and-control wording.
    if (matchesText(text, adjustment.keywords || [])) {
      score += Number(adjustment.score_delta || 0);
      if (adjustment.reason) reasons.push(adjustment.reason);
    }
  }

  if (String(alert.severity_label || '').toLowerCase() === 'low') {
    // Low/informational alerts are nudged down unless config overrides it.
    const lowAdjustment = (scoringRules.keyword_adjustments || []).find((item) => item.name === 'informational or low severity');
    const delta = lowAdjustment ? Number(lowAdjustment.score_delta || 0) : -8;
    score += delta;
    reasons.push(lowAdjustment?.reason || 'rule appears informational or low severity');
  }

  for (const adjustment of [...(scoringRules.rule_adjustments || []), ...(scoringRules.pair_adjustments || [])]) {
    // Main tuning path for known-benign local rules or source/destination pairs.
    if (matchesAdjustment(adjustment, alert, text)) {
      score += Number(adjustment.score_delta || 0);
      if (adjustment.reason) reasons.push(adjustment.reason);
    }
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const thresholds = scoringRules.thresholds;
  let level = 'low';
  if (score >= thresholds.critical_min) level = 'critical';
  else if (score >= thresholds.high_min) level = 'high';
  else if (score >= thresholds.medium_min) level = 'medium';

  let routing = 'store-only';
  if (level === 'critical' || level === 'high') routing = 'analyst-review-immediate';
  else if (level === 'medium') routing = 'analyst-review';

  return {
    score,
    level,
    routing,
    traffic_direction: direction,
    source_is_private: isPrivateIpv4(sourceIp),
    destination_is_private: isPrivateIpv4(destinationIp),
    source_is_infrastructure: isInfrastructureIp(sourceIp),
    destination_is_infrastructure: isInfrastructureIp(destinationIp),
    reasons,
  };
}

fs.mkdirSync(path.dirname(dbPath), {recursive: true});
const db = new sqlite3.Database(dbPath);
const sqliteBusyTimeoutMs = Number(process.env.ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS || 30000);
db.configure('busyTimeout', sqliteBusyTimeoutMs);
const sqliteJournalMode = String(process.env.ALERT_STORE_SQLITE_JOURNAL_MODE || 'DELETE').toUpperCase();
const sqliteSynchronous = String(process.env.ALERT_STORE_SQLITE_SYNCHRONOUS || 'FULL').toUpperCase();
const sqliteTempStore = String(process.env.ALERT_STORE_SQLITE_TEMP_STORE || 'DEFAULT').toUpperCase();
const allowedJournalModes = new Set(['DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL', 'OFF']);
const allowedSynchronousModes = new Set(['OFF', 'NORMAL', 'FULL', 'EXTRA']);
const allowedTempStoreModes = new Set(['DEFAULT', 'FILE', 'MEMORY']);
const validTriageLevels = new Set(['critical', 'high', 'medium', 'low', 'informational', 'info', 'unknown']);

function normalizeTriageLevel(value, fallback = '') {
  const level = String(value || '').trim().toLowerCase();
  if (validTriageLevels.has(level)) return level === 'info' ? 'informational' : level;
  const fallbackLevel = String(fallback || '').trim().toLowerCase();
  if (validTriageLevels.has(fallbackLevel)) return fallbackLevel === 'info' ? 'informational' : fallbackLevel;
  return 'unknown';
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
const enrichmentScheduler = createProviderScheduler({
  failureThreshold: enrichmentCircuitFailureThreshold,
  resetMs: enrichmentCircuitResetMs,
  formatTimestamp: formatProjectTimestamp,
});
let telegramOutboxDrainActive = false;
let enrichmentDrainActive = false;
let n8nPostCommitDrainActive = false;
let durableJobRecoveryActive = false;
let durableJobs;
let pipelineMetrics;
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
  const next = sqliteWriteGate.catch(() => undefined).then(task);
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

async function initDb() {
  // Schema upgrades are additive. ensureColumn keeps existing SQLite DBs usable
  // after new triage fields are introduced.
  const journalMode = allowedJournalModes.has(sqliteJournalMode) ? sqliteJournalMode : 'DELETE';
  const synchronousMode = allowedSynchronousModes.has(sqliteSynchronous) ? sqliteSynchronous : 'FULL';
  const tempStoreMode = allowedTempStoreModes.has(sqliteTempStore) ? sqliteTempStore : 'DEFAULT';
  await run(`PRAGMA journal_mode = ${journalMode}`);
  await run(`PRAGMA synchronous = ${synchronousMode}`);
  await run(`PRAGMA temp_store = ${tempStoreMode}`);
  await run(`PRAGMA busy_timeout = ${sqliteBusyTimeoutMs}`);
  if (journalMode === 'WAL') {
    await run('PRAGMA wal_autocheckpoint = 1000');
  }
  await run(`
    CREATE TABLE IF NOT EXISTS alerts (
      alert_id TEXT PRIMARY KEY,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      seen_count INTEGER NOT NULL DEFAULT 1,
      timestamp TEXT,
      rule_name TEXT,
      event_dataset TEXT,
      severity INTEGER,
      severity_label TEXT,
      source_ip TEXT,
      source_port INTEGER,
      destination_ip TEXT,
      destination_port INTEGER,
      network_protocol TEXT,
      transport_protocol TEXT,
      traffic_direction TEXT,
      triage_score INTEGER,
      triage_level TEXT,
      routing TEXT,
      filter_status TEXT,
      filter_reason TEXT,
      suppression_key TEXT,
      raw_event_json TEXT,
      enrichment_json TEXT,
      alert_json TEXT NOT NULL
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_rule_name ON alerts(rule_name)');
  await ensureColumn('alerts', 'traffic_direction', 'TEXT');
  await ensureColumn('alerts', 'source_port', 'INTEGER');
  await ensureColumn('alerts', 'destination_port', 'INTEGER');
  await ensureColumn('alerts', 'network_protocol', 'TEXT');
  await ensureColumn('alerts', 'transport_protocol', 'TEXT');
  await ensureColumn('alerts', 'triage_score', 'INTEGER');
  await ensureColumn('alerts', 'triage_level', 'TEXT');
  await ensureColumn('alerts', 'routing', 'TEXT');
  await ensureColumn('alerts', 'filter_status', 'TEXT');
  await ensureColumn('alerts', 'filter_reason', 'TEXT');
  await ensureColumn('alerts', 'suppression_key', 'TEXT');
  await ensureColumn('alerts', 'raw_event_json', 'TEXT');
  await ensureColumn('alerts', 'enrichment_json', 'TEXT');
  await ensureColumn('alerts', 'rule_id', 'TEXT');
  await ensureColumn('alerts', 'stable_group_key', 'TEXT');
  await ensureColumn('alerts', 'stable_group_id', 'TEXT');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_stable_group_id ON alerts(stable_group_id)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_triage_level ON alerts(triage_level)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_filter_status ON alerts(filter_status)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip ON alerts(destination_ip)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_source_port ON alerts(source_port)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_destination_port ON alerts(destination_port)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_transport_protocol ON alerts(transport_protocol)');
  // Group summary refreshes run on every stored alert. SQLite only uses an
  // expression index when its expression matches the query predicate, so
  // interpolate the single canonical expression instead of maintaining a
  // second hand-written variant. The versioned name repairs the earlier index
  // once without rebuilding a large correct index on every restart.
  await run('DROP INDEX IF EXISTS idx_alerts_group_key_expr');
  await run(`CREATE INDEX IF NOT EXISTS idx_alerts_group_key_expr_v2 ON alerts(${alertGroupKeySql})`);
  await run(`
    CREATE TABLE IF NOT EXISTS alert_group_summary (
      group_id TEXT PRIMARY KEY,
      group_key TEXT NOT NULL UNIQUE,
      representative_alert_id TEXT,
      first_seen TEXT,
      last_seen TEXT,
      raw_alert_count INTEGER NOT NULL DEFAULT 0,
      total_seen_count INTEGER NOT NULL DEFAULT 0,
      timestamp TEXT,
      rule_name TEXT,
      event_dataset TEXT,
      severity INTEGER,
      severity_label TEXT,
      source_ip TEXT,
      source_port INTEGER,
      destination_ip TEXT,
      destination_port INTEGER,
      network_protocol TEXT,
      transport_protocol TEXT,
      traffic_direction TEXT,
      triage_score INTEGER,
      triage_level TEXT,
      routing TEXT,
      filter_status TEXT,
      filter_reason TEXT,
      suppression_key TEXT,
      updated_at TEXT NOT NULL
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_summary_last_seen ON alert_group_summary(last_seen)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_summary_triage_level ON alert_group_summary(triage_level)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_summary_filter_status ON alert_group_summary(filter_status)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_summary_rule_name ON alert_group_summary(rule_name)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_summary_source_ip ON alert_group_summary(source_ip)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_summary_destination_ip ON alert_group_summary(destination_ip)');
  await run(`
    CREATE TABLE IF NOT EXISTS analyst_alert_group_state (
      group_id TEXT PRIMARY KEY,
      group_key TEXT,
      status TEXT NOT NULL CHECK(status IN ('acknowledged', 'suppressed')),
      repeat_count INTEGER NOT NULL DEFAULT 0,
      reason TEXT,
      updated_at TEXT NOT NULL,
      updated_by TEXT
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_state_status ON analyst_alert_group_state(status)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_state_updated_at ON analyst_alert_group_state(updated_at)');
  await run(`
    CREATE TABLE IF NOT EXISTS alert_group_alias (
      legacy_group_id TEXT PRIMARY KEY,
      stable_group_id TEXT NOT NULL,
      stable_group_key TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_alert_group_alias_stable ON alert_group_alias(stable_group_id)');
  await run(`
    CREATE TABLE IF NOT EXISTS alert_observables (
      group_id TEXT NOT NULL,
      group_key TEXT NOT NULL,
      alert_id TEXT NOT NULL,
      observable_type TEXT NOT NULL,
      observable_value TEXT NOT NULL,
      role TEXT NOT NULL,
      source TEXT NOT NULL,
      first_seen TEXT,
      last_seen TEXT,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (group_id, alert_id, observable_type, observable_value, role, source)
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_alert_observables_lookup ON alert_observables(observable_type, observable_value, group_id)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_observables_group ON alert_observables(group_id, last_seen)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_observables_alert ON alert_observables(alert_id)');
  await run(`
    CREATE TABLE IF NOT EXISTS ai_analysis_runs (
      analysis_id TEXT PRIMARY KEY,
      group_id TEXT NOT NULL,
      alert_id TEXT NOT NULL,
      agent_role TEXT NOT NULL DEFAULT 'soc-analyst',
      generated_at TEXT NOT NULL,
      model TEXT,
      model_path TEXT,
      detection_outcome TEXT,
      bluf TEXT,
      summary TEXT,
      confidence TEXT,
      artifact_path TEXT,
      evidence_hash TEXT,
      response_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
  await ensureColumn('ai_analysis_runs', 'agent_role', "TEXT NOT NULL DEFAULT 'soc-analyst'");
  await run('CREATE INDEX IF NOT EXISTS idx_ai_analysis_runs_group ON ai_analysis_runs(group_id, generated_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_ai_analysis_runs_alert ON ai_analysis_runs(alert_id, generated_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_ai_analysis_runs_role_group ON ai_analysis_runs(agent_role, group_id, generated_at DESC)');
  await run(`
    CREATE TABLE IF NOT EXISTS incident_response_cases (
      case_id TEXT PRIMARY KEY,
      group_id TEXT NOT NULL UNIQUE,
      dashboard_group_id TEXT NOT NULL,
      representative_alert_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'open'
        CHECK(status IN ('open', 'in_progress', 'resolved')),
      agent_status TEXT NOT NULL DEFAULT 'queued'
        CHECK(agent_status IN ('queued', 'analyzing', 'analyzed', 'failed')),
      escalated_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      escalated_by TEXT,
      reason TEXT,
      latest_analysis_id TEXT,
      latest_model TEXT,
      latest_generated_at TEXT,
      latest_error TEXT
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_incident_cases_status_updated ON incident_response_cases(status, updated_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_incident_cases_agent_status ON incident_response_cases(agent_status, updated_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_incident_cases_dashboard_group ON incident_response_cases(dashboard_group_id)');
  await run(`
    CREATE TABLE IF NOT EXISTS incident_response_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      actor TEXT,
      detail_json TEXT NOT NULL DEFAULT '{}',
      created_at TEXT NOT NULL,
      FOREIGN KEY(case_id) REFERENCES incident_response_cases(case_id)
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_incident_events_case_created ON incident_response_events(case_id, created_at DESC)');
  await run(`
    CREATE TABLE IF NOT EXISTS ai_second_opinion_runs (
      analysis_id TEXT PRIMARY KEY,
      group_id TEXT NOT NULL,
      alert_id TEXT NOT NULL,
      agent_role TEXT NOT NULL,
      trigger TEXT,
      status TEXT NOT NULL,
      primary_model TEXT,
      primary_model_path TEXT,
      primary_outcome TEXT,
      primary_confidence TEXT,
      reviewer_model TEXT,
      reviewer_model_path TEXT,
      reviewer_outcome TEXT,
      reviewer_confidence TEXT,
      agreement TEXT,
      material_disagreement INTEGER NOT NULL DEFAULT 0,
      disputed_fields_json TEXT NOT NULL DEFAULT '[]',
      comparison_json TEXT NOT NULL DEFAULT '{}',
      reviewer_runtime_seconds REAL,
      memory_candidates_promoted INTEGER NOT NULL DEFAULT 0,
      generated_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_ai_second_opinion_generated ON ai_second_opinion_runs(generated_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_ai_second_opinion_agreement ON ai_second_opinion_runs(agreement, generated_at DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_ai_second_opinion_group ON ai_second_opinion_runs(group_id, generated_at DESC)');
  await run(`
    CREATE TABLE IF NOT EXISTS alert_correlations (
      source_group_id TEXT NOT NULL,
      related_group_id TEXT NOT NULL,
      analysis_id TEXT NOT NULL,
      correlation_score REAL NOT NULL,
      reasons_json TEXT NOT NULL,
      shared_observables_json TEXT NOT NULL,
      model_status TEXT NOT NULL DEFAULT 'candidate',
      model_confidence TEXT,
      model_hypothesis TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (source_group_id, related_group_id)
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_alert_correlations_related ON alert_correlations(related_group_id, correlation_score DESC)');
  await run('CREATE INDEX IF NOT EXISTS idx_alert_correlations_source ON alert_correlations(source_group_id, correlation_score DESC)');
  await run(`
    CREATE TABLE IF NOT EXISTS notification_log (
      notification_key TEXT PRIMARY KEY,
      last_sent TEXT NOT NULL,
      sent_count INTEGER NOT NULL DEFAULT 1,
      channel TEXT NOT NULL,
      alert_id TEXT,
      triage_level TEXT,
      rule_name TEXT,
      source_ip TEXT,
      destination_ip TEXT
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS notification_outbox (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      notification_key TEXT NOT NULL,
      channel TEXT NOT NULL DEFAULT 'telegram',
      alert_id TEXT,
      triage_level TEXT,
      rule_name TEXT,
      source_ip TEXT,
      destination_ip TEXT,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      attempt_count INTEGER NOT NULL DEFAULT 0,
      next_attempt_at TEXT NOT NULL,
      last_error TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      sent_at TEXT
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_notification_outbox_due ON notification_outbox(status, next_attempt_at, id)');
  await run('CREATE INDEX IF NOT EXISTS idx_notification_outbox_key ON notification_outbox(notification_key, status)');
  // A process exit can interrupt delivery after claim. Retrying is safe because
  // notification_log cooldown still prevents a second queued alert message.
  await run("UPDATE notification_outbox SET status = 'pending', updated_at = ? WHERE status = 'delivering'", [nowUtc()]);
  await run(`
    CREATE TABLE IF NOT EXISTS suppression_log (
      suppression_key TEXT PRIMARY KEY,
      rule_name TEXT NOT NULL,
      reason TEXT,
      window_start TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      seen_count INTEGER NOT NULL DEFAULT 1,
      suppressed_count INTEGER NOT NULL DEFAULT 0,
      escalated_count INTEGER NOT NULL DEFAULT 0,
      ttl_seconds INTEGER NOT NULL,
      escalation_threshold INTEGER NOT NULL
    )
  `);
  await enrichmentCache.install();
  await run(`
    CREATE TABLE IF NOT EXISTS enrichment_rate_limit (
      source TEXT PRIMARY KEY,
      last_request_at TEXT NOT NULL
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS pcap_requests (
      request_id TEXT PRIMARY KEY,
      status TEXT NOT NULL,
      alert_id TEXT,
      group_id TEXT,
      group_key TEXT,
      first_seen TEXT,
      last_seen TEXT,
      source_ip TEXT,
      source_port INTEGER,
      destination_ip TEXT,
      destination_port INTEGER,
      network_protocol TEXT,
      transport_protocol TEXT,
      community_id TEXT,
      requested_by TEXT,
      reason TEXT NOT NULL,
      max_window_seconds INTEGER NOT NULL,
      relay_host TEXT,
      artifact_path TEXT,
      artifact_sha256 TEXT,
      artifact_size_bytes INTEGER,
      error TEXT,
      diagnostics_json TEXT,
      request_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      claimed_at TEXT,
      completed_at TEXT,
      updated_at TEXT NOT NULL
    )
  `);
  await ensureColumn('pcap_requests', 'claimed_at', 'TEXT');
  await ensureColumn('pcap_requests', 'completed_at', 'TEXT');
  await ensureColumn('pcap_requests', 'diagnostics_json', 'TEXT');
  await ensureColumn('pcap_requests', 'analysis_status', "TEXT NOT NULL DEFAULT 'not_ready'");
  await ensureColumn('pcap_requests', 'analysis_attempt_count', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('pcap_requests', 'analysis_error', 'TEXT');
  await ensureColumn('pcap_requests', 'analysis_started_at', 'TEXT');
  await ensureColumn('pcap_requests', 'analysis_completed_at', 'TEXT');
  await ensureColumn('pcap_requests', 'outcome', 'TEXT');
  await ensureColumn('pcap_requests', 'transfer_stage', 'TEXT');
  await ensureColumn('pcap_requests', 'transfer_bytes', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('pcap_requests', 'transfer_total_bytes', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('pcap_requests', 'transfer_progress_at', 'TEXT');
  await ensureColumn('pcap_requests', 'transfer_duration_seconds', 'INTEGER');
  await ensureColumn('pcap_requests', 'transfer_attempt_count', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('pcap_requests', 'transfer_retry_count', 'INTEGER NOT NULL DEFAULT 0');
  await ensureColumn('pcap_requests', 'transfer_last_error', 'TEXT');
  await ensureColumn('pcap_requests', 'transfer_last_failed_stage', 'TEXT');
  await ensureColumn('pcap_requests', 'next_attempt_at', 'TEXT');
  await run(`
    UPDATE pcap_requests
    SET transfer_duration_seconds = MAX(
      0,
      CAST(ROUND(
        (julianday(replace(completed_at, '  ', 'T')) -
         julianday(replace(claimed_at, '  ', 'T'))) * 86400
      ) AS INTEGER)
    )
    WHERE transfer_duration_seconds IS NULL
      AND claimed_at IS NOT NULL
      AND completed_at IS NOT NULL
  `);
  await backfillPcapOutcomes();
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_status_created ON pcap_requests(status, created_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_status_next_attempt ON pcap_requests(status, next_attempt_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_completed_at ON pcap_requests(completed_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_alert_id ON pcap_requests(alert_id)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_group_id ON pcap_requests(group_id)');
  durableJobs = createDurableJobQueue({
    run,
    get,
    all,
    now: nowUtc,
    transitionLeaseSeconds: aiAnalysisLeaseSeconds,
  });
  await durableJobs.install();
  pipelineMetrics = createPipelineMetrics({
    run,
    all,
    now: nowUtc,
    diskSnapshot: diskCapacitySnapshot,
    retentionHours: pipelineEventRetentionHours,
  });
  await pipelineMetrics.install();
  await backfillStableGroupIdentity();
  await backfillAlertObservables();
  await rebuildAlertGroupSummaries();
  await refreshGroupAliases();
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

async function indexAlertObservables(alert, row) {
  if (!row?.alert_id) return 0;
  const groupKey = row.stable_group_key || stableGroupKey({...row, rule_id: alert?.rule_id || row.rule_id});
  const groupId = row.stable_group_id || stableGroupId({...row, rule_id: alert?.rule_id || row.rule_id});
  const observables = buildAlertObservables(alert, row, extractAlertIndicators);
  await run('DELETE FROM alert_observables WHERE alert_id = ?', [row.alert_id]);
  for (const observable of observables) {
    await run(
      `INSERT INTO alert_observables (
         group_id, group_key, alert_id, observable_type, observable_value,
         role, source, first_seen, last_seen, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        groupId,
        groupKey,
        row.alert_id,
        observable.observable_type,
        observable.observable_value,
        observable.role,
        observable.source,
        row.first_seen || null,
        row.last_seen || row.timestamp || null,
        nowUtc(),
      ],
    );
  }
  return observables.length;
}

async function backfillAlertObservables() {
  const pending = await all(`
    SELECT a.*
    FROM alerts AS a
    WHERE NOT EXISTS (
      SELECT 1 FROM alert_observables AS observable WHERE observable.alert_id = a.alert_id
    )
    ORDER BY a.last_seen ASC
  `);
  if (!pending.length) return 0;
  // Treat the startup migration as one recoverable unit. This is materially
  // faster than autocommit for an existing corpus and prevents a restart from
  // leaving only part of the observable index populated.
  await withImmediateTransaction(async () => {
    for (const item of pending) {
      await indexAlertObservables(parseJsonObject(item.alert_json), item);
    }
  });
  return pending.length;
}

function normalizeCorrelationAssessment(value) {
  const assessment = value && typeof value === 'object' ? value : {};
  const relatedGroups = Array.isArray(assessment.related_groups)
    ? assessment.related_groups.map((item) => {
      if (typeof item === 'string') return safeString(item, 64).toLowerCase();
      return safeString(item?.group_id, 64).toLowerCase();
    }).filter(Boolean).slice(0, 20)
    : [];
  return {
    correlation_found: Boolean(assessment.correlation_found),
    confidence: safeString(assessment.confidence, 16).toLowerCase(),
    related_groups: new Set(relatedGroups),
    attack_chain_hypothesis: safeString(assessment.attack_chain_hypothesis, 2000),
  };
}

async function recordAiAnalysisResult(payload) {
  const alertId = safeString(payload?.alert_id, 1024);
  const analysisId = safeString(payload?.analysis_id, 128).toLowerCase();
  if (!alertId || !analysisId || !/^[a-z0-9_-]{8,128}$/.test(analysisId)) {
    throw new Error('analysis_id and alert_id are required');
  }
  const alertRow = await get(
    'SELECT alert_id, stable_group_id, stable_group_key FROM alerts WHERE alert_id = ?',
    [alertId],
  );
  if (!alertRow) throw new Error('analysis alert_id not found');
  const response = payload?.response && typeof payload.response === 'object' ? payload.response : {};
  const generatedAt = safeString(payload?.generated_at, 64) || nowUtc();
  const groupId = alertRow.stable_group_id;
  if (!groupId) throw new Error('analysis alert has no stable group identity');
  const requestedAgentRole = safeString(payload?.agent_role || 'soc-analyst', 64).toLowerCase();
  const agentRole = supportedAgentRoles.has(requestedAgentRole) ? requestedAgentRole : 'soc-analyst';

  await run(
    `INSERT INTO ai_analysis_runs (
       analysis_id, group_id, alert_id, agent_role, generated_at, model, model_path,
       detection_outcome, bluf, summary, confidence, artifact_path,
       evidence_hash, response_json, created_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(analysis_id) DO UPDATE SET
       group_id = excluded.group_id,
       alert_id = excluded.alert_id,
       agent_role = excluded.agent_role,
       generated_at = excluded.generated_at,
       model = excluded.model,
       model_path = excluded.model_path,
       detection_outcome = excluded.detection_outcome,
       bluf = excluded.bluf,
       summary = excluded.summary,
       confidence = excluded.confidence,
       artifact_path = excluded.artifact_path,
       evidence_hash = excluded.evidence_hash,
       response_json = excluded.response_json`,
    [
      analysisId,
      groupId,
      alertId,
      agentRole,
      generatedAt,
      safeString(payload?.model || response._analysis_model, 200),
      safeString(payload?.model_path || response._analysis_model_path, 100),
      safeString(response.detection_outcome, 100),
      safeString(response.bluf, 4000),
      safeString(response.summary, 8000),
      safeString(response.confidence, 16).toLowerCase(),
      safeString(payload?.artifact_path, 2048),
      safeString(payload?.evidence_hash, 128).toLowerCase(),
      jsonText(response),
      nowUtc(),
    ],
  );

  const secondOpinion = response._second_opinion && typeof response._second_opinion === 'object'
    ? response._second_opinion
    : null;
  let secondOpinionRecorded = false;
  if (secondOpinion) {
    const reviewer = secondOpinion.response && typeof secondOpinion.response === 'object'
      ? secondOpinion.response
      : {};
    const comparison = secondOpinion.comparison && typeof secondOpinion.comparison === 'object'
      ? secondOpinion.comparison
      : {};
    const memoryWriteback = secondOpinion.memory_writeback && typeof secondOpinion.memory_writeback === 'object'
      ? secondOpinion.memory_writeback
      : {};
    const runtime = Number(secondOpinion.runtime_seconds);
    const now = nowUtc();
    await run(
      `INSERT INTO ai_second_opinion_runs (
         analysis_id, group_id, alert_id, agent_role, trigger, status,
         primary_model, primary_model_path, primary_outcome, primary_confidence,
         reviewer_model, reviewer_model_path, reviewer_outcome, reviewer_confidence,
         agreement, material_disagreement, disputed_fields_json, comparison_json,
         reviewer_runtime_seconds, memory_candidates_promoted, generated_at,
         created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(analysis_id) DO UPDATE SET
         group_id = excluded.group_id,
         alert_id = excluded.alert_id,
         agent_role = excluded.agent_role,
         trigger = excluded.trigger,
         status = excluded.status,
         primary_model = excluded.primary_model,
         primary_model_path = excluded.primary_model_path,
         primary_outcome = excluded.primary_outcome,
         primary_confidence = excluded.primary_confidence,
         reviewer_model = excluded.reviewer_model,
         reviewer_model_path = excluded.reviewer_model_path,
         reviewer_outcome = excluded.reviewer_outcome,
         reviewer_confidence = excluded.reviewer_confidence,
         agreement = excluded.agreement,
         material_disagreement = excluded.material_disagreement,
         disputed_fields_json = excluded.disputed_fields_json,
         comparison_json = excluded.comparison_json,
         reviewer_runtime_seconds = excluded.reviewer_runtime_seconds,
         memory_candidates_promoted = excluded.memory_candidates_promoted,
         generated_at = excluded.generated_at,
         updated_at = excluded.updated_at`,
      [
        analysisId,
        groupId,
        alertId,
        agentRole,
        safeString(secondOpinion.trigger, 1000),
        safeString(secondOpinion.status || 'unknown', 32),
        safeString(payload?.model || response._analysis_model, 200),
        safeString(payload?.model_path || response._analysis_model_path, 100),
        safeString(response.detection_outcome, 100),
        safeString(response.confidence, 16).toLowerCase(),
        safeString(reviewer._analysis_model || secondOpinion.model_route, 200),
        safeString(reviewer._analysis_model_path, 100),
        safeString(reviewer.detection_outcome, 100),
        safeString(reviewer.confidence, 16).toLowerCase(),
        safeString(comparison.agreement, 64),
        comparison.material_disagreement ? 1 : 0,
        jsonText(Array.isArray(comparison.disputed_fields) ? comparison.disputed_fields : []),
        jsonText(comparison),
        Number.isFinite(runtime) && runtime >= 0 ? runtime : null,
        Math.max(0, Number(memoryWriteback.accepted) || 0),
        generatedAt,
        now,
        now,
      ],
    );
    secondOpinionRecorded = true;
  }

  if (agentRole === 'incident-responder') {
    const caseRow = await get('SELECT case_id FROM incident_response_cases WHERE group_id = ?', [groupId]);
    if (caseRow?.case_id) {
      const updatedAt = nowUtc();
      await run(
        `UPDATE incident_response_cases
         SET agent_status = 'analyzed', latest_analysis_id = ?, latest_model = ?,
             latest_generated_at = ?, latest_error = NULL, updated_at = ?
         WHERE case_id = ?`,
        [
          analysisId,
          safeString(payload?.model || response._analysis_model, 200),
          generatedAt,
          updatedAt,
          caseRow.case_id,
        ],
      );
      await run(
        `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
         VALUES (?, 'analysis_completed', 'incident-responder', ?, ?)`,
        [caseRow.case_id, jsonText({analysis_id: analysisId, generated_at: generatedAt}), updatedAt],
      );
    }
  }

  const assessment = normalizeCorrelationAssessment(response.correlation_assessment);
  const candidates = compactCorrelationCandidates(payload?.correlation_candidates);
  let correlations = 0;
  for (const candidate of candidates) {
    if (candidate.group_id === groupId) continue;
    const relatedExists = await get('SELECT 1 AS present FROM alerts WHERE stable_group_id = ? LIMIT 1', [candidate.group_id]);
    if (!relatedExists) continue;
    const modelRelated = assessment.related_groups.has(candidate.group_id);
    await run(
      `INSERT INTO alert_correlations (
         source_group_id, related_group_id, analysis_id, correlation_score,
         reasons_json, shared_observables_json, model_status, model_confidence,
         model_hypothesis, created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(source_group_id, related_group_id) DO UPDATE SET
         analysis_id = excluded.analysis_id,
         correlation_score = excluded.correlation_score,
         reasons_json = excluded.reasons_json,
         shared_observables_json = excluded.shared_observables_json,
         model_status = excluded.model_status,
         model_confidence = excluded.model_confidence,
         model_hypothesis = excluded.model_hypothesis,
         updated_at = excluded.updated_at`,
      [
        groupId,
        candidate.group_id,
        analysisId,
        candidate.score,
        jsonText(candidate.reasons),
        jsonText(candidate.shared_observables),
        modelRelated ? 'model-related' : 'candidate',
        modelRelated ? assessment.confidence : null,
        modelRelated ? assessment.attack_chain_hypothesis : null,
        nowUtc(),
        nowUtc(),
      ],
    );
    correlations += 1;
  }
  return {
    ok: true,
    status: 'analysis_indexed',
    analysis_id: analysisId,
    group_id: groupId,
    correlations,
    second_opinion_recorded: secondOpinionRecorded,
  };
}

async function refreshGroupAliases() {
  const groups = await all(`
    SELECT g.group_id AS legacy_group_id, a.stable_group_id, a.stable_group_key
    FROM alert_group_summary g JOIN alerts a ON a.alert_id = g.representative_alert_id
    WHERE a.stable_group_id IS NOT NULL AND a.stable_group_key IS NOT NULL
  `);
  if (!groups.length) return 0;
  await withImmediateTransaction(async () => {
    for (const item of groups) {
      await run(`INSERT INTO alert_group_alias (legacy_group_id, stable_group_id, stable_group_key, updated_at)
        VALUES (?, ?, ?, ?) ON CONFLICT(legacy_group_id) DO UPDATE SET
        stable_group_id = excluded.stable_group_id, stable_group_key = excluded.stable_group_key,
        updated_at = excluded.updated_at`,
      [item.legacy_group_id, item.stable_group_id, item.stable_group_key, nowUtc()]);
    }
  });
  return groups.length;
}

function alertGroupKeyFromRow(row) {
  if (!row) return '';
  if (row.suppression_key) return String(row.suppression_key);
  return [
    normalizeTriageLevel(row.triage_level, row.severity_label),
    row.rule_name || 'unknown-rule',
    row.source_ip || 'unknown-source',
    row.destination_ip || 'unknown-destination',
    row.filter_status || 'accepted',
  ].join('|');
}

async function currentAlertGroupKey(alertId) {
  const row = await get(`SELECT ${alertGroupKeySql} AS group_key FROM alerts WHERE alert_id = ?`, [alertId]);
  return row?.group_key || '';
}

async function refreshAlertGroupSummary(groupKey) {
  if (!groupKey) return;
  const aggregate = await get(
    `
      SELECT COUNT(*) AS raw_alert_count,
             COALESCE(SUM(MAX(1, COALESCE(seen_count, 1))), 0) AS total_seen_count,
             MIN(first_seen) AS first_seen,
             MAX(last_seen) AS last_seen
      FROM alerts
      WHERE ${alertGroupKeySql} = ?
    `,
    [groupKey],
  );
  const groupId = alertGroupId(groupKey);
  if (!aggregate || Number(aggregate.raw_alert_count || 0) === 0) {
    await run('DELETE FROM alert_group_summary WHERE group_id = ?', [groupId]);
    await run('DELETE FROM alert_group_alias WHERE legacy_group_id = ?', [groupId]);
    return;
  }
  const representative = await get(
    `
      SELECT alert_id, timestamp, rule_name, event_dataset, severity, severity_label,
             source_ip, source_port, destination_ip, destination_port,
             network_protocol, transport_protocol, traffic_direction, triage_score,
             triage_level, routing, filter_status, filter_reason, suppression_key
      FROM alerts
      WHERE ${alertGroupKeySql} = ?
      ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
               alert_id DESC
      LIMIT 1
    `,
    [groupKey],
  );
  if (!representative) {
    await run('DELETE FROM alert_group_summary WHERE group_id = ?', [groupId]);
    await run('DELETE FROM alert_group_alias WHERE legacy_group_id = ?', [groupId]);
    return;
  }
  await run(
    `
      INSERT INTO alert_group_summary (
        group_id, group_key, representative_alert_id, first_seen, last_seen,
        raw_alert_count, total_seen_count, timestamp, rule_name, event_dataset,
        severity, severity_label, source_ip, source_port, destination_ip,
        destination_port, network_protocol, transport_protocol, traffic_direction,
        triage_score, triage_level, routing, filter_status, filter_reason,
        suppression_key, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(group_id) DO UPDATE SET
        group_key = excluded.group_key,
        representative_alert_id = excluded.representative_alert_id,
        first_seen = excluded.first_seen,
        last_seen = excluded.last_seen,
        raw_alert_count = excluded.raw_alert_count,
        total_seen_count = excluded.total_seen_count,
        timestamp = excluded.timestamp,
        rule_name = excluded.rule_name,
        event_dataset = excluded.event_dataset,
        severity = excluded.severity,
        severity_label = excluded.severity_label,
        source_ip = excluded.source_ip,
        source_port = excluded.source_port,
        destination_ip = excluded.destination_ip,
        destination_port = excluded.destination_port,
        network_protocol = excluded.network_protocol,
        transport_protocol = excluded.transport_protocol,
        traffic_direction = excluded.traffic_direction,
        triage_score = excluded.triage_score,
        triage_level = excluded.triage_level,
        routing = excluded.routing,
        filter_status = excluded.filter_status,
        filter_reason = excluded.filter_reason,
        suppression_key = excluded.suppression_key,
        updated_at = excluded.updated_at
    `,
    [
      groupId,
      groupKey,
      representative.alert_id,
      aggregate.first_seen,
      aggregate.last_seen,
      Number(aggregate.raw_alert_count || 0),
      Number(aggregate.total_seen_count || 0),
      representative.timestamp,
      representative.rule_name,
      representative.event_dataset,
      representative.severity,
      representative.severity_label,
      representative.source_ip,
      representative.source_port,
      representative.destination_ip,
      representative.destination_port,
      representative.network_protocol,
      representative.transport_protocol,
      representative.traffic_direction,
      representative.triage_score,
      normalizeTriageLevel(representative.triage_level, representative.severity_label),
      representative.routing,
      representative.filter_status,
      representative.filter_reason,
      representative.suppression_key,
      nowUtc(),
    ],
  );
  const stableIdentity = await get(
    'SELECT stable_group_id, stable_group_key FROM alerts WHERE alert_id = ?',
    [representative.alert_id],
  );
  if (stableIdentity?.stable_group_id && stableIdentity?.stable_group_key) {
    await run(`INSERT INTO alert_group_alias (legacy_group_id, stable_group_id, stable_group_key, updated_at)
      VALUES (?, ?, ?, ?) ON CONFLICT(legacy_group_id) DO UPDATE SET
      stable_group_id = excluded.stable_group_id, stable_group_key = excluded.stable_group_key,
      updated_at = excluded.updated_at`,
    [groupId, stableIdentity.stable_group_id, stableIdentity.stable_group_key, nowUtc()]);
  }
}

async function rebuildAlertGroupSummariesUnlocked() {
  // One windowed scan replaces the former per-group aggregate and
  // representative queries. The small insert loop only writes final summaries.
  const groups = await all(`
    WITH ranked AS (
      SELECT ${alertGroupKeySql} AS group_key,
             alert_id, first_seen, last_seen, timestamp, rule_name, event_dataset,
             severity, severity_label, source_ip, source_port, destination_ip,
             destination_port, network_protocol, transport_protocol,
             traffic_direction, triage_score, triage_level, routing,
             filter_status, filter_reason, suppression_key,
             COUNT(*) OVER (PARTITION BY ${alertGroupKeySql}) AS raw_alert_count,
             SUM(MAX(1, COALESCE(seen_count, 1))) OVER (PARTITION BY ${alertGroupKeySql}) AS total_seen_count,
             MIN(first_seen) OVER (PARTITION BY ${alertGroupKeySql}) AS group_first_seen,
             MAX(last_seen) OVER (PARTITION BY ${alertGroupKeySql}) AS group_last_seen,
             ROW_NUMBER() OVER (
               PARTITION BY ${alertGroupKeySql}
               ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                        alert_id DESC
             ) AS representative_rank
      FROM alerts
    )
    SELECT * FROM ranked WHERE representative_rank = 1
  `);
  await run('BEGIN IMMEDIATE');
  try {
    await run('DELETE FROM alert_group_summary');
    for (const row of groups) {
      await run(
        `
          INSERT INTO alert_group_summary (
            group_id, group_key, representative_alert_id, first_seen, last_seen,
            raw_alert_count, total_seen_count, timestamp, rule_name, event_dataset,
            severity, severity_label, source_ip, source_port, destination_ip,
            destination_port, network_protocol, transport_protocol, traffic_direction,
            triage_score, triage_level, routing, filter_status, filter_reason,
            suppression_key, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          alertGroupId(row.group_key), row.group_key, row.alert_id,
          row.group_first_seen, row.group_last_seen,
          Number(row.raw_alert_count || 0), Number(row.total_seen_count || 0),
          row.timestamp, row.rule_name, row.event_dataset, row.severity,
          row.severity_label, row.source_ip, row.source_port, row.destination_ip,
          row.destination_port, row.network_protocol, row.transport_protocol,
          row.traffic_direction, row.triage_score,
          normalizeTriageLevel(row.triage_level, row.severity_label), row.routing,
          row.filter_status, row.filter_reason, row.suppression_key, nowUtc(),
        ],
      );
    }
    await run('COMMIT');
  } catch (error) {
    await run('ROLLBACK').catch(() => undefined);
    throw error;
  }
  return {ok: true, status: 'group_summary_rebuilt', groups: groups.length};
}

async function rebuildAlertGroupSummaries() {
  return withSqliteWriteGate(rebuildAlertGroupSummariesUnlocked);
}

function validAnalystGroupId(value) {
  const groupId = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{12}$/.test(groupId) ? groupId : '';
}

async function analystStatusSnapshotUnlocked() {
  const rows = await all(`
    SELECT state.group_id, state.group_key, state.status, state.repeat_count,
           state.reason, state.updated_at, state.updated_by,
           COALESCE(summary.total_seen_count, summary.raw_alert_count, state.repeat_count, 0) AS current_count
    FROM analyst_alert_group_state AS state
    LEFT JOIN alert_group_summary AS summary ON summary.group_id = state.group_id
    WHERE state.status IN ('acknowledged', 'suppressed')
  `);
  const expired = new Set(
    rows
      .filter((row) => row.status === 'acknowledged' && Number(row.current_count || 0) > Number(row.repeat_count || 0))
      .map((row) => row.group_id),
  );
  for (const groupId of expired) {
    await run('DELETE FROM analyst_alert_group_state WHERE group_id = ?', [groupId]);
  }
  const statuses = {};
  for (const row of rows) {
    if (expired.has(row.group_id)) continue;
    statuses[row.group_id] = {
      status: row.status,
      repeat_count: Number(row.repeat_count || 0),
      reason: row.reason || '',
      updated_at: row.updated_at,
      updated_by: row.updated_by || '',
      group_key: row.group_key || '',
    };
  }
  return {
    ok: true,
    statuses,
    acknowledged: Object.keys(statuses).filter((groupId) => statuses[groupId].status === 'acknowledged'),
    suppressed: Object.keys(statuses).filter((groupId) => statuses[groupId].status === 'suppressed'),
  };
}

async function analystStatusSnapshot() {
  return withSqliteWriteGate(analystStatusSnapshotUnlocked);
}

async function updateAnalystStatus(payload) {
  return withSqliteWriteGate(async () => {
    const groupId = validAnalystGroupId(payload?.id);
    if (!groupId) throw new Error('invalid analyst alert group id');
    const status = String(payload?.status || '').trim().toLowerCase();
    if (!['open', 'acknowledged', 'suppressed'].includes(status)) {
      throw new Error('invalid analyst alert status');
    }
    const summary = await get(
      'SELECT group_key, raw_alert_count, total_seen_count FROM alert_group_summary WHERE group_id = ?',
      [groupId],
    );
    if (!summary) throw new Error('analyst alert group not found');
    let repeatCount = Math.max(0, Number.parseInt(payload?.repeat_count, 10) || 0);
    if (status === 'acknowledged' && repeatCount <= 0) {
      repeatCount = Math.max(Number(summary.raw_alert_count || 0), Number(summary.total_seen_count || 0));
    }
    const reason = String(payload?.reason || '').trim().slice(0, analystStatusReasonMaxLength);
    if (status === 'suppressed' && !reason) throw new Error('suppression reason is required');
    if (status === 'open') {
      await run('DELETE FROM analyst_alert_group_state WHERE group_id = ?', [groupId]);
    } else {
      await run(
        `
          INSERT INTO analyst_alert_group_state (
            group_id, group_key, status, repeat_count, reason, updated_at, updated_by
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(group_id) DO UPDATE SET
            group_key = excluded.group_key,
            status = excluded.status,
            repeat_count = excluded.repeat_count,
            reason = excluded.reason,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by
        `,
        [groupId, summary.group_key || '', status, repeatCount, reason, nowUtc(), String(payload?.updated_by || 'dashboard').trim().slice(0, 80)],
      );
    }
    return analystStatusSnapshotUnlocked();
  });
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
    should_write_report: stored.status === 'accepted' && Boolean(stored.stored),
    report_decision: 'write_markdown_report',
    report_job_id: `alert-report:${row.alert_id || rawAlert.alert_id}`,
    committed_at: committedAt,
  };
}

async function storeAlert(rawAlert) {
  const alert = {
    ...rawAlert,
    triage: scoreAlert(rawAlert),
  };
  let wakeAiAfterCommit = false;
  const result = await withSqliteWriteGate(() => withImmediateTransaction(async () => {
    const stored = await storeAlertUnlocked(alert);
    if (stored.ok) {
      let enrichmentQueued = false;
      stored.notification = await queueTelegramNotification(
        alert,
        stored.alert,
        stored.stored,
        nowUtc(),
        stored.filter,
      );
      if (stored.status === 'accepted' && stored.stored && stored.alert?.alert_id) {
        const postCommitPayload = buildPostCommitPayload(rawAlert, stored);
        await durableJobs.enqueue(
          'n8n_post_commit',
          stored.alert.alert_id,
          postCommitPayload,
          {priority: severityRank[String(stored.alert.triage_level || 'informational').toLowerCase()] ?? 0,
            maxAttempts: n8nPostCommitMaxAttempts},
        );
        await pipelineMetrics.record('n8n_post_commit', 'enqueued', stored.alert.alert_id, {
          eventKey: `n8n_post_commit:enqueued:${stored.alert.alert_id}`,
          sizeBytes: Buffer.byteLength(JSON.stringify(postCommitPayload)),
        });
      }
      if (stored.alert?.alert_id && stored.status !== 'dropped' && !hasUsableExternalIntel(alert)) {
        const level = String(stored.alert.triage_level || nestedField(alert, 'triage.level') || 'informational').toLowerCase();
        await durableJobs.enqueue('public_enrichment', stored.alert.alert_id, {alert_id: stored.alert.alert_id}, {
          priority: severityRank[level] ?? 0,
          maxAttempts: enrichmentWorkerMaxAttempts,
        });
        await pipelineMetrics.record('public_enrichment', 'enqueued', stored.alert.alert_id, {
          eventKey: `public_enrichment:enqueued:${stored.alert.alert_id}:${stored.alert.seen_count || 1}`,
        });
        enrichmentQueued = true;
      }
      if (stored.alert?.alert_id && !['dropped', 'suppressed'].includes(stored.status)) {
        const groupKey = stored.alert.stable_group_key || alertGroupKeyFromRow(stored.alert);
        const groupId = stored.alert.stable_group_id || alertGroupId(groupKey);
        const level = String(stored.alert.triage_level || 'informational').toLowerCase();
        if (socAnalysisPolicy.matchesAnalysis(level)) {
          await durableJobs.enqueue('ai_analysis', groupId, {
            group_id: groupId,
            group_key: groupKey,
            representative_alert_id: stored.alert.alert_id,
          }, {priority: severityRank[level] ?? 0, maxAttempts: 8});
          await pipelineMetrics.record('ai_analysis', 'enqueued', groupId, {
            eventKey: `ai_analysis:enqueued:${groupId}:${stored.alert.seen_count || 1}`,
          });
          // Enrichment normally finishes in seconds. Let that committed
          // evidence wake AI first; launchd remains the bounded fallback.
          wakeAiAfterCommit = !enrichmentQueued;
        }
        // Automatic incident response owns a separate threshold and still
        // needs the worker even when base SOC analysis is below its floor.
        wakeAiAfterCommit = wakeAiAfterCommit || stored.incident?.status === 'queued';
      }
      await pipelineMetrics.record('alert_ingest', 'completed', stored.alert?.alert_id || 'unknown', {
        eventKey: `alert_ingest:completed:${stored.alert?.alert_id || 'unknown'}:${stored.alert?.seen_count || 1}`,
        sizeBytes: Buffer.byteLength(JSON.stringify(rawAlert || {})),
      });
    }
    return stored;
  }));
  if (!result.ok) return result;
  if (wakeAiAfterCommit) void signalAiWorkers('alert-committed');
  // Delivery is deliberately outside the ingest transaction. A Telegram
  // timeout cannot delay the webhook response or cause n8n to replay a safely
  // committed alert.
  void drainTelegramOutbox();
  void drainEnrichmentJobs();
  void drainN8nPostCommitJobs();
  return result;
}

async function transitionDurableJobStatus(jobType, dedupeKey, status, error = '', leaseToken = '') {
  let resolvedKey = dedupeKey;
  let transition = await durableJobs.transition(jobType, resolvedKey, status, error, leaseToken);
  let updated = Boolean(transition?.updated);
  if (!updated && ['ai_analysis', 'incident_response_analysis'].includes(jobType)) {
    // Workers deployed before stable V2 group identities report the legacy
    // dashboard key. Resolve that key at the write boundary so rolling
    // upgrades cannot leave healthy analysis work permanently pending.
    const alias = await get(
      'SELECT stable_group_id FROM alert_group_alias WHERE legacy_group_id = ?',
      [dedupeKey],
    );
    if (alias?.stable_group_id) {
      resolvedKey = String(alias.stable_group_id);
      transition = await durableJobs.transition(jobType, resolvedKey, status, error, leaseToken);
      updated = Boolean(transition?.updated);
    }
  }
  if (updated) {
    const job = await get(
      'SELECT status, attempt_count, updated_at, last_completed_at FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?',
      [jobType, resolvedKey],
    );
    const eventType = status === 'processing' ? 'started' : status;
    if (pipelineMetrics) {
      await pipelineMetrics.record(jobType, eventType, resolvedKey, {
        eventKey: `${jobType}:${eventType}:${resolvedKey}:${job?.attempt_count || 0}:${job?.last_completed_at || job?.updated_at || nowUtc()}`,
      });
    }
    if (jobType === 'ai_analysis' && status === 'completed' && job?.status === 'pending') {
      // Evidence arrived while this inference was running. The queue retained
      // one coalesced rerun request; wake launchd after the completed run.
      void signalAiWorkers('ai-rerun-pending');
    }
    if (jobType === 'incident_response_analysis') {
      const agentStatus = {
        pending: 'queued',
        processing: 'analyzing',
        completed: 'analyzed',
        failed: 'failed',
      }[job?.status] || 'queued';
      const caseRow = await get('SELECT case_id FROM incident_response_cases WHERE group_id = ?', [resolvedKey]);
      if (caseRow?.case_id) {
        await run(
          `UPDATE incident_response_cases
           SET agent_status = ?, latest_error = ?, updated_at = ?
           WHERE case_id = ?`,
          [agentStatus, job?.status === 'failed' ? safeString(error, 1000) : null, nowUtc(), caseRow.case_id],
        );
      }
      if (status === 'completed' && job?.status === 'pending') {
        void signalAiWorkers('incident-response-rerun-pending');
      }
    }
  }
  return {updated, resolvedKey, leaseToken: transition?.leaseToken || null};
}

async function recoverExpiredDurableJobs() {
  if (durableJobRecoveryActive || !durableJobs) return;
  durableJobRecoveryActive = true;
  try {
    const summary = await withSqliteWriteGate(() => withImmediateTransaction(
      () => durableJobs.recoverExpired(),
    ));
    if (!summary.recovered && !summary.failed) return;
    console.warn(`${nowUtc()} durable job lease recovery: ${JSON.stringify(summary)}`);
    if (summary.job_types.ai_analysis || summary.job_types.incident_response_analysis) {
      void signalAiWorkers('ai-lease-recovered');
    }
    if (summary.job_types.public_enrichment) void drainEnrichmentJobs();
    if (summary.job_types.n8n_post_commit) void drainN8nPostCommitJobs();
  } finally {
    durableJobRecoveryActive = false;
  }
}

async function resolveDashboardAlertGroup(dashboardGroupId) {
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
  return representative;
}

async function requestAiReanalysis(payload) {
  const dashboardGroupId = safeString(payload?.group_id, 64).toLowerCase();
  if (!/^[a-f0-9]{12}$/.test(dashboardGroupId)) {
    const error = new Error('valid dashboard group_id is required');
    error.statusCode = 400;
    throw error;
  }
  const representative = await resolveDashboardAlertGroup(dashboardGroupId);
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
  await durableJobs.enqueue('ai_analysis', stableGroupId, {
    alert_id: representative.alert_id,
    group_id: stableGroupId,
    dashboard_group_id: dashboardGroupId,
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
  const representative = await resolveDashboardAlertGroup(dashboardGroupId);
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
    manualReanalysis: true,
    eventType: 'escalated',
    priority: 1100,
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
      jsonText({dashboard_group_id: dashboardGroupId, reason: normalizedReason}),
      requestedAt,
    ],
  );
  await durableJobs.enqueue('incident_response_analysis', stableGroupId, {
    agent_role: 'incident-responder',
    case_id: incident.case_id,
    alert_id: representative.alert_id,
    group_id: stableGroupId,
    dashboard_group_id: dashboardGroupId,
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
    escalated_at: incident.escalated_at,
    requested_at: requestedAt,
  };
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
          if (socAnalysisPolicy.matchesAnalysis(level)) {
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
  // Store indexed summary fields for reports plus the full scored JSON for
  // investigation-note generation.
  const alertId = alert.alert_id;
  if (!alertId) {
    return {ok: false, status: 'rejected', reason: 'missing alert_id'};
  }

  const previousGroupKey = await currentAlertGroupKey(alertId);
  const timestamp = nowUtc();
  const dropRule = findDropRule(alert);
  if (dropRule) {
    return {
      ok: true,
      status: 'dropped',
      stored: false,
      alert: {
        alert_id: alertId,
        rule_name: alert.rule_name || null,
        event_dataset: alert.event_dataset || null,
        source_ip: nestedField(alert, 'source.ip'),
        destination_ip: nestedField(alert, 'destination.ip'),
        triage_score: nestedField(alert, 'triage.score'),
        triage_level: nestedField(alert, 'triage.level'),
        routing: 'dropped',
      },
      triage: {
        ...alert.triage,
        routing: 'dropped',
        reasons: [...(alert.triage.reasons || []), `dropped by policy: ${ruleName(dropRule)}`],
      },
      filter: {
        status: 'dropped',
        rule: ruleName(dropRule),
        reason: dropRule.reason || 'matched drop rule',
      },
      notification: {channel: 'telegram', status: 'skipped_filter'},
    };
  }

  const params = {
    $alert_id: alertId,
    $first_seen: timestamp,
    $last_seen: timestamp,
    $timestamp: normalizeTimestampValue(alert.timestamp),
    $rule_name: alert.rule_name || null,
    $event_dataset: alert.event_dataset || null,
    $severity: alert.severity ?? null,
    $severity_label: alert.severity_label || null,
    $source_ip: nestedField(alert, 'source.ip'),
    $source_port: integerField(nestedField(alert, 'source.port')),
    $destination_ip: nestedField(alert, 'destination.ip'),
    $destination_port: integerField(nestedField(alert, 'destination.port')),
    $network_protocol: nestedField(alert, 'network.protocol'),
    $transport_protocol: nestedField(alert, 'network.transport') || nestedField(alert, 'network.iana_number'),
    $traffic_direction: nestedField(alert, 'triage.traffic_direction'),
    $triage_score: nestedField(alert, 'triage.score'),
    $triage_level: nestedField(alert, 'triage.level'),
    $routing: nestedField(alert, 'triage.routing'),
    $filter_status: 'accepted',
    $filter_reason: null,
    $suppression_key: null,
    $raw_event_json: jsonText(nestedField(alert, 'security_onion.raw_event')),
    $enrichment_json: jsonText(enrichmentRecord(alert)),
    $alert_json: jsonText(alert),
  };

  const insert = await run(
    `
      INSERT OR IGNORE INTO alerts (
        alert_id, first_seen, last_seen, seen_count, timestamp,
        rule_name, event_dataset, severity, severity_label,
        source_ip, source_port, destination_ip, destination_port,
        network_protocol, transport_protocol, traffic_direction, triage_score,
        triage_level, routing, filter_status, filter_reason,
        suppression_key, raw_event_json, enrichment_json, alert_json
      )
      VALUES (
        $alert_id, $first_seen, $last_seen, 1, $timestamp,
        $rule_name, $event_dataset, $severity, $severity_label,
        $source_ip, $source_port, $destination_ip, $destination_port,
        $network_protocol, $transport_protocol, $traffic_direction, $triage_score,
        $triage_level, $routing, $filter_status, $filter_reason,
        $suppression_key, $raw_event_json, $enrichment_json, $alert_json
      )
    `,
    params,
  );

  const inserted = insert.changes === 1;
  const suppression = inserted ? await applySuppressionPolicy(alert, timestamp) : {status: 'not_applicable'};
  if (suppression.status === 'suppressed') {
    alert.triage = {
      ...alert.triage,
      routing: 'suppressed',
      reasons: [...(alert.triage.reasons || []), `suppressed by policy: ${suppression.rule}`],
    };
  }
  if (suppression.status === 'escalated') {
    alert.triage = {
      ...alert.triage,
      reasons: [...(alert.triage.reasons || []), `suppression escalation threshold reached: ${suppression.seen_count} in window`],
    };
  }

  if (!inserted) {
    // Duplicate alert IDs update seen_count/last_seen and can be rescored, but
    // they do not create new Telegram notifications.
    await run(
      `
        UPDATE alerts
        SET last_seen = $last_seen,
            seen_count = seen_count + 1,
            source_port = $source_port,
            destination_port = $destination_port,
            network_protocol = $network_protocol,
            transport_protocol = $transport_protocol,
            traffic_direction = $traffic_direction,
            triage_score = $triage_score,
            triage_level = $triage_level,
            routing = $routing,
            filter_status = $filter_status,
            filter_reason = $filter_reason,
            suppression_key = $suppression_key,
            raw_event_json = $raw_event_json,
            enrichment_json = $enrichment_json,
            alert_json = $alert_json
        WHERE alert_id = $alert_id
      `,
      {
        $last_seen: timestamp,
        $source_port: params.$source_port,
        $destination_port: params.$destination_port,
        $network_protocol: params.$network_protocol,
        $transport_protocol: params.$transport_protocol,
        $traffic_direction: nestedField(alert, 'triage.traffic_direction'),
        $triage_score: nestedField(alert, 'triage.score'),
        $triage_level: nestedField(alert, 'triage.level'),
        $routing: nestedField(alert, 'triage.routing'),
        $filter_status: 'duplicate',
        $filter_reason: null,
        $suppression_key: null,
        $raw_event_json: params.$raw_event_json,
        $enrichment_json: params.$enrichment_json,
        $alert_json: params.$alert_json,
        $alert_id: params.$alert_id,
      },
    );
  } else if (suppression.status === 'suppressed' || suppression.status === 'escalated') {
    await run(
      `
        UPDATE alerts
        SET source_port = $source_port,
            destination_port = $destination_port,
            network_protocol = $network_protocol,
            transport_protocol = $transport_protocol,
            routing = $routing,
            filter_status = $filter_status,
            filter_reason = $filter_reason,
            suppression_key = $suppression_key,
            raw_event_json = $raw_event_json,
            enrichment_json = $enrichment_json,
            alert_json = $alert_json
        WHERE alert_id = $alert_id
      `,
      {
        $source_port: integerField(nestedField(alert, 'source.port')),
        $destination_port: integerField(nestedField(alert, 'destination.port')),
        $network_protocol: nestedField(alert, 'network.protocol'),
        $transport_protocol: nestedField(alert, 'network.transport') || nestedField(alert, 'network.iana_number'),
        $routing: nestedField(alert, 'triage.routing'),
        $filter_status: suppression.status,
        $filter_reason: suppression.reason || null,
        $suppression_key: suppression.key || null,
        $raw_event_json: jsonText(nestedField(alert, 'security_onion.raw_event')),
        $enrichment_json: jsonText(enrichmentRecord(alert)),
        $alert_json: jsonText(alert),
        $alert_id: alertId,
      },
    );
  }

  const row = await get(
    `
      SELECT alert_id, first_seen, last_seen, seen_count, timestamp,
             rule_name, event_dataset, severity, severity_label,
             source_ip, source_port, destination_ip, destination_port,
             network_protocol, transport_protocol, traffic_direction, triage_score,
             triage_level, routing, filter_status, filter_reason,
             suppression_key
      FROM alerts
      WHERE alert_id = ?
    `,
    [alertId],
  );
  const stableIdentity = await persistStableIdentity(alertId, row, alert);
  Object.assign(row, stableIdentity);
  await indexAlertObservables(alert, row);
  const nextGroupKey = alertGroupKeyFromRow(row);
  if (previousGroupKey && previousGroupKey !== nextGroupKey) {
    await refreshAlertGroupSummary(previousGroupKey);
  }
  await refreshAlertGroupSummary(nextGroupKey);
  const pcap = await maybeQueueAutomaticPcapRequest(alert, row, inserted, suppression);
  const incident = await maybeQueueAutomaticIncidentResponse(alert, row, inserted, suppression);

  return {
    ok: true,
    status: inserted ? (suppression.status === 'suppressed' ? 'suppressed' : 'accepted') : 'already_seen',
    stored: inserted,
    alert: row,
    triage: alert.triage,
    filter: suppression,
    pcap,
    incident,
    notification: {channel: 'telegram', status: 'pending'},
  };
}

async function applySuppressionPolicy(alert, now) {
  // Suppression windows are time-boxed. They reduce repeat notifications and
  // Markdown reports, but every alert row still lands in SQLite for evidence.
  const rule = findSuppressRule(alert);
  if (!rule) return {status: 'accepted'};

  const key = suppressionKey(rule, alert);
  const ttlSeconds = Number(rule.ttl_seconds || rule.suppress_seconds || 1800);
  const escalationThreshold = Number(rule.escalation_threshold || 0);
  const existing = await get('SELECT * FROM suppression_log WHERE suppression_key = ?', [key]);
  const expired = existing ? secondsSince(existing.window_start, now) >= ttlSeconds : true;

  if (!existing || expired) {
    await run(
      `
        INSERT INTO suppression_log (
          suppression_key, rule_name, reason, window_start, last_seen,
          seen_count, suppressed_count, escalated_count, ttl_seconds,
          escalation_threshold
        )
        VALUES (?, ?, ?, ?, ?, 1, 0, 0, ?, ?)
        ON CONFLICT(suppression_key) DO UPDATE SET
          rule_name = excluded.rule_name,
          reason = excluded.reason,
          window_start = excluded.window_start,
          last_seen = excluded.last_seen,
          seen_count = 1,
          suppressed_count = 0,
          escalated_count = 0,
          ttl_seconds = excluded.ttl_seconds,
          escalation_threshold = excluded.escalation_threshold
      `,
      [key, ruleName(rule), rule.reason || null, now, now, ttlSeconds, escalationThreshold],
    );
    return {
      status: 'accepted',
      key,
      rule: ruleName(rule),
      reason: rule.reason || null,
      ttl_seconds: ttlSeconds,
      seen_count: 1,
    };
  }

  const nextSeenCount = Number(existing.seen_count || 0) + 1;
  const shouldEscalate = escalationThreshold > 0 && nextSeenCount % escalationThreshold === 0;
  // Escalation lets a noisy pattern break through periodically so a real
  // compromise is not hidden forever by a broad suppression rule.
  await run(
    `
      UPDATE suppression_log
      SET last_seen = ?,
          seen_count = seen_count + 1,
          suppressed_count = suppressed_count + ?,
          escalated_count = escalated_count + ?
      WHERE suppression_key = ?
    `,
    [now, shouldEscalate ? 0 : 1, shouldEscalate ? 1 : 0, key],
  );

  return {
    status: shouldEscalate ? 'escalated' : 'suppressed',
    key,
    rule: ruleName(rule),
    reason: rule.reason || null,
    ttl_seconds: ttlSeconds,
    escalation_threshold: escalationThreshold || null,
    seen_count: nextSeenCount,
  };
}

async function rescoreAlertsUnlocked() {
  // POST /rescore after editing scoring_rules.json to update existing rows
  // without replaying historical alerts from Security Onion.
  const rows = await all('SELECT alert_id, alert_json FROM alerts');
  let rescored = 0;
  let skipped = 0;

  for (const row of rows) {
    try {
      const alert = JSON.parse(row.alert_json);
      alert.triage = scoreAlert(alert);
      await run(
        `
          UPDATE alerts
          SET source_port = $source_port,
              destination_port = $destination_port,
              network_protocol = $network_protocol,
              transport_protocol = $transport_protocol,
              traffic_direction = $traffic_direction,
              triage_score = $triage_score,
              triage_level = $triage_level,
              routing = $routing,
              raw_event_json = $raw_event_json,
              enrichment_json = $enrichment_json,
              alert_json = $alert_json
          WHERE alert_id = $alert_id
        `,
        {
          $source_port: integerField(nestedField(alert, 'source.port')),
          $destination_port: integerField(nestedField(alert, 'destination.port')),
          $network_protocol: nestedField(alert, 'network.protocol'),
          $transport_protocol: nestedField(alert, 'network.transport') || nestedField(alert, 'network.iana_number'),
          $traffic_direction: alert.triage.traffic_direction,
          $triage_score: alert.triage.score,
          $triage_level: alert.triage.level,
          $routing: alert.triage.routing,
          $raw_event_json: jsonText(nestedField(alert, 'security_onion.raw_event')),
          $enrichment_json: jsonText(enrichmentRecord(alert)),
          $alert_json: jsonText(alert),
          $alert_id: row.alert_id,
        },
      );
      rescored += 1;
    } catch (error) {
      skipped += 1;
    }
  }

  const groupSummary = await rebuildAlertGroupSummariesUnlocked();

  return {
    ok: true,
    status: 'rescored',
    total_alerts: rows.length,
    rescored,
    skipped,
    group_summary_groups: groupSummary.groups,
    scoring_rules: path.basename(scoringRulesPath),
  };
}

async function rescoreAlerts() {
  // Maintenance writes must not interleave with multi-statement ingestion.
  return withSqliteWriteGate(rescoreAlertsUnlocked);
}

function isTelegramConfigured() {
  return Boolean(telegramBotToken && telegramChatId);
}

function notificationKey(alert) {
  // Cooldown groups similar alerts by level/rule/source/destination instead of
  // raw alert_id, so a burst creates one phone notification.
  const level = String(nestedField(alert, 'triage.level') || 'unknown').toLowerCase();
  const ruleName = alert.rule_name || 'unknown-rule';
  const sourceIp = nestedField(alert, 'source.ip') || 'unknown-source';
  const destinationIp = nestedField(alert, 'destination.ip') || 'unknown-destination';
  return `${level}|${ruleName}|${sourceIp}|${destinationIp}`;
}

function secondsSince(isoTimestamp, nowIso) {
  return Math.floor((Date.parse(nowIso) - Date.parse(isoTimestamp)) / 1000);
}

function escapeTelegram(text) {
  // Telegram HTML mode needs these escapes for generated alert text.
  return String(text ?? '').replace(/[&<>]/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
  }[char]));
}

function shortAlertId(alertId) {
  const value = String(alertId || 'unknown');
  const lastPart = value.split(':').pop() || value;
  return lastPart.length > 18 ? `${lastPart.slice(0, 18)}...` : lastPart;
}

function whyThisAlerted(triage) {
  // Lead with one meaningful reason for lock-screen readability.
  const level = String(triage.level || 'unknown').toLowerCase();
  const direction = triage.traffic_direction || 'unknown direction';
  const reasons = Array.isArray(triage.reasons) ? triage.reasons : [];
  const notableReason = reasons.find((reason) => !String(reason).startsWith('base severity score'));
  if (level === 'critical') {
    return notableReason ? `Critical score driven by ${notableReason}.` : 'Critical deterministic triage score.';
  }
  if (level === 'high') {
    return notableReason ? `High priority because ${notableReason}.` : 'High deterministic triage score.';
  }
  return `Alert routed as ${level} based on ${direction} traffic and rule context.`;
}

function formatTelegramAlert(alert, storedAlert) {
  // Keep phone alerts compact but actionable: rule, time, score, route,
  // source/destination, and the top deterministic reasons.
  const triage = alert.triage || {};
  const level = String(triage.level || storedAlert.triage_level || 'unknown').toUpperCase();
  const score = triage.score ?? storedAlert.triage_score ?? 'unknown';
  const direction = triage.traffic_direction || storedAlert.traffic_direction || 'unknown';
  const sourceIp = nestedField(alert, 'source.ip') || storedAlert.source_ip || 'unknown';
  const destinationIp = nestedField(alert, 'destination.ip') || storedAlert.destination_ip || 'unknown';
  const timestamp = normalizeTimestampValue(alert.timestamp || storedAlert.timestamp) || 'unknown time';
  const alertId = shortAlertId(alert.alert_id || storedAlert.alert_id);
  const reasons = Array.isArray(triage.reasons) ? triage.reasons.slice(0, 4) : [];
  const reasonText = reasons.length
    ? reasons.map((reason) => `- ${escapeTelegram(reason)}`).join('\n')
    : '- no deterministic reasons provided';

  return [
    `<b>[${escapeTelegram(level)}] Security Onion Alert</b>`,
    escapeTelegram(alert.rule_name || storedAlert.rule_name || 'Unknown rule'),
    '',
    `Time: ${escapeTelegram(timestamp)}`,
    `Alert ID: ${escapeTelegram(alertId)}`,
    `Score: ${escapeTelegram(score)}`,
    `Direction: ${escapeTelegram(direction)}`,
    `Route: ${escapeTelegram(triage.routing || storedAlert.routing || 'unknown')}`,
    '',
    `${escapeTelegram(sourceIp)} -> ${escapeTelegram(destinationIp)}`,
    '',
    `<b>Why this alerted</b>`,
    escapeTelegram(whyThisAlerted(triage)),
    '',
    '<b>Reasons</b>',
    reasonText,
  ].join('\n');
}

function postTelegramMessage(text) {
  // alert-store sends Telegram messages directly so n8n can stay a thin
  // validation/routing layer.
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      chat_id: telegramChatId,
      text,
      parse_mode: 'HTML',
      disable_web_page_preview: true,
    });
    const req = require('https').request(
      {
        hostname: 'api.telegram.org',
        port: 443,
        path: `/bot${telegramBotToken}/sendMessage`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
        timeout: 10000,
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => body += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve({ok: true, statusCode: res.statusCode});
          } else {
            reject(new Error(`Telegram returned HTTP ${res.statusCode}: ${body.slice(0, 300)}`));
          }
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('Telegram request timed out')));
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function queueTelegramNotification(alert, storedAlert, inserted, now, suppression = {status: 'accepted'}) {
  // This function runs inside the alert transaction. It never performs network
  // I/O, so the alert and its durable notification intent commit together.
  if (!inserted) {
    return {channel: 'telegram', status: 'skipped_duplicate'};
  }
  if (suppression.status === 'suppressed') {
    return {
      channel: 'telegram',
      status: 'skipped_suppression',
      suppression_key: suppression.key || null,
      suppression_rule: suppression.rule || null,
      suppression_ttl_seconds: suppression.ttl_seconds || null,
      suppression_seen_count: suppression.seen_count || null,
    };
  }
  if (!isTelegramConfigured()) {
    return {channel: 'telegram', status: 'disabled'};
  }

  const triageLevel = String(nestedField(alert, 'triage.level') || '').toLowerCase();
  if (!telegramAlertLevels.has(triageLevel)) {
    return {channel: 'telegram', status: 'skipped_level', triage_level: triageLevel};
  }

  const key = notificationKey(alert);
  const existing = await get(
    'SELECT last_sent, sent_count FROM notification_log WHERE notification_key = ?',
    [key],
  );
  if (existing && secondsSince(existing.last_sent, now) < telegramCooldownSeconds) {
    return {
      channel: 'telegram',
      status: 'skipped_cooldown',
      cooldown_seconds: telegramCooldownSeconds,
    };
  }
  const pending = await get(
    `SELECT id FROM notification_outbox
     WHERE notification_key = ? AND status IN ('pending', 'delivering')
     ORDER BY id DESC LIMIT 1`,
    [key],
  );
  if (pending) {
    return {channel: 'telegram', status: 'skipped_pending', triage_level: triageLevel};
  }
  await run(
    `
      INSERT INTO notification_outbox (
        notification_key, channel, alert_id, triage_level, rule_name,
        source_ip, destination_ip, payload_json, status, attempt_count,
        next_attempt_at, created_at, updated_at
      )
      VALUES (?, 'telegram', ?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)
    `,
    [
      key,
      alert.alert_id,
      triageLevel,
      alert.rule_name || null,
      nestedField(alert, 'source.ip'),
      nestedField(alert, 'destination.ip'),
      JSON.stringify({text: formatTelegramAlert(alert, storedAlert)}),
      now,
      now,
      now,
    ],
  );
  return {channel: 'telegram', status: 'queued', triage_level: triageLevel};
}

function outboxRetryTimestamp(attemptCount) {
  const delaySeconds = Math.min(
    telegramOutboxMaxRetrySeconds,
    telegramOutboxBaseRetrySeconds * (2 ** Math.max(0, attemptCount - 1)),
  );
  return formatProjectTimestamp(new Date(Date.now() + delaySeconds * 1000));
}

async function claimTelegramOutboxItem() {
  return withSqliteWriteGate(() => withImmediateTransaction(async () => {
    const row = await get(
      `SELECT * FROM notification_outbox
       WHERE status = 'pending' AND next_attempt_at <= ?
       ORDER BY next_attempt_at ASC, id ASC LIMIT 1`,
      [nowUtc()],
    );
    if (!row) return null;
    await run(
      "UPDATE notification_outbox SET status = 'delivering', attempt_count = attempt_count + 1, updated_at = ? WHERE id = ?",
      [nowUtc(), row.id],
    );
    return {...row, attempt_count: Number(row.attempt_count || 0) + 1};
  }));
}

async function completeTelegramOutboxItem(item) {
  const sentAt = nowUtc();
  await withSqliteWriteGate(() => withImmediateTransaction(async () => {
    await run(
      "UPDATE notification_outbox SET status = 'sent', sent_at = ?, updated_at = ?, last_error = NULL WHERE id = ?",
      [sentAt, sentAt, item.id],
    );
    await run(
      `INSERT INTO notification_log (
         notification_key, last_sent, sent_count, channel, alert_id,
         triage_level, rule_name, source_ip, destination_ip
       ) VALUES (?, ?, 1, 'telegram', ?, ?, ?, ?, ?)
       ON CONFLICT(notification_key) DO UPDATE SET
         last_sent = excluded.last_sent,
         sent_count = notification_log.sent_count + 1,
         alert_id = excluded.alert_id,
         triage_level = excluded.triage_level,
         rule_name = excluded.rule_name,
         source_ip = excluded.source_ip,
         destination_ip = excluded.destination_ip`,
      [item.notification_key, sentAt, item.alert_id, item.triage_level, item.rule_name, item.source_ip, item.destination_ip],
    );
  }));
}

async function failTelegramOutboxItem(item, error) {
  const terminal = Number(item.attempt_count || 0) >= telegramOutboxMaxAttempts;
  await withSqliteWriteGate(() => run(
    `UPDATE notification_outbox
     SET status = ?, next_attempt_at = ?, last_error = ?, updated_at = ?
     WHERE id = ?`,
    [
      terminal ? 'failed' : 'pending',
      terminal ? nowUtc() : outboxRetryTimestamp(item.attempt_count),
      String(error.message || error).slice(0, 500),
      nowUtc(),
      item.id,
    ],
  ));
}

async function drainTelegramOutbox() {
  if (!telegramOutboxAutostart || !isTelegramConfigured() || telegramOutboxDrainActive) return;
  telegramOutboxDrainActive = true;
  try {
    for (let processed = 0; processed < 10; processed += 1) {
      const item = await claimTelegramOutboxItem();
      if (!item) break;
      try {
        const payload = JSON.parse(item.payload_json || '{}');
        await postTelegramMessage(String(payload.text || ''));
        await completeTelegramOutboxItem(item);
      } catch (error) {
        await failTelegramOutboxItem(item, error);
        break;
      }
    }
  } catch (error) {
    console.error(`Telegram outbox drain failed: ${error.message}`);
  } finally {
    telegramOutboxDrainActive = false;
  }
}

async function telegramOutboxSnapshot() {
  const rows = await all('SELECT status, COUNT(*) AS count FROM notification_outbox GROUP BY status');
  return Object.fromEntries(rows.map((row) => [row.status, Number(row.count || 0)]));
}

function safeString(value, maxLength = 240) {
  return String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, maxLength);
}

function safeFileToken(value, fallback = 'artifact') {
  const cleaned = safeString(value, 180)
    .replace(/[^A-Za-z0-9_.-]+/g, '-')
    .replace(/^[.-]+|[.-]+$/g, '');
  return cleaned || fallback;
}

function parseJsonObject(value) {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (_) {
    return {};
  }
}

function pcapRequestId(seed) {
  return crypto.createHash('sha256').update(JSON.stringify(seed)).digest('hex').slice(0, 16);
}

function pcapCandidateFromRow(row) {
  if (!row) return {};
  const alertJson = parseJsonObject(row.alert_json);
  const rawEventJson = parseJsonObject(row.raw_event_json);
  const captureFile =
    nestedField(rawEventJson, 'suricata.capture_file') ||
    nestedField(rawEventJson, 'message.capture_file') ||
    nestedField(alertJson, 'suricata.capture_file') ||
    nestedField(alertJson, 'capture_file') ||
    null;
  return {
    alert_id: row.alert_id || row.representative_alert_id || null,
    group_id: row.group_id || null,
    group_key: row.group_key || null,
    first_seen: row.first_seen || row.timestamp || null,
    last_seen: row.last_seen || row.timestamp || null,
    source_ip: row.source_ip || nestedField(alertJson, 'source.ip') || nestedField(rawEventJson, 'source.ip') || null,
    source_port: integerField(row.source_port ?? nestedField(alertJson, 'source.port') ?? nestedField(rawEventJson, 'source.port')),
    destination_ip: row.destination_ip || nestedField(alertJson, 'destination.ip') || nestedField(rawEventJson, 'destination.ip') || null,
    destination_port: integerField(row.destination_port ?? nestedField(alertJson, 'destination.port') ?? nestedField(rawEventJson, 'destination.port')),
    network_protocol: row.network_protocol || nestedField(alertJson, 'network.protocol') || nestedField(rawEventJson, 'network.protocol') || null,
    transport_protocol: row.transport_protocol || nestedField(alertJson, 'network.transport') || nestedField(rawEventJson, 'network.transport') || null,
    community_id: nestedField(alertJson, 'network.community_id') || nestedField(rawEventJson, 'network.community_id') || null,
    capture_file: captureFile,
  };
}

async function pcapCandidateFromPayload(payload) {
  if (payload.alert_id) {
    const row = await get('SELECT * FROM alerts WHERE alert_id = ?', [String(payload.alert_id)]);
    if (row) return pcapCandidateFromRow(row);
  }
  if (payload.group_id) {
    const row = await get('SELECT * FROM alert_group_summary WHERE group_id = ?', [String(payload.group_id)]);
    if (row) {
      if (row.representative_alert_id) {
        const representative = await get('SELECT * FROM alerts WHERE alert_id = ?', [row.representative_alert_id]);
        if (representative) return pcapCandidateFromRow(representative);
      }
      const newest = await get(`
        SELECT *
        FROM alerts
        WHERE COALESCE(
          NULLIF(suppression_key, ''),
          COALESCE(triage_level, 'unknown-level') || '|' ||
          COALESCE(rule_name, 'unknown-rule') || '|' ||
          COALESCE(source_ip, 'unknown-source') || '|' ||
          COALESCE(destination_ip, 'unknown-destination') || '|' ||
          COALESCE(filter_status, 'accepted')
        ) = ?
        ORDER BY last_seen DESC
        LIMIT 1
      `, [row.group_key]);
      if (newest) return pcapCandidateFromRow(newest);
      return pcapCandidateFromRow(row);
    }
  }
  return {};
}

function normalizePcapRequest(payload, candidate = {}) {
  const merged = {...candidate, ...(payload || {})};
  const reason = safeString(merged.reason, 240);
  if (!reason) throw new Error('pcap request reason is required');
  const sourceIp = safeString(merged.source_ip, 64);
  const destinationIp = safeString(merged.destination_ip, 64);
  if (!sourceIp || !destinationIp) throw new Error('pcap request requires source_ip and destination_ip');
  const destinationPort = integerField(merged.destination_port);
  const sourcePort = integerField(merged.source_port);
  const firstSeen = normalizeTimestampValue(merged.first_seen || merged.timestamp || merged.last_seen);
  const lastSeen = normalizeTimestampValue(merged.last_seen || merged.timestamp || merged.first_seen);
  if (!firstSeen || !lastSeen) throw new Error('pcap request requires first_seen and last_seen timestamps');
  const requestedWindow = Number(merged.max_window_seconds || pcapRequestDefaultWindowSeconds);
  const maxWindowSeconds = Math.min(
    pcapRequestMaxWindowSeconds,
    Math.max(30, Number.isFinite(requestedWindow) ? Math.round(requestedWindow) : pcapRequestDefaultWindowSeconds),
  );
  const request = {
    alert_id: safeString(merged.alert_id, 512) || null,
    group_id: safeString(merged.group_id, 64) || null,
    group_key: safeString(merged.group_key, 512) || null,
    first_seen: firstSeen,
    last_seen: lastSeen,
    source_ip: sourceIp,
    source_port: sourcePort,
    destination_ip: destinationIp,
    destination_port: destinationPort,
    network_protocol: safeString(merged.network_protocol, 32) || null,
    transport_protocol: safeString(merged.transport_protocol, 32).toLowerCase() || null,
    community_id: safeString(merged.community_id, 128) || null,
    capture_file: safeString(merged.capture_file, 512) || null,
    requested_by: safeString(merged.requested_by || 'soc-analyst', 80),
    reason,
    max_window_seconds: maxWindowSeconds,
    require_source_port: Boolean(merged.require_source_port),
  };
  request.request_id = pcapRequestId({
    alert_id: request.alert_id,
    group_id: request.group_id,
    first_seen: request.first_seen,
    last_seen: request.last_seen,
    source_ip: request.source_ip,
    source_port: request.source_port,
    destination_ip: request.destination_ip,
    destination_port: request.destination_port,
    community_id: request.community_id,
    capture_file: request.capture_file,
    reason: request.reason,
  });
  return request;
}

function pcapRetentionError(lastSeen) {
  if (!pcapCaptureRetentionSeconds || !lastSeen) return null;
  const occurredAt = Date.parse(String(lastSeen).replace('  ', 'T'));
  if (!Number.isFinite(occurredAt)) return null;
  const ageSeconds = Math.floor((Date.now() - occurredAt) / 1000);
  if (ageSeconds <= pcapCaptureRetentionSeconds) return null;
  return `PCAP request exceeds configured capture retention (${pcapCaptureRetentionSeconds}s)`;
}

function pcapRequestFromRow(row) {
  const requestJson = parseJsonObject(row.request_json);
  return {
    request_id: row.request_id,
    status: row.status,
    alert_id: row.alert_id,
    group_id: row.group_id,
    group_key: row.group_key,
    first_seen: row.first_seen,
    last_seen: row.last_seen,
    source_ip: row.source_ip,
    source_port: row.source_port,
    destination_ip: row.destination_ip,
    destination_port: row.destination_port,
    network_protocol: row.network_protocol,
    transport_protocol: row.transport_protocol,
    community_id: row.community_id,
    capture_file: requestJson.capture_file || null,
    requested_by: row.requested_by,
    reason: row.reason,
    max_window_seconds: row.max_window_seconds,
    require_source_port: Boolean(requestJson.require_source_port),
    relay_host: row.relay_host,
    artifact_path: row.artifact_path,
    artifact_sha256: row.artifact_sha256,
    artifact_size_bytes: row.artifact_size_bytes,
    error: row.error,
    outcome: row.outcome || classifyPcapOutcome(row.status, row.error, parseJsonObject(row.diagnostics_json)),
    diagnostics: parseJsonObject(row.diagnostics_json),
    analysis_status: row.analysis_status || 'not_ready',
    analysis_attempt_count: Number(row.analysis_attempt_count || 0),
    analysis_error: row.analysis_error || null,
    analysis_started_at: row.analysis_started_at || null,
    analysis_completed_at: row.analysis_completed_at || null,
    transfer_stage: row.transfer_stage || null,
    transfer_bytes: Number(row.transfer_bytes || 0),
    transfer_total_bytes: Number(row.transfer_total_bytes || 0),
    transfer_progress_at: row.transfer_progress_at || null,
    transfer_duration_seconds: row.transfer_duration_seconds == null
      ? null
      : Number(row.transfer_duration_seconds),
    transfer_attempt_count: Number(row.transfer_attempt_count || 0),
    transfer_retry_count: Number(row.transfer_retry_count || 0),
    transfer_last_error: row.transfer_last_error || null,
    transfer_last_failed_stage: row.transfer_last_failed_stage || null,
    next_attempt_at: row.next_attempt_at || null,
    created_at: row.created_at,
    claimed_at: row.claimed_at,
    completed_at: row.completed_at,
    updated_at: row.updated_at,
  };
}

const PCAP_OUTCOMES = new Set([
  'captured', 'no_packets_available', 'expired', 'oversize', 'timeout',
  'transport_failed', 'checksum_failed', 'rejected', 'failed',
]);

function classifyPcapOutcome(status, error, diagnostics = {}) {
  const state = String(status || '').toLowerCase();
  const detail = `${String(error || '')} ${JSON.stringify(diagnostics || {})}`.toLowerCase();
  if (state === 'fulfilled') return 'captured';
  if (detail.includes('no matching packet')) return 'no_packets_available';
  if (detail.includes('capture retention') || detail.includes('expired')) return 'expired';
  if (detail.includes('exceed') && (detail.includes('size') || detail.includes('artifact'))) return 'oversize';
  if (detail.includes('timeout') || detail.includes('timed out')) return 'timeout';
  if (detail.includes('sha256') || detail.includes('checksum')) return 'checksum_failed';
  if (detail.includes('rsync') || detail.includes('artifact upload') || detail.includes('connection') || detail.includes('ssh')) {
    return 'transport_failed';
  }
  if (state === 'rejected') return 'rejected';
  return state === 'failed' ? 'failed' : '';
}

async function backfillPcapOutcomes() {
  const rows = await all("SELECT request_id, status, error, diagnostics_json FROM pcap_requests WHERE outcome IS NULL OR outcome = '' OR outcome = 'failed'");
  for (const row of rows) {
    const outcome = classifyPcapOutcome(row.status, row.error, parseJsonObject(row.diagnostics_json));
    if (outcome) await run('UPDATE pcap_requests SET outcome = ? WHERE request_id = ?', [outcome, row.request_id]);
  }
}

async function createPcapRequest(payload) {
  const candidate = await pcapCandidateFromPayload(payload);
  const normalized = normalizePcapRequest(payload, candidate);
  const now = nowUtc();
  const retentionError = pcapRetentionError(normalized.last_seen);
  const initialStatus = retentionError ? 'rejected' : 'pending';
  await run(
    `
      INSERT INTO pcap_requests (
        request_id, status, alert_id, group_id, group_key, first_seen, last_seen,
        source_ip, source_port, destination_ip, destination_port, network_protocol,
        transport_protocol, community_id, requested_by, reason, max_window_seconds,
        error, outcome, request_json, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(request_id) DO UPDATE SET
        status = excluded.status,
        reason = excluded.reason,
        requested_by = excluded.requested_by,
        max_window_seconds = excluded.max_window_seconds,
        request_json = excluded.request_json,
        claimed_at = NULL,
        completed_at = NULL,
        error = NULL,
        artifact_path = NULL,
        artifact_sha256 = NULL,
        artifact_size_bytes = NULL,
        transfer_stage = NULL,
        transfer_bytes = 0,
        transfer_total_bytes = 0,
        transfer_progress_at = NULL,
        transfer_duration_seconds = NULL,
        transfer_attempt_count = 0,
        transfer_retry_count = 0,
        transfer_last_error = NULL,
        transfer_last_failed_stage = NULL,
        next_attempt_at = NULL,
        outcome = excluded.outcome,
        updated_at = excluded.updated_at
    `,
    [
      normalized.request_id,
      initialStatus,
      normalized.alert_id,
      normalized.group_id,
      normalized.group_key,
      normalized.first_seen,
      normalized.last_seen,
      normalized.source_ip,
      normalized.source_port,
      normalized.destination_ip,
      normalized.destination_port,
      normalized.network_protocol,
      normalized.transport_protocol,
      normalized.community_id,
      normalized.requested_by,
      normalized.reason,
      normalized.max_window_seconds,
      retentionError || null,
      retentionError ? 'expired' : null,
      jsonText(normalized),
      now,
      now,
    ],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [normalized.request_id]);
  await pipelineMetrics.record('pcap_transfer', initialStatus === 'pending' ? 'enqueued' : 'failed', normalized.request_id, {
    eventKey: `pcap_transfer:${initialStatus === 'pending' ? 'enqueued' : 'failed'}:${normalized.request_id}:${row.updated_at}`,
  });
  return {
    ok: true,
    status: row.status,
    request: pcapRequestFromRow(row),
    execution: {
      enabled: false,
      reason: 'PCAP fulfillment is intentionally brokered by the relay/Security Onion forced-command path, not by alert-store.',
    },
  };
}

async function maybeQueueAutomaticPcapRequest(alert, storedRow, inserted, suppression) {
  if (!inserted) return {status: 'skipped_duplicate'};
  if (!storedRow || ['suppressed', 'dropped'].includes(String(storedRow.filter_status || '').toLowerCase())) {
    return {status: 'skipped_filter'};
  }
  if (suppression?.status === 'suppressed') return {status: 'skipped_suppression'};

  const level = String(nestedField(alert, 'triage.level') || storedRow.triage_level || '').toLowerCase();
  const threshold = socAnalysisPolicy.read().soc_analyst_pcap_min_severity;
  if (!socAnalysisPolicy.matchesPcap(level)) {
    return {status: 'skipped_level', triage_level: level, threshold};
  }

  try {
    const groupKey = alertGroupKeyFromRow(storedRow);
    const groupId = alertGroupId(groupKey);
    const stableId = storedRow.stable_group_id || groupId;
    const existingPending = await get(
      `SELECT p.* FROM pcap_requests p
       LEFT JOIN alert_group_alias a ON a.legacy_group_id = p.group_id
       WHERE COALESCE(a.stable_group_id, p.group_id) = ? AND p.status = 'pending'
       ORDER BY p.created_at DESC LIMIT 1`,
      [stableId],
    );
    if (existingPending) {
      const existingPayload = parseJsonObject(existingPending.request_json);
      existingPayload.last_seen = storedRow.last_seen || existingPayload.last_seen;
      existingPayload.alert_id = storedRow.alert_id || existingPayload.alert_id;
      await run(
        `UPDATE pcap_requests SET alert_id = ?, last_seen = ?, request_json = ?,
           reason = ?, updated_at = ? WHERE request_id = ? AND status = 'pending'`,
        [storedRow.alert_id, storedRow.last_seen, jsonText(existingPayload),
          `Coalesced automatic PCAP request for ${level} alert group`, nowUtc(), existingPending.request_id],
      );
      return {
        status: 'coalesced',
        request_id: existingPending.request_id,
        group_id: groupId,
        triage_level: level,
        threshold,
      };
    }
    const result = await createPcapRequest({
      group_id: groupId,
      alert_id: storedRow.alert_id,
      requested_by: 'alert-store-auto-pcap',
      reason: `Automatic PCAP request for ${level} alert`,
      max_window_seconds: pcapRequestDefaultWindowSeconds,
    });
    return {
      status: result.request?.status || 'pending',
      request_id: result.request?.request_id || null,
      group_id: groupId,
      triage_level: level,
      threshold,
    };
  } catch (error) {
    return {status: 'failed', reason: error.message, triage_level: level, threshold};
  }
}

async function maybeQueueAutomaticIncidentResponse(alert, storedRow, inserted, suppression) {
  if (!inserted) return {status: 'skipped_duplicate'};
  if (!storedRow || ['suppressed', 'dropped'].includes(String(storedRow.filter_status || '').toLowerCase())) {
    return {status: 'skipped_filter'};
  }
  if (suppression?.status === 'suppressed') return {status: 'skipped_suppression'};

  const level = String(nestedField(alert, 'triage.level') || storedRow.triage_level || '').toLowerCase();
  const threshold = socAnalysisPolicy.read().soc_analyst_incident_min_severity;
  if (!socAnalysisPolicy.matchesIncident(level)) {
    return {status: 'skipped_level', triage_level: level, threshold};
  }

  try {
    const dashboardGroupId = alertGroupId(alertGroupKeyFromRow(storedRow));
    const result = await queueIncidentResponseForGroup({
      dashboardGroupId,
      representative: storedRow,
      requestedBy: 'alert-store-auto-incident',
      reason: `Automatic incident response for ${level} alert at configured ${threshold} threshold`,
      relatedLimit: 250,
      pcapAnalysisLimit: 25,
      manualReanalysis: false,
      eventType: 'auto_escalated',
      priority: 100 + (severityRank[level] ?? 0),
    });
    return {...result, triage_level: level, threshold};
  } catch (error) {
    return {status: 'failed', reason: error.message, triage_level: level, threshold};
  }
}

async function listPcapRequests(query = new URLSearchParams()) {
  const allowed = new Set(['pending', 'claimed', 'fulfilled', 'failed', 'rejected']);
  const requestedStatus = safeString(query.get('status'), 32).toLowerCase();
  const status = allowed.has(requestedStatus) ? requestedStatus : '';
  const limit = Math.min(100, Math.max(1, Number(query.get('limit') || 25) || 25));
  await rejectExpiredPendingPcapRequests();
  await requeueStalePcapClaims();
  const rows = status
    ? await all(
      `
        SELECT p.*
        FROM pcap_requests AS p
        LEFT JOIN alert_group_summary AS g ON g.group_id = p.group_id
        WHERE p.status = ?
          AND (p.status <> 'pending' OR p.next_attempt_at IS NULL OR datetime(p.next_attempt_at) <= datetime(?))
        ORDER BY
          -- Critical and high packet evidence remains preemptive. Below that
          -- tier, bounded aging prevents a steady medium-alert stream from
          -- starving older low/informational captures forever.
          CASE lower(COALESCE(g.triage_level, ''))
            WHEN 'critical' THEN 2
            WHEN 'high' THEN 1
            ELSE 0
          END DESC,
          CASE WHEN lower(COALESCE(g.triage_level, '')) NOT IN ('critical', 'high')
            AND CAST(strftime('%s', replace(?, '  ', 'T')) AS INTEGER)
              - CAST(strftime('%s', replace(p.created_at, '  ', 'T')) AS INTEGER) >= ?
            THEN 1 ELSE 0
          END DESC,
          CASE WHEN lower(COALESCE(g.triage_level, '')) NOT IN ('critical', 'high')
            AND CAST(strftime('%s', replace(?, '  ', 'T')) AS INTEGER)
              - CAST(strftime('%s', replace(p.created_at, '  ', 'T')) AS INTEGER) >= ?
            THEN datetime(replace(p.created_at, '  ', 'T'))
            ELSE NULL
          END ASC,
          CASE lower(COALESCE(g.triage_level, ''))
            WHEN 'critical' THEN 4
            WHEN 'high' THEN 3
            WHEN 'medium' THEN 2
            WHEN 'low' THEN 1
            WHEN 'informational' THEN 0
            WHEN 'info' THEN 0
            ELSE -1
          END DESC,
          CASE WHEN ? > 0 AND p.last_seen IS NOT NULL
            THEN datetime(replace(p.last_seen, '  ', 'T'), '+' || ? || ' seconds')
            ELSE datetime(p.created_at, '+100 years')
          END ASC,
          p.created_at DESC
        LIMIT ?
      `,
      [status, nowUtc(), nowUtc(), pcapPriorityMaxWaitSeconds,
        nowUtc(), pcapPriorityMaxWaitSeconds,
        pcapCaptureRetentionSeconds, pcapCaptureRetentionSeconds, limit],
    )
    : await all('SELECT * FROM pcap_requests ORDER BY created_at DESC LIMIT ?', [limit]);
  return {ok: true, status: status || 'all', requests: rows.map(pcapRequestFromRow)};
}

async function rejectExpiredPendingPcapRequests() {
  if (!pcapCaptureRetentionSeconds) return;
  const cutoff = new Date(Date.now() - pcapCaptureRetentionSeconds * 1000).toISOString();
  const now = nowUtc();
  await run(
    `
      UPDATE pcap_requests
      SET status = 'rejected',
          outcome = 'expired',
          error = ?,
          completed_at = ?,
          updated_at = ?
      WHERE status = 'pending'
        AND last_seen IS NOT NULL
        AND datetime(replace(last_seen, '  ', 'T')) < datetime(?)
    `,
    [`PCAP request exceeds configured capture retention (${pcapCaptureRetentionSeconds}s)`, now, now, cutoff],
  );
}

async function requeuePcapRequests(payload) {
  const requestIds = Array.isArray(payload?.request_ids)
    ? [...new Set(payload.request_ids.map((value) => safeString(value, 64)).filter(Boolean))].slice(0, 500)
    : [];
  if (!requestIds.length) throw new Error('request_ids must contain at least one PCAP request id');
  const now = nowUtc();
  const placeholders = requestIds.map(() => '?').join(', ');
  await run(
    `
      UPDATE pcap_requests
      SET status = 'pending',
          outcome = NULL,
          relay_host = NULL,
          claimed_at = NULL,
          completed_at = NULL,
          error = 'requeued after PCAP capture-selection upgrade',
          diagnostics_json = NULL,
          transfer_stage = NULL,
          transfer_bytes = 0,
          transfer_total_bytes = 0,
          transfer_progress_at = NULL,
          transfer_duration_seconds = NULL,
          transfer_attempt_count = 0,
          transfer_retry_count = 0,
          transfer_last_error = NULL,
          transfer_last_failed_stage = NULL,
          next_attempt_at = NULL,
          updated_at = ?
      WHERE status = 'failed'
        AND request_id IN (${placeholders})
    `,
    [now, ...requestIds],
  );
  const rows = await all(`SELECT * FROM pcap_requests WHERE request_id IN (${placeholders})`, requestIds);
  return {ok: true, requests: rows.map(pcapRequestFromRow)};
}

async function requeueStalePcapClaims() {
  const cutoff = formatProjectTimestamp(new Date(Date.now() - pcapClaimLeaseSeconds * 1000));
  const now = nowUtc();
  await run(
    `
      UPDATE pcap_requests
      SET status = CASE WHEN transfer_attempt_count >= ? THEN 'failed' ELSE 'pending' END,
          outcome = CASE WHEN transfer_attempt_count >= ? THEN 'timeout' ELSE outcome END,
          relay_host = NULL,
          claimed_at = NULL,
          error = 'requeued after stale relay claim lease expired',
          transfer_retry_count = transfer_retry_count + 1,
          transfer_last_error = 'relay claim lease expired without progress',
          transfer_last_failed_stage = COALESCE(transfer_stage, 'claimed'),
          next_attempt_at = CASE WHEN transfer_attempt_count >= ? THEN NULL ELSE ? END,
          completed_at = CASE WHEN transfer_attempt_count >= ? THEN ? ELSE NULL END,
          updated_at = ?
      WHERE status = 'claimed'
        AND COALESCE(transfer_progress_at, claimed_at, updated_at, created_at) < ?
    `,
    [pcapTransferMaxAttempts, pcapTransferMaxAttempts, pcapTransferMaxAttempts, now,
      pcapTransferMaxAttempts, now, now, cutoff],
  );
}

async function claimPcapRequest(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const relayHost = safeString(payload?.relay_host || 'relay', 120);
  const now = nowUtc();
  const existing = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!existing) throw new Error('pcap request not found');
  if (existing.status !== 'pending') {
    return {ok: true, claimed: false, status: existing.status, request: pcapRequestFromRow(existing)};
  }
  if (existing.next_attempt_at && Date.parse(existing.next_attempt_at) > Date.now()) {
    return {ok: true, claimed: false, status: existing.status, request: pcapRequestFromRow(existing)};
  }
  const claimResult = await run(
    `
      UPDATE pcap_requests
      SET status = 'claimed',
          relay_host = ?,
          error = NULL,
          claimed_at = ?,
          transfer_stage = COALESCE(transfer_stage, 'claimed'),
          transfer_progress_at = ?,
          transfer_attempt_count = transfer_attempt_count + 1,
          next_attempt_at = NULL,
          updated_at = ?
      WHERE request_id = ?
        AND status = 'pending'
        AND (next_attempt_at IS NULL OR datetime(next_attempt_at) <= datetime(?))
    `,
    [relayHost, now, now, now, requestId, now],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  return {
    ok: true,
    claimed: claimResult.changes === 1,
    status: row.status,
    request: pcapRequestFromRow(row),
  };
}

const PCAP_TRANSFER_STAGES = new Set([
  'claimed', 'exporting', 'security_onion_to_relay', 'relay_to_mac', 'verifying',
]);

async function updatePcapTransferProgress(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const stage = safeString(payload?.stage, 64).toLowerCase();
  if (!PCAP_TRANSFER_STAGES.has(stage)) throw new Error('invalid PCAP transfer stage');
  const transferredBytes = nonNegativeIntegerField(payload?.transferred_bytes) || 0;
  const totalBytes = nonNegativeIntegerField(payload?.total_bytes) || 0;
  if (totalBytes && transferredBytes > totalBytes) throw new Error('transferred_bytes cannot exceed total_bytes');
  const now = nowUtc();
  const result = await run(
    `UPDATE pcap_requests
     SET transfer_stage = ?,
         transfer_bytes = ?,
         transfer_total_bytes = CASE WHEN ? > 0 THEN ? ELSE transfer_total_bytes END,
         transfer_progress_at = ?,
         updated_at = ?
     WHERE request_id = ? AND status = 'claimed'`,
    [stage, transferredBytes, totalBytes, totalBytes, now, now, requestId],
  );
  if (result.changes !== 1) throw new Error('claimed PCAP request not found');
  return {
    ok: true,
    request_id: requestId,
    stage,
    transferred_bytes: transferredBytes,
    total_bytes: totalBytes,
    progress_at: now,
  };
}

async function retryPcapRequest(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const existing = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!existing) throw new Error('pcap request not found');
  if (existing.status === 'pending') {
    return {ok: true, retry_scheduled: true, exhausted: false, request: pcapRequestFromRow(existing)};
  }
  if (existing.status !== 'claimed') {
    return {ok: true, retry_scheduled: false, exhausted: false, request: pcapRequestFromRow(existing)};
  }

  const error = safeString(payload?.error, 1000) || 'transient PCAP transfer failure';
  const requestedStage = safeString(payload?.stage, 64).toLowerCase();
  const failedStage = PCAP_TRANSFER_STAGES.has(requestedStage)
    ? requestedStage
    : (existing.transfer_stage || 'claimed');
  const requestedDelay = nonNegativeIntegerField(payload?.retry_after_seconds) || 0;
  const retryAfterSeconds = Math.min(pcapTransferMaxRetrySeconds, requestedDelay);
  const attempts = Number(existing.transfer_attempt_count || 0);
  const exhausted = attempts >= pcapTransferMaxAttempts;
  const now = nowUtc();
  const nextAttemptAt = exhausted
    ? null
    : formatProjectTimestamp(new Date(Date.now() + retryAfterSeconds * 1000));
  const outcome = classifyPcapOutcome('failed', error, payload?.diagnostics || {}) || 'failed';
  const diagnostics = payload?.diagnostics && typeof payload.diagnostics === 'object' && !Array.isArray(payload.diagnostics)
    ? JSON.stringify(payload.diagnostics).slice(0, 12000)
    : null;

  await run(
    `UPDATE pcap_requests
     SET status = ?,
         outcome = ?,
         relay_host = NULL,
         claimed_at = NULL,
         completed_at = ?,
         error = ?,
         diagnostics_json = CASE WHEN ? IS NOT NULL THEN ? ELSE diagnostics_json END,
         transfer_retry_count = transfer_retry_count + 1,
         transfer_last_error = ?,
         transfer_last_failed_stage = ?,
         next_attempt_at = ?,
         updated_at = ?
     WHERE request_id = ? AND status = 'claimed'`,
    [
      exhausted ? 'failed' : 'pending',
      exhausted ? outcome : null,
      exhausted ? now : null,
      exhausted ? error : `retry scheduled after ${failedStage} failure: ${error}`,
      diagnostics,
      diagnostics,
      error,
      failedStage,
      nextAttemptAt,
      now,
      requestId,
    ],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  const eventType = exhausted ? 'failed' : 'deferred';
  await pipelineMetrics.record('pcap_transfer', eventType, requestId, {
    eventKey: `pcap_transfer:${eventType}:${requestId}:${attempts}:${now}`,
  });
  return {
    ok: true,
    retry_scheduled: !exhausted,
    exhausted,
    max_attempts: pcapTransferMaxAttempts,
    request: pcapRequestFromRow(row),
  };
}

async function completePcapRequest(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const requestedStatus = safeString(payload?.status, 32).toLowerCase();
  if (!['fulfilled', 'failed', 'rejected'].includes(requestedStatus)) {
    throw new Error('status must be fulfilled, failed, or rejected');
  }
  const now = nowUtc();
  const artifactPath = safeString(payload?.artifact_path, 1024) || null;
  const artifactSha256 = safeString(payload?.artifact_sha256, 128) || null;
  const artifactSizeBytes = nonNegativeIntegerField(payload?.artifact_size_bytes);
  const relayHost = safeString(payload?.relay_host, 120) || null;
  const error = safeString(payload?.error, 500) || null;
  const diagnostics = payload?.diagnostics && typeof payload.diagnostics === 'object' && !Array.isArray(payload.diagnostics)
    ? JSON.stringify(payload.diagnostics).slice(0, 12000)
    : null;
  const requestedOutcome = safeString(payload?.outcome, 64).toLowerCase();
  const classifiedOutcome = classifyPcapOutcome(requestedStatus, error, payload?.diagnostics || {});
  const outcome = PCAP_OUTCOMES.has(requestedOutcome) && requestedOutcome !== 'failed'
    ? requestedOutcome
    : classifiedOutcome || requestedOutcome;
  if (requestedStatus === 'fulfilled' && (!artifactPath || !artifactSha256 || !artifactSizeBytes)) {
    throw new Error('fulfilled pcap request requires artifact_path, artifact_sha256, and artifact_size_bytes');
  }
  await run(
    `
      UPDATE pcap_requests
      SET status = ?,
          relay_host = COALESCE(?, relay_host),
          artifact_path = ?,
          artifact_sha256 = ?,
          artifact_size_bytes = ?,
          error = ?,
          outcome = ?,
          diagnostics_json = ?,
          analysis_status = CASE WHEN ? = 'fulfilled' THEN 'pending' ELSE 'not_ready' END,
          analysis_error = NULL,
          analysis_started_at = NULL,
          analysis_completed_at = NULL,
          transfer_stage = ?,
          transfer_bytes = CASE WHEN ? = 'fulfilled' THEN ? ELSE transfer_bytes END,
          transfer_total_bytes = CASE WHEN ? = 'fulfilled' THEN ? ELSE transfer_total_bytes END,
          transfer_progress_at = ?,
          next_attempt_at = NULL,
          transfer_duration_seconds = CASE
            WHEN claimed_at IS NULL THEN NULL
            ELSE MAX(
              0,
              CAST(ROUND(
                (julianday(replace(?, '  ', 'T')) -
                 julianday(replace(claimed_at, '  ', 'T'))) * 86400
              ) AS INTEGER)
            )
          END,
          completed_at = ?,
          updated_at = ?
      WHERE request_id = ?
    `,
    [
      requestedStatus,
      relayHost,
      artifactPath,
      artifactSha256,
      artifactSizeBytes,
      requestedStatus === 'fulfilled' ? null : error,
      outcome || null,
      requestedStatus === 'fulfilled' ? null : diagnostics,
      requestedStatus,
      requestedStatus,
      requestedStatus,
      artifactSizeBytes,
      requestedStatus,
      artifactSizeBytes,
      now,
      now,
      now,
      now,
      requestId,
    ],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!row) throw new Error('pcap request not found');
  const eventType = requestedStatus === 'fulfilled' ? 'completed' : 'failed';
  await pipelineMetrics.record('pcap_transfer', eventType, requestId, {
    eventKey: `pcap_transfer:${eventType}:${requestId}:${row.claimed_at || row.created_at}`,
    sizeBytes: row.artifact_size_bytes || 0,
  });
  return {
    ok: true,
    status: row.status,
    request: pcapRequestFromRow(row),
    wake_pcap_analysis: requestedStatus === 'fulfilled',
  };
}

async function completePcapAnalysis(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const status = safeString(payload?.status, 32).toLowerCase();
  if (!['processing', 'completed', 'failed'].includes(status)) {
    throw new Error('analysis status must be processing, completed, or failed');
  }
  const now = nowUtc();
  const result = await run(
    `UPDATE pcap_requests SET analysis_status = ?,
       analysis_attempt_count = analysis_attempt_count + CASE WHEN ? = 'processing' THEN 1 ELSE 0 END,
       analysis_error = ?,
       analysis_started_at = CASE WHEN ? = 'processing' THEN COALESCE(analysis_started_at, ?) ELSE analysis_started_at END,
       analysis_completed_at = CASE WHEN ? IN ('completed', 'failed') THEN ? ELSE NULL END,
       updated_at = ?
     WHERE request_id = ? AND status = 'fulfilled'`,
    [status, status, safeString(payload?.error, 1000) || null, status, now, status, now, now, requestId],
  );
  if (result.changes !== 1) throw new Error('fulfilled PCAP request not found');
  const row = await get(
    `SELECT p.artifact_size_bytes, p.analysis_attempt_count, p.analysis_started_at,
            p.analysis_completed_at, p.alert_id,
            COALESCE(a.stable_group_id, ga.stable_group_id, p.group_id) AS queue_group_id,
            COALESCE(a.stable_group_key, ga.stable_group_key, p.group_key, g.group_key) AS queue_group_key,
            COALESCE(a.triage_level, g.triage_level, 'informational') AS triage_level
     FROM pcap_requests p
     LEFT JOIN alerts a ON a.alert_id = p.alert_id
     LEFT JOIN alert_group_alias ga ON ga.legacy_group_id = p.group_id
     LEFT JOIN alert_group_summary g ON g.group_id = p.group_id
     WHERE p.request_id = ?`,
    [requestId],
  );
  const eventType = status === 'processing' ? 'started' : status;
  await pipelineMetrics.record('pcap_analysis', eventType, requestId, {
    eventKey: `pcap_analysis:${eventType}:${requestId}:${row?.analysis_attempt_count || 0}:${row?.analysis_completed_at || row?.analysis_started_at || now}`,
    sizeBytes: row?.artifact_size_bytes || 0,
  });
  let wakeAiAnalysis = false;
  if (
    status === 'completed'
    && row?.queue_group_id
    && socAnalysisPolicy.matchesAnalysis(row.triage_level)
  ) {
    const groupId = String(row.queue_group_id);
    const groupKey = String(row.queue_group_key || groupId);
    const level = String(row.triage_level || 'informational').toLowerCase();
    await durableJobs.enqueue('ai_analysis', groupId, {
      group_id: groupId,
      group_key: groupKey,
      representative_alert_id: row.alert_id || null,
    }, {priority: severityRank[level] ?? 0, maxAttempts: 8});
    await pipelineMetrics.record('ai_analysis', 'enqueued', groupId, {
      eventKey: `ai_analysis:enqueued:${groupId}:pcap:${requestId}:${row.analysis_attempt_count || 0}`,
      sizeBytes: row.artifact_size_bytes || 0,
    });
    wakeAiAnalysis = true;
  }
  return {
    ok: true,
    request_id: requestId,
    analysis_status: status,
    wake_ai_analysis: wakeAiAnalysis,
  };
}

function readJsonBody(request) {
  return readJsonObject(request, {maxBytes: maxRequestBytes});
}

function sendJson(response, code, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  response.end(body);
}

async function operationalMetricsSnapshot() {
  const durable = durableJobs ? await durableJobs.stats() : [];
  const oldestJob = await get(`SELECT MAX(0, CAST((julianday('now') - julianday(replace(MIN(next_attempt_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
    FROM durable_jobs WHERE status = 'pending'`);
  const oldestJobsByType = await all(`SELECT job_type,
      MAX(0, CAST((julianday('now') - julianday(replace(MIN(next_attempt_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
    FROM durable_jobs WHERE status = 'pending' GROUP BY job_type`);
  const latestCompletedJobsByType = await all(`SELECT job_type,
      MAX(0, CAST((julianday('now') - julianday(replace(MAX(last_completed_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
    FROM durable_jobs WHERE last_completed_at IS NOT NULL GROUP BY job_type`);
  const oldestProcessingJobsByType = await all(`SELECT job_type,
      MAX(0, CAST((julianday('now') - julianday(replace(MIN(updated_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
    FROM durable_jobs WHERE status = 'processing' GROUP BY job_type`);
  const pcap = await all('SELECT status, analysis_status, COUNT(*) AS count FROM pcap_requests GROUP BY status, analysis_status');
  const pcapOutcomes = await all("SELECT COALESCE(outcome, 'unknown') AS outcome, COUNT(*) AS count FROM pcap_requests GROUP BY COALESCE(outcome, 'unknown')");
  const pcapStorage = await get(`SELECT
      COUNT(*) AS fulfilled_count,
      COALESCE(SUM(artifact_size_bytes), 0) AS artifact_bytes_total,
      COALESCE(AVG(artifact_size_bytes), 0) AS artifact_bytes_average,
      COALESCE(MAX(artifact_size_bytes), 0) AS artifact_bytes_maximum,
      COALESCE(SUM(CASE WHEN datetime(replace(completed_at, '  ', 'T')) >= datetime('now', '-24 hours') THEN artifact_size_bytes ELSE 0 END), 0) AS artifact_bytes_24h,
      SUM(CASE WHEN datetime(replace(completed_at, '  ', 'T')) >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS fulfilled_24h
    FROM pcap_requests WHERE status = 'fulfilled'`);
  const oldestPcap = await get(`SELECT MAX(0, CAST((julianday('now') - julianday(replace(MIN(COALESCE(updated_at, created_at)), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
    FROM pcap_requests WHERE status = 'pending'`);
  const pageCount = await get('PRAGMA page_count');
  const pageSize = await get('PRAGMA page_size');
  const sqliteBytes = Number(pageCount?.page_count || 0) * Number(pageSize?.page_size || 0);
  return {
    generated_at: nowUtc(),
    process: {
      ...serviceMetrics,
      post_request_admission: postRequestAdmission.snapshot(),
      ingest_latency_ms_average: serviceMetrics.ingest_requests
        ? Math.round(serviceMetrics.ingest_latency_ms_total / serviceMetrics.ingest_requests) : 0,
    },
    durable_jobs: durable,
    oldest_pending_job_seconds: Number(oldestJob?.seconds || 0),
    oldest_pending_jobs: oldestJobsByType,
    latest_completed_jobs: latestCompletedJobsByType,
    oldest_processing_jobs: oldestProcessingJobsByType,
    pcap,
    pcap_outcomes: pcapOutcomes,
    pcap_storage: pcapStorage || {},
    oldest_pending_pcap_seconds: Number(oldestPcap?.seconds || 0),
    enrichment_cache: await enrichmentCache.stats(),
    telegram_outbox: await telegramOutboxSnapshot(),
    sqlite_bytes: sqliteBytes,
    disk_capacity: diskCapacitySnapshot(),
    pipeline: pipelineMetrics ? await pipelineMetrics.snapshot() : null,
  };
}

async function capturePipelineDiskSample() {
  if (!pipelineMetrics) return;
  const pageCount = await get('PRAGMA page_count');
  const pageSize = await get('PRAGMA page_size');
  const sqliteBytes = Number(pageCount?.page_count || 0) * Number(pageSize?.page_size || 0);
  await withSqliteWriteGate(() => pipelineMetrics.captureDiskSample(sqliteBytes));
}

async function handleRequest(request, response) {
  try {
    const parsedUrl = new URL(request.url, 'http://alert-store.local');
    if (request.method === 'GET' && request.url === '/health') {
      // Used by the Mac Studio monitor LaunchAgent.
      sendJson(response, 200, {
        ok: true,
        status: 'healthy',
        telegram_outbox: await telegramOutboxSnapshot(),
        enrichment_scheduler: enrichmentScheduler.snapshot(),
        enrichment_cache: enrichmentCache.snapshot(),
        disk_capacity: diskCapacitySnapshot(),
      });
      return;
    }
    if (request.method === 'GET' && parsedUrl.pathname === '/metrics') {
      sendJson(response, 200, {ok: true, metrics: await operationalMetricsSnapshot()});
      return;
    }
    if (request.method === 'GET' && parsedUrl.pathname === '/analyst-status') {
      sendJson(response, 200, await analystStatusSnapshot());
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/analyst-status') {
      const payload = await readJsonBody(request);
      sendJson(response, 200, await updateAnalystStatus(payload));
      return;
    }
    if (request.method === 'POST' && request.url === '/alert') {
      // Main ingestion endpoint called by the n8n workflow.
      const startedAt = Date.now();
      serviceMetrics.ingest_requests += 1;
      const alert = await readJsonBody(request);
      writeN8nBeacon('received', alert);
      if (isRelayHeartbeat(alert)) {
        const result = {ok: true, status: 'heartbeat', stored: false};
        const beacon = writeN8nBeacon('heartbeat', alert, result);
        sendJson(response, 200, {...result, beacon});
        return;
      }
      assertDiskWriteAdmission('alert ingestion');
      const result = await storeAlert(alert);
      const latency = Date.now() - startedAt;
      serviceMetrics.ingest_latency_ms_total += latency;
      serviceMetrics.ingest_latency_ms_max = Math.max(serviceMetrics.ingest_latency_ms_max, latency);
      writeN8nBeacon('stored', alert, result);
      sendJson(response, result.ok ? 200 : 400, result);
      return;
    }
    if (request.method === 'POST' && request.url === '/enrich') {
      // n8n calls this as a dedicated enrichment stage before /alert storage.
      // Public lookups are skipped unless their key is configured, except
      // intentionally keyless public sources such as Shodan InternetDB, KEV,
      // EPSS, and NVD without a key.
      const alert = await readJsonBody(request);
      assertDiskWriteAdmission('alert enrichment');
      const result = await enrichAlert(alert);
      sendJson(response, result.ok ? 200 : 400, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/analysis/result') {
      // AI workers submit compact, structured results here so alert-store
      // remains the only SQLite writer. The endpoint is idempotent by
      // analysis_id and never accepts raw PCAP bytes or unbounded artifacts.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => withImmediateTransaction(
        () => recordAiAnalysisResult(payload),
      ));
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/ai/request') {
      // The dashboard records intent only. The worker builds a fresh bounded
      // prompt at execution time so every rerun sees current alerts, public
      // enrichment, parsed PCAP evidence, notes, memory, and prior analyses.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => withImmediateTransaction(
        () => requestAiReanalysis(payload),
      ));
      void signalAiWorkers('manual-ai-reanalysis');
      sendJson(response, 202, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/incidents/escalate') {
      // Escalation is an idempotent case transition plus a distinct agent job.
      // It never overwrites or masquerades as the SOC Analyst's prior result.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => withImmediateTransaction(
        () => requestIncidentEscalation(payload),
      ));
      void signalAiWorkers('incident-response-escalation');
      sendJson(response, 202, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/request') {
      // Queues a bounded PCAP evidence request. This endpoint never shells out
      // or contacts Security Onion; relay-side fulfillment will use its own
      // forced-command SSH path with additional Security Onion validation.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => createPcapRequest(payload));
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'GET' && parsedUrl.pathname === '/pcap/requests') {
      // Intended for relay polling and operator diagnostics.
      const result = await listPcapRequests(parsedUrl.searchParams);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'GET' && parsedUrl.pathname === '/jobs/stats') {
      sendJson(response, 200, {ok: true, jobs: durableJobs ? await durableJobs.stats() : []});
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/jobs/status') {
      const payload = await readJsonBody(request);
      const jobType = safeString(payload?.job_type, 64);
      const dedupeKey = safeString(payload?.dedupe_key, 256);
      const status = safeString(payload?.status, 32).toLowerCase();
      const leaseToken = safeString(payload?.lease_token, 128);
      if (!jobType || !dedupeKey) throw new Error('job_type and dedupe_key are required');
      const transition = await withSqliteWriteGate(() => transitionDurableJobStatus(
        jobType, dedupeKey, status, safeString(payload?.error, 1000), leaseToken,
      ));
      sendJson(response, transition.updated ? 200 : 404, {
        ok: transition.updated,
        job_type: jobType,
        dedupe_key: transition.resolvedKey,
        status,
        lease_token: transition.leaseToken,
      });
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/jobs/reconcile-completed') {
      // Local workers reconcile queue intent with durable artifacts in one
      // bounded write. This avoids stale pending rows when an up-to-date AI
      // artifact makes a queued group ineligible for duplicate analysis.
      const payload = await readJsonBody(request);
      const jobType = safeString(payload?.job_type, 64);
      const dedupeKeys = Array.isArray(payload?.dedupe_keys)
        ? payload.dedupe_keys.map((value) => safeString(value, 256)).filter(Boolean).slice(0, 2000)
        : [];
      if (!jobType || !dedupeKeys.length) throw new Error('job_type and dedupe_keys are required');
      const completed = await withSqliteWriteGate(() => withImmediateTransaction(
        () => durableJobs.completePendingByDedupeKeys(jobType, dedupeKeys),
      ));
      sendJson(response, 200, {ok: true, job_type: jobType, reconciled: completed});
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/claim') {
      // Relay claims a pending request before contacting Security Onion.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => claimPcapRequest(payload));
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/complete') {
      // Relay reports fulfillment metadata only. Packet artifacts stay on the
      // controlled runtime path and are never committed to the DR repo.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => completePcapRequest(payload));
      if (result.wake_pcap_analysis) void signalWorker(pcapAnalysisWakePath, 'pcap-transfer-completed');
      delete result.wake_pcap_analysis;
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/progress') {
      // A fresh progress heartbeat renews the relay claim lease while large,
      // resumable transfers are actively moving through the SSD spool.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => updatePcapTransferProgress(payload));
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/retry') {
      // A retry preserves transfer-stage checkpoints and relay/Mac artifacts.
      // The bounded server-side attempt cap prevents permanent queue loops.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => retryPcapRequest(payload));
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/analysis-status') {
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => withImmediateTransaction(
        () => completePcapAnalysis(payload),
      ));
      if (result.wake_ai_analysis) void signalAiWorkers('pcap-analysis-completed');
      delete result.wake_ai_analysis;
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/requeue') {
      // Internal operator recovery endpoint. The relay cannot call this route;
      // it is used only after a reviewed broker or selector repair.
      const payload = await readJsonBody(request);
      const result = await withSqliteWriteGate(() => requeuePcapRequests(payload));
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && request.url === '/rescore') {
      // Manual tuning endpoint after changing scoring rules.
      const result = await rescoreAlerts();
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && request.url === '/refresh-groups') {
      // Manual repair endpoint after DB restore or schema troubleshooting.
      const result = await rebuildAlertGroupSummaries();
      sendJson(response, 200, result);
      return;
    }
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

async function dispatchRequest(request, response) {
  if (request.method !== 'POST') {
    await handleRequest(request, response);
    return;
  }
  const release = postRequestAdmission.tryAcquire();
  if (!release) {
    request.resume();
    response.setHeader('Retry-After', '1');
    sendJson(response, 503, {ok: false, status: 'busy', reason: 'alert-store POST capacity is busy'});
    return;
  }
  try {
    await handleRequest(request, response);
  } finally {
    release();
  }
}

initDb().then(() => {
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
  });
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
  setInterval(() => {
    void withSqliteWriteGate(() => pipelineMetrics.prune())
      .catch((error) => console.error(`pipeline metric retention failed: ${error.message}`));
  }, 60 * 60 * 1000).unref();
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
