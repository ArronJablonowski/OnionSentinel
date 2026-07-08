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
const path = require('path');
// n8n's Docker image already includes sqlite3 in its pnpm tree, so this service
// can run inside that image without building a custom Node container.
const sqlite3 = require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3');

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
const host = process.env.ALERT_STORE_HOST || '0.0.0.0';
const port = Number(process.env.ALERT_STORE_PORT || 8787);
const telegramBotToken = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const telegramChatId = (process.env.TELEGRAM_CHAT_ID || '').trim();
const maxRequestBytes = Math.max(1024, Number(process.env.ALERT_STORE_MAX_REQUEST_BYTES || 5 * 1024 * 1024));
const pcapArtifactDir = process.env.PCAP_ARTIFACT_DIR || '/pcap-artifacts';
const pcapArtifactMaxBytes = Math.max(
  1024,
  Number(process.env.PCAP_ARTIFACT_MAX_BYTES || Math.floor(maxRequestBytes * 0.7)),
);
const pcapArtifactChunkMaxBytes = Math.max(
  1024,
  Math.min(pcapArtifactMaxBytes, Number(process.env.PCAP_ARTIFACT_CHUNK_MAX_BYTES || 512 * 1024)),
);
const telegramAlertLevels = new Set(
  (process.env.TELEGRAM_ALERT_LEVELS || 'critical,high')
    .split(',')
    .map((level) => level.trim().toLowerCase())
    .filter(Boolean),
);
const telegramCooldownSeconds = Number(process.env.TELEGRAM_COOLDOWN_SECONDS || 900);
const enrichmentCacheDefaultTtlSeconds = Number(process.env.ENRICHMENT_CACHE_TTL_SECONDS || 86400);
const vulnerabilityCacheDefaultTtlSeconds = Number(process.env.ENRICHMENT_VULN_CACHE_TTL_SECONDS || 86400);
const enrichmentTimeoutMs = Number(process.env.ENRICHMENT_TIMEOUT_MS || 5000);
const virustotalMinimumLevel = String(process.env.VIRUSTOTAL_MINIMUM_LEVEL || 'high').toLowerCase();
const urlscanSubmitEnabled = ['1', 'true', 'yes'].includes(String(process.env.URLSCAN_SUBMIT_ENABLED || '').toLowerCase());
const pcapRequestMaxWindowSeconds = Math.max(30, Number(process.env.PCAP_REQUEST_MAX_WINDOW_SECONDS || 300));
const pcapRequestDefaultWindowSeconds = Math.min(
  pcapRequestMaxWindowSeconds,
  Math.max(30, Number(process.env.PCAP_REQUEST_DEFAULT_WINDOW_SECONDS || 120)),
);
const autoPcapLevels = new Set(
  (process.env.PCAP_AUTO_REQUEST_LEVELS || 'critical,high')
    .split(',')
    .map((level) => level.trim().toLowerCase())
    .filter(Boolean),
);

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

const severityRank = {informational: 0, info: 0, low: 1, medium: 2, high: 3, critical: 4};

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
  };
  for (const filePath of beaconPaths) {
    try {
      writeJsonAtomic(filePath, payload);
    } catch (writeError) {
      console.error(`Unable to write n8n beacon ${filePath}: ${writeError.message}`);
    }
  }
  if (stage !== 'received') {
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

function requestJson({method = 'GET', url, headers = {}, body = null, timeoutMs = enrichmentTimeoutMs}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const client = parsed.protocol === 'https:' ? require('https') : http;
    const payload = body === null || body === undefined ? null : (typeof body === 'string' ? body : JSON.stringify(body));
    const req = client.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers: {
          Accept: 'application/json',
          ...(payload ? {'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload)} : {}),
          ...headers,
        },
        timeout: timeoutMs,
      },
      (res) => {
        let responseBody = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => responseBody += chunk);
        res.on('end', () => {
          let parsedBody = null;
          try {
            parsedBody = responseBody ? JSON.parse(responseBody) : null;
          } catch {
            parsedBody = {raw: responseBody.slice(0, 2000)};
          }
          resolve({statusCode: res.statusCode, headers: res.headers, body: parsedBody});
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error(`request timed out: ${parsed.hostname}`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
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
  return ['cisa_kev', 'epss', 'nvd'].includes(source) ? vulnerabilityCacheDefaultTtlSeconds : enrichmentCacheDefaultTtlSeconds;
}

function cacheKey(source, indicatorType, indicator) {
  return crypto.createHash('sha256').update(`${source}|${indicatorType}|${indicator}`).digest('hex');
}

async function readEnrichmentCache(source, indicatorType, indicator) {
  const row = await get('SELECT * FROM enrichment_cache WHERE cache_key = ? AND expires_at > ?', [cacheKey(source, indicatorType, indicator), nowUtc()]);
  if (!row) return null;
  return {
    source: row.source,
    indicator: row.indicator,
    indicator_type: row.indicator_type,
    verdict: row.verdict || 'unknown',
    confidence: row.confidence ?? 0,
    tags: JSON.parse(row.tags_json || '[]'),
    first_seen: row.first_seen || null,
    last_seen: row.last_seen || null,
    raw_response: JSON.parse(row.raw_response_json || 'null'),
    cached_at: row.cached_at,
  };
}

async function writeEnrichmentCache(record, ttlSeconds) {
  const now = nowUtc();
  const expiresAt = isoFromMs(epochMs() + secondsToMs(ttlSeconds)).replace('T', '  ');
  await run(
    `
      INSERT INTO enrichment_cache (
        cache_key, source, indicator, indicator_type, verdict, confidence, tags_json,
        first_seen, last_seen, raw_response_json, cached_at, expires_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(cache_key) DO UPDATE SET
        verdict = excluded.verdict,
        confidence = excluded.confidence,
        tags_json = excluded.tags_json,
        first_seen = excluded.first_seen,
        last_seen = excluded.last_seen,
        raw_response_json = excluded.raw_response_json,
        cached_at = excluded.cached_at,
        expires_at = excluded.expires_at
    `,
    [
      cacheKey(record.source, record.indicator_type, record.indicator),
      record.source,
      record.indicator,
      record.indicator_type,
      record.verdict,
      record.confidence,
      jsonText(record.tags || []),
      record.first_seen || null,
      record.last_seen || null,
      jsonText(record.raw_response ?? null),
      now,
      expiresAt,
    ],
  );
  return {...record, cached_at: now};
}

async function waitForRateLimit(source) {
  const minimumMs = sourceRateLimitMs(source);
  const row = await get('SELECT last_request_at FROM enrichment_rate_limit WHERE source = ?', [source]);
  if (row?.last_request_at) {
    const elapsed = epochMs() - epochMs(String(row.last_request_at).replace('  ', 'T'));
    const waitMs = minimumMs - elapsed;
    if (waitMs > 0) await new Promise((resolve) => setTimeout(resolve, waitMs));
  }
  await run(
    'INSERT INTO enrichment_rate_limit (source, last_request_at) VALUES (?, ?) ON CONFLICT(source) DO UPDATE SET last_request_at = excluded.last_request_at',
    [source, nowUtc()],
  );
}

async function cachedLookup(source, indicatorType, indicator, lookup) {
  const cached = await readEnrichmentCache(source, indicatorType, indicator);
  if (cached) return {record: cached, cached: true};
  await waitForRateLimit(source);
  const record = await lookup();
  const saved = await writeEnrichmentCache(record, sourceTtlSeconds(source));
  return {record: saved, cached: false};
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
  });
  const body = response.body || {};
  const classification = String(body.classification || '').toLowerCase();
  const verdict = classification === 'malicious' ? 'malicious' : classification === 'benign' ? 'noise/scanner' : body.noise ? 'noise/scanner' : 'unknown';
  return normalizedEnrichmentRecord('greynoise', ip, 'ip', verdict, body.noise ? 80 : 30, [body.classification, body.name, body.link ? 'greynoise-link' : null], body, null, body.last_seen || null);
}

async function lookupShodanInternetDb(ip) {
  const response = await requestJson({url: `https://internetdb.shodan.io/${encodeURIComponent(ip)}`});
  const body = response.statusCode === 404 ? {status: 'not_found'} : response.body || {};
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
  });
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
  });
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
  const response = await requestJson({url: `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(enrichmentSecrets.shodan)}`});
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
    const response = await requestJson({url: `https://api.platform.censys.io/v3/global/asset/host/${encodeURIComponent(ip)}`, headers});
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new Error(`Censys Platform API returned HTTP ${response.statusCode}`);
    }
    const body = response.body || {};
    const services = body.result?.services || body.resource?.services || body.host?.services || [];
    const tags = services.map((service) => service.service_name || service.port || service.transport_protocol).filter(Boolean).slice(0, 10);
    return normalizedEnrichmentRecord('censys', ip, 'ip', services.length ? 'unknown' : 'benign', services.length ? 35 : 55, tags, body);
  }
  const auth = Buffer.from(`${enrichmentSecrets.censysId}:${enrichmentSecrets.censysSecret}`).toString('base64');
  const headers = {Authorization: `Basic ${auth}`};
  const response = await requestJson({url: `https://search.censys.io/api/v2/hosts/${encodeURIComponent(ip)}`, headers});
  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw new Error(`Censys Search API returned HTTP ${response.statusCode}`);
  }
  const body = response.body || {};
  const services = body.result?.services || [];
  const tags = services.map((service) => service.service_name).filter(Boolean).slice(0, 10);
  return normalizedEnrichmentRecord('censys', ip, 'ip', services.length ? 'unknown' : 'benign', services.length ? 35 : 55, tags, body);
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
    summary.sources[source] = {status: result.cached ? 'cached' : 'queried', limit_note: sourceLimitNote(source)};
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
    errors: [],
    privacy: {
      submitted_private_ips: false,
      submitted_internal_urls: false,
      url_query_strings_redacted: true,
      urlscan_submit_enabled: urlscanSubmitEnabled,
    },
  };

  for (const ip of indicators.public_ips.slice(0, 4)) {
    await runEnrichmentLookup('abuseipdb', 'ip', ip, () => lookupAbuseIpdb(ip), summary);
    await runEnrichmentLookup('greynoise', 'ip', ip, () => lookupGreynoise(ip), summary);
    await runEnrichmentLookup('shodan_internetdb', 'ip', ip, () => lookupShodanInternetDb(ip), summary);
    await runEnrichmentLookup('otx', 'ip', ip, () => lookupOtx('ip', ip), summary);
    await runEnrichmentLookup('shodan', 'ip', ip, () => lookupShodan(ip), summary);
    await runEnrichmentLookup('censys', 'ip', ip, () => lookupCensys(ip), summary);
  }

  for (const domain of indicators.domains.slice(0, 4)) {
    await runEnrichmentLookup('otx', 'domain', domain, () => lookupOtx('domain', domain), summary);
    await runEnrichmentLookup('urlscan', 'domain', domain, () => lookupUrlscan('domain', domain), summary);
    await runEnrichmentLookup('threatfox', 'domain', domain, () => lookupThreatFox('domain', domain), summary);
    if (shouldUseVirusTotal(alert)) {
      await runEnrichmentLookup('virustotal', 'domain', domain, () => lookupVirusTotal('domain', domain), summary);
    } else {
      summary.skipped.push({source: 'virustotal', indicator: domain, indicator_type: 'domain', reason: `below_${virustotalMinimumLevel}_severity`, limit_note: sourceLimitNote('virustotal')});
    }
  }

  for (const urlValue of indicators.urls.slice(0, 3)) {
    await runEnrichmentLookup('urlhaus', 'url', urlValue, () => lookupUrlhaus(urlValue), summary);
    await runEnrichmentLookup('urlscan', 'url', urlValue, () => lookupUrlscan('url', urlValue), summary);
    await runEnrichmentLookup('google_safe_browsing', 'url', urlValue, () => lookupGoogleSafeBrowsing(urlValue), summary);
    await runEnrichmentLookup('phishtank', 'url', urlValue, () => lookupPhishTank(urlValue), summary);
    await runEnrichmentLookup('otx', 'url', urlValue, () => lookupOtx('url', urlValue), summary);
    if (shouldUseVirusTotal(alert)) {
      await runEnrichmentLookup('virustotal', 'url', urlValue, () => lookupVirusTotal('url', urlValue), summary);
    } else {
      summary.skipped.push({source: 'virustotal', indicator: urlValue, indicator_type: 'url', reason: `below_${virustotalMinimumLevel}_severity`, limit_note: sourceLimitNote('virustotal')});
    }
  }

  for (const hash of indicators.hashes.slice(0, 4)) {
    await runEnrichmentLookup('malwarebazaar', 'hash', hash.value, () => lookupMalwareBazaar(hash.value), summary);
    await runEnrichmentLookup('otx', 'hash', hash.value, () => lookupOtx('hash', hash.value), summary);
    await runEnrichmentLookup('threatfox', 'hash', hash.value, () => lookupThreatFox('hash', hash.value), summary);
    if (shouldUseVirusTotal(alert)) {
      await runEnrichmentLookup('virustotal', 'hash', hash.value, () => lookupVirusTotal('hash', hash.value), summary);
    } else {
      summary.skipped.push({source: 'virustotal', indicator: hash.value, indicator_type: 'hash', reason: `below_${virustotalMinimumLevel}_severity`, limit_note: sourceLimitNote('virustotal')});
    }
  }

  for (const cve of indicators.cves.slice(0, 6)) {
    await runEnrichmentLookup('cisa_kev', 'cve', cve, () => lookupCisaKev(cve), summary);
    await runEnrichmentLookup('epss', 'cve', cve, () => lookupEpss(cve), summary);
    await runEnrichmentLookup('nvd', 'cve', cve, () => lookupNvd(cve), summary);
  }

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
db.configure('busyTimeout', Number(process.env.ALERT_STORE_SQLITE_BUSY_TIMEOUT_MS || 10000));
const sqliteJournalMode = String(process.env.ALERT_STORE_SQLITE_JOURNAL_MODE || 'DELETE').toUpperCase();
const sqliteSynchronous = String(process.env.ALERT_STORE_SQLITE_SYNCHRONOUS || 'NORMAL').toUpperCase();
const sqliteTempStore = String(process.env.ALERT_STORE_SQLITE_TEMP_STORE || 'DEFAULT').toUpperCase();
const allowedJournalModes = new Set(['DELETE', 'TRUNCATE', 'PERSIST', 'MEMORY', 'WAL', 'OFF']);
const allowedSynchronousModes = new Set(['OFF', 'NORMAL', 'FULL', 'EXTRA']);
const allowedTempStoreModes = new Set(['DEFAULT', 'FILE', 'MEMORY']);
const alertGroupKeySql = `
  COALESCE(
    NULLIF(suppression_key, ''),
    COALESCE(triage_level, 'unknown-level') || '|' ||
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

async function initDb() {
  // Schema upgrades are additive. ensureColumn keeps existing SQLite DBs usable
  // after new triage fields are introduced.
  const journalMode = allowedJournalModes.has(sqliteJournalMode) ? sqliteJournalMode : 'DELETE';
  const synchronousMode = allowedSynchronousModes.has(sqliteSynchronous) ? sqliteSynchronous : 'NORMAL';
  const tempStoreMode = allowedTempStoreModes.has(sqliteTempStore) ? sqliteTempStore : 'DEFAULT';
  await run(`PRAGMA journal_mode = ${journalMode}`);
  await run(`PRAGMA synchronous = ${synchronousMode}`);
  await run(`PRAGMA temp_store = ${tempStoreMode}`);
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
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_triage_level ON alerts(triage_level)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_filter_status ON alerts(filter_status)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_destination_ip ON alerts(destination_ip)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_source_port ON alerts(source_port)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_destination_port ON alerts(destination_port)');
  await run('CREATE INDEX IF NOT EXISTS idx_alerts_transport_protocol ON alerts(transport_protocol)');
  // Group summary refreshes run on every stored alert. Keep the expression
  // index in lockstep with alertGroupKeySql so inserts avoid table scans as
  // alert_json and enrichment_json grow.
  await run(`
    CREATE INDEX IF NOT EXISTS idx_alerts_group_key_expr ON alerts(
      COALESCE(
        NULLIF(suppression_key, ''),
        COALESCE(triage_level, 'unknown-level') || '|' ||
        COALESCE(rule_name, 'unknown-rule') || '|' ||
        COALESCE(source_ip, 'unknown-source') || '|' ||
        COALESCE(destination_ip, 'unknown-destination') || '|' ||
        COALESCE(filter_status, 'accepted')
      )
    )
  `);
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
  await run(`
    CREATE TABLE IF NOT EXISTS enrichment_cache (
      cache_key TEXT PRIMARY KEY,
      source TEXT NOT NULL,
      indicator TEXT NOT NULL,
      indicator_type TEXT NOT NULL,
      verdict TEXT,
      confidence INTEGER,
      tags_json TEXT,
      first_seen TEXT,
      last_seen TEXT,
      raw_response_json TEXT,
      cached_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    )
  `);
  await run('CREATE INDEX IF NOT EXISTS idx_enrichment_cache_expires_at ON enrichment_cache(expires_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_enrichment_cache_indicator ON enrichment_cache(indicator)');
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
      request_json TEXT NOT NULL,
      created_at TEXT NOT NULL,
      claimed_at TEXT,
      completed_at TEXT,
      updated_at TEXT NOT NULL
    )
  `);
  await run(`
    CREATE TABLE IF NOT EXISTS pcap_artifact_chunks (
      request_id TEXT NOT NULL,
      chunk_index INTEGER NOT NULL,
      chunk_count INTEGER NOT NULL,
      chunk_sha256 TEXT NOT NULL,
      chunk_size_bytes INTEGER NOT NULL,
      artifact_sha256 TEXT NOT NULL,
      artifact_size_bytes INTEGER NOT NULL,
      chunk_path TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (request_id, chunk_index)
    )
  `);
  await ensureColumn('pcap_requests', 'claimed_at', 'TEXT');
  await ensureColumn('pcap_requests', 'completed_at', 'TEXT');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_status_created ON pcap_requests(status, created_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_completed_at ON pcap_requests(completed_at)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_alert_id ON pcap_requests(alert_id)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_requests_group_id ON pcap_requests(group_id)');
  await run('CREATE INDEX IF NOT EXISTS idx_pcap_artifact_chunks_created ON pcap_artifact_chunks(created_at)');
  await rebuildAlertGroupSummaries();
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

function alertGroupKeyFromRow(row) {
  if (!row) return '';
  if (row.suppression_key) return String(row.suppression_key);
  return [
    row.triage_level || 'unknown-level',
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
      representative.triage_level,
      representative.routing,
      representative.filter_status,
      representative.filter_reason,
      representative.suppression_key,
      nowUtc(),
    ],
  );
}

async function rebuildAlertGroupSummaries() {
  await run('DELETE FROM alert_group_summary');
  const groups = await all(`SELECT DISTINCT ${alertGroupKeySql} AS group_key FROM alerts`);
  for (const group of groups) {
    await refreshAlertGroupSummary(group.group_key);
  }
  return {ok: true, status: 'group_summary_rebuilt', groups: groups.length};
}

async function storeAlert(rawAlert) {
  // Store indexed summary fields for reports plus the full scored JSON for
  // investigation-note generation.
  let alert = {
    ...rawAlert,
    triage: scoreAlert(rawAlert),
  };
  if (!hasUsableExternalIntel(alert)) {
    const enrichmentResult = await enrichAlert(alert);
    if (enrichmentResult.ok && enrichmentResult.alert) {
      alert = {
        ...enrichmentResult.alert,
        triage: alert.triage,
      };
    }
  }
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
  const nextGroupKey = alertGroupKeyFromRow(row);
  if (previousGroupKey && previousGroupKey !== nextGroupKey) {
    await refreshAlertGroupSummary(previousGroupKey);
  }
  await refreshAlertGroupSummary(nextGroupKey);
  const pcap = await maybeQueueAutomaticPcapRequest(alert, row, inserted, suppression);

  return {
    ok: true,
    status: inserted ? (suppression.status === 'suppressed' ? 'suppressed' : 'accepted') : 'already_seen',
    stored: inserted,
    alert: row,
    triage: alert.triage,
    filter: suppression,
    pcap,
    notification: await maybeNotifyTelegram(alert, row, inserted, timestamp, suppression),
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

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => {
      if (error) reject(error);
      else resolve(rows);
    });
  });
}

async function rescoreAlerts() {
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

  const groupSummary = await rebuildAlertGroupSummaries();

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

async function maybeNotifyTelegram(alert, storedAlert, inserted, now, suppression = {status: 'accepted'}) {
  // Notification order: new alert only, Telegram configured, level allowed,
  // cooldown clear, then send and record.
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

  await postTelegramMessage(formatTelegramAlert(alert, storedAlert));
  await run(
    `
      INSERT INTO notification_log (
        notification_key, last_sent, sent_count, channel, alert_id,
        triage_level, rule_name, source_ip, destination_ip
      )
      VALUES (?, ?, 1, 'telegram', ?, ?, ?, ?, ?)
      ON CONFLICT(notification_key) DO UPDATE SET
        last_sent = excluded.last_sent,
        sent_count = notification_log.sent_count + 1,
        alert_id = excluded.alert_id,
        triage_level = excluded.triage_level,
        rule_name = excluded.rule_name,
        source_ip = excluded.source_ip,
        destination_ip = excluded.destination_ip
    `,
    [
      key,
      now,
      alert.alert_id,
      triageLevel,
      alert.rule_name || null,
      nestedField(alert, 'source.ip'),
      nestedField(alert, 'destination.ip'),
    ],
  );

  return {channel: 'telegram', status: 'sent', triage_level: triageLevel};
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
  };
}

async function pcapCandidateFromPayload(payload) {
  if (payload.alert_id) {
    const row = await get('SELECT * FROM alerts WHERE alert_id = ?', [String(payload.alert_id)]);
    if (row) return pcapCandidateFromRow(row);
  }
  if (payload.group_id) {
    const row = await get('SELECT * FROM alert_group_summary WHERE group_id = ?', [String(payload.group_id)]);
    if (row) return pcapCandidateFromRow(row);
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
    reason: request.reason,
  });
  return request;
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
    requested_by: row.requested_by,
    reason: row.reason,
    max_window_seconds: row.max_window_seconds,
    require_source_port: Boolean(requestJson.require_source_port),
    relay_host: row.relay_host,
    artifact_path: row.artifact_path,
    artifact_sha256: row.artifact_sha256,
    artifact_size_bytes: row.artifact_size_bytes,
    error: row.error,
    created_at: row.created_at,
    claimed_at: row.claimed_at,
    completed_at: row.completed_at,
    updated_at: row.updated_at,
  };
}

async function createPcapRequest(payload) {
  const candidate = await pcapCandidateFromPayload(payload);
  const normalized = normalizePcapRequest(payload, candidate);
  const now = nowUtc();
  await run(
    `
      INSERT INTO pcap_requests (
        request_id, status, alert_id, group_id, group_key, first_seen, last_seen,
        source_ip, source_port, destination_ip, destination_port, network_protocol,
        transport_protocol, community_id, requested_by, reason, max_window_seconds,
        request_json, created_at, updated_at
      )
      VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(request_id) DO UPDATE SET
        reason = excluded.reason,
        requested_by = excluded.requested_by,
        max_window_seconds = excluded.max_window_seconds,
        request_json = excluded.request_json,
        updated_at = excluded.updated_at
    `,
    [
      normalized.request_id,
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
      jsonText(normalized),
      now,
      now,
    ],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [normalized.request_id]);
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
  if (!inserted || autoPcapLevels.size === 0) return {status: 'skipped_policy'};
  if (!storedRow || ['suppressed', 'dropped'].includes(String(storedRow.filter_status || '').toLowerCase())) {
    return {status: 'skipped_filter'};
  }
  if (suppression?.status === 'suppressed') return {status: 'skipped_suppression'};

  const level = String(nestedField(alert, 'triage.level') || storedRow.triage_level || '').toLowerCase();
  if (!autoPcapLevels.has(level)) return {status: 'skipped_level', triage_level: level};

  try {
    const groupKey = alertGroupKeyFromRow(storedRow);
    const groupId = alertGroupId(groupKey);
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
    };
  } catch (error) {
    return {status: 'failed', reason: error.message, triage_level: level};
  }
}

async function listPcapRequests(query = new URLSearchParams()) {
  const allowed = new Set(['pending', 'claimed', 'fulfilled', 'failed', 'rejected']);
  const requestedStatus = safeString(query.get('status'), 32).toLowerCase();
  const status = allowed.has(requestedStatus) ? requestedStatus : '';
  const limit = Math.min(100, Math.max(1, Number(query.get('limit') || 25) || 25));
  const rows = status
    ? await all('SELECT * FROM pcap_requests WHERE status = ? ORDER BY created_at ASC LIMIT ?', [status, limit])
    : await all('SELECT * FROM pcap_requests ORDER BY created_at DESC LIMIT ?', [limit]);
  return {ok: true, status: status || 'all', requests: rows.map(pcapRequestFromRow)};
}

async function claimPcapRequest(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const relayHost = safeString(payload?.relay_host || 'relay', 120);
  const now = nowUtc();
  const existing = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!existing) throw new Error('pcap request not found');
  if (existing.status && !['pending', 'claimed'].includes(existing.status)) {
    return {ok: true, claimed: false, status: existing.status, request: pcapRequestFromRow(existing)};
  }
  await run(
    `
      UPDATE pcap_requests
      SET status = 'claimed',
          relay_host = ?,
          error = NULL,
          claimed_at = COALESCE(claimed_at, ?),
          updated_at = ?
      WHERE request_id = ?
        AND status IN ('pending', 'claimed')
    `,
    [relayHost, now, now, requestId],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  return {ok: true, claimed: row.status === 'claimed', status: row.status, request: pcapRequestFromRow(row)};
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
      now,
      now,
      requestId,
    ],
  );
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!row) throw new Error('pcap request not found');
  return {ok: true, status: row.status, request: pcapRequestFromRow(row)};
}

async function ingestPcapArtifact(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!row) throw new Error('pcap request not found');
  if (!['claimed', 'fulfilled'].includes(String(row.status || '').toLowerCase())) {
    throw new Error(`pcap request must be claimed or fulfilled before artifact upload; current status is ${row.status}`);
  }
  const artifactPath = safeString(payload?.artifact_path || row.artifact_path, 1024);
  if (!artifactPath.startsWith('/nsm/pcapout/onion-sentinel/')) {
    throw new Error('artifact_path is outside the allowed Security Onion PCAP output directory');
  }
  const artifactSha256 = safeString(payload?.artifact_sha256 || row.artifact_sha256, 128).toLowerCase();
  const artifactSizeBytes = nonNegativeIntegerField(payload?.artifact_size_bytes ?? row.artifact_size_bytes);
  const artifactBase64 = safeString(payload?.artifact_base64, maxRequestBytes);
  if (!artifactSha256 || !artifactSizeBytes || !artifactBase64) {
    throw new Error('artifact upload requires artifact_sha256, artifact_size_bytes, and artifact_base64');
  }
  if (artifactSizeBytes > pcapArtifactMaxBytes) {
    throw new Error(`artifact_size_bytes exceeds ${pcapArtifactMaxBytes} byte PCAP artifact limit`);
  }
  if (!/^[a-f0-9]{64}$/.test(artifactSha256)) throw new Error('artifact_sha256 must be a hex sha256 digest');
  if (!/^[A-Za-z0-9+/=\r\n ]+$/.test(artifactBase64)) throw new Error('artifact_base64 contains invalid characters');
  const artifactBytes = Buffer.from(artifactBase64.replace(/\s+/g, ''), 'base64');
  if (artifactBytes.length !== artifactSizeBytes) {
    throw new Error('artifact_size_bytes does not match decoded artifact length');
  }
  if (artifactBytes.length > pcapArtifactMaxBytes) {
    throw new Error(`decoded PCAP artifact exceeds ${pcapArtifactMaxBytes} byte limit`);
  }
  const digest = crypto.createHash('sha256').update(artifactBytes).digest('hex');
  if (digest !== artifactSha256) throw new Error('artifact sha256 mismatch');

  const requestDir = path.join(pcapArtifactDir, safeFileToken(requestId, 'pcap-request'));
  const fileName = safeFileToken(path.basename(artifactPath), `${safeFileToken(requestId)}.tar`);
  const destination = path.join(requestDir, fileName);
  const artifactRoot = path.resolve(pcapArtifactDir);
  if (!path.resolve(destination).startsWith(`${artifactRoot}${path.sep}`)) {
    throw new Error('resolved artifact destination escaped artifact directory');
  }
  await fs.promises.mkdir(requestDir, {recursive: true, mode: 0o700});
  const tempPath = `${destination}.tmp-${process.pid}`;
  await fs.promises.writeFile(tempPath, artifactBytes, {mode: 0o600});
  await fs.promises.rename(tempPath, destination);
  return {
    ok: true,
    status: 'artifact_stored',
    request_id: requestId,
    artifact_file: destination,
    artifact_size_bytes: artifactBytes.length,
    artifact_sha256: digest,
  };
}

async function ingestPcapArtifactChunk(payload) {
  const requestId = safeString(payload?.request_id, 64);
  if (!requestId) throw new Error('request_id is required');
  const row = await get('SELECT * FROM pcap_requests WHERE request_id = ?', [requestId]);
  if (!row) throw new Error('pcap request not found');
  if (!['claimed', 'fulfilled'].includes(String(row.status || '').toLowerCase())) {
    throw new Error(`pcap request must be claimed or fulfilled before artifact upload; current status is ${row.status}`);
  }
  const artifactPath = safeString(payload?.artifact_path || row.artifact_path, 1024);
  if (!artifactPath.startsWith('/nsm/pcapout/onion-sentinel/')) {
    throw new Error('artifact_path is outside the allowed Security Onion PCAP output directory');
  }
  const artifactSha256 = safeString(payload?.artifact_sha256 || row.artifact_sha256, 128).toLowerCase();
  const artifactSizeBytes = nonNegativeIntegerField(payload?.artifact_size_bytes ?? row.artifact_size_bytes);
  const chunkIndex = nonNegativeIntegerField(payload?.chunk_index);
  const chunkCount = nonNegativeIntegerField(payload?.chunk_count);
  const chunkSha256 = safeString(payload?.chunk_sha256, 128).toLowerCase();
  const chunkBase64 = safeString(payload?.chunk_base64, maxRequestBytes);
  if (!artifactSha256 || !artifactSizeBytes || !chunkSha256 || !chunkBase64) {
    throw new Error('chunk upload requires artifact_sha256, artifact_size_bytes, chunk_sha256, and chunk_base64');
  }
  if (!Number.isInteger(chunkIndex) || !Number.isInteger(chunkCount) || chunkCount < 1 || chunkIndex >= chunkCount) {
    throw new Error('chunk_index and chunk_count must describe a valid zero-based chunk range');
  }
  if (artifactSizeBytes > pcapArtifactMaxBytes) {
    throw new Error(`artifact_size_bytes exceeds ${pcapArtifactMaxBytes} byte PCAP artifact limit`);
  }
  if (!/^[a-f0-9]{64}$/.test(artifactSha256)) throw new Error('artifact_sha256 must be a hex sha256 digest');
  if (!/^[a-f0-9]{64}$/.test(chunkSha256)) throw new Error('chunk_sha256 must be a hex sha256 digest');
  if (!/^[A-Za-z0-9+/=\r\n ]+$/.test(chunkBase64)) throw new Error('chunk_base64 contains invalid characters');
  const chunkBytes = Buffer.from(chunkBase64.replace(/\s+/g, ''), 'base64');
  if (chunkBytes.length < 1) throw new Error('decoded chunk is empty');
  if (chunkBytes.length > pcapArtifactChunkMaxBytes) {
    throw new Error(`decoded PCAP artifact chunk exceeds ${pcapArtifactChunkMaxBytes} byte limit`);
  }
  const digest = crypto.createHash('sha256').update(chunkBytes).digest('hex');
  if (digest !== chunkSha256) throw new Error('chunk sha256 mismatch');

  const requestDir = path.join(pcapArtifactDir, safeFileToken(requestId, 'pcap-request'));
  const chunkDir = path.join(requestDir, '.chunks');
  const artifactRoot = path.resolve(pcapArtifactDir);
  if (!path.resolve(chunkDir).startsWith(`${artifactRoot}${path.sep}`)) {
    throw new Error('resolved chunk destination escaped artifact directory');
  }
  await fs.promises.mkdir(chunkDir, {recursive: true, mode: 0o700});
  const chunkPath = path.join(chunkDir, `${String(chunkIndex).padStart(8, '0')}.chunk`);
  const tempPath = `${chunkPath}.tmp-${process.pid}`;
  await fs.promises.writeFile(tempPath, chunkBytes, {mode: 0o600});
  await fs.promises.rename(tempPath, chunkPath);
  const now = nowUtc();
  await run(
    `
      INSERT INTO pcap_artifact_chunks (
        request_id, chunk_index, chunk_count, chunk_sha256, chunk_size_bytes,
        artifact_sha256, artifact_size_bytes, chunk_path, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(request_id, chunk_index) DO UPDATE SET
        chunk_count = excluded.chunk_count,
        chunk_sha256 = excluded.chunk_sha256,
        chunk_size_bytes = excluded.chunk_size_bytes,
        artifact_sha256 = excluded.artifact_sha256,
        artifact_size_bytes = excluded.artifact_size_bytes,
        chunk_path = excluded.chunk_path,
        created_at = excluded.created_at
    `,
    [requestId, chunkIndex, chunkCount, chunkSha256, chunkBytes.length, artifactSha256, artifactSizeBytes, chunkPath, now],
  );
  const chunks = await all('SELECT * FROM pcap_artifact_chunks WHERE request_id = ? ORDER BY chunk_index ASC', [requestId]);
  if (chunks.length !== chunkCount) {
    return {ok: true, status: 'chunk_stored', request_id: requestId, chunks_received: chunks.length, chunk_count: chunkCount};
  }
  const expectedIndexes = chunks.map((chunk) => chunk.chunk_index).join(',');
  const completeIndexes = Array.from({length: chunkCount}, (_, index) => index).join(',');
  if (expectedIndexes !== completeIndexes) {
    return {ok: true, status: 'chunk_stored', request_id: requestId, chunks_received: chunks.length, chunk_count: chunkCount};
  }
  const fileName = safeFileToken(path.basename(artifactPath), `${safeFileToken(requestId)}.tar`);
  const destination = path.join(requestDir, fileName);
  if (!path.resolve(destination).startsWith(`${artifactRoot}${path.sep}`)) {
    throw new Error('resolved artifact destination escaped artifact directory');
  }
  const buffers = [];
  for (const chunk of chunks) buffers.push(await fs.promises.readFile(chunk.chunk_path));
  const artifactBytes = Buffer.concat(buffers);
  if (artifactBytes.length !== artifactSizeBytes) throw new Error('reassembled artifact size mismatch');
  const artifactDigest = crypto.createHash('sha256').update(artifactBytes).digest('hex');
  if (artifactDigest !== artifactSha256) throw new Error('reassembled artifact sha256 mismatch');
  const artifactTempPath = `${destination}.tmp-${process.pid}`;
  await fs.promises.writeFile(artifactTempPath, artifactBytes, {mode: 0o600});
  await fs.promises.rename(artifactTempPath, destination);
  await fs.promises.rm(chunkDir, {recursive: true, force: true});
  await run('DELETE FROM pcap_artifact_chunks WHERE request_id = ?', [requestId]);
  return {
    ok: true,
    status: 'artifact_stored',
    request_id: requestId,
    artifact_file: destination,
    artifact_size_bytes: artifactBytes.length,
    artifact_sha256: artifactDigest,
    chunks_received: chunks.length,
    chunk_count: chunkCount,
  };
}

function readJsonBody(request) {
  // n8n should POST one alert object per request. Arrays are rejected to avoid
  // partial batch inserts that are harder to reason about.
  return new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let rejected = false;
    request.on('data', (chunk) => {
      if (rejected) return;
      bytes += chunk.length;
      if (bytes > maxRequestBytes) {
        rejected = true;
        request.destroy(new Error(`payload exceeds ${maxRequestBytes} byte limit`));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (rejected) return;
      try {
        const body = Buffer.concat(chunks).toString('utf8');
        const parsed = JSON.parse(body || '{}');
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('payload must be a JSON object');
        }
        resolve(parsed);
      } catch (error) {
        reject(error);
      }
    });
    request.on('error', reject);
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

async function handleRequest(request, response) {
  try {
    const parsedUrl = new URL(request.url, 'http://alert-store.local');
    if (request.method === 'GET' && request.url === '/health') {
      // Used by the Mac Studio monitor LaunchAgent.
      sendJson(response, 200, {ok: true, status: 'healthy'});
      return;
    }
    if (request.method === 'POST' && request.url === '/alert') {
      // Main ingestion endpoint called by the n8n workflow.
      const alert = await readJsonBody(request);
      writeN8nBeacon('received', alert);
      if (isRelayHeartbeat(alert)) {
        const result = {ok: true, status: 'heartbeat', stored: false};
        const beacon = writeN8nBeacon('heartbeat', alert, result);
        sendJson(response, 200, {...result, beacon});
        return;
      }
      const result = await storeAlert(alert);
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
      const result = await enrichAlert(alert);
      sendJson(response, result.ok ? 200 : 400, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/request') {
      // Queues a bounded PCAP evidence request. This endpoint never shells out
      // or contacts Security Onion; relay-side fulfillment will use its own
      // forced-command SSH path with additional Security Onion validation.
      const payload = await readJsonBody(request);
      const result = await createPcapRequest(payload);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'GET' && parsedUrl.pathname === '/pcap/requests') {
      // Intended for relay polling and operator diagnostics.
      const result = await listPcapRequests(parsedUrl.searchParams);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/claim') {
      // Relay claims a pending request before contacting Security Onion.
      const payload = await readJsonBody(request);
      const result = await claimPcapRequest(payload);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/complete') {
      // Relay reports fulfillment metadata only. Packet artifacts stay on the
      // controlled runtime path and are never committed to the DR repo.
      const payload = await readJsonBody(request);
      const result = await completePcapRequest(payload);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/artifact') {
      // Relay uploads bounded PCAP artifacts through n8n. Store runtime-only
      // evidence after validating size and sha256 against broker metadata.
      const payload = await readJsonBody(request);
      const result = await ingestPcapArtifact(payload);
      sendJson(response, 200, result);
      return;
    }
    if (request.method === 'POST' && parsedUrl.pathname === '/pcap/artifact-chunk') {
      // Chunked uploads keep each relay-to-Mac request small. The final chunk
      // triggers reassembly only after all chunks and hashes are verified.
      const payload = await readJsonBody(request);
      const result = await ingestPcapArtifactChunk(payload);
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
      writeN8nBeacon('error', {}, null, error);
    }
    sendJson(response, 400, {
      ok: false,
      status: 'rejected',
      reason: error.message,
    });
  }
}

initDb().then(() => {
  http.createServer(handleRequest).listen(port, host, () => {
    console.log(`alert-store listening on ${host}:${port}, db=${dbPath}`);
  });
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
