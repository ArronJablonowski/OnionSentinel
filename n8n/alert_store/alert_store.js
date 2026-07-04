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
const host = process.env.ALERT_STORE_HOST || '0.0.0.0';
const port = Number(process.env.ALERT_STORE_PORT || 8787);
const telegramBotToken = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const telegramChatId = (process.env.TELEGRAM_CHAT_ID || '').trim();
const telegramAlertLevels = new Set(
  (process.env.TELEGRAM_ALERT_LEVELS || 'critical,high')
    .split(',')
    .map((level) => level.trim().toLowerCase())
    .filter(Boolean),
);
const telegramCooldownSeconds = Number(process.env.TELEGRAM_COOLDOWN_SECONDS || 900);

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

function nowUtc() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z').replace('T', '  ');
}

function normalizeTimestampValue(value) {
  // Keep project-visible timestamps consistent while leaving raw alert JSON
  // untouched for evidence. Accept historical T/single-space/two-space values.
  if (value === null || value === undefined || value === '') return null;
  return String(value).replace(/(\d{4}-\d{2}-\d{2})(?:T|\s+)(?=\d{2}:\d{2}:\d{2})/g, '$1  ');
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
  };
  for (const filePath of beaconPaths) {
    try {
      writeJsonAtomic(filePath, payload);
    } catch (writeError) {
      console.error(`Unable to write n8n beacon ${filePath}: ${writeError.message}`);
    }
  }
  return payload;
}

function isRelayHeartbeat(payload) {
  return payload?.message_type === 'relay_heartbeat';
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

function jsonText(value) {
  return JSON.stringify(value ?? null);
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
  };
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

async function initDb() {
  // Schema upgrades are additive. ensureColumn keeps existing SQLite DBs usable
  // after new triage fields are introduced.
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
  const alert = {
    ...rawAlert,
    triage: scoreAlert(rawAlert),
  };
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
    $alert_json: JSON.stringify(alert),
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
        $alert_json: JSON.stringify(alert),
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

  return {
    ok: true,
    status: inserted ? (suppression.status === 'suppressed' ? 'suppressed' : 'accepted') : 'already_seen',
    stored: inserted,
    alert: row,
    triage: alert.triage,
    filter: suppression,
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
          $alert_json: JSON.stringify(alert),
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

function readJsonBody(request) {
  // n8n should POST one alert object per request. Arrays are rejected to avoid
  // partial batch inserts that are harder to reason about.
  return new Promise((resolve, reject) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
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
