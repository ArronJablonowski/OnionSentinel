'use strict';

const validTriageLevels = new Set([
  'critical', 'high', 'medium', 'low', 'informational', 'info', 'unknown',
]);

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

function normalizeTriageLevel(value, fallback = '') {
  const level = String(value || '').trim().toLowerCase();
  if (validTriageLevels.has(level)) return level === 'info' ? 'informational' : level;
  const fallbackLevel = String(fallback || '').trim().toLowerCase();
  if (validTriageLevels.has(fallbackLevel)) {
    return fallbackLevel === 'info' ? 'informational' : fallbackLevel;
  }
  return 'unknown';
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

module.exports = {
  isRelayHeartbeat,
  nestedField,
  integerField,
  nonNegativeIntegerField,
  enrichmentRecord,
  normalizeTriageLevel,
  safeString,
  safeFileToken,
  parseJsonObject,
};
