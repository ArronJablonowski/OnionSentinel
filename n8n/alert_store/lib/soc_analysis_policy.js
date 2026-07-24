'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');

const SEVERITY_RANK = Object.freeze({
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});
const THRESHOLD_VALUES = new Set(['disabled', ...Object.keys(SEVERITY_RANK)]);
const DEFAULT_POLICY = Object.freeze({
  // Preserve the existing all-severity PCAP behavior during rolling upgrades.
  soc_analyst_pcap_min_severity: 'informational',
  // Automatic incident escalation is opt-in because it creates analyst cases.
  soc_analyst_incident_min_severity: 'disabled',
});

function normalizeSeverity(value) {
  const severity = String(value || '').trim().toLowerCase();
  return severity === 'info' ? 'informational' : severity;
}

function normalizeThreshold(value, fallback) {
  const threshold = normalizeSeverity(value);
  return THRESHOLD_VALUES.has(threshold) ? threshold : fallback;
}

function matchesSeverityThreshold(severity, threshold) {
  const normalizedSeverity = normalizeSeverity(severity);
  const normalizedThreshold = normalizeThreshold(threshold, 'disabled');
  if (normalizedThreshold === 'disabled') return false;
  if (!(normalizedSeverity in SEVERITY_RANK)) return false;
  return SEVERITY_RANK[normalizedSeverity] >= SEVERITY_RANK[normalizedThreshold];
}

function legacyPcapThreshold(value) {
  const levels = String(value || '')
    .split(',')
    .map(normalizeSeverity)
    .filter((level) => level in SEVERITY_RANK);
  if (!levels.length) return 'disabled';
  return levels.reduce(
    (lowest, level) => SEVERITY_RANK[level] < SEVERITY_RANK[lowest] ? level : lowest,
    levels[0],
  );
}

function createSocAnalysisPolicy(options = {}) {
  const runtimeDir = String(
    options.runtimeDir || process.env.ONION_SENTINEL_RUNTIME_DIR || path.join(os.homedir(), 'n8n-local'),
  ).trim();
  const settingsPath = String(
    options.settingsPath
      || process.env.AI_MODEL_SETTINGS_FILE
      || path.join(runtimeDir, 'config', 'ai_model_settings.json'),
  ).trim();
  const cacheTtlMs = Math.max(250, Number(options.cacheTtlMs || 5000));
  let cachedAt = 0;
  let cachedMtimeMs = -1;
  let cachedPolicy = null;

  function defaults() {
    const legacyThreshold = process.env.PCAP_AUTO_REQUEST_LEVELS === undefined
      ? DEFAULT_POLICY.soc_analyst_pcap_min_severity
      : legacyPcapThreshold(process.env.PCAP_AUTO_REQUEST_LEVELS);
    return {
      ...DEFAULT_POLICY,
      soc_analyst_pcap_min_severity: legacyThreshold,
    };
  }

  function read(force = false) {
    const now = Date.now();
    if (!force && cachedPolicy && now - cachedAt < cacheTtlMs) return cachedPolicy;

    let mtimeMs = -1;
    try {
      mtimeMs = fs.statSync(settingsPath).mtimeMs;
    } catch (_) {
      cachedPolicy = defaults();
      cachedMtimeMs = -1;
      cachedAt = now;
      return cachedPolicy;
    }
    if (!force && cachedPolicy && mtimeMs === cachedMtimeMs) {
      cachedAt = now;
      return cachedPolicy;
    }

    let raw = {};
    try {
      const text = fs.readFileSync(settingsPath, 'utf8');
      // Settings are operator-authored and tiny; reject anomalously large files
      // before parsing so a damaged runtime file cannot pressure ingestion.
      if (Buffer.byteLength(text, 'utf8') > 256 * 1024) {
        throw new Error('AI settings file exceeds 256 KiB');
      }
      raw = JSON.parse(text);
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) raw = {};
    } catch (error) {
      console.error(`Unable to load SOC analysis policy from ${settingsPath}: ${error.message}`);
      raw = {};
    }
    const fallback = defaults();
    cachedPolicy = {
      soc_analyst_pcap_min_severity: normalizeThreshold(
        raw.soc_analyst_pcap_min_severity,
        fallback.soc_analyst_pcap_min_severity,
      ),
      soc_analyst_incident_min_severity: normalizeThreshold(
        raw.soc_analyst_incident_min_severity,
        fallback.soc_analyst_incident_min_severity,
      ),
    };
    cachedMtimeMs = mtimeMs;
    cachedAt = now;
    return cachedPolicy;
  }

  return {
    settingsPath,
    read,
    matchesPcap(severity) {
      return matchesSeverityThreshold(severity, read().soc_analyst_pcap_min_severity);
    },
    matchesIncident(severity) {
      return matchesSeverityThreshold(severity, read().soc_analyst_incident_min_severity);
    },
  };
}

module.exports = {
  DEFAULT_POLICY,
  SEVERITY_RANK,
  createSocAnalysisPolicy,
  legacyPcapThreshold,
  matchesSeverityThreshold,
  normalizeSeverity,
  normalizeThreshold,
};
