'use strict';

// Correlation observables are deliberately small, normalized facts. Provider
// responses and model prose are never recursively mined because that would let
// untrusted or noisy text create self-reinforcing relationships between alerts.

const OBSERVABLE_TYPES = new Set([
  'ip',
  'domain',
  'url',
  'hash',
  'cve',
  'port',
  'rule',
  'dataset',
  'protocol',
  'community_id',
  'host',
  'user',
]);
// A v1 Community ID is a base64 SHA-1 digest. The final base64 character has
// two zero pad bits and is therefore limited to this canonical alphabet.
const COMMUNITY_ID_V1_PATTERN = /^1:[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]=$/;

function nestedField(object, dottedPath) {
  return dottedPath.split('.').reduce((value, key) => value?.[key], object);
}

function cleanText(value, maxLength = 512) {
  const normalized = String(value ?? '').trim().replace(/[\u0000-\u001f\u007f]/g, '');
  return normalized.slice(0, maxLength);
}

function normalizedObservableValue(type, value) {
  const text = cleanText(value);
  if (!text) return '';
  if (type === 'community_id') {
    return COMMUNITY_ID_V1_PATTERN.test(text) ? text : '';
  }
  if (['domain', 'hash', 'cve', 'rule', 'dataset', 'protocol', 'host', 'user'].includes(type)) {
    return text.toLowerCase();
  }
  if (type === 'url') {
    try {
      const parsed = new URL(text);
      parsed.hash = '';
      return parsed.toString().slice(0, 1024);
    } catch {
      return text.slice(0, 1024);
    }
  }
  if (type === 'port') {
    const port = Number.parseInt(text, 10);
    return Number.isInteger(port) && port >= 0 && port <= 65535 ? String(port) : '';
  }
  return text.toLowerCase();
}

function buildAlertObservables(alert = {}, row = {}, extractIndicators = () => ({})) {
  const records = new Map();
  const add = (type, value, role, source = 'alert') => {
    if (!OBSERVABLE_TYPES.has(type)) return;
    const normalized = normalizedObservableValue(type, value);
    if (!normalized) return;
    const normalizedRole = cleanText(role || 'observed', 64).toLowerCase() || 'observed';
    const normalizedSource = cleanText(source || 'alert', 64).toLowerCase() || 'alert';
    const key = `${type}\u0000${normalized}\u0000${normalizedRole}\u0000${normalizedSource}`;
    records.set(key, {
      observable_type: type,
      observable_value: normalized,
      role: normalizedRole,
      source: normalizedSource,
    });
  };

  add('ip', row.source_ip ?? nestedField(alert, 'source.ip'), 'source');
  add('ip', row.destination_ip ?? nestedField(alert, 'destination.ip'), 'destination');
  add('port', row.source_port ?? nestedField(alert, 'source.port'), 'source');
  add('port', row.destination_port ?? nestedField(alert, 'destination.port'), 'destination');
  add('rule', row.rule_id ?? alert.rule_id ?? row.rule_name ?? alert.rule_name, 'detection');
  add('dataset', row.event_dataset ?? alert.event_dataset, 'event');
  add('protocol', row.transport_protocol ?? row.network_protocol ?? nestedField(alert, 'network.transport'), 'network');
  add('community_id', nestedField(alert, 'network.community_id') ?? alert.community_id, 'flow');
  add('host', nestedField(alert, 'host.name'), 'host');
  add('host', nestedField(alert, 'observer.name'), 'sensor');
  add('user', nestedField(alert, 'user.name'), 'user');

  const indicators = extractIndicators(alert) || {};
  for (const ip of indicators.public_ips || []) add('ip', ip, 'indicator', 'alert-indicator');
  for (const domain of indicators.domains || []) add('domain', domain, 'indicator', 'alert-indicator');
  for (const url of indicators.urls || []) add('url', url, 'indicator', 'alert-indicator');
  for (const hash of indicators.hashes || []) add('hash', hash?.value ?? hash, hash?.type || 'indicator', 'alert-indicator');
  for (const cve of indicators.cves || []) add('cve', cve, 'indicator', 'alert-indicator');

  return [...records.values()];
}

function compactCorrelationCandidates(value, maxItems = 20) {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maxItems).map((candidate) => ({
    group_id: cleanText(candidate?.group_id, 64).toLowerCase(),
    score: Math.max(0, Math.min(100, Number(candidate?.score) || 0)),
    reasons: Array.isArray(candidate?.correlation_reasons)
      ? candidate.correlation_reasons.slice(0, 12).map((item) => cleanText(item, 240)).filter(Boolean)
      : [],
    shared_observables: Array.isArray(candidate?.shared_observables)
      ? candidate.shared_observables.slice(0, 20).map((item) => ({
        type: cleanText(item?.type, 32).toLowerCase(),
        value: cleanText(item?.value, 1024),
        selected_role: cleanText(item?.selected_role, 64).toLowerCase(),
        related_role: cleanText(item?.related_role, 64).toLowerCase(),
      })).filter((item) => item.type && item.value)
      : [],
  })).filter((candidate) => candidate.group_id);
}

module.exports = {
  OBSERVABLE_TYPES,
  buildAlertObservables,
  compactCorrelationCandidates,
  normalizedObservableValue,
};
