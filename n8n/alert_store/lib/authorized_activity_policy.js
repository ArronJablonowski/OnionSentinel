'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');

const MAX_POLICIES = 100;

function exactStrings(value, name, validator = () => true) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    throw new Error(`${name} must contain between 1 and 100 exact values`);
  }
  const normalized = value.map((item) => String(item ?? '').trim().toLowerCase());
  if (normalized.some((item) => !item || !validator(item))) {
    throw new Error(`${name} contains an invalid exact value`);
  }
  return [...new Set(normalized)];
}

function optionalExactStrings(value, name, validator = () => true) {
  if (value == null) return [];
  return exactStrings(value, name, validator);
}

function optionalExactPorts(value, name) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length < 1 || value.length > 100) {
    throw new Error(`${name} must contain between 1 and 100 exact ports`);
  }
  const ports = value.map(Number);
  if (ports.some((port) => !Number.isSafeInteger(port) || port < 1 || port > 65535)) {
    throw new Error(`${name} contains an invalid exact port`);
  }
  return [...new Set(ports)];
}

function optionalPortRanges(value, name) {
  if (value == null) return [];
  if (!Array.isArray(value) || value.length < 1 || value.length > 20) {
    throw new Error(`${name} must contain between 1 and 20 port ranges`);
  }
  return value.map((range, index) => {
    if (!Array.isArray(range) || range.length !== 2) {
      throw new Error(`${name}[${index}] must be a [start, end] pair`);
    }
    const start = Number(range[0]);
    const end = Number(range[1]);
    if (
      !Number.isSafeInteger(start) || !Number.isSafeInteger(end)
      || start < 1 || end > 65535 || start > end
    ) {
      throw new Error(`${name}[${index}] is invalid`);
    }
    return Object.freeze([start, end]);
  });
}

function boundedInteger(value, name, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
  return parsed;
}

function exactTimestamp(value, name) {
  if (typeof value !== 'string' || !value.trim() || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${name} must be an ISO 8601 timestamp`);
  }
  return new Date(value).toISOString();
}

function normalizePolicy(policy, index) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error(`policies[${index}] must be an object`);
  }
  const id = String(policy.id || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{2,79}$/.test(id)) {
    throw new Error(`policies[${index}].id is invalid`);
  }
  const authorizationStart = exactTimestamp(policy.authorization_start, `${id}.authorization_start`);
  const authorizationEnd = exactTimestamp(policy.authorization_end, `${id}.authorization_end`);
  if (Date.parse(authorizationEnd) <= Date.parse(authorizationStart)) {
    throw new Error(`${id}.authorization_end must follow authorization_start`);
  }
  const authorization = policy.authorization;
  if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) {
    throw new Error(`${id}.authorization must be an object`);
  }
  const authorizedBy = String(authorization.authorized_by || '').trim();
  const scope = String(authorization.scope || '').trim();
  const provenance = String(authorization.provenance || '').trim();
  if (!authorizedBy || !scope || !provenance) {
    throw new Error(`${id}.authorization requires authorized_by, scope, and provenance`);
  }
  const sourceIps = optionalExactStrings(
    policy.source_ips,
    `${id}.source_ips`,
    (item) => net.isIP(item) !== 0,
  );
  const destinationIps = optionalExactStrings(
    policy.destination_ips,
    `${id}.destination_ips`,
    (item) => net.isIP(item) !== 0,
  );
  if (!sourceIps.length && !destinationIps.length) {
    throw new Error(`${id} requires exact source_ips or destination_ips`);
  }
  const destinationPorts = optionalExactPorts(policy.destination_ports, `${id}.destination_ports`);
  const destinationPortRanges = optionalPortRanges(
    policy.destination_port_ranges,
    `${id}.destination_port_ranges`,
  );
  if (!destinationPorts.length && !destinationPortRanges.length) {
    throw new Error(`${id} requires exact destination_ports or destination_port_ranges`);
  }
  return Object.freeze({
    id,
    enabled: policy.enabled === true,
    source_ips: sourceIps,
    destination_ips: destinationIps,
    rule_ids: exactStrings(policy.rule_ids, `${id}.rule_ids`, (item) => /^[a-z0-9_.:-]{1,128}$/.test(item)),
    source_ports: optionalExactPorts(policy.source_ports, `${id}.source_ports`),
    destination_ports: destinationPorts,
    destination_port_ranges: destinationPortRanges,
    transport_protocols: exactStrings(
      policy.transport_protocols,
      `${id}.transport_protocols`,
      (item) => /^[a-z0-9_.-]{1,32}$/.test(item),
    ),
    authorization_start: authorizationStart,
    authorization_end: authorizationEnd,
    window_seconds: boundedInteger(policy.window_seconds, `${id}.window_seconds`, 60, 86400),
    pcap_sample_limit: boundedInteger(policy.pcap_sample_limit, `${id}.pcap_sample_limit`, 0, 25),
    enrichment_sample_limit: boundedInteger(
      policy.enrichment_sample_limit,
      `${id}.enrichment_sample_limit`,
      0,
      100,
    ),
    investigation_mode: policy.investigation_mode === 'incident_response_only'
      ? 'incident_response_only'
      : (() => { throw new Error(`${id}.investigation_mode is unsupported`); })(),
    reconcile_existing_pending: policy.reconcile_existing_pending === true,
    authorization: Object.freeze({
      status: 'operator_authorized',
      authorized_by: authorizedBy.slice(0, 100),
      scope: scope.slice(0, 1000),
      provenance: provenance.slice(0, 200),
    }),
  });
}

function loadAuthorizedActivityPolicy(filePath) {
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed) || parsed.version !== 1) {
    throw new Error('authorized activity policy must be a version 1 object');
  }
  if (!Array.isArray(parsed.policies) || parsed.policies.length > MAX_POLICIES) {
    throw new Error(`authorized activity policy may contain at most ${MAX_POLICIES} policies`);
  }
  const policies = parsed.policies.map(normalizePolicy);
  const ids = new Set(policies.map((policy) => policy.id));
  if (ids.size !== policies.length) throw new Error('authorized activity policy IDs must be unique');
  return Object.freeze({version: 1, policies: Object.freeze(policies)});
}

function eventTimestamp(alert, row) {
  const candidates = [alert?.timestamp, row?.timestamp, row?.last_seen, row?.first_seen];
  for (const value of candidates) {
    const parsed = Date.parse(String(value || '').replace('  ', 'T'));
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function matchAuthorizedActivity(registry, alert, row) {
  const timestampMs = eventTimestamp(alert, row);
  if (timestampMs == null) return null;
  const sourceIp = String(row?.source_ip || alert?.source?.ip || '').trim().toLowerCase();
  const sourcePort = Number(row?.source_port ?? alert?.source?.port);
  const destinationIp = String(
    row?.destination_ip || alert?.destination?.ip || '',
  ).trim().toLowerCase();
  const ruleId = String(row?.rule_id || alert?.rule_id || '').trim().toLowerCase();
  const destinationPort = Number(row?.destination_port ?? alert?.destination?.port);
  const protocol = String(
    row?.transport_protocol || row?.network_protocol || alert?.network?.transport || alert?.network?.protocol || '',
  ).trim().toLowerCase();
  for (const policy of registry?.policies || []) {
    if (
      policy.enabled
      && timestampMs >= Date.parse(policy.authorization_start)
      && timestampMs <= Date.parse(policy.authorization_end)
      && (!policy.source_ips.length || policy.source_ips.includes(sourceIp))
      && (!policy.destination_ips.length || policy.destination_ips.includes(destinationIp))
      && policy.rule_ids.includes(ruleId)
      && (!policy.source_ports.length || policy.source_ports.includes(sourcePort))
      && (
        policy.destination_ports.includes(destinationPort)
        || policy.destination_port_ranges.some(
          ([start, end]) => destinationPort >= start && destinationPort <= end,
        )
      )
      && policy.transport_protocols.includes(protocol)
    ) {
      const windowMs = policy.window_seconds * 1000;
      const bucketStartMs = Math.floor(timestampMs / windowMs) * windowMs;
      const bucketStart = new Date(bucketStartMs).toISOString();
      const bucketEnd = new Date(bucketStartMs + windowMs).toISOString();
      const campaignKey = [policy.id, bucketStart].join('|');
      const campaignId = `campaign-${crypto.createHash('sha256').update(campaignKey).digest('hex').slice(0, 20)}`;
      return {...policy, campaign_id: campaignId, campaign_key: campaignKey, bucket_start: bucketStart, bucket_end: bucketEnd};
    }
  }
  return null;
}

module.exports = {
  loadAuthorizedActivityPolicy,
  matchAuthorizedActivity,
};
