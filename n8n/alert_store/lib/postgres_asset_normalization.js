'use strict';

const crypto = require('crypto');
const net = require('net');

function cleanText(value, maximum, field, {required = false} = {}) {
  const text = String(value ?? '').trim();
  if ((required && !text) || text.length > maximum) {
    throw new Error(`${field} is invalid`);
  }
  return text;
}

function normalizeMac(value, field, {required = false} = {}) {
  const normalized = cleanText(value, 17, field, {required})
    .toLowerCase().replaceAll('-', ':');
  if (!normalized && !required) return '';
  if (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(normalized)) {
    throw new Error(`${field} is invalid`);
  }
  return normalized;
}

function macScope(value) {
  if (!value) return 'unknown';
  const firstOctet = Number.parseInt(value.split(':', 1)[0], 16);
  if (firstOctet & 1) return 'multicast';
  if (firstOctet & 2) return 'locally_administered';
  return 'globally_administered';
}

function normalizedHostname(value, field = 'expected_hostname') {
  return cleanText(value, 253, field).toLowerCase().replace(/\.$/, '');
}

function assertFreshObservation(observation) {
  const lastSeen = new Date(String(observation.last_seen || '')).getTime();
  let leaseExpires = new Date(
    String(observation.lease_expires_at || observation.last_seen || ''),
  ).getTime();
  if (!Number.isFinite(leaseExpires)) leaseExpires = lastSeen;
  if (
    !Number.isFinite(lastSeen)
    || (lastSeen < Date.now() - 24 * 60 * 60 * 1000 && leaseExpires < Date.now())
  ) {
    throw new Error('stale DHCP identity cannot be approved');
  }
}

function observationFingerprint(observation) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(observation, Object.keys(observation).sort()))
    .digest('hex');
}

function timestamp(value, field, {nullable = false} = {}) {
  if (nullable && (value === null || value === undefined || value === '')) return null;
  const parsed = new Date(String(value || ''));
  if (!Number.isFinite(parsed.getTime()) || !/(?:Z|[+-]\d\d:\d\d)$/.test(String(value || ''))) {
    throw new Error(`${field} must be an offset-aware timestamp`);
  }
  return parsed.toISOString();
}

function stringArray(value, maximumItems, maximumLength, field) {
  if (!Array.isArray(value) || value.length > maximumItems) {
    throw new Error(`${field} is invalid`);
  }
  const result = [];
  for (const item of value) {
    const cleaned = cleanText(item, maximumLength, field, {required: true});
    if (!result.includes(cleaned)) result.push(cleaned);
  }
  return result;
}

function identifiersFromRecord(record) {
  const identifiers = record && typeof record.identifiers === 'object'
    ? record.identifiers : {};
  const ips = identifiers.ip_addresses ?? identifiers.ip ?? [];
  const macs = identifiers.mac_addresses ?? identifiers.mac ?? [];
  const hostnames = identifiers.hostnames ?? identifiers.hostname ?? [];
  return {
    ip: stringArray(ips, 64, 64, 'IP identifiers').map((value) => {
      if (!net.isIP(value)) throw new Error('IP identifier is invalid');
      return value;
    }),
    mac: stringArray(macs, 64, 17, 'MAC identifiers').map((value) => {
      const normalized = value.toLowerCase().replaceAll('-', ':');
      if (!/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(normalized)) {
        throw new Error('MAC identifier is invalid');
      }
      return normalized;
    }),
    hostname: stringArray(hostnames, 64, 253, 'hostname identifiers')
      .map((value) => value.toLowerCase().replace(/\.$/, '')),
  };
}

function normalizeInventoryRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error('asset record must be an object');
  }
  const validFrom = timestamp(record.valid_from, 'valid_from');
  const validUntil = timestamp(record.valid_until, 'valid_until', {nullable: true});
  if (validUntil && Date.parse(validUntil) <= Date.parse(validFrom)) {
    throw new Error('valid_until must be later than valid_from');
  }
  const criticality = cleanText(record.criticality || 'unknown', 16, 'criticality');
  const confidence = cleanText(record.confidence || 'unknown', 16, 'confidence');
  if (!['low', 'medium', 'high', 'critical', 'unknown'].includes(criticality)) {
    throw new Error('criticality is invalid');
  }
  if (!['low', 'medium', 'high', 'unknown'].includes(confidence)) {
    throw new Error('confidence is invalid');
  }
  if (
    record.share_with_hosted_models !== undefined
    && typeof record.share_with_hosted_models !== 'boolean'
  ) {
    throw new Error('share_with_hosted_models must be boolean');
  }
  const expectedServices = record.expected_services ?? [];
  const expectedBehaviors = record.expected_behaviors ?? [];
  if (!Array.isArray(expectedServices) || expectedServices.length > 128) {
    throw new Error('expected_services is invalid');
  }
  if (!Array.isArray(expectedBehaviors) || expectedBehaviors.length > 128) {
    throw new Error('expected_behaviors is invalid');
  }
  const identifiers = identifiersFromRecord(record);
  if (!Object.values(identifiers).some((values) => values.length)) {
    throw new Error('asset record must contain at least one identifier');
  }
  return {
    asset_id: cleanText(record.asset_id, 160, 'asset_id', {required: true}),
    valid_from: validFrom,
    valid_until: validUntil,
    identifiers,
    role: cleanText(record.role, 160, 'role'),
    platform: cleanText(record.platform, 160, 'platform'),
    owner_ref: cleanText(record.owner_ref, 300, 'owner_ref'),
    criticality,
    expected_services: expectedServices,
    expected_behaviors: expectedBehaviors,
    source_type: cleanText(record.source_type, 160, 'source_type'),
    source_ref: cleanText(record.source_ref, 500, 'source_ref'),
    confidence,
    share_with_hosted_models: Boolean(record.share_with_hosted_models),
  };
}

function normalizeDhcpState(state) {
  if (
    !state
    || state.schema !== 'onion-sentinel-dhcp-asset-observations-v1'
    || !Array.isArray(state.observations)
    || state.observations.length > 100_000
    || !state.collection
    || typeof state.collection !== 'object'
  ) {
    throw new Error('DHCP observation state failed schema validation');
  }
  const observations = state.observations.map((item) => {
    if (!item || typeof item !== 'object') throw new Error('DHCP observation is invalid');
    const discoveryId = cleanText(item.discovery_id, 20, 'discovery_id', {required: true});
    if (!/^[0-9a-f]{20}$/.test(discoveryId)) throw new Error('discovery_id is invalid');
    const currentIp = cleanText(item.current_ip, 64, 'current_ip', {required: true});
    if (!net.isIP(currentIp)) throw new Error('DHCP current_ip is invalid');
    const mac = cleanText(item.mac_address, 17, 'mac_address').toLowerCase();
    if (mac && !/^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac)) {
      throw new Error('DHCP MAC is invalid');
    }
    return {
      ...item,
      discovery_id: discoveryId,
      current_ip: currentIp,
      mac_address: mac,
      hostname: cleanText(item.hostname, 253, 'hostname').toLowerCase().replace(/\.$/, ''),
      first_seen: timestamp(item.first_seen, 'first_seen'),
      last_seen: timestamp(item.last_seen, 'last_seen'),
      lease_expires_at: timestamp(item.lease_expires_at, 'lease_expires_at', {nullable: true}),
      observation_count: Math.max(0, Number(item.observation_count) || 0),
      message_types: stringArray(item.message_types || [], 64, 80, 'message_types'),
      sensors: stringArray(item.sensors || [], 64, 160, 'sensors'),
      evidence_ids: stringArray(item.evidence_ids || [], 128, 160, 'evidence_ids'),
    };
  });
  return {...state, observations};
}

function inventoryPayload(records, generatedAt = new Date().toISOString()) {
  return {
    schema: 'onion-sentinel-asset-inventory-v1',
    version: 1,
    generated_at: generatedAt,
    inventory_status: 'database',
    assets: records.map((record) => ({
      asset_id: record.asset_id,
      valid_from: new Date(record.valid_from).toISOString(),
      valid_until: record.valid_until ? new Date(record.valid_until).toISOString() : null,
      identifiers: {
        ip_addresses: record.ip_addresses || [],
        mac_addresses: record.mac_addresses || [],
        hostnames: record.hostnames || [],
      },
      role: record.role,
      platform: record.platform,
      owner_ref: record.owner_ref,
      criticality: record.criticality,
      expected_services: record.expected_services || [],
      expected_behaviors: record.expected_behaviors || [],
      source_type: record.source_type,
      source_ref: record.source_ref,
      confidence: record.confidence,
      share_with_hosted_models: Boolean(record.share_with_hosted_models),
    })),
  };
}

function publicRecord(record, now) {
  const from = new Date(record.valid_from).getTime();
  const until = record.valid_until ? new Date(record.valid_until).getTime() : null;
  const point = now.getTime();
  const state = point < from ? 'scheduled' : (until !== null && point >= until ? 'expired' : 'current');
  return {
    asset_id: record.asset_id,
    state,
    ip_addresses: record.ip_addresses || [],
    mac_addresses: record.mac_addresses || [],
    hostnames: record.hostnames || [],
    role: record.role,
    platform: record.platform,
    criticality: record.criticality,
    confidence: record.confidence,
    valid_from: new Date(record.valid_from).toISOString(),
    valid_until: record.valid_until ? new Date(record.valid_until).toISOString() : '',
    source_type: record.source_type,
    source_ref: record.source_ref,
  };
}

module.exports = {
  cleanText,
  normalizeMac,
  macScope,
  normalizedHostname,
  assertFreshObservation,
  observationFingerprint,
  timestamp,
  stringArray,
  normalizeInventoryRecord,
  normalizeDhcpState,
  inventoryPayload,
  publicRecord,
};
