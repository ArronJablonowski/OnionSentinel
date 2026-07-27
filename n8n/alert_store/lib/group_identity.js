'use strict';

const crypto = require('crypto');

const STABLE_GROUP_KEY_MAX_UTF8_BYTES = 2048;

function text(value, fallback) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return normalized || fallback;
}

function validPinnedStableGroupKey(value) {
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.includes('\0')
  ) {
    return false;
  }
  const encoded = Buffer.from(value, 'utf8');
  return (
    encoded.length <= STABLE_GROUP_KEY_MAX_UTF8_BYTES
    && encoded.toString('utf8') === value
  );
}

// V2 intentionally excludes severity, routing, filter state, and analyst state.
// Those fields can change during tuning and must never change detection identity.
function stableGroupKey(row = {}) {
  return [
    'v2',
    text(row.rule_id, text(row.rule_name, 'unknown-rule')),
    text(row.event_dataset, 'unknown-dataset'),
    text(row.source_ip, 'unknown-source'),
    text(row.destination_ip, 'unknown-destination'),
    text(row.destination_port, 'unknown-port'),
    text(row.transport_protocol || row.network_protocol, 'unknown-protocol'),
  ].join('|');
}

function stableGroupId(row) {
  return crypto.createHash('sha256').update(stableGroupKey(row)).digest('hex').slice(0, 20);
}

module.exports = {
  STABLE_GROUP_KEY_MAX_UTF8_BYTES,
  stableGroupKey,
  stableGroupId,
  validPinnedStableGroupKey,
};
