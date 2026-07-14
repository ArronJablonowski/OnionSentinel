'use strict';

const crypto = require('crypto');

function text(value, fallback) {
  const normalized = String(value ?? '').trim().toLowerCase();
  return normalized || fallback;
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

module.exports = {stableGroupKey, stableGroupId};
