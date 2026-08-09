'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapPolicy} = require('../lib/pcap_policy');

function nestedField(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

function integerField(value) {
  const parsed = Number(value);
  return Number.isInteger(parsed) ? parsed : null;
}

function safeString(value, maxLength = 240) {
  return String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, maxLength);
}

function parseJsonObject(value) {
  try {
    const parsed = JSON.parse(value || '');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch (_) {
    return {};
  }
}

function policy(overrides = {}) {
  return createPcapPolicy({
    safeString,
    parseJsonObject,
    nestedField,
    integerField,
    normalizeTimestampValue: (value) => value ? String(value).replace('T', '  ') : null,
    defaultWindowSeconds: 120,
    maxWindowSeconds: 300,
    captureRetentionSeconds: 3600,
    nowMs: () => Date.parse('2026-08-09T12:00:00Z'),
    ...overrides,
  });
}

test('candidate projection preserves row precedence and Suricata capture provenance', () => {
  const candidate = policy().pcapCandidateFromRow({
    alert_id: 'alert-1',
    timestamp: '2026-08-09  11:55:00Z',
    source_ip: '198.51.100.1',
    raw_event_json: JSON.stringify({
      source: {ip: '198.51.100.2', port: 4444},
      destination: {ip: '203.0.113.8', port: 443},
      suricata: {capture_file: 'eve-0001.pcap'},
    }),
  });
  assert.equal(candidate.source_ip, '198.51.100.1');
  assert.equal(candidate.source_port, 4444);
  assert.equal(candidate.destination_ip, '203.0.113.8');
  assert.equal(candidate.capture_file, 'eve-0001.pcap');
  assert.equal(candidate.event_timestamp, '2026-08-09  11:55:00Z');
});

test('normalization anchors exact alerts, bounds windows, and keeps stable identity', () => {
  const subject = policy();
  const candidate = {
    alert_id: 'alert-1',
    event_timestamp: '2026-08-09T11:55:00Z',
    first_seen: '2026-08-09T11:00:00Z',
    last_seen: '2026-08-09T12:00:00Z',
    source_ip: '198.51.100.1',
    destination_ip: '203.0.113.8',
  };
  const request = subject.normalizePcapRequest({
    reason: '  analyst   review  ',
    transport_protocol: 'TCP',
    max_window_seconds: 999,
  }, candidate);
  assert.equal(request.first_seen, '2026-08-09  11:55:00Z');
  assert.equal(request.last_seen, '2026-08-09  11:55:00Z');
  assert.equal(request.max_window_seconds, 300);
  assert.equal(request.transport_protocol, 'tcp');
  assert.equal(request.reason, 'analyst review');
  assert.equal(request.request_id, subject.normalizePcapRequest({
    reason: 'analyst review', transport_protocol: 'TCP', max_window_seconds: 300,
  }, candidate).request_id);
});

test('normalization rejects incomplete requests without inventing evidence', () => {
  const subject = policy();
  assert.throws(() => subject.normalizePcapRequest({}), /reason is required/);
  assert.throws(
    () => subject.normalizePcapRequest({reason: 'review'}),
    /requires source_ip and destination_ip/,
  );
  assert.throws(
    () => subject.normalizePcapRequest({
      reason: 'review', source_ip: '198.51.100.1', destination_ip: '203.0.113.8',
    }),
    /requires first_seen and last_seen timestamps/,
  );
});

test('retention and terminal outcome classification preserve exact categories', () => {
  const subject = policy();
  assert.equal(subject.pcapRetentionError('2026-08-09T11:30:00Z'), null);
  assert.match(subject.pcapRetentionError('2026-08-09T10:00:00Z'), /3600s/);
  assert.equal(subject.classifyPcapOutcome('fulfilled', null), 'captured');
  assert.equal(subject.classifyPcapOutcome('failed', 'no matching packet'), 'no_packets_available');
  assert.equal(subject.classifyPcapOutcome('failed', 'artifact size exceeded'), 'oversize');
  assert.equal(subject.classifyPcapOutcome('failed', 'ssh connection failed'), 'transport_failed');
  assert.equal(subject.classifyPcapOutcome('failed', 'sha256 mismatch'), 'checksum_failed');
  assert.equal(subject.classifyPcapOutcome('rejected', null), 'rejected');
});

test('row projection preserves response defaults and bounded numeric state', () => {
  const request = policy().pcapRequestFromRow({
    request_id: 'pcap-1',
    status: 'failed',
    error: 'timed out',
    request_json: JSON.stringify({capture_file: 'eve.pcap', require_source_port: true}),
    diagnostics_json: JSON.stringify({stage: 'transfer'}),
    analysis_attempt_count: '2',
    transfer_bytes: '42',
    transfer_total_bytes: '100',
    transfer_duration_seconds: null,
  });
  assert.equal(request.capture_file, 'eve.pcap');
  assert.equal(request.require_source_port, true);
  assert.equal(request.outcome, 'timeout');
  assert.deepEqual(request.diagnostics, {stage: 'transfer'});
  assert.equal(request.analysis_status, 'not_ready');
  assert.equal(request.analysis_attempt_count, 2);
  assert.equal(request.transfer_bytes, 42);
  assert.equal(request.transfer_duration_seconds, null);
});

test('explicit PCAP outcomes retain compatibility membership', () => {
  assert.deepEqual([...policy().pcapOutcomes], [
    'captured', 'no_packets_available', 'expired', 'oversize', 'timeout',
    'transport_failed', 'checksum_failed', 'rejected', 'failed',
  ]);
});
