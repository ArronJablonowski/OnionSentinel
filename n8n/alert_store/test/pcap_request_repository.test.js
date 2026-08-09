'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapRequestRepository} = require('../repositories/pcap_request_repository');

function harness({gets = [], alls = []} = {}) {
  const calls = [];
  const repository = createPcapRequestRepository({
    get: async (sql, params) => { calls.push({name: 'get', sql, params}); return gets.shift(); },
    all: async (sql, params) => { calls.push({name: 'all', sql, params}); return alls.shift() || []; },
    run: async (sql, params) => { calls.push({name: 'run', sql, params}); return {changes: 1}; },
    safeString: (value, max) => String(value ?? '').trim().slice(0, max),
    parseJsonObject: (value) => {
      try { return JSON.parse(value || '{}'); } catch (_) { return {}; }
    },
    jsonText: JSON.stringify,
    nowUtc: () => '2026-08-09  12:00:00Z',
    pcapCandidateFromRow: (row) => ({alert_id: row.alert_id || row.representative_alert_id}),
    normalizePcapRequest: (_payload, candidate) => ({
      request_id: 'pcap-1', alert_id: candidate.alert_id || null, group_id: null,
      group_key: null, first_seen: 'a', last_seen: 'b', source_ip: 's', source_port: 1,
      destination_ip: 'd', destination_port: 2, network_protocol: null,
      transport_protocol: 'tcp', community_id: null, requested_by: 'analyst',
      reason: 'review', max_window_seconds: 120,
    }),
    pcapRetentionError: () => null,
    pcapRequestFromRow: (row) => ({request_id: row.request_id, status: row.status}),
    classifyPcapOutcome: (status) => (
      status === 'fulfilled' ? 'captured' : status === 'failed' ? 'failed' : ''
    ),
    recordMetric: async (...args) => calls.push({name: 'metric', args}),
    readCaptureLossThreshold: () => 5,
    requeueStaleClaims: async () => calls.push({name: 'stale'}),
    priorityMaxWaitSeconds: 1200,
    captureRetentionSeconds: 3600,
    nowMs: () => Date.parse('2026-08-09T12:00:00Z'),
  });
  return {calls, repository};
}

test('candidate lookup pins an exact representative before group fallback', async () => {
  const env = harness({gets: [
    {representative_alert_id: 'alert-1', group_key: 'group-key'},
    {alert_id: 'alert-1'},
  ]});
  assert.deepEqual(await env.repository.candidateFromPayload({group_id: 'group-1'}), {alert_id: 'alert-1'});
  assert.match(env.calls[0].sql, /alert_group_summary/);
  assert.match(env.calls[1].sql, /alerts WHERE alert_id/);
});

test('create upsert resets all transfer state and records stable metric provenance', async () => {
  const env = harness({gets: [
    {alert_id: 'alert-1'},
    {request_id: 'pcap-1', status: 'pending', updated_at: 'clock-1'},
  ]});
  const result = await env.repository.createRequest({alert_id: 'alert-1'});
  assert.equal(result.execution.enabled, false);
  const insert = env.calls.find(({name}) => name === 'run');
  assert.match(insert.sql, /ON CONFLICT\(request_id\) DO UPDATE SET/);
  assert.match(insert.sql, /transfer_attempt_count = 0/);
  assert.equal(env.calls.at(-1).args[1], 'enqueued');
  assert.match(env.calls.at(-1).args[3].eventKey, /pcap-1:clock-1$/);
});

test('list preserves status bounds, priority aging, retention, and stale recovery', async () => {
  const env = harness({alls: [[{request_id: 'p1', status: 'pending'}]]});
  const result = await env.repository.listRequests(new URLSearchParams('status=pending&limit=999'));
  assert.equal(result.status, 'pending');
  assert.equal(result.policy.capture_loss_threshold_percent, 5);
  assert.equal(env.calls[0].name, 'run');
  assert.equal(env.calls[1].name, 'stale');
  const query = env.calls.find(({name}) => name === 'all');
  assert.match(query.sql, /WHEN 'critical' THEN 2/);
  assert.match(query.sql, /p.next_attempt_at IS NULL/);
  assert.equal(query.params.at(-1), 100);
});

test('bulk requeue deduplicates, bounds, and resets failed requests only', async () => {
  const ids = Array.from({length: 510}, (_, index) => `p${index}`);
  const env = harness({alls: [[]]});
  await env.repository.requeueRequests({request_ids: [...ids, 'p1']});
  const update = env.calls.find(({name}) => name === 'run');
  assert.match(update.sql, /WHERE status = 'failed'/);
  assert.equal(update.params.length, 501);
  assert.equal(new Set(update.params.slice(1)).size, 500);
});

test('outcome backfill rewrites only classified rows', async () => {
  const env = harness({alls: [[
    {request_id: 'p1', status: 'fulfilled'},
    {request_id: 'p2', status: 'pending'},
  ]]});
  await env.repository.backfillOutcomes();
  const updates = env.calls.filter(({name}) => name === 'run');
  assert.equal(updates.length, 1);
  assert.deepEqual(updates[0].params, ['captured', 'p1']);
});
