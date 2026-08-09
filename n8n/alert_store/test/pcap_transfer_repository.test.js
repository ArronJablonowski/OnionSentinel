'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapTransferRepository} = require('../repositories/pcap_transfer_repository');

const NOW = '2026-08-09  12:00:00Z';
const NOW_MS = Date.parse('2026-08-09T12:00:00Z');

function harness({rows = [], changes = 1} = {}) {
  const calls = [];
  const pendingRows = [...rows];
  const repository = createPcapTransferRepository({
    get: async (sql, params) => {
      calls.push({name: 'get', sql, params});
      return pendingRows.shift();
    },
    run: async (sql, params) => {
      calls.push({name: 'run', sql, params});
      return {changes};
    },
    safeString: (value, maxLength) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, maxLength),
    nonNegativeIntegerField: (value) => {
      const parsed = Number(value);
      return Number.isInteger(parsed) && parsed >= 0 ? parsed : null;
    },
    nowUtc: () => NOW,
    formatProjectTimestamp: (value) => value.toISOString().replace('T', '  '),
    pcapRequestFromRow: (row) => ({request_id: row.request_id, status: row.status}),
    classifyPcapOutcome: (_status, error) => error?.includes('timeout') ? 'timeout' : 'failed',
    pcapOutcomes: new Set(['captured', 'timeout', 'failed']),
    pipelineMetrics: {
      record: async (...args) => calls.push({name: 'metric', args}),
    },
    claimLeaseSeconds: 1800,
    maxAttempts: 3,
    maxRetrySeconds: 300,
    nowMs: () => NOW_MS,
  });
  return {calls, repository};
}

test('stale claim recovery retains bounded retry and terminal timeout policy', async () => {
  const env = harness();
  await env.repository.requeueStaleClaims();
  const call = env.calls[0];
  assert.equal(call.name, 'run');
  assert.match(call.sql, /transfer_attempt_count >= \?/);
  assert.match(call.sql, /COALESCE\(transfer_progress_at, claimed_at, updated_at, created_at\)/);
  assert.deepEqual(call.params.slice(0, 7), [3, 3, 3, NOW, 3, NOW, NOW]);
});

test('claim remains compare-and-set and honors durable retry clocks', async () => {
  const deferred = harness({rows: [{request_id: 'p1', status: 'pending', next_attempt_at: '2026-08-09T12:01:00Z'}]});
  assert.equal((await deferred.repository.claimRequest({request_id: 'p1'})).claimed, false);
  assert.equal(deferred.calls.some(({name}) => name === 'run'), false);

  const claimed = harness({rows: [
    {request_id: 'p1', status: 'pending'},
    {request_id: 'p1', status: 'claimed'},
  ]});
  const result = await claimed.repository.claimRequest({request_id: 'p1', relay_host: 'relay-1'});
  assert.equal(result.claimed, true);
  const update = claimed.calls.find(({name}) => name === 'run');
  assert.match(update.sql, /status = 'pending'/);
  assert.match(update.sql, /transfer_attempt_count = transfer_attempt_count \+ 1/);
});

test('progress validates stage and byte bounds before renewing a claim', async () => {
  const env = harness();
  await assert.rejects(
    env.repository.updateTransferProgress({request_id: 'p1', stage: 'unknown'}),
    /invalid PCAP transfer stage/,
  );
  await assert.rejects(
    env.repository.updateTransferProgress({request_id: 'p1', stage: 'exporting', transferred_bytes: 2, total_bytes: 1}),
    /cannot exceed/,
  );
  const result = await env.repository.updateTransferProgress({
    request_id: 'p1', stage: 'relay_to_mac', transferred_bytes: 2, total_bytes: 4,
  });
  assert.equal(result.progress_at, NOW);
  assert.match(env.calls.at(-1).sql, /WHERE request_id = \? AND status = 'claimed'/);
});

test('retry state is bounded, stage-aware, durable, and metrically observable', async () => {
  const deferred = harness({rows: [
    {request_id: 'p1', status: 'claimed', transfer_attempt_count: 1, transfer_stage: 'exporting'},
    {request_id: 'p1', status: 'pending'},
  ]});
  const result = await deferred.repository.retryRequest({
    request_id: 'p1', error: 'connection timeout', stage: 'relay_to_mac', retry_after_seconds: 999,
  });
  assert.equal(result.retry_scheduled, true);
  const update = deferred.calls.find(({name}) => name === 'run');
  assert.equal(update.params[0], 'pending');
  assert.equal(update.params[7], 'relay_to_mac');
  assert.equal(deferred.calls.at(-1).args[1], 'deferred');

  const exhausted = harness({rows: [
    {request_id: 'p2', status: 'claimed', transfer_attempt_count: 3},
    {request_id: 'p2', status: 'failed'},
  ]});
  assert.equal((await exhausted.repository.retryRequest({request_id: 'p2', error: 'timeout'})).exhausted, true);
  assert.equal(exhausted.calls.find(({name}) => name === 'run').params[0], 'failed');
});

test('completion validates artifacts and exposes only post-write wake intent', async () => {
  const invalid = harness();
  await assert.rejects(
    invalid.repository.completeRequest({request_id: 'p1', status: 'fulfilled'}),
    /requires artifact_path/,
  );
  assert.equal(invalid.calls.some(({name}) => name === 'run'), false);

  const env = harness({rows: [{
    request_id: 'p1', status: 'fulfilled', claimed_at: NOW, artifact_size_bytes: 42,
  }]});
  const result = await env.repository.completeRequest({
    request_id: 'p1',
    status: 'fulfilled',
    artifact_path: '/bounded/evidence.pcap',
    artifact_sha256: 'a'.repeat(64),
    artifact_size_bytes: 42,
  });
  assert.equal(result.wake_pcap_analysis, true);
  assert.equal(env.calls.find(({name}) => name === 'run').params[5], null);
  assert.equal(env.calls.at(-1).name, 'metric');
  assert.equal(env.calls.at(-1).args[1], 'completed');
});
