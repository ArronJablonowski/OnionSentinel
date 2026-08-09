'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createDurableJobRecovery} = require('../services/durable_job_recovery');

function harness(summary, {attempts = 0, authorized = {reconciled: 1}} = {}) {
  const calls = [];
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  let blockRecovery = false;
  const owner = createDurableJobRecovery({
    durableJobs: () => ({recoverExpired: async () => {
      calls.push('recover');
      if (blockRecovery) await blocked;
      return structuredClone(summary);
    }}),
    withWriteGate: async (task) => { calls.push('gate'); return task(); },
    withTransaction: async (task) => { calls.push('transaction'); return task(); },
    reconcileIncidentAttempts: async () => { calls.push('attempts'); return attempts; },
    reconcileAuthorizedActivity: async () => { calls.push('authorized'); return authorized; },
    nowUtc: () => '2026-08-09  12:00:00Z',
    warn: (message) => calls.push(['warn', message]),
    signalAiWorkers: async (reason) => calls.push(['ai', reason]),
    drainEnrichmentJobs: async () => calls.push('enrichment'),
    drainPostCommitJobs: async () => calls.push('post-commit'),
  });
  return {calls, owner, release, setBlocked: () => { blockRecovery = true; }};
}

test('empty recovery remains silent and skips campaign reconciliation', async () => {
  const env = harness({recovered: 0, failed: 0, job_types: {}});
  await env.owner.recover();
  assert.deepEqual(env.calls, ['gate', 'transaction', 'recover', 'attempts']);
});

test('AI recovery re-applies campaign admission before signaling worker', async () => {
  const env = harness({recovered: 1, failed: 0, job_types: {ai_analysis: 1}});
  await env.owner.recover();
  assert.deepEqual(env.calls.slice(0, 5), ['gate', 'transaction', 'recover', 'attempts', 'authorized']);
  assert.match(env.calls[5][1], /durable job lease recovery/);
  assert.deepEqual(env.calls[6], ['ai', 'ai-lease-recovered']);
});

test('recovered job types wake only their bounded owners', async () => {
  const env = harness({recovered: 2, failed: 0, job_types: {
    public_enrichment: 1, n8n_post_commit: 1,
  }});
  await env.owner.recover();
  assert.equal(env.calls.includes('authorized'), false);
  assert.equal(env.calls.includes('enrichment'), true);
  assert.equal(env.calls.includes('post-commit'), true);
});

test('reentrancy guard drops an overlapping scheduler tick and resets afterward', async () => {
  const env = harness({recovered: 0, failed: 0, job_types: {}});
  env.setBlocked();
  const first = env.owner.recover();
  await Promise.resolve();
  await env.owner.recover();
  assert.equal(env.calls.filter((item) => item === 'recover').length, 1);
  env.release();
  await first;
  await env.owner.recover();
  assert.equal(env.calls.filter((item) => item === 'recover').length, 2);
});

test('failure releases the reentrancy guard for the next recovery tick', async () => {
  let attempts = 0;
  const owner = createDurableJobRecovery({
    durableJobs: () => ({recoverExpired: async () => { attempts += 1; throw new Error('failed'); }}),
    withWriteGate: (task) => task(), withTransaction: (task) => task(),
    reconcileIncidentAttempts: async () => 0, reconcileAuthorizedActivity: async () => ({}),
    nowUtc: () => '', warn: () => {}, signalAiWorkers: async () => {},
    drainEnrichmentJobs: async () => {}, drainPostCommitJobs: async () => {},
  });
  await assert.rejects(owner.recover(), {message: 'failed'});
  await assert.rejects(owner.recover(), {message: 'failed'});
  assert.equal(attempts, 2);
});
