'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createDurableJobService} = require('../services/durable_job_service');

function boundedString(value, limit) {
  return String(value || '').trim().slice(0, limit);
}

function harness(overrides = {}) {
  const calls = [];
  const service = createDurableJobService({
    safeString: boundedString,
    withWriteGate: async (callback) => {
      calls.push('gate:begin');
      const result = await callback();
      calls.push('gate:end');
      return result;
    },
    withTransaction: async (callback) => {
      calls.push('transaction:begin');
      const result = await callback();
      calls.push('transaction:commit');
      return result;
    },
    controlledTransitionAdmission: async (payload) => {
      calls.push('controlled:admit');
      return {payload};
    },
    transitionJobStatus: async (...args) => {
      calls.push('durable:transition');
      return overrides.transition || {
        updated: true,
        resolvedKey: 'stable-key',
        leaseToken: 'lease-next',
        claim: {job_id: 42},
      };
    },
    applyControlledTransition: () => calls.push('controlled:apply'),
    completePendingByDedupeKeys: async (jobType, keys) => {
      calls.push({name: 'durable:reconcile', jobType, keys});
      return 3;
    },
  });
  return {calls, service};
}

test('commits the durable transition before applying its controlled mirror', async () => {
  const env = harness();
  const payload = {
    job_type: ' ai_analysis ',
    dedupe_key: ' group-1 ',
    status: ' COMPLETED ',
    lease_token: ' lease-1 ',
    error: ' bounded error ',
    retryable: false,
  };
  assert.deepEqual(await env.service.transitionStatus(payload), {
    updated: true,
    job_type: 'ai_analysis',
    dedupe_key: 'stable-key',
    status: 'completed',
    lease_token: 'lease-next',
    claim: {job_id: 42},
  });
  assert.deepEqual(env.calls, [
    'gate:begin',
    'transaction:begin',
    'controlled:admit',
    'durable:transition',
    'transaction:commit',
    'controlled:apply',
    'gate:end',
  ]);
});

test('does not apply the controlled mirror after a failed transaction', async () => {
  const env = harness();
  const expected = new Error('commit failed');
  env.service = createDurableJobService({
    safeString: boundedString,
    withWriteGate: (callback) => callback(),
    withTransaction: async (callback) => {
      await callback();
      throw expected;
    },
    controlledTransitionAdmission: async () => null,
    transitionJobStatus: async () => ({updated: true}),
    applyControlledTransition: () => env.calls.push('controlled:apply'),
    completePendingByDedupeKeys: async () => 0,
  });
  await assert.rejects(env.service.transitionStatus({
    job_type: 'ai_analysis', dedupe_key: 'group-1', status: 'completed',
  }), expected);
  assert.equal(env.calls.includes('controlled:apply'), false);
});

test('preserves a missing transition without inventing claim data', async () => {
  const env = harness({transition: {
    updated: false,
    resolvedKey: 'group-1',
    leaseToken: '',
  }});
  const result = await env.service.transitionStatus({
    job_type: 'ai_analysis', dedupe_key: 'group-1', status: 'failed',
  });
  assert.equal(result.updated, false);
  assert.equal(result.claim, null);
});

test('normalizes, bounds, and transactionally reconciles dedupe keys', async () => {
  const env = harness();
  const requested = ['', ' first ', ...Array.from({length: 2100}, (_, index) => `key-${index}`)];
  assert.deepEqual(await env.service.reconcileCompleted({
    job_type: ' ai_analysis ', dedupe_keys: requested,
  }), {job_type: 'ai_analysis', reconciled: 3});
  const call = env.calls.find((item) => typeof item === 'object');
  assert.equal(call.keys.length, 2000);
  assert.equal(call.keys[0], 'first');
  assert.equal(call.keys.at(-1), 'key-1998');
  assert.deepEqual(env.calls.slice(0, 2), ['gate:begin', 'transaction:begin']);
  assert.deepEqual(env.calls.slice(-2), ['transaction:commit', 'gate:end']);
});

test('rejects missing durable job identities before acquiring the write gate', async () => {
  const env = harness();
  await assert.rejects(env.service.transitionStatus({status: 'completed'}),
    /job_type and dedupe_key are required/);
  await assert.rejects(env.service.reconcileCompleted({job_type: 'ai_analysis'}),
    /job_type and dedupe_keys are required/);
  assert.deepEqual(env.calls, []);
});
