'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createControlledRetirementCommand} = require('../services/controlled_retirement_command');

function owner(overrides = {}) {
  const calls = [];
  const result = createControlledRetirementCommand({
    normalizeIdentity: (value) => value,
    sha256: () => 'retirement-1',
    replay: async () => null,
    validatePostState: async () => calls.push('validate-post'),
    projectCensus: async () => ({members: []}),
    get: async () => null,
    all: async () => [],
    run: async () => ({changes: 1}),
    parseJobPayload: () => ({}),
    projectJob: () => ({}),
    parseJsonObject: () => ({}),
    leaseKey: () => 'lease',
    hasLease: () => false,
    nowUtc: () => 'time',
    retirePendingExact: async () => true,
    refreshRun: async () => ({status: 'partial', total_count: 1}),
    receiptSchema: 'schema',
    eventType: 'event',
    canonicalJsonText: JSON.stringify,
    validateReceipt: () => undefined,
    conflict: (message) => new Error(message),
    ...overrides,
  });
  return {calls, result};
}

test('returns a verified canonical replay without performing mutations', async () => {
  const replayed = {receipt_sha256: 'hash'};
  let mutations = 0;
  const {calls, result} = owner({
    replay: async () => replayed,
    run: async () => { mutations += 1; return {changes: 1}; },
    retirePendingExact: async () => { mutations += 1; return true; },
  });
  assert.equal(await result.retire({case_id: 'case-1'}), replayed);
  assert.deepEqual(calls, ['validate-post']);
  assert.equal(mutations, 0);
});

test('fails closed before mutation when durable pre-state is missing', async () => {
  let mutations = 0;
  const {result} = owner({
    run: async () => { mutations += 1; return {changes: 1}; },
    retirePendingExact: async () => { mutations += 1; return true; },
  });
  await assert.rejects(
    result.retire({
      member_rank: 1,
      cohort_id: 'cohort-1',
      stable_group_id: 'group-1',
      expected_prior_analysis_id: '',
    }),
    /retirement pre-state changed/,
  );
  assert.equal(mutations, 0);
});
