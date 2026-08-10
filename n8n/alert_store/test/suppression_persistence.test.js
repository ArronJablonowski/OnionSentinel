'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createSuppressionPersistence} = require('../services/suppression_persistence');

function owner(overrides = {}) {
  const writes = [];
  let reads = 0;
  let reviewChecks = 0;
  const rule = {name: 'suppress-1', reason: 'known noise', ttl_seconds: 60,
    escalation_threshold: 3};
  const service = createSuppressionPersistence({
    findSuppressRule: () => rule,
    stableGroupId: () => 'stable-id',
    nestedField: (value, path) => path.split('.').reduce((item, key) => item?.[key], value),
    pendingHumanReview: async () => { reviewChecks += 1; return false; },
    suppressionKey: () => 'suppression-key',
    ruleName: (value) => value.name,
    get: async () => { reads += 1; return null; },
    run: async (sql, params) => { writes.push({sql: sql.replace(/\s+/g, ' ').trim(), params}); },
    ...overrides,
  });
  return {service, writes, counts: () => ({reads, reviewChecks})};
}

test('unmatched alert remains accepted without review or persistence access', async () => {
  const {service, writes, counts} = owner({findSuppressRule: () => null});
  assert.deepEqual(await service.apply({}, 'time'), {status: 'accepted'});
  assert.deepEqual(counts(), {reads: 0, reviewChecks: 0});
  assert.deepEqual(writes, []);
});

test('pending human review bypasses automatic suppression before log reads', async () => {
  const {service, writes, counts} = owner({pendingHumanReview: async () => true});
  const result = await service.apply({}, 'time');
  assert.equal(result.review_status, 'pending_human_review');
  assert.equal(counts().reads, 0);
  assert.deepEqual(writes, []);
});

test('new window atomically resets counters and accepts the first event', async () => {
  const {service, writes} = owner();
  const result = await service.apply({}, 'time');
  assert.equal(result.status, 'accepted');
  assert.equal(result.seen_count, 1);
  assert.equal(writes.length, 1);
  assert(writes[0].sql.startsWith('INSERT INTO suppression_log'));
  assert(writes[0].sql.includes('seen_count = 1'));
});

test('unexpired repeat increments suppression count without escalation', async () => {
  const {service, writes} = owner({get: async () => ({
    window_start: '2026-08-10T00:00:00.000Z', seen_count: 1,
  })});
  const result = await service.apply({}, '2026-08-10T00:00:59.999Z');
  assert.equal(result.status, 'suppressed');
  assert.equal(result.seen_count, 2);
  assert.deepEqual(writes[0].params,
    ['2026-08-10T00:00:59.999Z', 1, 0, 'suppression-key']);
});

test('threshold repeat increments escalation count and remains visible', async () => {
  const {service, writes} = owner({get: async () => ({
    window_start: '2026-08-10T00:00:00.000Z', seen_count: 2,
  })});
  const result = await service.apply({}, '2026-08-10T00:00:59.999Z');
  assert.equal(result.status, 'escalated');
  assert.equal(result.seen_count, 3);
  assert.deepEqual(writes[0].params,
    ['2026-08-10T00:00:59.999Z', 0, 1, 'suppression-key']);
});

test('expired window resets instead of escalating the prior count', async () => {
  const {service, writes} = owner({
    get: async () => ({window_start: '2026-08-10T00:00:00.000Z', seen_count: 2}),
  });
  const result = await service.apply({}, '2026-08-10T00:01:00.000Z');
  assert.equal(result.status, 'accepted');
  assert(writes[0].sql.startsWith('INSERT INTO suppression_log'));
});
