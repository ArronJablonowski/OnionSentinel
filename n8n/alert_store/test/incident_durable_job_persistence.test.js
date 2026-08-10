'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createIncidentDurableJobPersistence,
} = require('../services/incident_durable_job_persistence');

function conflict(message) {
  return Object.assign(new Error(message), {statusCode: 409});
}

function owner({processing = null, changes = 0} = {}) {
  const reads = [];
  const writes = [];
  const persistence = createIncidentDurableJobPersistence({
    get: async (sql, params) => { reads.push({sql, params}); return processing; },
    run: async (sql, params) => { writes.push({sql, params}); return {changes}; },
    conflict,
  });
  return {persistence, reads, writes};
}

test('requires read, write, and conflict dependency owners', () => {
  assert.throws(() => createIncidentDurableJobPersistence({run() {}, conflict}), /get/);
  assert.throws(() => createIncidentDurableJobPersistence({get() {}, conflict}), /run/);
  assert.throws(() => createIncidentDurableJobPersistence({get() {}, run() {}}), /conflict/);
});

test('empty normalized inputs perform no database work', async () => {
  const {persistence, reads, writes} = owner();
  assert.equal(await persistence.rejectProcessing('ai_analysis', [null, 7, '  ']), undefined);
  assert.equal(await persistence.retirePendingIncident(undefined, 'time'), 0);
  assert.deepEqual(reads, []);
  assert.deepEqual(writes, []);
});

test('processing guard preserves normalized dedupe order and exact query scope', async () => {
  const {persistence, reads} = owner();
  await persistence.rejectProcessing('ai_analysis', [
    ' ABCDEF123456 ', 'abcdef123457', 'ABCDEF123456', '', null,
  ]);
  assert.equal(reads.length, 1);
  assert.deepEqual(reads[0].params, [
    'ai_analysis', 'abcdef123456', 'abcdef123457',
  ]);
  assert.match(reads[0].sql, /job_type = \? AND status = 'processing'/);
  assert.match(reads[0].sql, /dedupe_key IN \(\?, \?\)/);
  assert.match(reads[0].sql, /ORDER BY id ASC LIMIT 1/);
});

test('first processing conflict retains exact job and returned dedupe identity', async () => {
  const {persistence} = owner({
    processing: {id: 7, dedupe_key: 'abcdef123457'},
  });
  await assert.rejects(
    persistence.rejectProcessing('incident_response_analysis', [
      'abcdef123456', 'abcdef123457',
    ]),
    (error) => (
      error.statusCode === 409
      && error.message === 'controlled dispatch conflicts with processing '
        + 'incident_response_analysis job for abcdef123457'
    ),
  );
});

test('pending retirement preserves terminalization, lease cleanup, and parameters', async () => {
  const {persistence, writes} = owner({changes: '2'});
  assert.equal(await persistence.retirePendingIncident([
    ' ABCDEF123456 ', 'abcdef123457', 'ABCDEF123456', null,
  ], '2026-08-10T03:00:00Z'), 2);
  assert.equal(writes.length, 1);
  assert.deepEqual(writes[0].params, [
    '2026-08-10T03:00:00Z', '2026-08-10T03:00:00Z',
    '2026-08-10T03:00:00Z', 'abcdef123456', 'abcdef123457',
  ]);
  for (const fragment of [
    "SET status = 'completed'", 'lease_expires_at = NULL', 'lease_token = NULL',
    'last_error = NULL', 'completed_at = COALESCE(completed_at, ?)',
    'last_completed_at = COALESCE(last_completed_at, ?)',
    'processing_started_at = NULL', 'rerun_requested = 0', 'updated_at = ?',
    "job_type = 'incident_response_analysis'", "status = 'pending'",
    'dedupe_key IN (?, ?)',
  ]) assert.match(writes[0].sql, new RegExp(fragment.replace(/[?()]/g, '\\$&')));
});

test('missing write change count retains zero result', async () => {
  const writes = [];
  const persistence = createIncidentDurableJobPersistence({
    get: async () => null,
    run: async (sql, params) => { writes.push({sql, params}); return {}; },
    conflict,
  });
  assert.equal(await persistence.retirePendingIncident(['abcdef123456'], 'time'), 0);
  assert.equal(writes.length, 1);
});
