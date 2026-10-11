'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {reconcilePages} = require('../../../operations/reconcile-postgres-shadow');

function local(id, extra = {}) {
  return {id, revision: 1, projected_revision: 1, payload_json: '{"b":2,"a":1}',
    job_type: 'test', dedupe_key: String(id), status: 'completed', priority: 0,
    attempt_count: 0, max_attempts: 8, rerun_requested: 0, ...extra};
}
function remote(row) {
  return {...row, sqlite_id: row.id, source_revision: row.revision,
    payload_json: {a: 1, b: 2}, rerun_requested: false};
}

test('reconciliation crosses pages without omitting mismatches, missing or extra rows', async () => {
  const rows = [local(1), local(3), local(6), local(8, {projected_revision: 0,
    projection_updated_at: new Date().toISOString()})];
  const projected = [remote(rows[0]), remote(local(4)), {...remote(rows[2]), status: 'pending'}];
  const ranges = [];
  const result = await reconcilePages({maximumId: 8, pageSize: 2,
    sqlitePage: async (lo, hi) => {ranges.push([lo, hi]); return rows.filter(x => x.id > lo && x.id <= hi);},
    postgresPage: async (lo, hi) => projected.filter(x => x.sqlite_id > lo && x.sqlite_id <= hi)});
  assert.deepEqual(ranges, [[0, 2], [2, 4], [4, 6], [6, 8]]);
  assert.deepEqual(result.missing_sample, [3]);
  assert.deepEqual(result.extra_sample, [4]);
  assert.deepEqual(result.mismatch_sample, [6]);
  assert.equal(result.pending_projection_count, 1);
  assert.equal(result.ok, false);
});

test('fully converged pages pass with canonical JSON key ordering', async () => {
  const row = local(2);
  const result = await reconcilePages({maximumId: 2, pageSize: 1,
    sqlitePage: async (lo, hi) => hi === 2 ? [row] : [],
    postgresPage: async (lo, hi) => hi === 2 ? [remote(row)] : []});
  assert.equal(result.ok, true);
  assert.equal(result.pending_projection_count, 0);
  assert.equal(result.sqlite_rows, result.postgres_rows);
});

test('stale pending projection remains a failure and sample memory is bounded', async () => {
  const result = await reconcilePages({maximumId: 100,
    sqlitePage: async () => [...Array.from({length: 20}, (_, i) => local(i + 1)),
      local(50, {projected_revision: 0, projection_updated_at: '2020-01-01T00:00:00Z'})],
    postgresPage: async () => []});
  assert.equal(result.missing_count, 20);
  assert.equal(result.missing_sample.length, 10);
  assert.equal(result.pending_projection_stale, true);
  assert.equal(result.ok, false);
});
