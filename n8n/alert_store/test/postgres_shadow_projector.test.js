'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPostgresShadowProjector} = require('../lib/postgres_shadow_projector');

function row(revision = 3) {
  return {
    entity_key: '42',
    revision,
    id: 42,
    job_type: 'ai_analysis',
    dedupe_key: 'group-42',
    payload_json: '{"version":3}',
    status: 'pending',
    priority: 4,
    attempt_count: 0,
    max_attempts: 8,
    next_attempt_at: '2026-07-29T12:00:00.000Z',
    created_at: '2026-07-29T12:00:00.000Z',
    updated_at: '2026-07-29T12:00:00.000Z',
    requested_at: '2026-07-29T12:00:00.000Z',
    rerun_requested: 0,
  };
}

test('successful projection acknowledges the exact SQLite revision', async () => {
  const acknowledged = [];
  const pool = {
    query: async (sql, values) => {
      assert.match(sql, /apply_shadow_durable_job/);
      assert.equal(values[0], 42);
      assert.equal(values[1], 3);
      return {rows: [{applied: true}]};
    },
    end: async () => undefined,
  };
  const outbox = {
    pending: async () => [row()],
    markProjected: async (...args) => {
      acknowledged.push(args);
      return true;
    },
    markFailure: async () => false,
  };
  const projector = createPostgresShadowProjector({
    pool,
    outbox,
    withWriteGate: (task) => task(),
    now: () => '2026-07-29T12:01:00.000Z',
  });

  const result = await projector.drain();

  assert.equal(result.projected, 1);
  assert.deepEqual(acknowledged, [
    ['42', 3, '2026-07-29T12:01:00.000Z'],
  ]);
});

test('database failure records one bounded retry and stops the batch', async () => {
  const failures = [];
  let queries = 0;
  const pool = {
    query: async () => {
      queries += 1;
      throw new Error('connection refused');
    },
    end: async () => undefined,
  };
  const outbox = {
    pending: async () => [row(1), {...row(2), entity_key: '43', id: 43}],
    markProjected: async () => false,
    markFailure: async (...args) => {
      failures.push(args);
      return true;
    },
  };
  const projector = createPostgresShadowProjector({
    pool,
    outbox,
    withWriteGate: (task) => task(),
    now: () => '2026-07-29T12:01:00.000Z',
  });

  const result = await projector.drain();

  assert.equal(queries, 1);
  assert.equal(result.failures, 1);
  assert.equal(failures.length, 1);
  assert.equal(failures[0][0], '42');
  assert.equal(failures[0][1], 1);
});
