'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const sqlite3 = require('sqlite3');
const {createDurableJobQueue} = require('../lib/durable_job_queue');
const {createPostgresShadowOutbox} = require('../lib/postgres_shadow_outbox');

function databaseHelpers() {
  const db = new sqlite3.Database(':memory:');
  const run = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function callback(error) {
      if (error) reject(error);
      else resolve({changes: this.changes, lastID: this.lastID});
    });
  });
  const get = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => (error ? reject(error) : resolve(row)));
  });
  const all = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
  });
  const close = () => new Promise((resolve, reject) => {
    db.close((error) => (error ? reject(error) : resolve()));
  });
  return {run, get, all, close};
}

async function fixture() {
  const helpers = databaseHelpers();
  const queue = createDurableJobQueue({
    ...helpers,
    now: () => '2026-07-29T12:00:00.000Z',
  });
  await queue.install();
  const outbox = createPostgresShadowOutbox(helpers);
  await outbox.install();
  return {...helpers, queue, outbox};
}

test('queue insert transactionally creates one dirty shadow marker', async (context) => {
  const env = await fixture();
  context.after(env.close);

  await env.run('BEGIN IMMEDIATE');
  await env.queue.enqueue('ai_analysis', 'group-1', {version: 1});
  await env.run('COMMIT');

  const pending = await env.outbox.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].job_type, 'ai_analysis');
  assert.equal(pending[0].dedupe_key, 'group-1');
  assert.equal(pending[0].revision, 1);
});

test('rolling back queue mutation also rolls back projection intent', async (context) => {
  const env = await fixture();
  context.after(env.close);

  await env.run('BEGIN IMMEDIATE');
  await env.queue.enqueue('ai_analysis', 'rolled-back', {version: 1});
  await env.run('ROLLBACK');

  assert.equal((await env.outbox.stats()).tracked, 0);
});

test('exact revision acknowledgement cannot hide a concurrent update', async (context) => {
  const env = await fixture();
  context.after(env.close);

  await env.queue.enqueue('ai_analysis', 'group-2', {version: 1});
  const first = (await env.outbox.pending())[0];
  await env.queue.enqueue('ai_analysis', 'group-2', {version: 2});

  assert.equal(
    await env.outbox.markProjected(
      first.entity_key,
      first.revision,
      '2026-07-29T12:01:00.000Z',
    ),
    true,
  );
  const pending = await env.outbox.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].revision, 2);
  assert.equal(JSON.parse(pending[0].payload_json).version, 2);
});

test('failure acknowledgement is revision-bound and observable', async (context) => {
  const env = await fixture();
  context.after(env.close);

  await env.queue.enqueue('ai_analysis', 'group-3', {version: 1});
  const first = (await env.outbox.pending())[0];
  assert.equal(
    await env.outbox.markFailure(
      first.entity_key,
      first.revision,
      'connection refused',
      '2099-01-01T00:00:00.000Z',
    ),
    true,
  );
  const stats = await env.outbox.stats();
  assert.equal(stats.tracked, 1);
  assert.equal(stats.pending, 1);
  assert.equal(stats.attempts, 1);
  assert.ok(stats.newest_pending_at);
  assert.ok(stats.oldest_pending_at);
});
