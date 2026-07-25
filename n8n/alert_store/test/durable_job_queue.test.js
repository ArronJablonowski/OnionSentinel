'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const sqlite3 = require('sqlite3');
const {createDurableJobQueue} = require('../lib/durable_job_queue');

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

async function fixture(options = {}) {
  const helpers = databaseHelpers();
  const queue = createDurableJobQueue({
    ...helpers,
    now: () => options.now || '2026-07-19T12:00:00.000Z',
    transitionLeaseSeconds: options.transitionLeaseSeconds || 300,
  });
  await queue.install();
  return {...helpers, queue};
}

test('claim ownership token rejects a stale worker after lease recovery', async (context) => {
  const env = await fixture();
  context.after(env.close);
  await env.queue.enqueue('ai_analysis', 'group-1', {alert_id: 'a-1'});
  const first = await env.queue.claim('ai_analysis', 60);
  assert.ok(first?.lease_token);

  await env.run(
    "UPDATE durable_jobs SET lease_expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?",
    [first.id],
  );
  const recovery = await env.queue.recoverExpired();
  assert.deepEqual(recovery, {recovered: 1, failed: 0, job_types: {ai_analysis: 1}});

  await env.run(
    "UPDATE durable_jobs SET next_attempt_at = '2000-01-01T00:00:00.000Z' WHERE id = ?",
    [first.id],
  );
  const second = await env.queue.claim('ai_analysis', 60);
  assert.ok(second?.lease_token);
  assert.notEqual(second.lease_token, first.lease_token);
  assert.equal(await env.queue.complete(first), false);
  assert.equal(await env.queue.fail(first, 'late worker failure'), false);
  assert.equal(await env.queue.complete(second), true);
  assert.equal((await env.get('SELECT status FROM durable_jobs WHERE id = ?', [first.id])).status, 'completed');
});

test('startup recovery requeues a tokenless processing job from an older schema', async (context) => {
  const env = await fixture();
  context.after(env.close);
  await env.queue.enqueue('ai_analysis', 'group-upgrade', {alert_id: 'a-upgrade'});
  const claimed = await env.queue.claim('ai_analysis', 3600);
  assert.ok(claimed?.lease_token);

  // A worker created before lease tokens were introduced cannot prove
  // ownership after an upgrade. Recover it immediately even when its legacy
  // timestamp is still in the future; otherwise it remains unfinishable.
  await env.run(
    "UPDATE durable_jobs SET lease_token = NULL, lease_expires_at = '2099-01-01T00:00:00.000Z' WHERE id = ?",
    [claimed.id],
  );
  const recovery = await env.queue.recoverExpired();
  assert.deepEqual(recovery, {recovered: 1, failed: 0, job_types: {ai_analysis: 1}});
  const recovered = await env.get('SELECT status, lease_token FROM durable_jobs WHERE id = ?', [claimed.id]);
  assert.equal(recovered.status, 'pending');
  assert.equal(recovered.lease_token, null);
});

test('enqueue during processing coalesces exactly one rerun', async (context) => {
  const env = await fixture();
  context.after(env.close);
  await env.queue.enqueue('ai_analysis', 'group-2', {version: 1});
  const claimed = await env.queue.claim('ai_analysis', 60);
  await env.queue.enqueue('ai_analysis', 'group-2', {version: 2});

  const during = await env.get('SELECT * FROM durable_jobs WHERE id = ?', [claimed.id]);
  assert.equal(during.status, 'processing');
  assert.equal(during.rerun_requested, 1);
  assert.equal(JSON.parse(during.payload_json).version, 2);
  assert.equal(await env.queue.complete(claimed), true);

  const after = await env.get('SELECT * FROM durable_jobs WHERE id = ?', [claimed.id]);
  assert.equal(after.status, 'pending');
  assert.equal(after.attempt_count, 0);
  assert.equal(after.rerun_requested, 0);
  assert.ok(after.last_completed_at);
});

test('external worker heartbeat extends only its current lease', async (context) => {
  const env = await fixture({transitionLeaseSeconds: 120});
  context.after(env.close);
  await env.queue.enqueue('ai_analysis', 'group-3', {});
  const claimed = await env.queue.transition('ai_analysis', 'group-3', 'processing');
  assert.equal(claimed.updated, true);
  assert.ok(claimed.leaseToken);

  await env.queue.enqueue('ai_analysis', 'group-3', {new_evidence: true});
  const heartbeat = await env.queue.transition(
    'ai_analysis', 'group-3', 'processing', '', claimed.leaseToken,
  );
  assert.deepEqual(heartbeat, {updated: true, leaseToken: claimed.leaseToken});
  const processing = await env.get(
    "SELECT attempt_count, rerun_requested FROM durable_jobs WHERE dedupe_key = 'group-3'",
  );
  assert.equal(processing.attempt_count, 1);
  assert.equal(processing.rerun_requested, 1);

  const intruder = await env.queue.transition('ai_analysis', 'group-3', 'completed', '', 'wrong-token');
  assert.equal(intruder.updated, false);
  const completed = await env.queue.transition(
    'ai_analysis', 'group-3', 'completed', '', claimed.leaseToken,
  );
  assert.equal(completed.updated, true);
  assert.equal(
    (await env.get("SELECT status FROM durable_jobs WHERE dedupe_key = 'group-3'")).status,
    'pending',
  );
});

test('exhausted processing jobs become terminal instead of retrying forever', async (context) => {
  const env = await fixture();
  context.after(env.close);
  await env.queue.enqueue('public_enrichment', 'alert-1', {}, {maxAttempts: 1});
  const claimed = await env.queue.claim('public_enrichment', 60);
  assert.equal(claimed.attempt_count, 1);
  assert.equal(await env.queue.fail(claimed, 'provider timeout'), true);
  const failed = await env.get('SELECT status, last_error FROM durable_jobs WHERE id = ?', [claimed.id]);
  assert.equal(failed.status, 'failed');
  assert.equal(failed.last_error, 'provider timeout');
  assert.equal(await env.queue.claim('public_enrichment', 60), null);
});

test('a deterministic non-retryable failure becomes terminal on its first attempt', async (context) => {
  const env = await fixture();
  context.after(env.close);
  await env.queue.enqueue('incident_response_analysis', 'group-context', {}, {maxAttempts: 12});
  const claimed = await env.queue.transition(
    'incident_response_analysis', 'group-context', 'processing',
  );
  assert.equal(claimed.updated, true);

  const transition = await env.queue.transition(
    'incident_response_analysis',
    'group-context',
    'failed',
    'model context window exhausted',
    claimed.leaseToken,
    false,
  );

  assert.equal(transition.updated, true);
  const failed = await env.get(
    "SELECT status, attempt_count, last_error FROM durable_jobs WHERE dedupe_key = 'group-context'",
  );
  assert.equal(failed.status, 'failed');
  assert.equal(failed.attempt_count, 1);
  assert.equal(failed.last_error, 'model context window exhausted');
});
