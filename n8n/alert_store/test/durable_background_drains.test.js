'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createDurableBackgroundDrains} = require('../services/durable_background_drains');

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return {promise, resolve};
}

function fixture(overrides = {}) {
  const events = [];
  const enrichmentJob = {
    id: 41,
    attempt_count: 2,
    dedupe_key: 'alert-1',
    payload: {alert_id: 'alert-1'},
  };
  const postCommitJob = {
    id: 52,
    attempt_count: 3,
    dedupe_key: 'report-1',
    payload: {report_job_id: 'report-1', should_write_report: true},
  };
  const queue = {
    claim: async (type, lease) => {
      events.push(['claim', type, lease]);
      if (overrides.claim) return overrides.claim(type, lease);
      return type === 'public_enrichment' ? enrichmentJob : postCommitJob;
    },
    enqueue: async (...args) => events.push(['enqueue', ...args]),
    complete: async (job) => {
      events.push(['complete', job.id]);
      return overrides.completed ?? true;
    },
    fail: async (...args) => events.push(['fail', ...args]),
  };
  const dependencies = {
    durableJobs: () => (overrides.queue === undefined ? queue : overrides.queue),
    withWriteTransaction: async (task) => {
      events.push(['transaction', 'start']);
      try {
        return await task();
      } finally {
        events.push(['transaction', 'end']);
      }
    },
    get: async (sql, params) => {
      events.push(['get', sql, params]);
      if (sql.includes('alert_json')) {
        return overrides.alertRow === undefined
          ? {alert_json: JSON.stringify({alert_id: 'alert-1', source: {ip: '10.0.0.1'}})}
          : overrides.alertRow;
      }
      if (sql.includes('SELECT * FROM alerts')) {
        return overrides.updatedRow === undefined
          ? {
            alert_id: 'alert-1',
            stable_group_id: 'group-1',
            stable_group_key: 'key-1',
            triage_level: 'high',
          }
          : overrides.updatedRow;
      }
      if (sql.includes('SELECT status FROM durable_jobs')) {
        return {status: overrides.failedStatus || 'pending'};
      }
      throw new Error(`unexpected get: ${sql}`);
    },
    run: async (...args) => events.push(['run', ...args]),
    enrichAlert: async (alert) => {
      events.push(['enrich', alert]);
      if (overrides.enrichmentError) throw overrides.enrichmentError;
      return overrides.enrichmentResult || {ok: true, alert: {...alert, enriched: true}};
    },
    enrichmentRecord: (alert) => ({enriched: Boolean(alert.enriched)}),
    jsonText: (value) => JSON.stringify(value),
    indexAlertObservables: async (...args) => events.push(['index', ...args]),
    groupKeyFromRow: () => 'derived-key',
    groupIdFromKey: (key) => `derived:${key}`,
    authorizedCampaignForAlertId: async () => overrides.campaign || null,
    matchesAnalysis: (level) => level !== 'informational',
    severityRank: {informational: 0, low: 1, medium: 2, high: 3, critical: 4},
    recordMetric: async (...args) => events.push(['metric', ...args]),
    signalAiWorkers: (reason) => events.push(['signal', reason]),
    requestJson: async (options) => {
      events.push(['request', options]);
      if (overrides.requestError) throw overrides.requestError;
      return overrides.response || {
        statusCode: 200,
        body: {ok: true, report_written: true},
      };
    },
    safeString: (value, limit) => String(value || '').slice(0, limit),
    enrichmentTimeoutMs: 5001,
    n8nPostCommitUrl: overrides.url === undefined ? 'http://n8n.test/hook' : overrides.url,
    n8nPostCommitToken: overrides.token === undefined ? 'test-token' : overrides.token,
    n8nPostCommitTimeoutMs: 5001,
    n8nPostCommitBaseRetrySeconds: 17,
  };
  return {
    owner: createDurableBackgroundDrains(dependencies),
    events,
    queue,
    enrichmentJob,
    postCommitJob,
  };
}

test('post-commit confirmation accepts direct and wrapped success envelopes', () => {
  const {owner} = fixture();
  assert.deepEqual(
    owner.postCommitResult({report_written: true, report_job_id: 'one'}),
    {ok: true, payload: {report_written: true, report_job_id: 'one'}},
  );
  assert.deepEqual(
    owner.postCommitResult([{json: {ok: true, report_written: true}}]),
    {ok: true, payload: {ok: true, report_written: true}},
  );
});

test('post-commit confirmation preserves rejection precedence and bounded fallback', () => {
  const {owner} = fixture();
  assert.deepEqual(
    owner.postCommitResult([
      {ok: false, reason: 'explicit rejection'},
      {report_written: true},
    ]),
    {ok: false, reason: 'explicit rejection'},
  );
  assert.deepEqual(owner.postCommitResult(null), {
    ok: false,
    reason: 'n8n did not confirm the committed alert report write',
  });
});

test('uninitialized and disabled drains are no-ops without transactions', async () => {
  const missing = fixture({queue: null});
  await missing.owner.drainEnrichment();
  await missing.owner.drainPostCommit();
  assert.deepEqual(missing.events, []);

  const disabled = fixture({url: '', token: ''});
  await disabled.owner.drainPostCommit();
  assert.deepEqual(disabled.events, []);
});

test('enrichment drain prevents overlap and resets its guard after an empty claim', async () => {
  const pending = deferred();
  let claims = 0;
  const state = fixture({
    claim: async () => {
      claims += 1;
      if (claims === 1) return pending.promise;
      return null;
    },
  });
  const first = state.owner.drainEnrichment();
  await Promise.resolve();
  await state.owner.drainEnrichment();
  assert.equal(claims, 1);
  pending.resolve(null);
  await first;
  await state.owner.drainEnrichment();
  assert.equal(claims, 2);
});

test('enrichment success preserves claim, persistence, AI, metric, and wake order', async () => {
  const state = fixture();
  await state.owner.drainEnrichment();

  assert.deepEqual(state.events[1], ['claim', 'public_enrichment', 101]);
  const labels = state.events.map((event) => event[0]);
  assert.ok(labels.indexOf('enrich') < labels.indexOf('run'));
  assert.ok(labels.indexOf('index') < labels.indexOf('enqueue'));
  assert.ok(labels.indexOf('enqueue') < labels.indexOf('complete'));
  assert.ok(labels.lastIndexOf('transaction') < labels.indexOf('signal'));
  assert.deepEqual(
    state.events.find((event) => event[0] === 'enqueue'),
    [
      'enqueue',
      'ai_analysis',
      'group-1',
      {group_id: 'group-1', group_key: 'key-1', representative_alert_id: 'alert-1'},
      {priority: 3, maxAttempts: 8},
    ],
  );
  assert.deepEqual(state.events.at(-1), ['signal', 'enrichment-completed']);
  assert.equal(
    state.events.some((event) => event[0] === 'metric'
      && event[1] === 'public_enrichment' && event[2] === 'completed'),
    true,
  );
});

test('incident-response-only enrichment completes without duplicate AI work', async () => {
  const state = fixture({campaign: {investigation_mode: 'incident_response_only'}});
  await state.owner.drainEnrichment();
  assert.equal(state.events.some((event) => event[0] === 'enqueue'), false);
  assert.equal(state.events.some((event) => event[0] === 'signal'), false);
  assert.equal(state.events.some((event) => event[0] === 'complete'), true);
});

test('enrichment failure is durable and wakes AI only after terminal exhaustion', async () => {
  const state = fixture({
    enrichmentError: new Error('provider unavailable'),
    failedStatus: 'failed',
  });
  await state.owner.drainEnrichment();

  const failed = state.events.find((event) => event[0] === 'fail');
  assert.equal(failed[1], state.enrichmentJob);
  assert.equal(failed[2], 'provider unavailable');
  assert.deepEqual(state.events.at(-1), ['signal', 'enrichment-exhausted']);
  assert.equal(
    state.events.some((event) => event[0] === 'metric'
      && event[1] === 'public_enrichment' && event[2] === 'failed'),
    true,
  );
});

test('post-commit success preserves authenticated request and completion transaction', async () => {
  const state = fixture();
  await state.owner.drainPostCommit();

  assert.deepEqual(state.events[1], ['claim', 'n8n_post_commit', 16]);
  const request = state.events.find((event) => event[0] === 'request')[1];
  assert.deepEqual(request, {
    method: 'POST',
    url: 'http://n8n.test/hook',
    headers: {'X-Relay-Token': 'test-token'},
    body: state.postCommitJob.payload,
    timeoutMs: 5001,
  });
  assert.equal(state.events.some((event) => event[0] === 'complete'), true);
  assert.equal(state.events.some((event) => event[0] === 'fail'), false);
  assert.equal(
    state.events.some((event) => event[0] === 'metric'
      && event[1] === 'n8n_post_commit' && event[2] === 'completed'),
    true,
  );
});

test('post-commit rejection preserves retry base, failure metric, and guard reset', async () => {
  let claims = 0;
  const state = fixture({
    claim: (type) => {
      claims += 1;
      return type === 'n8n_post_commit' && claims === 1
        ? {
          id: 52, attempt_count: 3, dedupe_key: 'report-1',
          payload: {report_job_id: 'report-1'},
        }
        : null;
    },
    response: {statusCode: 503, body: {ok: false, reason: 'synthetic outage'}},
  });
  await state.owner.drainPostCommit();
  await state.owner.drainPostCommit();

  const failed = state.events.find((event) => event[0] === 'fail');
  assert.equal(failed[2], 'synthetic outage');
  assert.equal(failed[3], 17);
  assert.equal(claims, 2);
  assert.equal(
    state.events.some((event) => event[0] === 'metric'
      && event[1] === 'n8n_post_commit' && event[2] === 'failed'),
    true,
  );
});
