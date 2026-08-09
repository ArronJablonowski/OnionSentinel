'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createDurableJobRoutes} = require('../routes/durable_job_routes');

function harness(overrides = {}) {
  const calls = [];
  const routes = createDurableJobRoutes({
    service: {
      transitionStatus: async () => overrides.transition || {
        updated: true,
        job_type: 'ai_analysis',
        dedupe_key: 'stable-key',
        status: 'processing',
        lease_token: 'lease-2',
        claim: {job_id: 42},
      },
      reconcileCompleted: async () => ({job_type: 'ai_analysis', reconciled: 2}),
    },
    readJsonBody: async () => ({job_type: 'ai_analysis'}),
    sendJson: (_response, status, payload) => calls.push({status, payload}),
  });
  return {calls, routes};
}

test('exports only the exact durable job routes', () => {
  assert.deepEqual(harness().routes.map(({method, path}) => `${method} ${path}`), [
    'POST /jobs/status',
    'POST /jobs/reconcile-completed',
  ]);
});

test('preserves successful transition and reconciliation envelopes', async () => {
  const env = harness();
  for (const route of env.routes) {
    await route.handler({request: {}, response: {}});
  }
  assert.deepEqual(env.calls, [
    {status: 200, payload: {
      ok: true,
      job_type: 'ai_analysis',
      dedupe_key: 'stable-key',
      status: 'processing',
      lease_token: 'lease-2',
      claim: {job_id: 42},
    }},
    {status: 200, payload: {ok: true, job_type: 'ai_analysis', reconciled: 2}},
  ]);
});

test('preserves the exact 404 envelope for a rejected transition', async () => {
  const env = harness({transition: {
    updated: false,
    job_type: 'ai_analysis',
    dedupe_key: 'group-1',
    status: 'completed',
    lease_token: '',
    claim: null,
  }});
  await env.routes[0].handler({request: {}, response: {}});
  assert.deepEqual(env.calls[0], {status: 404, payload: {
    ok: false,
    job_type: 'ai_analysis',
    dedupe_key: 'group-1',
    status: 'completed',
    lease_token: '',
    claim: null,
  }});
});
