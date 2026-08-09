'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createHealthRoutes} = require('../routes/health_routes');

test('preserves health, metrics, and job status envelopes', async () => {
  const sent = [];
  const routes = createHealthRoutes({
    service: {
      healthSnapshot: async () => ({ok: true, status: 'healthy'}),
      metricsSnapshot: async () => ({generated_at: 'now'}),
      jobStats: async () => [{status: 'pending', count: 1}],
    },
    sendJson: (_response, status, payload) => sent.push({status, payload}),
  });
  assert.deepEqual(routes.map(({method, path}) => `${method} ${path}`), [
    'GET /health', 'GET /metrics', 'GET /jobs/stats',
  ]);
  for (const route of routes) await route.handler({response: {}});
  assert.deepEqual(sent, [
    {status: 200, payload: {ok: true, status: 'healthy'}},
    {status: 200, payload: {ok: true, metrics: {generated_at: 'now'}}},
    {status: 200, payload: {ok: true, jobs: [{status: 'pending', count: 1}]}},
  ]);
});
