'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAnalysisRequestRoutes} = require('../routes/analysis_request_routes');

function harness() {
  const calls = [];
  const service = new Proxy({}, {
    get: (_target, name) => async (payload) => {
      calls.push({name, payload});
      return {operation: name};
    },
  });
  const routes = createAnalysisRequestRoutes({
    service,
    readJsonBody: async () => ({case_id: 'ir-one'}),
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
  });
  return {calls, routes};
}

test('exports the exact analysis request route surface', () => {
  assert.deepEqual(harness().routes.map(({method, path}) => `${method} ${path}`), [
    'POST /ai/request',
    'POST /incidents/escalate',
    'POST /incidents/reanalyze',
    'POST /controlled-evaluations/retire',
    'POST /incidents/reanalyze-all',
  ]);
});

test('invokes one service boundary and preserves each status code', async () => {
  const env = harness();
  const expected = [
    ['requestAi', 202],
    ['escalateIncident', 202],
    ['reanalyzeIncident', 202],
    ['retireEvaluation', 200],
    ['reanalyzeAllIncidents', 202],
  ];
  for (const [index, route] of env.routes.entries()) {
    const before = env.calls.length;
    await route.handler({request: {}, response: {}});
    assert.deepEqual(env.calls.slice(before).map(({name}) => name), [expected[index][0], 'sendJson']);
    assert.equal(env.calls.at(-1).status, expected[index][1]);
  }
});
