'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAnalystStateRoutes} = require('../routes/analyst_state_routes');

function harness() {
  const calls = [];
  const service = new Proxy({}, {
    get: (_target, name) => async (value) => {
      calls.push({name, value});
      return {operation: name};
    },
  });
  const routes = createAnalystStateRoutes({
    service,
    readJsonBody: async (request) => {
      calls.push({name: 'readJsonBody', value: request});
      return {payload: true};
    },
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
  });
  return {calls, routes};
}

test('exports the exact existing analyst state route surface', () => {
  assert.deepEqual(harness().routes.map(({method, path}) => `${method} ${path}`), [
    'GET /analyst-status',
    'POST /analyst-status',
    'GET /adjudications',
    'POST /adjudications',
    'POST /incidents/status',
  ]);
});

test('preserves status codes, payload parsing, and query forwarding', async () => {
  const env = harness();
  const expectedStatuses = [200, 200, 200, 201, 200];
  for (const [index, route] of env.routes.entries()) {
    const request = {method: route.method};
    const parsedUrl = new URL(`${route.path}?group_id=abcdef123456`, 'http://localhost');
    await route.handler({request, response: {}, parsedUrl});
    assert.equal(env.calls.at(-1).status, expectedStatuses[index]);
  }
  assert.deepEqual(
    env.calls.filter(({name}) => name === 'readJsonBody').length,
    3,
  );
  assert.equal(
    env.calls.find(({name}) => name === 'adjudicationSnapshot').value.get('group_id'),
    'abcdef123456',
  );
});
