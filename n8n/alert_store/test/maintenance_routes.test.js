'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createMaintenanceRoutes} = require('../routes/maintenance_routes');

function harness() {
  const calls = [];
  const routes = createMaintenanceRoutes({
    service: {
      rescore: async () => {
        calls.push('rescore');
        return {ok: true, rescored: 2};
      },
      refreshGroups: async () => {
        calls.push('refreshGroups');
        return {ok: true, groups: 1};
      },
    },
    sendJson: (_response, status, payload) => calls.push({status, payload}),
  });
  return {calls, routes};
}

test('exports only the exact existing maintenance routes', () => {
  assert.deepEqual(harness().routes.map(({method, path}) => `${method} ${path}`), [
    'POST /rescore', 'POST /refresh-groups',
  ]);
});

test('preserves exact URL matching and successful envelopes', async () => {
  const env = harness();
  await env.routes[0].handler({request: {url: '/rescore?unexpected=1'}, response: {}});
  assert.deepEqual(env.calls, [{status: 404, payload: {ok: false, status: 'not_found'}}]);

  const accepted = harness();
  await accepted.routes[0].handler({request: {url: '/rescore'}, response: {}});
  await accepted.routes[1].handler({request: {url: '/refresh-groups'}, response: {}});
  assert.deepEqual(accepted.calls, [
    'rescore', {status: 200, payload: {ok: true, rescored: 2}},
    'refreshGroups', {status: 200, payload: {ok: true, groups: 1}},
  ]);
});
