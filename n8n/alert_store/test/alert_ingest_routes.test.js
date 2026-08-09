'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAlertIngestRoutes} = require('../routes/alert_ingest_routes');

function harness(result = {ok: true}) {
  const calls = [];
  const routes = createAlertIngestRoutes({
    service: {ingest: async (request) => {
      calls.push({name: 'ingest', request});
      return result;
    }},
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
  });
  return {calls, route: routes[0], routes};
}

test('exports only POST /alert and preserves exact URL matching', async () => {
  const env = harness();
  assert.deepEqual(env.routes.map(({method, path}) => `${method} ${path}`), ['POST /alert']);
  await env.route.handler({request: {url: '/alert?unexpected=1'}, response: {}});
  assert.deepEqual(env.calls, [
    {name: 'sendJson', status: 404, payload: {ok: false, status: 'not_found'}},
  ]);
});

test('preserves successful and rejected ingest status codes', async () => {
  const accepted = harness({ok: true, status: 'accepted'});
  await accepted.route.handler({request: {url: '/alert'}, response: {}});
  assert.equal(accepted.calls.at(-1).status, 200);

  const rejected = harness({ok: false, status: 'rejected'});
  await rejected.route.handler({request: {url: '/alert'}, response: {}});
  assert.equal(rejected.calls.at(-1).status, 400);
});
