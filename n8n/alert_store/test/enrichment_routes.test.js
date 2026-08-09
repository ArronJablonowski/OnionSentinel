'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createEnrichmentRoutes} = require('../routes/enrichment_routes');

function harness({enrichResult = {ok: true}} = {}) {
  const calls = [];
  const service = {
    enrich: async (payload) => {
      calls.push({name: 'enrich', payload});
      return enrichResult;
    },
    cachedInvestigation: async (payload) => {
      calls.push({name: 'cachedInvestigation', payload});
      return {ok: true};
    },
    queryInvestigation: async (payload) => {
      calls.push({name: 'queryInvestigation', payload});
      return {ok: true};
    },
  };
  const routes = createEnrichmentRoutes({
    service,
    authorizeInvestigation: (request) => calls.push({name: 'authorize', request}),
    readJsonBody: async () => {
      calls.push({name: 'readJsonBody'});
      return {indicator: 'example.test'};
    },
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
  });
  return {calls, routes};
}

test('exports the exact existing enrichment route surface', () => {
  assert.deepEqual(harness().routes.map(({method, path}) => `${method} ${path}`), [
    'POST /enrich',
    'POST /investigations/enrichment/cache',
    'POST /investigations/enrichment/query',
  ]);
});

test('preserves exact-URL /enrich matching and result status', async () => {
  const env = harness({enrichResult: {ok: false, reason: 'failed'}});
  await env.routes[0].handler({request: {url: '/enrich?unexpected=1'}, response: {}});
  assert.deepEqual(env.calls, [
    {name: 'sendJson', status: 404, payload: {ok: false, status: 'not_found'}},
  ]);

  const accepted = harness({enrichResult: {ok: false, reason: 'failed'}});
  await accepted.routes[0].handler({request: {url: '/enrich'}, response: {}});
  assert.deepEqual(accepted.calls.map(({name}) => name), ['readJsonBody', 'enrich', 'sendJson']);
  assert.equal(accepted.calls.at(-1).status, 400);
});

test('authorizes investigation requests before reading their bodies', async () => {
  const env = harness();
  for (const route of env.routes.slice(1)) {
    const before = env.calls.length;
    await route.handler({request: {}, response: {}});
    assert.deepEqual(env.calls.slice(before).map(({name}) => name), [
      'authorize', 'readJsonBody', route.path.endsWith('/cache')
        ? 'cachedInvestigation' : 'queryInvestigation', 'sendJson',
    ]);
    assert.equal(env.calls.at(-1).status, 200);
  }
});
