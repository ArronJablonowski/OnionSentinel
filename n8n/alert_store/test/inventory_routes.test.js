'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createInventoryRoutes} = require('../routes/inventory_routes');

function harness(overrides = {}) {
  const calls = [];
  const service = new Proxy(overrides.service || {}, {
    get(target, name) {
      if (name in target) return target[name];
      return async (...args) => {
        calls.push({name, args});
        return {ok: true};
      };
    },
  });
  const routes = createInventoryRoutes({
    service,
    authorizeWrite: (request) => calls.push({name: 'authorizeWrite', args: [request]}),
    readJsonBody: async () => ({operator_ref: 'reviewed-operator'}),
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
    now: () => new Date('2026-08-09T21:00:00.000Z'),
  });
  async function invoke(method, target) {
    const parsedUrl = new URL(target, 'http://localhost');
    const route = routes.find((item) => item.method === method && item.path === parsedUrl.pathname);
    assert.ok(route, `missing route ${method} ${parsedUrl.pathname}`);
    await route.handler({request: {method}, response: {}, parsedUrl});
  }
  return {calls, invoke, routes};
}

test('exports the exact existing inventory route surface without duplicates', () => {
  const {routes} = harness();
  const keys = routes.map(({method, path}) => `${method} ${path}`);
  assert.equal(keys.length, 15);
  assert.equal(new Set(keys).size, keys.length);
  assert.deepEqual(keys.sort(), [
    'GET /ac-hunter/snapshot',
    'GET /assets/dhcp-state',
    'GET /assets/inventory',
    'GET /assets/snapshot',
    'GET /software-inventory',
    'POST /ac-hunter/snapshots',
    'POST /assets/approve-dhcp-ip-change',
    'POST /assets/demote',
    'POST /assets/dhcp-state',
    'POST /assets/import',
    'POST /assets/promote-dhcp',
    'POST /assets/update',
    'POST /software-inventory/import/chunk',
    'POST /software-inventory/import/commit',
    'POST /software-inventory/import/start',
  ]);
});

test('preserves empty AC Hunter status and successful ingest status codes', async () => {
  const empty = harness({service: {latestAcHunterSnapshot: async () => null}});
  await empty.invoke('GET', '/ac-hunter/snapshot');
  assert.deepEqual(empty.calls.at(-1), {
    name: 'sendJson',
    status: 404,
    payload: {
      ok: false,
      status: 'not_collected',
      error: 'AC Hunter has not completed a scheduled database collection yet',
    },
  });

  const changed = harness({service: {ingestAcHunterSnapshot: async () => ({ok: true, changed: true})}});
  await changed.invoke('POST', '/ac-hunter/snapshots');
  assert.equal(changed.calls[0].name, 'authorizeWrite');
  assert.equal(changed.calls.at(-1).status, 201);
});

test('preserves software query defaults and an explicit observation time', async () => {
  let query;
  const env = harness({service: {querySoftwareInventory: async (value) => {
    query = value;
    return {ok: true};
  }}});
  await env.invoke('GET', '/software-inventory?limit=25&observed_at=2026-08-01T00%3A00%3A00Z');
  assert.deepEqual(query, {
    limit: '25',
    offset: 0,
    search: '',
    tier: 'all',
    confidence: 'all',
    freshness: 'all',
    platform: 'all',
    window: '30d',
    sort: 'last_seen',
    direction: 'desc',
    observed_at: '2026-08-01T00:00:00Z',
  });
  assert.equal(env.calls.at(-1).status, 200);
});

test('authorizes asset mutations before invoking one service method', async () => {
  const env = harness();
  await env.invoke('POST', '/assets/promote-dhcp');
  assert.deepEqual(env.calls.map((call) => call.name), [
    'authorizeWrite',
    'promoteDhcpAsset',
    'sendJson',
  ]);
  assert.equal(env.calls.at(-1).status, 201);
});
