'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPcapRoutes} = require('../routes/pcap_routes');

function harness() {
  const calls = [];
  const service = new Proxy({}, {
    get: (_target, name) => async (value) => {
      calls.push({name, value});
      return {operation: name};
    },
  });
  const routes = createPcapRoutes({
    service,
    readJsonBody: async () => ({request_id: 'pcap-1'}),
    sendJson: (_response, status, payload) => calls.push({name: 'sendJson', status, payload}),
  });
  return {calls, routes};
}

test('exports the exact existing PCAP route surface without duplicates', () => {
  const keys = harness().routes.map(({method, path}) => `${method} ${path}`);
  assert.deepEqual(keys, [
    'POST /pcap/request',
    'GET /pcap/requests',
    'POST /pcap/claim',
    'POST /pcap/complete',
    'POST /pcap/progress',
    'POST /pcap/retry',
    'POST /pcap/analysis-status',
    'POST /pcap/requeue',
  ]);
  assert.equal(new Set(keys).size, keys.length);
});

test('invokes one service method and preserves 200 responses for every route', async () => {
  const env = harness();
  const expected = [
    'request', 'list', 'claim', 'complete', 'progress', 'retry', 'analysisStatus', 'requeue',
  ];
  for (const [index, route] of env.routes.entries()) {
    const before = env.calls.length;
    const parsedUrl = new URL(`${route.path}?status=pending`, 'http://localhost');
    await route.handler({request: {}, response: {}, parsedUrl});
    assert.deepEqual(env.calls.slice(before).map(({name}) => name), [expected[index], 'sendJson']);
    assert.equal(env.calls.at(-1).status, 200);
  }
  const listCall = env.calls.find(({name}) => name === 'list');
  assert.equal(listCall.value.get('status'), 'pending');
});
