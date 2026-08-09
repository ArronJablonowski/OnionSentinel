'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createRouteRegistry, routeKey} = require('../lib/route_registry');

test('normalizes methods and dispatches one exact pathname', async () => {
  const calls = [];
  const registry = createRouteRegistry([{
    method: 'get',
    path: '/health',
    handler: async (context) => calls.push(context.parsedUrl.pathname),
  }]);
  const handled = await registry.dispatch({
    request: {method: 'GET'},
    parsedUrl: new URL('http://localhost/health?full=1'),
  });
  assert.equal(handled, true);
  assert.deepEqual(calls, ['/health']);
  assert.deepEqual(registry.routeKeys(), ['GET /health']);
});

test('rejects duplicate batches atomically', () => {
  const registry = createRouteRegistry();
  assert.throws(() => registry.registerAll([
    {method: 'GET', path: '/same', handler() {}},
    {method: 'get', path: '/same', handler() {}},
  ]), /duplicate route registration: GET \/same/);
  assert.deepEqual(registry.routeKeys(), []);
});

test('rejects duplicate existing routes and malformed keys', () => {
  const registry = createRouteRegistry([
    {method: 'POST', path: '/jobs/status', handler() {}},
  ]);
  assert.throws(() => registry.registerAll([
    {method: 'POST', path: '/jobs/status', handler() {}},
  ]), /duplicate route registration/);
  assert.throws(() => routeKey('GET', '/health?full=1'), /exact pathname/);
  assert.throws(() => routeKey('GET /POST', '/health'), /only letters/);
});

test('returns false without invoking a fallback for an unknown route', async () => {
  const registry = createRouteRegistry();
  assert.equal(await registry.dispatch({
    request: {method: 'GET'},
    parsedUrl: new URL('http://localhost/not-found'),
  }), false);
});
