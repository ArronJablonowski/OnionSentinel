'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createHttpRequestBoundary} = require('../services/http_request_boundary');

function fixture(overrides = {}) {
  const calls = [];
  const metrics = {ingest_errors: 0};
  const request = {
    method: 'GET',
    url: '/health',
    resume: () => calls.push(['resume']),
  };
  const response = {};
  const options = {
    controlledEvaluationMode: true,
    controlledRequests: new Set(['GET /health', 'POST /alert']),
    isShutdownStarted: () => false,
    controlledRequestAuthorized: (value) => { calls.push(['authorize', value]); return true; },
    routeRegistry: {
      dispatch: async (context) => { calls.push(['dispatch', context]); return true; },
    },
    sendJson: (...args) => calls.push(['sendJson', ...args]),
    serviceMetrics: metrics,
    writeBeacon: (...args) => calls.push(['beacon', ...args]),
    ...overrides,
  };
  return {boundary: createHttpRequestBoundary(options), calls, metrics, request, response};
}

test('shutdown refusal has first precedence and resumes the request', async () => {
  const f = fixture({isShutdownStarted: () => true});
  f.request.method = 'POST';
  f.request.url = '/alert';
  await f.boundary.handle(f.request, f.response);
  assert.deepEqual(f.calls, [
    ['resume'],
    ['sendJson', f.response, 503, {ok: false, status: 'shutting_down'}],
  ]);
});

test('controlled POST authorization fails before allowlist or dispatch', async () => {
  const f = fixture({controlledRequestAuthorized: () => false});
  f.request.method = 'POST';
  f.request.url = '/alert';
  await f.boundary.handle(f.request, f.response);
  assert.deepEqual(f.calls, [
    ['resume'],
    ['sendJson', f.response, 403, {
      ok: false,
      status: 'forbidden',
      reason: 'controlled evaluation authorization failed',
    }],
  ]);
});

test('controlled allowlist matches the exact uppercase method and raw URL', async () => {
  const f = fixture();
  f.request.method = 'get';
  f.request.url = '/health?expanded=1';
  await f.boundary.handle(f.request, f.response);
  assert.deepEqual(f.calls, [
    ['resume'],
    ['sendJson', f.response, 403, {
      ok: false,
      status: 'forbidden',
      reason: 'route is disabled in controlled evaluation mode',
    }],
  ]);
});

test('disabled controlled mode bypasses authorization and allowlisting', async () => {
  const f = fixture({controlledEvaluationMode: false});
  f.request.method = 'POST';
  f.request.url = '/unrestricted?value=1';
  await f.boundary.handle(f.request, f.response);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][0], 'dispatch');
  assert.equal(f.calls[0][1].parsedUrl.pathname, '/unrestricted');
  assert.equal(f.calls[0][1].parsedUrl.search, '?value=1');
});

test('allowed request forwards the same objects and parsed URL to one registry', async () => {
  const f = fixture();
  await f.boundary.handle(f.request, f.response);
  const dispatch = f.calls.at(-1);
  assert.equal(dispatch[0], 'dispatch');
  assert.equal(dispatch[1].request, f.request);
  assert.equal(dispatch[1].response, f.response);
  assert.equal(dispatch[1].parsedUrl.href, 'http://alert-store.local/health');
});

test('unknown route preserves the exact bounded 404 envelope', async () => {
  const f = fixture({
    routeRegistry: {dispatch: async () => false},
  });
  await f.boundary.handle(f.request, f.response);
  assert.deepEqual(f.calls, [
    ['sendJson', f.response, 404, {ok: false, status: 'not_found'}],
  ]);
});

test('POST alert failure records ingest metric and beacon before rejection', async () => {
  const failure = Object.assign(new Error('storage unavailable'), {statusCode: 507});
  const f = fixture({
    controlledEvaluationMode: false,
    routeRegistry: {dispatch: async () => { throw failure; }},
  });
  f.request.method = 'POST';
  f.request.url = '/alert';
  await f.boundary.handle(f.request, f.response);
  assert.equal(f.metrics.ingest_errors, 1);
  assert.deepEqual(f.calls, [
    ['beacon', 'error', {}, null, failure],
    ['sendJson', f.response, 507, {
      ok: false,
      status: 'rejected',
      reason: 'storage unavailable',
    }],
  ]);
});

test('non-alert failure defaults to 400 without ingest telemetry', async () => {
  const failure = new Error('bad request');
  const f = fixture({
    controlledEvaluationMode: false,
    routeRegistry: {dispatch: async () => { throw failure; }},
  });
  f.request.url = '/maintenance';
  await f.boundary.handle(f.request, f.response);
  assert.equal(f.metrics.ingest_errors, 0);
  assert.deepEqual(f.calls, [
    ['sendJson', f.response, 400, {
      ok: false,
      status: 'rejected',
      reason: 'bad request',
    }],
  ]);
});
