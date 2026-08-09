'use strict';

const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {PassThrough} = require('node:stream');
const test = require('node:test');
const {createRequestDispatcher, requestPath} = require('../lib/http_dispatch');

function harness({method = 'GET', admission = () => () => {}, handler} = {}) {
  const calls = [];
  let tick = 1_000_000n;
  const request = new PassThrough();
  request.method = method;
  request.url = '/alerts?limit=1';
  request.socket = {remoteAddress: '127.0.0.9'};
  const response = new EventEmitter();
  response.statusCode = 200;
  response.headers = {};
  response.setHeader = (name, value) => { response.headers[name] = value; };
  const dispatch = createRequestDispatcher({
    handleRequest: handler || (async () => { calls.push({name: 'handle'}); }),
    postRequestAdmission: {tryAcquire: admission},
    logger: {log: (...args) => calls.push({name: 'log', args})},
    sendJson: (_response, status, payload) => {
      response.statusCode = status;
      calls.push({name: 'sendJson', status, payload});
    },
    randomUUID: () => 'request-1',
    monotonicNow: () => {
      const value = tick;
      tick += 2_000_000n;
      return value;
    },
  });
  return {calls, dispatch, request, response};
}

test('normalizes valid and malformed request paths without retaining queries', () => {
  assert.equal(requestPath('/alerts?limit=1'), '/alerts');
  assert.equal(requestPath('http://[invalid'), 'http://[invalid');
  assert.equal(requestPath(`/bad?${'x'.repeat(600)}`), '/bad');
});

test('preserves request ID and completion telemetry for a GET request', async () => {
  const env = harness();
  await env.dispatch(env.request, env.response);
  assert.equal(env.response.headers['X-Request-ID'], 'request-1');
  assert.deepEqual(env.calls.map(({name}) => name), ['handle']);
  env.response.emit('finish');
  assert.deepEqual(env.calls.at(-1), {
    name: 'log',
    args: ['info', 'http.request.completed', {
      request_id: 'request-1',
      method: 'GET',
      path: '/alerts',
      status_code: 200,
      duration_ms: 2,
      remote_address: '127.0.0.9',
    }],
  });
});

test('releases a POST admission lease after success and failure', async (context) => {
  for (const failure of [false, true]) {
    await context.test(failure ? 'failure' : 'success', async () => {
      let released = 0;
      const expected = new Error('handler failed');
      const env = harness({
        method: 'POST',
        admission: () => () => { released += 1; },
        handler: async () => {
          if (failure) throw expected;
        },
      });
      if (failure) await assert.rejects(env.dispatch(env.request, env.response), expected);
      else await env.dispatch(env.request, env.response);
      assert.equal(released, 1);
    });
  }
});

test('rejects excess POST work with the exact capacity response', async () => {
  const env = harness({method: 'POST', admission: () => null});
  await env.dispatch(env.request, env.response);
  assert.equal(env.response.headers['Retry-After'], '1');
  assert.deepEqual(env.calls.map(({name}) => name), ['log', 'sendJson']);
  assert.deepEqual(env.calls[0].args, ['warning', 'http.request.rejected_capacity', {
    request_id: 'request-1',
    method: 'POST',
    path: '/alerts',
  }]);
  assert.deepEqual(env.calls[1], {
    name: 'sendJson',
    status: 503,
    payload: {
      ok: false,
      status: 'busy',
      reason: 'alert-store POST capacity is busy',
    },
  });
});
