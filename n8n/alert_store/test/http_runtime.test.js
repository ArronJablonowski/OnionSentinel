'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const test = require('node:test');
const {PassThrough} = require('node:stream');
const {configureHttpServer, createRequestAdmission, readJsonObject} = require('../lib/http_runtime');

function requestWith(headers = {}) {
  const request = new PassThrough();
  request.headers = headers;
  return request;
}

test('accepts one bounded JSON object', async () => {
  const request = requestWith({'content-length': '11'});
  const parsed = readJsonObject(request, {maxBytes: 1024});
  request.end('{"ok":true}');
  assert.deepEqual(await parsed, {ok: true});
});

test('optionally binds the parsed object to the exact submitted body bytes', async () => {
  const rawBody = Buffer.from('{\n  "second": 2,\n  "first": 1\n}\n', 'utf8');
  const request = requestWith({'content-length': String(rawBody.length)});
  const parsed = readJsonObject(request, {
    maxBytes: 1024,
    includeBodySha256: true,
  });
  request.end(rawBody);

  const payload = await parsed;
  assert.deepEqual(payload, {second: 2, first: 1});
  assert.equal(
    payload.__body_sha256,
    crypto.createHash('sha256').update(rawBody).digest('hex'),
  );
  assert.equal(
    Object.prototype.propertyIsEnumerable.call(payload, '__body_sha256'),
    false,
  );
  assert.equal(JSON.stringify(payload), '{"second":2,"first":1}');
});

test('rejects arrays and malformed or truncated bodies', async (context) => {
  await context.test('array', async () => {
    const request = requestWith();
    const parsed = readJsonObject(request, {maxBytes: 1024});
    request.end('[]');
    await assert.rejects(parsed, (error) => error.statusCode === 400);
  });
  await context.test('truncated', async () => {
    const request = requestWith({'content-length': '20'});
    const parsed = readJsonObject(request, {maxBytes: 1024});
    request.end('{"ok":true}');
    await assert.rejects(parsed, (error) => error.statusCode === 400);
  });
});

test('rejects declared and chunked payloads above the limit with 413', async (context) => {
  await context.test('declared', async () => {
    const request = requestWith({'content-length': '2048'});
    await assert.rejects(readJsonObject(request, {maxBytes: 1024}), (error) => error.statusCode === 413);
  });
  await context.test('chunked', async () => {
    const request = requestWith();
    const parsed = readJsonObject(request, {maxBytes: 1024});
    request.write(Buffer.alloc(800, 1));
    request.end(Buffer.alloc(800, 1));
    await assert.rejects(parsed, (error) => error.statusCode === 413);
  });
});

test('configures explicit server resource ceilings', () => {
  const server = configureHttpServer(http.createServer(), {
    requestTimeoutMs: 12000,
    headersTimeoutMs: 4000,
    keepAliveTimeoutMs: 3000,
    maxRequestsPerSocket: 12,
    maxConnections: 24,
  });
  assert.equal(server.requestTimeout, 12000);
  assert.equal(server.headersTimeout, 4000);
  assert.equal(server.keepAliveTimeout, 3000);
  assert.equal(server.maxRequestsPerSocket, 12);
  assert.equal(server.maxConnections, 24);
  server.close();
});

test('request admission rejects overload and releases each slot exactly once', () => {
  const admission = createRequestAdmission(2);
  const releaseFirst = admission.tryAcquire();
  const releaseSecond = admission.tryAcquire();
  assert.equal(typeof releaseFirst, 'function');
  assert.equal(typeof releaseSecond, 'function');
  assert.equal(admission.tryAcquire(), null);
  assert.deepEqual(admission.snapshot(), {
    active_requests: 2,
    max_active_requests: 2,
    rejected_requests: 1,
  });
  releaseFirst();
  releaseFirst();
  assert.equal(admission.snapshot().active_requests, 1);
  assert.equal(typeof admission.tryAcquire(), 'function');
  releaseSecond();
});
