'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const {requestJson} = require('../lib/http_json_client');


async function withServer(handler, testBody) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await testBody(`http://127.0.0.1:${server.address().port}`);
  } finally {
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}

test('returns one bounded successful JSON response', async () => {
  await withServer((_request, response) => {
    response.setHeader('Content-Type', 'application/json');
    response.end('{"ok":true}');
  }, async (baseUrl) => {
    const result = await requestJson({url: `${baseUrl}/ok`, maxResponseBytes: 1024});
    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.body, {ok: true});
  });
});

test('rejects non-success status unless the caller explicitly allows it', async () => {
  await withServer((_request, response) => {
    response.statusCode = 404;
    response.setHeader('Content-Type', 'application/json');
    response.end('{"message":"not found"}');
  }, async (baseUrl) => {
    await assert.rejects(
      requestJson({url: `${baseUrl}/missing`}),
      (error) => error.code === 'ERR_HTTP_STATUS' && error.statusCode === 404,
    );
    const allowed = await requestJson({url: `${baseUrl}/missing`, allowedStatusCodes: [404]});
    assert.equal(allowed.statusCode, 404);
  });
});

test('rejects malformed, declared-oversized, and streamed-oversized responses', async (context) => {
  await context.test('malformed JSON', async () => {
    await withServer((_request, response) => response.end('not-json'), async (baseUrl) => {
      await assert.rejects(
        requestJson({url: baseUrl}),
        (error) => error.code === 'ERR_INVALID_JSON_RESPONSE',
      );
    });
  });
  await context.test('declared oversized', async () => {
    await withServer((_request, response) => {
      response.writeHead(200, {'Content-Type': 'application/json', 'Content-Length': '4096'});
      response.end('{}');
    }, async (baseUrl) => {
      await assert.rejects(
        requestJson({url: baseUrl, maxResponseBytes: 1024}),
        (error) => error.code === 'ERR_RESPONSE_TOO_LARGE',
      );
    });
  });
  await context.test('streamed oversized', async () => {
    await withServer((_request, response) => {
      response.setHeader('Content-Type', 'application/json');
      response.write('{"value":"');
      response.write('x'.repeat(2048));
      response.end('"}');
    }, async (baseUrl) => {
      await assert.rejects(
        requestJson({url: baseUrl, maxResponseBytes: 1024}),
        (error) => error.code === 'ERR_RESPONSE_TOO_LARGE',
      );
    });
  });
});

test('rejects a stalled response on the inactivity timeout', async () => {
  await withServer((_request, response) => {
    response.setHeader('Content-Type', 'application/json');
    response.write('{');
  }, async (baseUrl) => {
    await assert.rejects(
      requestJson({url: baseUrl, timeoutMs: 100}),
      (error) => error.code === 'ERR_REQUEST_TIMEOUT',
    );
  });
});
