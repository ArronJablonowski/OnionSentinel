'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createEnrichmentProviderClient} = require('../services/enrichment_provider_client');

function createHarness({responses = [], controlled = false, secrets = {}} = {}) {
  const requests = [];
  const normalized = [];
  const notFound = [];
  const queue = [...responses];
  const client = createEnrichmentProviderClient({
    controlledEvaluationMode: controlled,
    boundedRequestJson: async (options) => {
      requests.push(options);
      return queue.shift() || {statusCode: 200, body: {}};
    },
    timeoutMs: 5000,
    maxResponseBytes: 4096,
    safeString: (value, limit) => String(value || '').slice(0, limit),
    normalizedEnrichmentRecord: (...args) => {
      normalized.push(args);
      return {kind: 'normalized', args};
    },
    notFoundEnrichmentRecord: (...args) => {
      notFound.push(args);
      return {kind: 'not_found', args};
    },
    verdictFromStats: () => ({verdict: 'malicious', confidence: 90}),
    enrichmentSecrets: {
      abuseipdb: 'abuse-secret', greynoise: 'grey-secret', virustotal: 'vt-secret',
      censysToken: '', censysOrganizationId: '', censysId: 'id', censysSecret: 'secret',
      nvd: '', ...secrets,
    },
    isConfiguredSecret: (value) => Boolean(value && !String(value).startsWith('placeholder')),
    formatProjectTimestamp: (value) => value.toISOString(),
  });
  return {client, requests, normalized, notFound};
}

test('controlled evaluation denies outbound HTTP before invoking the client', async () => {
  const {client, requests} = createHarness({controlled: true});
  await assert.rejects(client.lookupAbuseIpdb('198.51.100.1'), /outbound HTTP is disabled/);
  assert.equal(requests.length, 0);
});

test('AbuseIPDB preserves bounded client limits, endpoint, credential header, and verdict', async () => {
  const {client, requests, normalized} = createHarness({responses: [{
    statusCode: 200,
    body: {data: {abuseConfidenceScore: 80, usageType: 'hosting'}},
  }]});
  await client.lookupAbuseIpdb('198.51.100.2');
  assert.equal(requests[0].timeoutMs, 5000);
  assert.equal(requests[0].maxResponseBytes, 4096);
  assert.match(requests[0].url, /ipAddress=198\.51\.100\.2/);
  assert.equal(requests[0].headers.Key, 'abuse-secret');
  assert.deepEqual(normalized[0].slice(0, 6), [
    'abuseipdb', '198.51.100.2', 'ip', 'malicious', 80, ['hosting', undefined, undefined],
  ]);
});

test('provider 404 remains honest unknown evidence through the not-found boundary', async () => {
  const {client, requests, notFound} = createHarness({responses: [{
    statusCode: 404, body: {message: 'not found'},
  }]});
  const result = await client.lookupGreynoise('203.0.113.9');
  assert.equal(result.kind, 'not_found');
  assert.deepEqual(requests[0].allowedStatusCodes, [404]);
  assert.deepEqual(notFound[0], [
    'greynoise', '203.0.113.9', 'ip', {message: 'not found'},
  ]);
});

test('Censys token mode takes precedence and records bounded provider errors', async () => {
  const {client, requests} = createHarness({
    secrets: {censysToken: 'token-secret', censysOrganizationId: 'org-1'},
    responses: [{statusCode: 429, body: {errors: [{message: 'quota exceeded'}]}}],
  });
  await assert.rejects(
    client.lookupCensys('203.0.113.10'),
    /Censys Platform API returned HTTP 429: quota exceeded/,
  );
  assert.match(requests[0].url, /api\.platform\.censys\.io\/v3/);
  assert.equal(requests[0].headers.Authorization, 'Bearer token-secret');
  assert.equal(requests[0].headers['X-Organization-ID'], 'org-1');
});

test('VirusTotal URL lookup retains base64url identity and analysis timestamp', async () => {
  const {client, requests, normalized} = createHarness({responses: [{
    statusCode: 200,
    body: {data: {attributes: {
      last_analysis_stats: {malicious: 2},
      last_analysis_date: 1_700_000_000,
    }}},
  }]});
  await client.lookupVirusTotal('url', 'https://example.com/path');
  assert.doesNotMatch(requests[0].url, /https:\/\/example\.com/);
  assert.match(requests[0].url, /virustotal\.com\/api\/v3\/urls\//);
  assert.equal(requests[0].headers['x-apikey'], 'vt-secret');
  assert.equal(normalized[0][3], 'malicious');
  assert.equal(normalized[0][4], 90);
  assert.match(normalized[0][8], /^2023-/);
});
