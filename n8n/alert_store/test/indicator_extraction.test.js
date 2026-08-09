'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createScoringPolicy} = require('../lib/scoring_policy');
const {createIndicatorExtraction} = require('../lib/indicator_extraction');

function nestedField(value, dottedPath) {
  return dottedPath.split('.').reduce(
    (current, part) => (current && typeof current === 'object'
      ? current[part] : undefined),
    value,
  );
}

const network = createScoringPolicy({
  rules: {
    infrastructure_ips: [], severity_base: {default: 0},
    direction_adjustments: {}, infrastructure_adjustments: {},
    keyword_adjustments: [], rule_adjustments: [], pair_adjustments: [],
    drop_rules: [], suppress_rules: [],
    thresholds: {critical_min: 85, high_min: 70, medium_min: 40},
  },
  nestedField,
});
const extraction = createIndicatorExtraction({
  parseIpv4: network.parseIpv4,
  isPrivateIpv4: network.isPrivateIpv4,
  nestedField,
});

test('rejects placeholder credentials and accepts configured secrets', () => {
  for (const value of ['', 'replace-me', 'YOUR-TOKEN', 'placeholder', 'changeme-now']) {
    assert.equal(extraction.isConfiguredSecret(value), false, value);
  }
  assert.equal(extraction.isConfiguredSecret('real-token-value'), true);
});

test('accepts public hosts and strips URL credentials, query, and fragments', () => {
  for (const host of ['localhost', 'printer.lan', 'host.internal', '10.0.0.1', 'tls.sni', '123.json']) {
    assert.equal(extraction.publicHostname(host), null, host);
  }
  assert.equal(extraction.publicHostname('Example.COM.'), 'example.com');
  assert.equal(extraction.publicHostname('198.51.100.4'), '198.51.100.4');
  assert.equal(
    extraction.redactUrlForPublicLookup('https://user:pass@example.com/path?q=secret#fragment'),
    'https://example.com/path',
  );
});

test('extracts and deduplicates bounded public detection indicators', () => {
  const md5 = 'A'.repeat(32);
  const indicators = extraction.extractAlertIndicators({
    message: `Observed evil.example and 198.51.100.4 CVE-2026-12345 ${md5}`,
    source: {ip: '10.0.0.1'},
    destination: {ip: '198.51.100.4'},
    url: {full: 'https://user:pass@evil.example/path?token=secret#x'},
    related: {hosts: ['EVIL.EXAMPLE'], ip: ['198.51.100.4']},
  });
  assert.deepEqual(indicators.public_ips, ['198.51.100.4']);
  assert.deepEqual(indicators.domains, ['evil.example']);
  assert.deepEqual(indicators.urls, ['https://evil.example/path']);
  assert.deepEqual(indicators.hashes, [{type: 'md5', value: md5.toLowerCase()}]);
  assert.deepEqual(indicators.cves, ['CVE-2026-12345']);
});

test('never derives indicators from prior provider enrichment responses', () => {
  const indicators = extraction.extractAlertIndicators({
    message: 'local-only event',
    enrichment: {
      external_intel: {
        records: [{raw_response: 'https://provider-only.example 203.0.113.99'}],
      },
    },
  });
  assert.deepEqual(indicators, {
    public_ips: [], domains: [], urls: [], hashes: [], cves: [],
  });
  assert.equal(extraction.hasUsableExternalIntel({
    enrichment: {external_intel: {records: [{}]}},
  }), true);
  assert.equal(extraction.hasUsableExternalIntel({}), false);
});
