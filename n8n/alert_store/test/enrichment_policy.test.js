'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createEnrichmentPolicy} = require('../lib/enrichment_policy');

function createPolicy(overrides = {}) {
  return createEnrichmentPolicy({
    normalizeTimestampValue: (value) => value ? `normalized:${value}` : null,
    nowUtc: () => '2026-08-09 22:25:00+00:00',
    isConfiguredSecret: (value) => String(value || '').startsWith('configured:'),
    enrichmentSecrets: {nvd: '', censysId: '', censysSecret: '', ...overrides.secrets},
    defaultTtlSeconds: 86400,
    vulnerabilityTtlSeconds: 172800,
    sourceTtlDefaults: {virustotal: 43200},
    staleIfErrorSeconds: 3600,
    vulnerabilityStaleIfErrorSeconds: 7200,
    severityRank: {low: 1, high: 3, critical: 4},
    virusTotalMinimumLevel: 'high',
    parseIpv4: (value) => /^\d+\.\d+\.\d+\.\d+$/.test(value) ? value : null,
    isPrivateIpv4: (value) => value.startsWith('10.'),
    publicHostname: (value) => value === 'example.com' ? value : null,
    redactUrlForPublicLookup: (value) => value.startsWith('https://example.com')
      ? 'https://example.com/path' : null,
    environment: overrides.environment || {},
  });
}

test('normalizes bounded records and honest not-found evidence', () => {
  const policy = createPolicy();
  const record = policy.normalizedEnrichmentRecord(
    'provider', 'ioc', 'domain', 'suspicious', 70,
    [...Array.from({length: 22}, (_, index) => `tag-${index}`), ''],
    {raw: true}, 'first', 'last',
  );
  assert.equal(record.tags.length, 20);
  assert.equal(record.first_seen, 'normalized:first');
  assert.equal(record.cached_at, '2026-08-09 22:25:00+00:00');
  assert.deepEqual(
    policy.notFoundEnrichmentRecord('provider', 'ioc', 'domain', null),
    {
      source: 'provider', indicator: 'ioc', indicator_type: 'domain',
      verdict: 'unknown', confidence: 0, tags: ['not_found'],
      first_seen: null, last_seen: null, raw_response: {status: 'not_found'},
      cached_at: '2026-08-09 22:25:00+00:00',
    },
  );
});

test('preserves verdict thresholds and confidence clamps', () => {
  const policy = createPolicy();
  assert.deepEqual(policy.verdictFromStats({malicious: 9}), {
    verdict: 'malicious', confidence: 100,
  });
  assert.deepEqual(policy.verdictFromStats({suspicious: 2}), {
    verdict: 'suspicious', confidence: 70,
  });
  assert.deepEqual(policy.verdictFromStats({harmless: 1}), {
    verdict: 'benign', confidence: 60,
  });
  assert.deepEqual(policy.verdictFromStats({}), {verdict: 'unknown', confidence: 0});
});

test('keeps credential isolation, public sources, and NVD pacing', () => {
  const missing = createPolicy();
  assert.equal(missing.sourceConfigured('abuseipdb'), false);
  assert.equal(missing.sourceConfigured('cisa_kev'), true);
  assert.equal(missing.sourceConfigured('unknown'), false);
  assert.equal(missing.sourceRateLimitMs('nvd'), 7000);
  const configured = createPolicy({secrets: {nvd: 'configured:key'}});
  assert.equal(configured.sourceRateLimitMs('nvd'), 1000);
  assert.match(configured.sourceLimitNote('virustotal'), /4 requests\/minute/);
});

test('honors per-source TTL overrides and vulnerability stale windows', () => {
  const policy = createPolicy({environment: {
    ENRICHMENT_CACHE_VIRUSTOTAL_TTL_SECONDS: '901.9',
  }});
  assert.equal(policy.sourceTtlSeconds('virustotal'), 901);
  assert.equal(policy.sourceTtlSeconds('nvd'), 172800);
  assert.equal(policy.sourceTtlSeconds('unknown'), 86400);
  assert.equal(policy.sourceStaleIfErrorSeconds('epss'), 7200);
  assert.equal(policy.sourceStaleIfErrorSeconds('otx'), 3600);
});

test('validates public pivots and preserves deterministic correlation identity', () => {
  const policy = createPolicy();
  assert.deepEqual(policy.normalizeInvestigationEnrichmentIndicator(
    'url', 'https://example.com/path?secret=1',
  ), {type: 'url', value: 'https://example.com/path'});
  assert.throws(
    () => policy.normalizeInvestigationEnrichmentIndicator('ip', '10.0.0.1'),
    (error) => error.statusCode === 400,
  );
  assert.throws(
    () => policy.normalizeInvestigationEnrichmentIndicator('email', 'a@example.com'),
    (error) => error.statusCode === 400,
  );
  const first = policy.investigationIndicatorAlert('domain', 'example.com');
  const second = policy.investigationIndicatorAlert('domain', 'example.com');
  assert.equal(first.alert_id, second.alert_id);
  assert.deepEqual(first.dns, {question: {name: 'example.com'}});
  assert.equal(policy.shouldUseVirusTotal({triage: {level: 'high'}}), true);
  assert.equal(policy.shouldUseVirusTotal({severity_label: 'low'}), false);
});
