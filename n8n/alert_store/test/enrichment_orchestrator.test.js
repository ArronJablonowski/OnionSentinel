'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createEnrichmentOrchestrator} = require('../services/enrichment_orchestrator');

function createHarness(overrides = {}) {
  const writes = [];
  const cacheLookups = [];
  const peeks = [...(overrides.peeks || [])];
  let gateCalls = 0;
  let transactionCalls = 0;
  const providerRecord = (source, indicatorType, indicator) => ({
    source, indicator_type: indicatorType, indicator, verdict: 'unknown',
  });
  const providers = new Proxy({}, {
    get: (_target, name) => async (...args) => {
      const source = String(name).replace(/^lookup/, '').toLowerCase();
      const indicatorType = args.length > 1 ? args[0] : 'ip';
      const indicator = args.at(-1);
      return providerRecord(source, indicatorType, indicator);
    },
  });
  const policy = {
    sourceRateLimitMs: () => 1000,
    sourceTtlSeconds: () => 3600,
    sourceStaleIfErrorSeconds: () => 7200,
    sourceConfigured: (source) => !String(source).startsWith('missing'),
    sourceLimitNote: (source) => `limit:${source}`,
    shouldUseVirusTotal: (alert) => alert.triage?.level === 'high',
    investigationEnrichmentSources: {domain: ['otx', 'missing-provider']},
    normalizeInvestigationEnrichmentIndicator: (type, value) => ({type, value}),
    investigationIndicatorAlert: (type, value) => ({
      alert_id: `pivot:${type}:${value}`, triage: {level: 'high'},
    }),
    ...overrides.policy,
  };
  const cache = {
    lookup: async (options) => {
      cacheLookups.push(options);
      const record = await options.loader();
      return {record, cached: false, cache_state: 'miss'};
    },
    peek: async () => peeks.shift() || {cached: false, cache_state: 'miss'},
  };
  const orchestrator = createEnrichmentOrchestrator({
    cache,
    scheduler: {run: async (_source, task) => task()},
    providers,
    policy,
    extractAlertIndicators: overrides.extractAlertIndicators || (() => ({
      public_ips: [], domains: [], urls: [], hashes: [], cves: [],
    })),
    isRelayHeartbeat: (alert) => alert?.message_type === 'relay_heartbeat',
    nowUtc: () => '2026-08-09 22:30:00+00:00',
    formatProjectTimestamp: (value) => value.toISOString(),
    withSqliteWriteGate: async (task) => {
      gateCalls += 1;
      return task();
    },
    withImmediateTransaction: async (task) => {
      transactionCalls += 1;
      return task();
    },
    get: async () => overrides.rateLimitRow || null,
    run: async (sql, params) => writes.push({sql, params}),
    defaultTtlSeconds: 86400,
    vulnerabilityTtlSeconds: 172800,
    negativeTtlSeconds: 900,
    virusTotalMinimumLevel: 'high',
    urlscanSubmitEnabled: false,
    nowMs: () => Date.parse('2026-08-09T22:30:00Z'),
    delay: async () => undefined,
  });
  return {
    orchestrator,
    writes,
    cacheLookups,
    counts: () => ({gateCalls, transactionCalls}),
  };
}

test('rate-limit reservations are persisted inside one write transaction', async () => {
  const {orchestrator, writes, counts} = createHarness({
    rateLimitRow: {last_request_at: '2026-08-09  22:29:59.500Z'},
  });
  assert.equal(await orchestrator.reserveProviderRateLimitSlot('otx'), 500);
  assert.equal(counts().gateCalls, 1);
  assert.equal(counts().transactionCalls, 1);
  assert.match(writes[0].sql, /INSERT INTO enrichment_rate_limit/);
  assert.deepEqual(writes[0].params, ['otx', '2026-08-09  22:30:00.500Z']);
});

test('cached lookup retains TTL, negative TTL, stale window, scheduler, and reservation', async () => {
  const {orchestrator, cacheLookups, writes} = createHarness();
  const result = await orchestrator.cachedLookup(
    'otx', 'domain', 'example.com',
    async () => ({source: 'otx', indicator_type: 'domain', indicator: 'example.com'}),
  );
  assert.equal(result.cache_state, 'miss');
  assert.equal(cacheLookups[0].ttlSeconds, 3600);
  assert.equal(cacheLookups[0].negativeTtlSeconds, 900);
  assert.equal(cacheLookups[0].staleIfErrorSeconds, 7200);
  assert.equal(writes.length, 1);
});

test('heartbeat and invalid payloads remain no-op enrichment results', async () => {
  const {orchestrator} = createHarness();
  assert.equal((await orchestrator.enrichAlert(null)).status, 'invalid_skipped');
  assert.equal((await orchestrator.enrichAlert({message_type: 'relay_heartbeat'})).status, 'heartbeat_skipped');
});

test('alert fan-out remains bounded, stable, and severity-gates VirusTotal', async () => {
  const {orchestrator} = createHarness({
    extractAlertIndicators: () => ({
      public_ips: [], domains: ['z.example', 'a.example'], urls: [], hashes: [], cves: [],
    }),
  });
  const result = await orchestrator.enrichAlert({triage: {level: 'low'}});
  assert.equal(result.status, 'enriched');
  assert.equal(result.enrichment.records.length, 6);
  assert.equal(
    result.enrichment.skipped.filter((item) => item.source === 'virustotal').length,
    2,
  );
  assert.deepEqual(
    result.enrichment.records.map((record) => record.indicator),
    ['a.example', 'z.example', 'a.example', 'z.example', 'a.example', 'z.example'],
  );
  assert.deepEqual(result.enrichment.verdict_counts, {unknown: 6});
});

test('investigation cache is read-only, sorted, and reports missing providers', async () => {
  const {orchestrator, writes} = createHarness({peeks: [
    {cached: true, record: {source: 'zeta'}},
  ]});
  const result = await orchestrator.cachedInvestigationEnrichment('domain', 'example.com');
  assert.equal(result.cache_complete, true);
  assert.deepEqual(result.records, [{source: 'zeta'}]);
  assert.deepEqual(result.skipped, [{source: 'missing-provider', reason: 'missing_api_key'}]);
  assert.equal(writes.length, 0);
});
