'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const sqlite3 = require('sqlite3');
const {
  cacheKey,
  createEnrichmentCache,
  normalizeIndicator,
} = require('../lib/enrichment_cache');

function databaseHelpers() {
  const db = new sqlite3.Database(':memory:');
  const run = (sql, params = []) => new Promise((resolve, reject) => {
    db.run(sql, params, function callback(error) {
      if (error) reject(error);
      else resolve({changes: this.changes, lastID: this.lastID});
    });
  });
  const get = (sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => (error ? reject(error) : resolve(row)));
  });
  const all = (sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => (error ? reject(error) : resolve(rows)));
  });
  const close = () => new Promise((resolve, reject) => {
    db.close((error) => (error ? reject(error) : resolve()));
  });
  return {run, get, all, close};
}

async function fixture(options = {}) {
  const helpers = databaseHelpers();
  let currentMs = Date.parse('2026-07-21T12:00:00.000Z');
  let gate = Promise.resolve();
  const withWriteGate = (task) => {
    const next = gate.catch(() => undefined).then(task);
    gate = next.catch(() => undefined);
    return next;
  };
  const withTransaction = async (task) => {
    await helpers.run('BEGIN IMMEDIATE');
    try {
      const result = await task();
      await helpers.run('COMMIT');
      return result;
    } catch (error) {
      await helpers.run('ROLLBACK').catch(() => undefined);
      throw error;
    }
  };
  const cache = createEnrichmentCache({
    ...helpers,
    withWriteGate,
    withTransaction,
    now: () => new Date(currentMs),
    formatTimestamp: (date) => date.toISOString(),
    l1MaxEntries: options.l1MaxEntries || 32,
    l1TtlSeconds: options.l1TtlSeconds || 300,
    l1MaxBytes: options.l1MaxBytes || 16384,
    maxEntries: options.maxEntries || 100,
    maxBytes: options.maxBytes || 1024 * 1024,
    rawResponseMaxBytes: options.rawResponseMaxBytes || 4096,
    staleIfErrorSeconds: options.staleIfErrorSeconds || 300,
  });
  await cache.install();
  return {
    ...helpers,
    cache,
    advance(seconds) {
      currentMs += seconds * 1000;
    },
  };
}

function record(indicator, overrides = {}) {
  return {
    source: 'otx',
    indicator,
    indicator_type: 'domain',
    verdict: 'suspicious',
    confidence: 70,
    tags: ['test'],
    raw_response: {pulse_count: 2},
    ...overrides,
  };
}

test('indicator normalization produces stable provider cache keys', () => {
  assert.equal(normalizeIndicator('domain', 'EXAMPLE.COM.'), 'example.com');
  assert.equal(
    cacheKey('OTX', 'domain', 'EXAMPLE.COM.'),
    cacheKey('otx', 'DOMAIN', 'example.com'),
  );
  assert.equal(
    normalizeIndicator('url', 'https://user:secret@Example.COM/path#fragment'),
    'https://example.com/path',
  );
  assert.equal(
    normalizeIndicator('ip', '2001:0db8:0:0:0:0:0:1'),
    '2001:db8::1',
  );
});

test('fresh L1 and SQLite hits do not call the provider again', async (context) => {
  const env = await fixture({l1TtlSeconds: 10});
  context.after(env.close);
  let loads = 0;
  const lookup = () => env.cache.lookup({
    source: 'otx',
    indicatorType: 'domain',
    indicator: 'example.com',
    ttlSeconds: 3600,
    loader: async () => {
      loads += 1;
      return record('example.com');
    },
  });

  assert.equal((await lookup()).cache_state, 'refreshed');
  assert.equal((await lookup()).cache_state, 'fresh');
  env.advance(11);
  assert.equal((await lookup()).cache_state, 'fresh');
  assert.equal(loads, 1);
  const metrics = env.cache.snapshot();
  assert.equal(metrics.l1_hits, 1);
  assert.equal(metrics.l2_hits, 1);
});

test('concurrent misses for one indicator coalesce into one provider request', async (context) => {
  const env = await fixture();
  context.after(env.close);
  let loads = 0;
  const results = await Promise.all(Array.from({length: 20}, () => env.cache.lookup({
    source: 'abuseipdb',
    indicatorType: 'ip',
    indicator: '198.51.100.10',
    ttlSeconds: 3600,
    loader: async () => {
      loads += 1;
      await new Promise((resolve) => setTimeout(resolve, 20));
      return record('198.51.100.10', {source: 'abuseipdb', indicator_type: 'ip'});
    },
  })));

  assert.equal(loads, 1);
  assert.equal(results.length, 20);
  assert.equal(results.every((result) => result.record.verdict === 'suspicious'), true);
  assert.equal(env.cache.snapshot().coalesced, 19);
});

test('expired data is served only when provider refresh fails inside the stale window', async (context) => {
  const env = await fixture({staleIfErrorSeconds: 300});
  context.after(env.close);
  await env.cache.lookup({
    source: 'otx',
    indicatorType: 'domain',
    indicator: 'example.com',
    ttlSeconds: 60,
    loader: async () => record('example.com'),
  });
  env.advance(61);

  const fallback = await env.cache.lookup({
    source: 'otx',
    indicatorType: 'domain',
    indicator: 'example.com',
    ttlSeconds: 60,
    staleIfErrorSeconds: 300,
    loader: async () => {
      throw new Error('provider unavailable');
    },
  });
  assert.equal(fallback.cache_state, 'stale');
  assert.equal(fallback.fallback_error, 'provider unavailable');
  assert.equal(fallback.record.verdict, 'suspicious');

  env.advance(301);
  await assert.rejects(
    env.cache.lookup({
      source: 'otx',
      indicatorType: 'domain',
      indicator: 'example.com',
      ttlSeconds: 60,
      staleIfErrorSeconds: 300,
      loader: async () => {
        throw new Error('still unavailable');
      },
    }),
    /still unavailable/,
  );
});

test('unknown zero-confidence lookups use the shorter negative TTL', async (context) => {
  const env = await fixture();
  context.after(env.close);
  await env.cache.lookup({
    source: 'greynoise',
    indicatorType: 'ip',
    indicator: '203.0.113.25',
    ttlSeconds: 3600,
    negativeTtlSeconds: 60,
    loader: async () => record('203.0.113.25', {
      source: 'greynoise',
      indicator_type: 'ip',
      verdict: 'unknown',
      confidence: 0,
    }),
  });
  const row = await env.get('SELECT cached_at, expires_at FROM enrichment_cache');
  assert.equal((Date.parse(row.expires_at) - Date.parse(row.cached_at)) / 1000, 60);
});

test('raw provider payloads and total cache rows remain bounded', async (context) => {
  const env = await fixture({rawResponseMaxBytes: 1024, maxEntries: 2});
  context.after(env.close);
  for (const domain of ['one.example', 'two.example', 'three.example']) {
    await env.cache.lookup({
      source: 'otx',
      indicatorType: 'domain',
      indicator: domain,
      ttlSeconds: 3600,
      loader: async () => record(domain, {raw_response: {payload: 'x'.repeat(5000)}}),
    });
    env.advance(1);
  }

  const pruning = await env.cache.prune();
  const stats = await env.cache.stats();
  assert.equal(pruning.overflow_pruned, 1);
  assert.equal(stats.entries, 2);
  assert.equal(stats.raw_responses_truncated, 3);
  assert.ok(stats.largest_raw_response_bytes < 1024);
});

test('retention compacts oversized provider responses written by older deployments', async (context) => {
  const env = await fixture({rawResponseMaxBytes: 1024});
  context.after(env.close);
  const key = cacheKey('otx', 'domain', 'legacy.example');
  await env.run(`
    INSERT INTO enrichment_cache (
      cache_key, source, indicator, indicator_type, verdict, confidence, tags_json,
      raw_response_json, cached_at, expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    key,
    'otx',
    'legacy.example',
    'domain',
    'suspicious',
    70,
    '[]',
    JSON.stringify({payload: 'x'.repeat(5000)}),
    '2026-07-21T12:00:00.000Z',
    '2026-07-21T13:00:00.000Z',
  ]);

  const pruning = await env.cache.prune();
  const row = await env.get(
    'SELECT verdict, length(raw_response_json) AS raw_bytes, raw_response_json FROM enrichment_cache WHERE cache_key = ?',
    [key],
  );
  assert.equal(pruning.legacy_raw_responses_truncated, 1);
  assert.equal(row.verdict, 'suspicious');
  assert.ok(row.raw_bytes < 1024);
  assert.equal(JSON.parse(row.raw_response_json).truncated, true);
});

test('memory and durable payload byte budgets evict oldest records', async (context) => {
  const env = await fixture({
    l1MaxBytes: 1400,
    maxBytes: 1400,
    maxEntries: 100,
    rawResponseMaxBytes: 4096,
  });
  context.after(env.close);
  for (const domain of ['one.example', 'two.example', 'three.example']) {
    await env.cache.lookup({
      source: 'otx',
      indicatorType: 'domain',
      indicator: domain,
      ttlSeconds: 3600,
      loader: async () => record(domain, {raw_response: {payload: 'x'.repeat(500)}}),
    });
    env.advance(1);
  }

  assert.ok(env.cache.snapshot().l1_bytes <= 1400);
  const pruning = await env.cache.prune();
  const stats = await env.cache.stats();
  assert.ok(pruning.byte_pruned >= 1);
  assert.ok(stats.entries < 3);
  assert.ok(stats.payload_bytes <= 1400);
});
