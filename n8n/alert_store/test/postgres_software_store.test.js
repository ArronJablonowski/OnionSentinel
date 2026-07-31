'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  normalizeRecord,
  parseQuery,
} = require('../lib/postgres_software_store');

function record(overrides = {}) {
  return {
    evidence_id: 'a'.repeat(24),
    source: 'osquery_apps',
    source_dataset: 'osquery_manager.result',
    tier: 'installed',
    confidence: 'high',
    asset_ref_type: 'host',
    asset_ref: 'b'.repeat(24),
    platform: 'darwin',
    operating_system_type: 'macOS',
    operating_system_version: '26.0',
    operating_system_source: 'osquery_manager.result:host.os',
    operating_system_confidence: 'high',
    product: 'Firefox',
    version: '140',
    category: 'application',
    first_seen: '2026-07-30T10:00:00Z',
    last_seen: '2026-07-30T11:00:00Z',
    observation_count: 2,
    ...overrides,
  };
}

test('normalizes the complete bounded provenance record', () => {
  const result = normalizeRecord(record());
  assert.equal(result.product, 'Firefox');
  assert.equal(result.last_seen, '2026-07-30T11:00:00.000Z');
  assert.equal(result.observation_count, 2);
});

test('rejects provenance and timestamp mismatches', () => {
  assert.throws(
    () => normalizeRecord(record({source: 'user_supplied'})),
    /provenance/,
  );
  assert.throws(
    () => normalizeRecord(record({
      first_seen: '2026-07-30T12:00:00Z',
      last_seen: '2026-07-30T11:00:00Z',
    })),
    /precedes/,
  );
});

test('bounds database query pagination and filters', () => {
  assert.deepEqual(parseQuery({
    limit: '250',
    offset: '100000',
    tier: 'installed',
    confidence: 'high',
    freshness: 'current',
    window: '7d',
    sort: 'product',
    direction: 'asc',
  }), {
    limit: 250,
    offset: 100000,
    search: '',
    tier: 'installed',
    confidence: 'high',
    freshness: 'current',
    platform: 'all',
    window: '7d',
    sort: 'product',
    direction: 'asc',
  });
  assert.throws(() => parseQuery({limit: '251'}), /limit/);
  assert.throws(() => parseQuery({window: '365d'}), /window/);
});

test('alert-store route serializes the default observation time', () => {
  const source = require('node:fs').readFileSync(
    require('node:path').join(__dirname, '..', 'alert_store.js'),
    'utf8',
  );
  assert.match(
    source,
    /parsedUrl\.searchParams\.get\('observed_at'\)[\s\S]{0,100}new Date\(\)\.toISOString\(\)/,
  );
});
