'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  RETENTION_SECONDS,
  SCHEDULE_MINUTE,
  datasetDigest,
  normalizeSnapshot,
  publicSnapshot,
} = require('../lib/postgres_ac_hunter_store');

function snapshot(overrides = {}) {
  return {
    schema: 'onion-sentinel-ac-hunter-review-v1',
    version: 1,
    ok: true,
    last_pulled_at: '2026-07-31T12:35:00Z',
    metadata: {
      dataset: 'security-onion-rolling',
      source_statuses: {beacons: {status: 'ok', http_status: 200, error: ''}},
    },
    dataset: {
      name: 'security-onion-rolling',
      time_range: {start: '2026-07-30T12:00:00Z', end: '2026-07-31T12:00:00Z'},
    },
    time_range: {start: '2026-07-30T12:00:00Z', end: '2026-07-31T12:00:00Z'},
    cache: {status: 'fresh', age_seconds: 0},
    modules: {
      beacons: {
        count: 1,
        status: 'ok',
        error: '',
        findings: [{source_ip: '10.0.0.5', destination_ip: '203.0.113.9', score: 0.9}],
      },
    },
    counts: {beacons: 1},
    verdict_counts: {'Needs review': 1},
    top_hosts: [{source_ip: '10.0.0.5'}],
    top_risky_internal_hosts: [{source_ip: '10.0.0.5'}],
    correlated_hosts: [],
    analyst_notes: [],
    disclaimer: 'Behavioral triage only.',
    ...overrides,
  };
}

test('dataset digest ignores pull metadata but detects evidence changes', () => {
  const first = snapshot();
  const identicalData = snapshot({
    last_pulled_at: '2026-07-31T13:35:00Z',
    cache: {status: 'stale', age_seconds: 3600},
    metadata: {dataset: 'security-onion-rolling', source_statuses: {}},
  });
  assert.equal(datasetDigest(first), datasetDigest(identicalData));

  const changed = snapshot();
  changed.modules.beacons.findings[0].score = 0.91;
  assert.notEqual(datasetDigest(first), datasetDigest(changed));
});

test('snapshot validation rejects secrets and the wrong dataset', () => {
  assert.equal(normalizeSnapshot(snapshot()).dataset.name, 'security-onion-rolling');
  assert.throws(
    () => normalizeSnapshot({...snapshot(), token: 'must-not-be-stored'}),
    /prohibited material/,
  );
  assert.throws(
    () => normalizeSnapshot({
      ...snapshot(), dataset: {name: 'another-dataset', time_range: {}},
    }),
    /dataset is invalid/,
  );
});

test('public cache view exposes PostgreSQL retention and schedule metadata', () => {
  const payload = publicSnapshot({
    payload: snapshot(),
    current_digest: 'a'.repeat(64),
    last_checked_at: '2026-07-31T13:35:00Z',
    last_changed_at: '2026-07-31T12:35:00Z',
    last_pull_changed: false,
  }, 3, new Date('2026-07-31T13:36:00Z'));
  assert.equal(payload.cache.storage_backend, 'postgresql');
  assert.equal(payload.cache.retention_seconds, RETENTION_SECONDS);
  assert.equal(payload.cache.scheduled_minute, SCHEDULE_MINUTE);
  assert.equal(payload.cache.history_count, 3);
  assert.equal(payload.cache.last_pull_changed, false);
  assert.equal(payload.last_pulled_at, '2026-07-31T13:35:00.000Z');
});
