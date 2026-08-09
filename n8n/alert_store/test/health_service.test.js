'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createHealthService} = require('../services/health_service');

function baseState(overrides = {}) {
  return {
    controlledEvaluationMode: false,
    controlledEvaluationLeases: new Map(),
    controlledRoutes: new Set(['GET /health']),
    runtimeReleaseId: 'a'.repeat(40),
    host: '127.0.0.1',
    port: 8787,
    activeSqliteWrites: 0,
    telegramOutboxSnapshot: async () => ({sent: 2}),
    enrichmentScheduler: {snapshot: () => ({active: false})},
    enrichmentCache: {snapshot: () => ({l1_hits: 1}), stats: async () => ({rows: 3})},
    authorizedActivityPolicyPath: '/runtime/policy.json',
    authorizedActivityPolicyCount: 3,
    authorizedCampaignReconciliation: {status: 'ok'},
    diskCapacitySnapshot: () => ({free_bytes: 1000}),
    postgresShadowOutbox: null,
    postgresShadowProjector: null,
    postgresShadowEnabled: true,
    postgresAssetStore: null,
    assetPostgresEnabled: true,
    postgresAssetStoreError: 'not ready',
    postgresSoftwareStore: null,
    softwarePostgresEnabled: true,
    postgresSoftwareStoreError: 'not ready',
    postgresAcHunterStore: null,
    acHunterPostgresEnabled: true,
    postgresAcHunterStoreError: 'not ready',
    durableJobs: {stats: async () => [{job_type: 'ai_analysis', count: 1}]},
    serviceMetrics: {ingest_requests: 2, ingest_latency_ms_total: 9},
    postRequestAdmission: {snapshot: () => ({active: 0})},
    pipelineMetrics: null,
    nowUtc: () => '2026-08-09T21:00:00Z',
    ...overrides,
  };
}

function service(state) {
  return createHealthService({
    repository: {
      jobAges: async () => ({
        oldestPendingSeconds: 7,
        oldestPending: [{job_type: 'ai_analysis', seconds: 7}],
        latestCompleted: [],
        oldestProcessing: [],
      }),
      pcapStats: async () => ({
        status: [], outcomes: [], storage: {}, oldestPendingSeconds: 0,
      }),
      sqliteBytes: async () => 4096,
    },
    runtime: () => state,
  });
}

test('controlled health exposes only the bounded isolated runtime fields', async () => {
  const state = baseState({
    controlledEvaluationMode: true,
    controlledEvaluationLeases: new Map([
      ['lease-1', {resultCommitted: true}],
      ['lease-2', {resultCommitted: false}],
    ]),
  });
  const health = await service(state).healthSnapshot();
  assert.equal(health.runtime_mode, 'controlled-evaluation');
  assert.equal(health.active_controlled_leases, 2);
  assert.equal(health.controlled_results_pending_completion, 1);
  assert.deepEqual(health.route_allowlist, ['GET /health']);
  assert.equal(health.background_jobs_enabled, false);
  assert.equal('telegram_outbox' in health, false);
  assert.equal('asset_inventory' in health, false);
});

test('production health preserves unavailable PostgreSQL component schemas', async () => {
  const health = await service(baseState()).healthSnapshot();
  assert.equal(health.runtime_mode, 'production');
  assert.deepEqual(health.telegram_outbox, {sent: 2});
  assert.deepEqual(health.postgres_shadow_projector, {enabled: true, active: false});
  for (const key of ['asset_inventory', 'software_inventory', 'ac_hunter']) {
    assert.deepEqual(health[key], {
      enabled: true,
      backend: 'postgresql',
      available: false,
      error: 'not ready',
    });
  }
});

test('metrics preserve SLO job clocks, process average, and bounded stores', async () => {
  const metrics = await service(baseState()).metricsSnapshot();
  assert.equal(metrics.generated_at, '2026-08-09T21:00:00Z');
  assert.equal(metrics.process.ingest_latency_ms_average, 5);
  assert.equal(metrics.oldest_pending_job_seconds, 7);
  assert.deepEqual(metrics.oldest_pending_jobs, [
    {job_type: 'ai_analysis', seconds: 7},
  ]);
  assert.equal(metrics.sqlite_bytes, 4096);
  assert.deepEqual(metrics.durable_jobs, [
    {job_type: 'ai_analysis', count: 1},
  ]);
  assert.equal(metrics.pipeline, null);
});
