'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createMutableRuntimeOwners,
} = require('../composition/mutable_runtime_owners');

function createOptions(overrides = {}) {
  return {
    database: {
      get: async () => undefined,
      all: async () => [],
      run: async () => ({changes: 0}),
      withWriteGate: async (task) => task(),
    },
    runtime: {
      nowUtc: () => '2026-08-10T00:00:00.000Z',
      aiAnalysisLeaseSeconds: 900,
      postgresShadowEnabled: false,
      controlledEvaluationMode: false,
      postgresShadowBatchSize: 25,
      diskCapacitySnapshot: () => ({free_bytes: 1024}),
      pipelineEventRetentionHours: 24,
      pcapClaimLeaseSeconds: 300,
      pcapTransferMaxAttempts: 8,
      pcapTransferMaxRetrySeconds: 3600,
      ...overrides.runtime,
    },
    pcap: {
      safeString: (value) => String(value || ''),
      nonNegativeIntegerField: (value) => Math.max(0, Number(value) || 0),
      formatProjectTimestamp: (value) => value.toISOString(),
      pcapRequestFromRow: (row) => row,
      classifyPcapOutcome: () => 'success',
      pcapOutcomes: new Set(['success']),
    },
    platform: {
      env: {},
      console: {error: () => {}},
      createPostgresPool: () => {
        throw new Error('pool should not be constructed');
      },
      ...overrides.platform,
    },
  };
}

test('fails closed when a required dependency section is absent', () => {
  assert.throws(
    () => createMutableRuntimeOwners({database: {}}),
    /runtime mutable runtime owner section is required/,
  );
});

test('owns lazy runtime state and initializes paired metrics repositories', () => {
  const owners = createMutableRuntimeOwners(createOptions());
  assert.deepEqual(owners.snapshot(), {
    durableJobs: undefined,
    postgresShadowOutbox: undefined,
    postgresShadowProjector: undefined,
    pipelineMetrics: undefined,
  });
  assert.equal(owners.pcapTransferRepository(), undefined);

  owners.initializeDurableJobs();
  owners.initializePostgresShadowOutbox();
  owners.initializePostgresShadowProjector();
  owners.initializePipelineMetrics();

  assert.equal(typeof owners.durableJobs().enqueue, 'function');
  assert.equal(typeof owners.postgresShadowOutbox().install, 'function');
  assert.equal(owners.postgresShadowProjector(), undefined);
  assert.equal(typeof owners.pipelineMetrics().record, 'function');
  assert.equal(typeof owners.pcapTransferRepository().claimRequest, 'function');
});

test('shadow projection fails before pool construction when credentials are missing', () => {
  let poolConstructions = 0;
  const owners = createMutableRuntimeOwners(createOptions({
    runtime: {postgresShadowEnabled: true},
    platform: {createPostgresPool: () => { poolConstructions += 1; }},
  }));
  owners.initializePostgresShadowOutbox();
  assert.throws(
    () => owners.initializePostgresShadowProjector(),
    /missing ALERT_STORE_POSTGRES_HOST/,
  );
  assert.equal(poolConstructions, 0);
});
