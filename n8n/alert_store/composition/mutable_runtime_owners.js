'use strict';

const {createDurableJobQueue} = require('../lib/durable_job_queue');
const {createPostgresShadowOutbox} = require('../lib/postgres_shadow_outbox');
const {createPostgresShadowProjector} = require('../lib/postgres_shadow_projector');
const {createPipelineMetrics} = require('../lib/pipeline_metrics');
const {createPcapTransferRepository} = require('../repositories/pcap_transfer_repository');

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} mutable runtime owner section is required`);
  }
  return section;
}

function createMutableRuntimeOwners(options = {}) {
  const database = requireSection(options, 'database');
  const runtime = requireSection(options, 'runtime');
  const pcap = requireSection(options, 'pcap');
  const platform = requireSection(options, 'platform');

  let durableJobs;
  let postgresShadowOutbox;
  let postgresShadowProjector;
  let pipelineMetrics;
  let pcapTransferRepository;

  function initializeDurableJobs() {
    durableJobs = createDurableJobQueue({
      run: database.run,
      get: database.get,
      all: database.all,
      now: runtime.nowUtc,
      transitionLeaseSeconds: runtime.aiAnalysisLeaseSeconds,
    });
  }

  function initializePostgresShadowOutbox() {
    postgresShadowOutbox = createPostgresShadowOutbox(database);
  }

  function initializePostgresShadowProjector() {
    if (!runtime.postgresShadowEnabled || runtime.controlledEvaluationMode) return;
    const requiredKeys = [
      'ALERT_STORE_POSTGRES_HOST',
      'ALERT_STORE_POSTGRES_DATABASE',
      'ALERT_STORE_POSTGRES_USER',
      'ALERT_STORE_POSTGRES_PASSWORD',
    ];
    const missing = requiredKeys.filter(
      (key) => !String(platform.env[key] || '').trim(),
    );
    if (missing.length) {
      throw new Error(
        `PostgreSQL shadow projection is enabled but missing ${missing.join(', ')}`,
      );
    }
    const pool = platform.createPostgresPool({
      host: String(platform.env.ALERT_STORE_POSTGRES_HOST),
      port: Number(platform.env.ALERT_STORE_POSTGRES_PORT || 5433),
      database: String(platform.env.ALERT_STORE_POSTGRES_DATABASE),
      user: String(platform.env.ALERT_STORE_POSTGRES_USER),
      password: String(platform.env.ALERT_STORE_POSTGRES_PASSWORD),
      max: 2,
      connectionTimeoutMillis: 3000,
      idleTimeoutMillis: 10000,
      application_name: 'onion-sentinel-shadow-projector',
    });
    // Shadow availability must never control the authoritative SQLite service.
    pool.on('error', (error) => {
      platform.console.error(
        `PostgreSQL shadow idle connection failed: ${String(error.message || error).slice(0, 500)}`,
      );
    });
    postgresShadowProjector = createPostgresShadowProjector({
      pool,
      outbox: postgresShadowOutbox,
      withWriteGate: database.withWriteGate,
      now: runtime.nowUtc,
      batchSize: runtime.postgresShadowBatchSize,
    });
  }

  function initializePipelineMetrics() {
    pipelineMetrics = createPipelineMetrics({
      run: database.run,
      all: database.all,
      now: runtime.nowUtc,
      diskSnapshot: runtime.diskCapacitySnapshot,
      retentionHours: runtime.pipelineEventRetentionHours,
    });
    pcapTransferRepository = createPcapTransferRepository({
      get: database.get,
      run: database.run,
      safeString: pcap.safeString,
      nonNegativeIntegerField: pcap.nonNegativeIntegerField,
      nowUtc: runtime.nowUtc,
      formatProjectTimestamp: pcap.formatProjectTimestamp,
      pcapRequestFromRow: pcap.pcapRequestFromRow,
      classifyPcapOutcome: pcap.classifyPcapOutcome,
      matchesPcap: pcap.matchesPcap,
      readPcapThreshold: pcap.readPcapThreshold,
      pcapOutcomes: pcap.pcapOutcomes,
      pipelineMetrics,
      claimLeaseSeconds: runtime.pcapClaimLeaseSeconds,
      maxAttempts: runtime.pcapTransferMaxAttempts,
      maxRetrySeconds: runtime.pcapTransferMaxRetrySeconds,
    });
  }

  return {
    initializeDurableJobs,
    initializePostgresShadowOutbox,
    initializePostgresShadowProjector,
    initializePipelineMetrics,
    durableJobs: () => durableJobs,
    postgresShadowOutbox: () => postgresShadowOutbox,
    postgresShadowProjector: () => postgresShadowProjector,
    pipelineMetrics: () => pipelineMetrics,
    pcapTransferRepository: () => pcapTransferRepository,
    snapshot: () => ({
      durableJobs,
      postgresShadowOutbox,
      postgresShadowProjector,
      pipelineMetrics,
    }),
  };
}

module.exports = {createMutableRuntimeOwners};
