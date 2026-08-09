'use strict';

function unavailable(enabled, error) {
  return {
    enabled,
    backend: 'postgresql',
    available: false,
    error: error || null,
  };
}

function createHealthService({repository, runtime}) {
  if (!repository || typeof repository !== 'object') {
    throw new TypeError('health repository is required');
  }
  if (typeof runtime !== 'function') {
    throw new TypeError('health runtime provider must be a function');
  }

  async function healthSnapshot() {
    const state = runtime();
    const controlled = state.controlledEvaluationMode === true;
    const leases = state.controlledEvaluationLeases || new Map();
    const health = {
      ok: true,
      status: 'healthy',
      service: 'onion-sentinel-alert-store',
      controlled_evaluation: controlled,
      evaluation_mode: controlled,
      runtime_mode: controlled ? 'controlled-evaluation' : 'production',
      release_id: state.runtimeReleaseId || 'unversioned',
      listen_host: state.host,
      listen_port: state.port,
      accepting_requests: true,
      active_writes: state.activeSqliteWrites,
      active_controlled_leases: controlled ? leases.size : 0,
      controlled_results_pending_completion: controlled
        ? [...leases.values()].filter((lease) => lease.resultCommitted).length
        : 0,
      route_allowlist: controlled ? [...state.controlledRoutes].sort() : [],
      background_jobs_enabled: !controlled,
      outbound_network_enabled: !controlled,
      worker_wake_signaling_enabled: !controlled,
    };
    if (controlled) return health;
    health.telegram_outbox = await state.telegramOutboxSnapshot();
    health.enrichment_scheduler = state.enrichmentScheduler.snapshot();
    health.enrichment_cache = state.enrichmentCache.snapshot();
    health.authorized_activity_campaigns = {
      policy_path: state.authorizedActivityPolicyPath,
      configured_policy_count: state.authorizedActivityPolicyCount,
      reconciliation: state.authorizedCampaignReconciliation,
    };
    health.disk_capacity = state.diskCapacitySnapshot();
    health.postgres_shadow_outbox = state.postgresShadowOutbox
      ? await state.postgresShadowOutbox.stats() : null;
    health.postgres_shadow_projector = state.postgresShadowProjector
      ? state.postgresShadowProjector.snapshot()
      : {enabled: state.postgresShadowEnabled, active: false};
    health.asset_inventory = state.postgresAssetStore
      ? await state.postgresAssetStore.stats()
      : unavailable(state.assetPostgresEnabled, state.postgresAssetStoreError);
    health.software_inventory = state.postgresSoftwareStore
      ? await state.postgresSoftwareStore.stats()
      : unavailable(state.softwarePostgresEnabled, state.postgresSoftwareStoreError);
    health.ac_hunter = state.postgresAcHunterStore
      ? await state.postgresAcHunterStore.stats()
      : unavailable(state.acHunterPostgresEnabled, state.postgresAcHunterStoreError);
    return health;
  }

  async function metricsSnapshot() {
    const state = runtime();
    const jobAges = await repository.jobAges();
    const pcap = await repository.pcapStats();
    const sqliteBytes = await repository.sqliteBytes();
    const durable = state.durableJobs ? await state.durableJobs.stats() : [];
    return {
      generated_at: state.nowUtc(),
      process: {
        ...state.serviceMetrics,
        post_request_admission: state.postRequestAdmission.snapshot(),
        ingest_latency_ms_average: state.serviceMetrics.ingest_requests
          ? Math.round(
            state.serviceMetrics.ingest_latency_ms_total
              / state.serviceMetrics.ingest_requests,
          ) : 0,
      },
      durable_jobs: durable,
      postgres_shadow_outbox: state.postgresShadowOutbox
        ? await state.postgresShadowOutbox.stats() : null,
      postgres_shadow_projector: state.postgresShadowProjector
        ? state.postgresShadowProjector.snapshot()
        : {enabled: state.postgresShadowEnabled, active: false},
      asset_inventory: state.postgresAssetStore
        ? await state.postgresAssetStore.stats()
        : unavailable(state.assetPostgresEnabled, state.postgresAssetStoreError),
      ac_hunter: state.postgresAcHunterStore
        ? await state.postgresAcHunterStore.stats()
        : unavailable(state.acHunterPostgresEnabled, state.postgresAcHunterStoreError),
      oldest_pending_job_seconds: jobAges.oldestPendingSeconds,
      oldest_pending_jobs: jobAges.oldestPending,
      latest_completed_jobs: jobAges.latestCompleted,
      oldest_processing_jobs: jobAges.oldestProcessing,
      pcap: pcap.status,
      pcap_outcomes: pcap.outcomes,
      pcap_storage: pcap.storage,
      oldest_pending_pcap_seconds: pcap.oldestPendingSeconds,
      enrichment_cache: await state.enrichmentCache.stats(),
      telegram_outbox: await state.telegramOutboxSnapshot(),
      sqlite_bytes: sqliteBytes,
      disk_capacity: state.diskCapacitySnapshot(),
      pipeline: state.pipelineMetrics ? await state.pipelineMetrics.snapshot() : null,
    };
  }

  async function jobStats() {
    const jobs = runtime().durableJobs;
    return jobs ? jobs.stats() : [];
  }

  return {healthSnapshot, metricsSnapshot, jobStats};
}

module.exports = {createHealthService};
