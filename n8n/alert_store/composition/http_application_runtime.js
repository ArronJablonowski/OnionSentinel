'use strict';

const {createRequestDispatcher} = require('../lib/http_dispatch');
const {configureHttpServer, readJsonObject} = require('../lib/http_runtime');
const {createHttpRequestBoundary} = require('../services/http_request_boundary');
const {createServiceRuntimeLifecycle} = require('../services/service_runtime_lifecycle');
const {createRouteComposition} = require('./route_composition');

const controlledEvaluationRequests = new Set([
  'GET /health',
  'POST /ai/request',
  'POST /analysis/result',
  'POST /controlled-evaluations/retire',
  'POST /incidents/reanalyze',
  'POST /jobs/status',
]);

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} HTTP application runtime section is required`);
  }
  return section;
}

function createHttpApplicationRuntime(options = {}) {
  const runtime = requireSection(options, 'runtime');
  const platform = requireSection(options, 'platform');
  const database = requireSection(options, 'database');
  const foundation = requireSection(options, 'foundation');
  const application = requireSection(options, 'application');
  const controlled = requireSection(options, 'controlled');
  const evidence = requireSection(options, 'evidence');
  const mutable = requireSection(options, 'mutable');
  const startup = requireSection(options, 'startup');
  const serialization = requireSection(options, 'serialization');
  const factories = options.factories || {
    createRouteComposition,
    createHttpRequestBoundary,
    createRequestDispatcher,
    createServiceRuntimeLifecycle,
  };

  const readJsonBody = (request, includeBodySha256 = false) => readJsonObject(request, {
    maxBytes: runtime.maxRequestBytes,
    includeBodySha256,
  });
  function sendJson(response, code, payload) {
    const body = JSON.stringify(payload);
    response.writeHead(code, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    });
    response.end(body);
  }
  const signalAiWorkers = (eventName) => (
    foundation.workerWakeSignaling.signalAiWorkers(eventName)
  );
  const writeBeacon = (stage, alert = {}, result = null, error = null) => (
    foundation.beaconPersistence.writeBeacon(stage, alert, result, error)
  );
  async function rescoreAlerts() {
    return database.withWriteGate(() => application.rescorePersistence.rescore());
  }
  async function capturePipelineDiskSample() {
    const pipelineMetrics = mutable.pipelineMetrics();
    if (!pipelineMetrics) return;
    const pageCount = await database.get('PRAGMA page_count');
    const pageSize = await database.get('PRAGMA page_size');
    const sqliteBytes = Number(pageCount?.page_count || 0)
      * Number(pageSize?.page_size || 0);
    await database.withWriteGate(() => pipelineMetrics.captureDiskSample(sqliteBytes));
  }

  const modularRoutes = factories.createRouteComposition({
    http: {readJsonBody, sendJson},
    transaction: {
      withWriteGate: database.withWriteGate,
      withTransaction: database.withTransaction,
    },
    inventory: {
      requireAcHunterStore: foundation.postgresAuxiliaryStores.requireAcHunterStore,
      requireSoftwareStore: foundation.postgresAuxiliaryStores.requireSoftwareStore,
      requireAssetStore: foundation.postgresAuxiliaryStores.requireAssetStore,
      authorizeWrite: foundation.requestAuthorization.requireAssetWrite,
    },
    health: {
      get: database.get,
      all: database.all,
      runtime: () => ({
        controlledEvaluationMode: runtime.controlledEvaluationMode,
        controlledEvaluationLeases: controlled.controlledEvaluationLeases,
        controlledRoutes: controlledEvaluationRequests,
        runtimeReleaseId: runtime.runtimeReleaseIdValue,
        host: runtime.host,
        port: runtime.port,
        activeSqliteWrites: database.sqliteRuntime.activeWrites(),
        telegramOutboxSnapshot: foundation.notificationService.telegramOutboxSnapshot,
        enrichmentScheduler: foundation.enrichmentScheduler,
        enrichmentCache: foundation.enrichmentCache,
        authorizedActivityPolicyPath: runtime.authorizedActivityPolicyPath,
        authorizedActivityPolicyCount: runtime.authorizedActivityPolicy.policies.length,
        authorizedCampaignReconciliation: (
          application.authorizedCampaignPersistence.reconciliationState()
        ),
        diskCapacitySnapshot: foundation.diskWriteAdmission.diskCapacitySnapshot,
        ...mutable.snapshot(),
        postgresShadowEnabled: runtime.postgresShadowEnabled,
        ...foundation.postgresAuxiliaryStores.state(),
        serviceMetrics: foundation.serviceMetrics,
        postRequestAdmission: foundation.postRequestAdmission,
        nowUtc: serialization.nowUtc,
      }),
    },
    analystState: {
      analystStatusSnapshot: application.analystDecisionPersistence.statusSnapshot,
      updateAnalystStatus: application.analystDecisionPersistence.updateStatus,
      analystAdjudicationSnapshot: application.analystReviewProjection.adjudicationSnapshot,
      recordAnalystAdjudication: application.analystDecisionPersistence.recordAdjudication,
      updateIncidentCaseStatus: application.analystDecisionPersistence.updateIncidentCaseStatus,
    },
    durableJob: {
      safeString: serialization.safeString,
      controlledTransitionAdmission: controlled.controlledJobTransitionAuthority.admit,
      transitionJobStatus: controlled.durableJobTransitionExecutor.transition,
      applyControlledTransition: controlled.controlledJobTransitionAuthority.apply,
      completePendingByDedupeKeys: (...args) => (
        mutable.durableJobs().completePendingByDedupeKeys(...args)
      ),
    },
    analysisRequest: {
      controlledEvaluationMode: () => runtime.controlledEvaluationMode,
      identityConflict: serialization.incidentIdentityConflict,
      requestAiReanalysis: controlled.manualAnalysisDispatch.requestAiReanalysis,
      requestIncidentEscalation: controlled.manualAnalysisDispatch.requestIncidentEscalation,
      requestIncidentReanalysis: controlled.incidentReanalysisRequestOwner.request,
      retireControlledEvaluation: controlled.controlledRetirementCommandOwner.retire,
      signalAiWorkers,
    },
    analysisResult: {
      controlledEvaluationMode: () => runtime.controlledEvaluationMode,
      requestHasOwnField: serialization.requestHasOwnField,
      identityConflict: serialization.incidentIdentityConflict,
      controlledResultAdmission: controlled.controlledResultAdmissionAuthority.admit,
      recordAnalysisResult: evidence.aiAnalysisAcceptance.record,
      transitionJobStatus: controlled.durableJobTransitionExecutor.transition,
      applyControlledResultAdmission: controlled.controlledResultAdmissionAuthority.apply,
    },
    pcap: {
      createRequest: (...args) => evidence.pcapRequestRepository.createRequest(...args),
      listRequests: (...args) => evidence.pcapRequestRepository.listRequests(...args),
      claimRequest: (...args) => mutable.pcapTransferRepository().claimRequest(...args),
      completeRequest: (...args) => mutable.pcapTransferRepository().completeRequest(...args),
      updateTransferProgress: (...args) => (
        mutable.pcapTransferRepository().updateTransferProgress(...args)
      ),
      retryRequest: (...args) => mutable.pcapTransferRepository().retryRequest(...args),
      completeAnalysis: (...args) => evidence.pcapAnalysisCompletion.complete(...args),
      requeueRequests: (...args) => evidence.pcapRequestRepository.requeueRequests(...args),
      signalPcapWorker: (reason) => (
        foundation.workerWakeSignaling.signalWorker(runtime.pcapAnalysisWakePath, reason)
      ),
      signalAiWorkers,
    },
    enrichment: {
      assertDiskWriteAdmission: foundation.diskWriteAdmission.assertDiskWriteAdmission,
      enrichAlert: foundation.enrichmentOrchestrator.enrichAlert,
      cachedInvestigationEnrichment: foundation.enrichmentOrchestrator.cachedInvestigationEnrichment,
      queryInvestigationEnrichment: foundation.enrichmentOrchestrator.queryInvestigationEnrichment,
      authorizeInvestigation: foundation.requestAuthorization.requireAssetWrite,
    },
    maintenance: {
      rescore: rescoreAlerts,
      refreshGroups: foundation.alertGroupService.rebuildAlertGroupSummaries,
    },
    alertIngest: {
      metrics: foundation.serviceMetrics,
      now: platform.dateNow,
      readJsonBody,
      writeBeacon,
      isRelayHeartbeat: serialization.isRelayHeartbeat,
      assertDiskWriteAdmission: foundation.diskWriteAdmission.assertDiskWriteAdmission,
      storeAlert: application.alertIngestOrchestrator.store,
    },
  });

  let serviceRuntimeLifecycle;
  const httpRequestBoundary = factories.createHttpRequestBoundary({
    controlledEvaluationMode: runtime.controlledEvaluationMode,
    controlledRequests: controlledEvaluationRequests,
    isShutdownStarted: () => serviceRuntimeLifecycle.isShutdownStarted(),
    controlledRequestAuthorized: foundation.requestAuthorization.controlledEvaluationAuthorized,
    routeRegistry: modularRoutes,
    sendJson,
    serviceMetrics: foundation.serviceMetrics,
    writeBeacon,
  });
  const dispatchRequest = factories.createRequestDispatcher({
    handleRequest: (request, response) => httpRequestBoundary.handle(request, response),
    postRequestAdmission: foundation.postRequestAdmission,
    logger: foundation.applicationLogger,
    sendJson,
    randomUUID: platform.randomUUID,
    monotonicNow: platform.monotonicNow,
  });
  serviceRuntimeLifecycle = factories.createServiceRuntimeLifecycle({
    initDb: startup.initDb,
    initializePostgresAssetStore: foundation.postgresAuxiliaryStores.initializeAssetStore,
    initializePostgresSoftwareStore: foundation.postgresAuxiliaryStores.initializeSoftwareStore,
    initializePostgresAcHunterStore: foundation.postgresAuxiliaryStores.initializeAcHunterStore,
    getPostgresStoreState: () => foundation.postgresAuxiliaryStores.state(),
    applicationLogger: foundation.applicationLogger,
    databaseLogFields: {
      database_path: runtime.dbPath,
      postgres_shadow_enabled: runtime.postgresShadowEnabled,
      asset_postgres_enabled: runtime.assetPostgresEnabled,
      software_postgres_enabled: runtime.softwarePostgresEnabled,
      ac_hunter_postgres_enabled: runtime.acHunterPostgresEnabled,
    },
    httpCreateServer: platform.httpCreateServer,
    configureHttpServer,
    dispatchRequest,
    sendJson,
    httpConfiguration: {
      requestTimeoutMs: runtime.httpRequestTimeoutMs,
      headersTimeoutMs: runtime.httpHeadersTimeoutMs,
      keepAliveTimeoutMs: runtime.httpKeepAliveTimeoutMs,
      maxRequestsPerSocket: runtime.httpMaxRequestsPerSocket,
      maxConnections: runtime.httpMaxConnections,
    },
    host: runtime.host,
    port: runtime.port,
    dbPath: runtime.dbPath,
    controlledEvaluationMode: runtime.controlledEvaluationMode,
    processLike: platform.processLike,
    consoleLike: platform.consoleLike,
    database: database.db,
    waitForSqliteWrites: database.sqliteRuntime.waitForWrites,
    getActiveSqliteWrites: database.sqliteRuntime.activeWrites,
    setIntervalFn: platform.setIntervalFn,
    setTimeoutFn: platform.setTimeoutFn,
    workers: {
      telegram: {
        enabled: runtime.telegramOutboxAutostart,
        intervalMs: runtime.telegramOutboxIntervalMs,
        drain: foundation.notificationService.drainTelegramOutbox,
      },
      enrichment: {
        intervalMs: runtime.enrichmentWorkerIntervalMs,
        drain: evidence.durableBackgroundDrains.drainEnrichment,
      },
      enrichmentCache: {
        intervalMs: runtime.enrichmentCacheCleanupIntervalMs,
        prune: foundation.enrichmentCache.prune,
      },
      n8nPostCommit: {
        intervalMs: runtime.n8nPostCommitIntervalMs,
        drain: evidence.durableBackgroundDrains.drainPostCommit,
      },
      durableRecovery: {
        intervalMs: runtime.durableJobRecoveryIntervalMs,
        recover: controlled.durableJobRecovery.recover,
      },
      pipelineDisk: {
        intervalMs: runtime.pipelineDiskSampleIntervalMs,
        capture: capturePipelineDiskSample,
      },
      postgresShadow: {
        enabled: () => Boolean(mutable.postgresShadowProjector()),
        intervalMs: runtime.postgresShadowIntervalMs,
        drain: () => mutable.postgresShadowProjector().drain(),
      },
      pipelineMetrics: {
        intervalMs: 60 * 60 * 1000,
        prune: () => mutable.pipelineMetrics().prune(),
        withWriteGate: database.withWriteGate,
      },
    },
  });

  return {
    controlledEvaluationRequests,
    modularRoutes,
    dispatchRequest,
    serviceRuntimeLifecycle,
    run: () => serviceRuntimeLifecycle.run(),
  };
}

module.exports = {createHttpApplicationRuntime};
