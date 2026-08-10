'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createHttpApplicationRuntime,
} = require('../composition/http_application_runtime');

const noOp = () => {};

function createOptions() {
  const captured = {};
  const runtime = new Proxy({
    controlledEvaluationMode: false,
    authorizedActivityPolicy: {policies: []},
    runtimeReleaseIdValue: 'a'.repeat(40),
    host: '127.0.0.1',
    port: 8787,
    dbPath: '/tmp/test.sqlite3',
  }, {get: (target, key) => key in target ? target[key] : 0});
  const foundation = {
    workerWakeSignaling: {signalAiWorkers: noOp, signalWorker: noOp},
    beaconPersistence: {writeBeacon: noOp},
    diskWriteAdmission: {assertDiskWriteAdmission: noOp, diskCapacitySnapshot: noOp},
    postgresAuxiliaryStores: {
      requireAcHunterStore: noOp,
      requireSoftwareStore: noOp,
      requireAssetStore: noOp,
      initializeAssetStore: noOp,
      initializeSoftwareStore: noOp,
      initializeAcHunterStore: noOp,
      state: () => ({}),
    },
    requestAuthorization: {
      requireAssetWrite: noOp,
      controlledEvaluationAuthorized: noOp,
    },
    notificationService: {telegramOutboxSnapshot: noOp, drainTelegramOutbox: noOp},
    enrichmentScheduler: {},
    enrichmentCache: {prune: noOp},
    serviceMetrics: {},
    postRequestAdmission: {},
    enrichmentOrchestrator: {
      enrichAlert: noOp,
      cachedInvestigationEnrichment: noOp,
      queryInvestigationEnrichment: noOp,
    },
    alertGroupService: {rebuildAlertGroupSummaries: noOp},
    applicationLogger: {},
  };
  const application = {
    authorizedCampaignPersistence: {reconciliationState: () => ({})},
    analystDecisionPersistence: {
      statusSnapshot: noOp,
      updateStatus: noOp,
      recordAdjudication: noOp,
      updateIncidentCaseStatus: noOp,
    },
    analystReviewProjection: {adjudicationSnapshot: noOp},
    rescorePersistence: {rescore: noOp},
    alertIngestOrchestrator: {store: noOp},
  };
  const controlled = {
    controlledEvaluationLeases: {},
    controlledJobTransitionAuthority: {admit: noOp, apply: noOp},
    durableJobTransitionExecutor: {transition: noOp},
    manualAnalysisDispatch: {requestAiReanalysis: noOp, requestIncidentEscalation: noOp},
    incidentReanalysisRequestOwner: {request: noOp},
    controlledRetirementCommandOwner: {retire: noOp},
    controlledResultAdmissionAuthority: {admit: noOp, apply: noOp},
    durableJobRecovery: {recover: noOp},
  };
  const evidence = {
    aiAnalysisAcceptance: {record: noOp},
    pcapRequestRepository: {createRequest: noOp, listRequests: noOp, requeueRequests: noOp},
    pcapAnalysisCompletion: {complete: noOp},
    durableBackgroundDrains: {drainEnrichment: noOp, drainPostCommit: noOp},
  };
  const mutable = {
    pipelineMetrics: () => ({captureDiskSample: noOp, prune: noOp}),
    durableJobs: () => ({completePendingByDedupeKeys: noOp}),
    pcapTransferRepository: () => ({
      claimRequest: noOp,
      completeRequest: noOp,
      updateTransferProgress: noOp,
      retryRequest: noOp,
    }),
    postgresShadowProjector: () => undefined,
    snapshot: () => ({}),
  };
  const lifecycle = {isShutdownStarted: () => false, run: () => { captured.ran = true; }};
  return {
    captured,
    options: {
      runtime,
      platform: {
        httpCreateServer: noOp,
        processLike: {},
        consoleLike: {},
        dateNow: () => 0,
        randomUUID: () => 'uuid',
        monotonicNow: () => 0n,
        setIntervalFn: noOp,
        setTimeoutFn: noOp,
      },
      database: {
        db: {},
        get: async () => ({}),
        all: async () => [],
        withWriteGate: async (task) => task(),
        withTransaction: async (task) => task(),
        sqliteRuntime: {activeWrites: () => 0, waitForWrites: noOp},
      },
      foundation,
      application,
      controlled,
      evidence,
      mutable,
      startup: {initDb: noOp},
      serialization: {
        nowUtc: noOp,
        safeString: String,
        isRelayHeartbeat: noOp,
        incidentIdentityConflict: noOp,
        requestHasOwnField: noOp,
      },
      factories: {
        createRouteComposition: (value) => { captured.routes = value; return {}; },
        createHttpRequestBoundary: (value) => {
          captured.boundary = value;
          return {handle: noOp};
        },
        createRequestDispatcher: (value) => { captured.dispatch = value; return noOp; },
        createServiceRuntimeLifecycle: (value) => {
          captured.lifecycle = value;
          return lifecycle;
        },
      },
    },
  };
}

test('fails closed when a required owner section is absent', () => {
  assert.throws(
    () => createHttpApplicationRuntime({runtime: {}}),
    /platform HTTP application runtime section is required/,
  );
});

test('owns exact controlled routes, public port groups, workers, and lifecycle run', () => {
  const fixture = createOptions();
  const runtime = createHttpApplicationRuntime(fixture.options);
  assert.deepEqual([...runtime.controlledEvaluationRequests], [
    'GET /health',
    'POST /ai/request',
    'POST /analysis/result',
    'POST /controlled-evaluations/retire',
    'POST /incidents/reanalyze',
    'POST /jobs/status',
  ]);
  assert.deepEqual(Object.keys(fixture.captured.routes), [
    'http', 'transaction', 'inventory', 'health', 'analystState', 'durableJob',
    'analysisRequest', 'analysisResult', 'pcap', 'enrichment', 'maintenance',
    'alertIngest',
  ]);
  assert.deepEqual(Object.keys(fixture.captured.lifecycle.workers), [
    'telegram', 'enrichment', 'enrichmentCache', 'n8nPostCommit',
    'durableRecovery', 'pipelineDisk', 'postgresShadow', 'pipelineMetrics',
  ]);
  runtime.run();
  assert.equal(fixture.captured.ran, true);
});
