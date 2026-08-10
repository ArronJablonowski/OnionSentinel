'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createRouteComposition} = require('../composition/route_composition');

const asyncNoop = async () => ({});
const transaction = async (task) => task();

function options() {
  return {
    http: {readJsonBody: asyncNoop, sendJson() {}},
    transaction: {withWriteGate: transaction, withTransaction: transaction},
    inventory: {
      requireAcHunterStore: () => ({}),
      requireSoftwareStore: () => ({}),
      requireAssetStore: () => ({}),
      authorizeWrite() {},
    },
    health: {get: asyncNoop, all: asyncNoop, runtime: () => ({})},
    analystState: {
      analystStatusSnapshot: asyncNoop,
      updateAnalystStatus: asyncNoop,
      analystAdjudicationSnapshot: asyncNoop,
      recordAnalystAdjudication: asyncNoop,
      updateIncidentCaseStatus: asyncNoop,
    },
    durableJob: {
      safeString: (value) => String(value || ''),
      controlledTransitionAdmission: asyncNoop,
      transitionJobStatus: asyncNoop,
      applyControlledTransition: asyncNoop,
      completePendingByDedupeKeys: asyncNoop,
    },
    analysisRequest: {
      controlledEvaluationMode: () => false,
      identityConflict: (message) => new Error(message),
      requestAiReanalysis: asyncNoop,
      requestIncidentEscalation: asyncNoop,
      requestIncidentReanalysis: asyncNoop,
      retireControlledEvaluation: asyncNoop,
      signalAiWorkers: asyncNoop,
    },
    analysisResult: {
      controlledEvaluationMode: () => false,
      requestHasOwnField: () => false,
      identityConflict: (message) => new Error(message),
      controlledResultAdmission: asyncNoop,
      recordAnalysisResult: asyncNoop,
      transitionJobStatus: asyncNoop,
      applyControlledResultAdmission: asyncNoop,
    },
    pcap: {
      createRequest: asyncNoop,
      listRequests: asyncNoop,
      claimRequest: asyncNoop,
      completeRequest: asyncNoop,
      updateTransferProgress: asyncNoop,
      retryRequest: asyncNoop,
      completeAnalysis: asyncNoop,
      requeueRequests: asyncNoop,
      signalPcapWorker: asyncNoop,
      signalAiWorkers: asyncNoop,
    },
    enrichment: {
      assertDiskWriteAdmission() {},
      enrichAlert: asyncNoop,
      cachedInvestigationEnrichment: asyncNoop,
      queryInvestigationEnrichment: asyncNoop,
      authorizeInvestigation() {},
    },
    maintenance: {rescore: asyncNoop, refreshGroups: asyncNoop},
    alertIngest: {
      metrics: {},
      now: Date.now,
      readJsonBody: asyncNoop,
      writeBeacon: asyncNoop,
      isRelayHeartbeat: () => false,
      assertDiskWriteAdmission() {},
      storeAlert: asyncNoop,
    },
  };
}

test('composes the exact public route surface without duplicates', () => {
  const routes = createRouteComposition(options());
  assert.equal(routes.routeKeys().length, 45);
  for (const key of [
    'POST /alert',
    'GET /health',
    'POST /jobs/status',
    'POST /analysis/result',
    'POST /controlled-evaluations/retire',
    'POST /pcap/analysis-status',
    'POST /investigations/enrichment/query',
    'POST /assets/approve-dhcp-ip-change',
  ]) assert.ok(routes.routeKeys().includes(key), key);
});

test('fails closed when a required composition section is absent', () => {
  const invalid = options();
  delete invalid.analysisResult;
  assert.throws(
    () => createRouteComposition(invalid),
    /analysisResult route composition section is required/,
  );
});
