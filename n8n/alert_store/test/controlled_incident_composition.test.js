'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createControlledIncidentComposition,
} = require('../composition/controlled_incident_composition');

const asyncNoop = async () => undefined;

function options() {
  const identityConflict = (message) => {
    const error = new Error(message);
    error.statusCode = 409;
    return error;
  };
  const safeString = (value) => String(value || '');
  return {
    persistence: {get: asyncNoop, all: asyncNoop, run: asyncNoop},
    identity: {
      safeString,
      validCaseId: () => true,
      validPinnedStableGroupKey: () => true,
      stableGroupIdPattern: /^[a-f0-9]{20}$/,
      representativeAlertIdPattern: /^[A-Za-z0-9._:@=-]{1,256}$/,
      dispatchIdPattern: /^[a-f0-9]{64}$/,
      cohortIdPattern: /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/,
      releaseIdPattern: /^[a-f0-9]{40}$/,
      controlledRoutePattern: /^codex-cli:gpt-5\.6-sol:high$/,
      controlledRouteModelIdentity: (route) => String(route).split(':').slice(0, -1).join(':'),
      requestHasOwnField: (payload, field) => Object.hasOwn(payload || {}, field),
      identityConflict,
    },
    runtime: {
      controlledEvaluationMode: false,
      runtimeReleaseId: 'a'.repeat(40),
      controlledRuntimeReleaseId: () => 'a'.repeat(40),
      incidentReanalysisReleaseId: () => 'a'.repeat(40),
      aiAnalysisLeaseSeconds: 300,
      nowUtc: () => '2026-08-10T00:00:00.000Z',
      randomUuid: () => '00000000-0000-4000-8000-000000000000',
      sha256Text: () => 'b'.repeat(64),
      warn() {},
    },
    durable: {
      available: () => true,
      owner: () => ({retirePendingExact: asyncNoop}),
      pipelineMetrics: () => ({record: asyncNoop}),
      enqueue: asyncNoop,
      retirePendingExact: asyncNoop,
      reconcileAuthorizedActivity: asyncNoop,
      recordMetric: asyncNoop,
      signalAiWorkers: asyncNoop,
    },
    transaction: {
      withWriteGate: async (task) => task(),
      withTransaction: async (task) => task(),
    },
    drains: {drainEnrichmentJobs: asyncNoop, drainPostCommitJobs: asyncNoop},
    serialization: {
      parseJsonObject: () => ({}),
      jsonText: JSON.stringify,
      canonicalJsonText: JSON.stringify,
      parseProjectTimestamp: (value) => value,
      formatProjectTimestamp: (value) => value,
    },
  };
}

test('owns the complete controlled evaluation and incident reanalysis graph', () => {
  const composition = createControlledIncidentComposition(options());
  assert.ok(composition.controlledEvaluationLeases instanceof Map);
  assert.equal(typeof composition.controlledJobTransitionAuthority.admit, 'function');
  assert.equal(typeof composition.controlledResultAdmissionAuthority.admit, 'function');
  assert.equal(typeof composition.controlledRetirementCommandOwner.retire, 'function');
  assert.equal(typeof composition.durableJobRecovery.recover, 'function');
  assert.equal(typeof composition.durableJobTransitionExecutor.transition, 'function');
  assert.equal(typeof composition.incidentAnalysisCompletion.complete, 'function');
  assert.equal(typeof composition.incidentReanalysisBindingService.bindResult, 'function');
  assert.equal(typeof composition.incidentReanalysisRecovery.reconcile, 'function');
  assert.equal(typeof composition.incidentReanalysisRequestOwner.request, 'function');
  assert.equal(typeof composition.manualAnalysisDispatch.requestAiReanalysis, 'function');
  assert.equal(typeof composition.manualDispatchIdentityOwner.normalize, 'function');
});

test('fails closed when a required composition section is absent', () => {
  const invalid = options();
  delete invalid.durable;
  assert.throws(
    () => createControlledIncidentComposition(invalid),
    /durable controlled incident composition section is required/,
  );
});
