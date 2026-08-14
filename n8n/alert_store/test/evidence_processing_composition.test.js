'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createEvidenceProcessingComposition,
} = require('../composition/evidence_processing_composition');

function createOptions() {
  const noOp = async () => ({changes: 0});
  return {
    database: {
      get: async () => undefined,
      all: async () => [],
      run: noOp,
      withWriteTransaction: async (task) => task(),
    },
    runtime: {},
    policy: {
      pcapCandidateFromRow: (row) => row,
      normalizePcapRequest: (value) => value,
      pcapRetentionError: () => new Error('expired'),
      pcapRequestFromRow: (row) => row,
      classifyPcapOutcome: () => 'success',
      readCaptureLossThreshold: () => 10,
      readPcapThreshold: () => 'medium',
      matchesAnalysis: () => true,
      severityRank: {
        informational: 0, low: 1, medium: 2, high: 3, critical: 4,
      },
      compactCorrelationCandidates: () => [],
      enrichmentRecord: () => ({}),
      groupKeyFromRow: () => 'group-key',
      groupIdFromKey: () => 'group-id',
      supportedAgentRoles: new Set(['soc-analyst']),
    },
    services: {
      pipelineMetrics: () => ({record: noOp}),
      pcapTransferRepository: () => ({requeueStaleClaims: noOp}),
      durableJobs: () => ({enqueue: noOp}),
      authorizedCampaignForAlertId: async () => null,
      enrichAlert: async (alert) => ({alert}),
      indexAlertObservables: noOp,
      signalAiWorkers: noOp,
      requestJson: noOp,
    },
    serialization: {
      safeString: (value) => String(value || ''),
      parseJsonObject: () => ({}),
      jsonText: JSON.stringify,
      canonicalJsonText: JSON.stringify,
      normalizeTimestampValue: (value) => value,
      nowUtc: () => '2026-08-10T00:00:00.000Z',
    },
  };
}

test('fails closed when a composition section is absent', () => {
  assert.throws(
    () => createEvidenceProcessingComposition({database: {}}),
    /runtime evidence processing composition section is required/,
  );
});

test('owns evidence repositories and defers incident-bound acceptance', () => {
  const composition = createEvidenceProcessingComposition(createOptions());
  assert.equal(typeof composition.pcapRequestRepository.createRequest, 'function');
  assert.equal(typeof composition.pcapAnalysisCompletion.complete, 'function');
  assert.equal(typeof composition.durableBackgroundDrains.drainEnrichment, 'function');
  assert.equal(typeof composition.aiReviewRepository.recordSecondOpinion, 'function');
  assert.throws(
    () => composition.createAiAcceptance(),
    /incident evidence processing composition section is required/,
  );
  const acceptance = composition.createAiAcceptance({
    bindingAuthority: async () => ({}),
    analysisCompletion: {complete: async () => ({})},
  });
  assert.equal(typeof acceptance.record, 'function');
});
