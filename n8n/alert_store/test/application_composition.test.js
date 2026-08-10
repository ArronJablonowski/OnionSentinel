'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createApplicationComposition} = require('../composition/application_composition');

const asyncNoop = async () => undefined;
const noop = () => undefined;

function options() {
  return {
    database: {
      get: asyncNoop,
      all: asyncNoop,
      run: asyncNoop,
      withWriteGate: async (task) => task(),
      withTransaction: async (task) => task(),
      ensureColumn: asyncNoop,
    },
    schema: {
      controlledEvaluationMode: false,
      sqliteBusyTimeoutMs: 30000,
      allowedJournalModes: new Set(['DELETE']),
      sqliteJournalMode: 'DELETE',
      allowedSynchronousModes: new Set(['FULL']),
      sqliteSynchronous: 'FULL',
      allowedTempStoreModes: new Set(['DEFAULT']),
      sqliteTempStore: 'DEFAULT',
      alertGroupKeySql: 'COALESCE(stable_group_key, alert_id)',
    },
    policy: {
      authorizedActivityPolicy: {policies: []},
      matchAuthorizedActivity: noop,
      integerField: () => 0,
      stableGroupKey: () => 'stable-key',
      stableGroupId: () => 'stable-id',
      buildAlertObservables: () => [],
      extractAlertIndicators: () => [],
      createAnalystReviewProjection: () => ({
        reviewState: asyncNoop,
        pendingHumanReview: asyncNoop,
        adjudicationSnapshot: asyncNoop,
      }),
      safeString: (value) => String(value || ''),
      conservativeReviewerTelemetry: noop,
      reviewerAutomationAuthorization: noop,
      reviewerFailureStatuses: new Set(),
      validAnalystGroupId: () => true,
      validIncidentCaseId: () => true,
      analystAdjudicationOutcomes: new Set(),
      analystAdjudicationConfidences: new Set(),
      analystEventStatuses: new Set(),
      analystDetectionValidities: new Set(),
      analystActivityDispositions: new Set(),
      analystHandlingValues: new Set(),
      analystVerdictContradictions: () => [],
      analystAdjudicationTextMaxLength: 1000,
      analystStatusReasonMaxLength: 1000,
      findSuppressRule: noop,
      nestedField: noop,
      suppressionKey: noop,
      ruleName: noop,
      scoreAlert: noop,
      enrichmentRecord: noop,
      scoringRulesName: 'scoring_rules.json',
      readSocAnalysisPolicy: () => ({}),
      matchesPcap: () => false,
      matchesIncident: () => false,
      matchesAnalysis: () => false,
      groupKeyFromRow: noop,
      groupIdFromKey: noop,
      currentGroupKey: noop,
      findDropRule: noop,
      pcapRequestDefaultWindowSeconds: 900,
      severityRank: {},
      postCommitMaxAttempts: 3,
      hasUsableExternalIntel: () => false,
      enrichmentMaxAttempts: 3,
    },
    services: {
      installEnrichmentCache: asyncNoop,
      backfillPcapOutcomes: asyncNoop,
      completePendingJobs: asyncNoop,
      resolveDashboardAlertGroup: asyncNoop,
      randomUUID: () => '00000000-0000-4000-8000-000000000000',
      rebuildGroupSummaries: asyncNoop,
      createPcapRequest: asyncNoop,
      queueIncidentResponseForGroup: asyncNoop,
      persistStableIdentity: asyncNoop,
      refreshGroupSummary: asyncNoop,
      queueNotification: asyncNoop,
      enqueueJob: asyncNoop,
      recordMetric: asyncNoop,
      signalAiWorkers: asyncNoop,
      drainNotificationOutbox: asyncNoop,
      drainEnrichmentJobs: asyncNoop,
      drainPostCommitJobs: asyncNoop,
    },
    lifecycle: {
      initializeDurableJobs: noop,
      installDurableJobs: asyncNoop,
      initializePostgresShadowOutbox: noop,
      installPostgresShadowOutbox: asyncNoop,
      initializePostgresShadowProjector: noop,
      reconcileRecoveredIncidentAttempts: asyncNoop,
      initializePipelineMetrics: noop,
      installPipelineMetrics: asyncNoop,
      backfillStableGroupIdentity: asyncNoop,
      rebuildAlertGroupSummaries: asyncNoop,
      refreshGroupAliases: asyncNoop,
    },
    serialization: {
      nowUtc: () => '2026-08-10T00:00:00.000Z',
      parseJsonObject: () => ({}),
      jsonText: JSON.stringify,
      normalizeTimestampValue: (value) => value,
    },
  };
}

test('owns schema, domain persistence, ingest, and startup construction', () => {
  const composition = createApplicationComposition(options());
  const expectedMethods = {
    alertStoreSchemaFoundation: 'configureRuntime',
    controlledEvaluationSchema: 'assertSchema',
    incidentAnalysisSchema: 'install',
    aiReviewSchema: 'install',
    notificationEnrichmentSchema: 'install',
    pcapSchema: 'install',
    authorizedCampaignPersistence: 'recordCampaign',
    analystDecisionPersistence: 'recordAdjudication',
    suppressionPersistence: 'apply',
    rescorePersistence: 'rescore',
    automaticResponseRouting: 'queuePcap',
    alertPersistence: 'store',
    alertIngestOrchestrator: 'store',
    startupPersistenceOrchestrator: 'initialize',
  };
  for (const [owner, method] of Object.entries(expectedMethods)) {
    assert.equal(typeof composition[owner][method], 'function', `${owner}.${method}`);
  }
});

test('fails closed when a required composition section is absent', () => {
  const invalid = options();
  delete invalid.lifecycle;
  assert.throws(
    () => createApplicationComposition(invalid),
    /lifecycle application composition section is required/,
  );
});
