'use strict';

const analystReviewDefinitions = require('../services/analyst_review_projection');
const {createControlledIncidentComposition} = require('./controlled_incident_composition');
const {createApplicationComposition} = require('./application_composition');
const {createMutableRuntimeOwners} = require('./mutable_runtime_owners');
const {createEvidenceProcessingComposition} = require('./evidence_processing_composition');
const {createStartupPersistenceCompatibility} = require('./startup_persistence_compatibility');
const {createApplicationRuntimePorts} = require('./application_runtime_ports');
const {createPcapPolicy} = require('../lib/pcap_policy');
const {
  nestedField,
  integerField,
  nonNegativeIntegerField,
  enrichmentRecord,
  safeString,
  parseJsonObject,
} = require('../lib/alert_value_normalization');
const {
  analystAdjudicationOutcomes,
  analystAdjudicationConfidences,
  analystEventStatuses,
  analystDetectionValidities,
  analystActivityDispositions,
  analystHandlingValues,
  reviewerFailureStatuses,
  analystVerdictContradictions,
} = require('../lib/analyst_review_policy');
const {matchAuthorizedActivity} = require('../lib/authorized_activity_policy');
const {
  stableGroupKey,
  stableGroupId,
  validPinnedStableGroupKey,
} = require('../lib/group_identity');
const {
  buildAlertObservables,
  compactCorrelationCandidates,
} = require('../lib/correlation_context');

const cohortIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const stableGroupIdPattern = /^[a-f0-9]{20}$/;
const dispatchIdPattern = /^[a-f0-9]{64}$/;
const releaseIdPattern = /^[a-f0-9]{40}$/;
const representativeAlertIdPattern = /^[A-Za-z0-9._:@=-]{1,256}$/;
const controlledRoutePattern = /^codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):(?:low|medium|high|xhigh)$/;

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} application graph runtime section is required`);
  }
  return section;
}

function controlledRouteModelIdentity(route) {
  return String(route || '').split(':').slice(0, -1).join(':');
}

function requestHasOwnField(payload, field) {
  return Boolean(
    payload
    && typeof payload === 'object'
    && Object.prototype.hasOwnProperty.call(payload, field)
  );
}

function incidentIdentityConflict(message) {
  const error = new Error(message);
  error.statusCode = 409;
  return error;
}

function createApplicationGraphRuntime(options = {}) {
  const runtime = requireSection(options, 'runtime');
  const platform = requireSection(options, 'platform');
  const foundation = requireSection(options, 'foundation');
  const serialization = requireSection(options, 'serialization');
  const {
    database: db,
    run,
    get,
    all,
    withWriteGate,
    withImmediateTransaction: withTransaction,
  } = foundation.sqliteRuntime;
  const startupCompatibility = createStartupPersistenceCompatibility({
    database: {db, run, all, withTransaction},
    identity: {stableGroupKey, stableGroupId},
    serialization: {parseJsonObject},
  });
  const pcapPolicy = createPcapPolicy({
    safeString,
    parseJsonObject,
    nestedField,
    integerField,
    normalizeTimestampValue: serialization.normalizeTimestampValue,
    defaultWindowSeconds: runtime.pcapRequestDefaultWindowSeconds,
    maxWindowSeconds: runtime.pcapRequestMaxWindowSeconds,
    captureRetentionSeconds: runtime.pcapCaptureRetentionSeconds,
  });
  const diskCapacitySnapshot = (additionalBytes = 0) => (
    foundation.diskWriteAdmission.diskCapacitySnapshot(additionalBytes)
  );
  const signalAiWorkers = (eventName) => (
    foundation.workerWakeSignaling.signalAiWorkers(eventName)
  );
  const mutableRuntimeOwners = createMutableRuntimeOwners({
    database: {get, all, run, withWriteGate},
    runtime: {
      nowUtc: serialization.nowUtc,
      aiAnalysisLeaseSeconds: runtime.aiAnalysisLeaseSeconds,
      postgresShadowEnabled: runtime.postgresShadowEnabled,
      controlledEvaluationMode: runtime.controlledEvaluationMode,
      postgresShadowBatchSize: runtime.postgresShadowBatchSize,
      diskCapacitySnapshot,
      pipelineEventRetentionHours: runtime.pipelineEventRetentionHours,
      pcapClaimLeaseSeconds: runtime.pcapClaimLeaseSeconds,
      pcapTransferMaxAttempts: runtime.pcapTransferMaxAttempts,
      pcapTransferMaxRetrySeconds: runtime.pcapTransferMaxRetrySeconds,
    },
    pcap: {
      safeString,
      nonNegativeIntegerField,
      formatProjectTimestamp: serialization.formatProjectTimestamp,
      pcapRequestFromRow: pcapPolicy.pcapRequestFromRow,
      classifyPcapOutcome: pcapPolicy.classifyPcapOutcome,
      matchesPcap: (level) => foundation.socAnalysisPolicy.matchesPcap(level),
      readPcapThreshold: () => (
        foundation.socAnalysisPolicy.read().soc_analyst_pcap_min_severity
      ),
      pcapOutcomes: pcapPolicy.pcapOutcomes,
    },
    platform: {
      env: platform.env,
      console: platform.consoleLike,
      createPostgresPool: platform.createPostgresPool,
    },
  });

  let applicationOwners;
  const evidenceProcessing = createEvidenceProcessingComposition({
    database: {
      get,
      all,
      run,
      withWriteTransaction: (task) => withWriteGate(() => withTransaction(task)),
    },
    runtime: {
      pcapPriorityMaxWaitSeconds: runtime.pcapPriorityMaxWaitSeconds,
      pcapCaptureRetentionSeconds: runtime.pcapCaptureRetentionSeconds,
      enrichmentTimeoutMs: runtime.enrichmentTimeoutMs,
      n8nPostCommitUrl: runtime.n8nPostCommitUrl,
      n8nPostCommitToken: runtime.n8nPostCommitToken,
      n8nPostCommitTimeoutMs: runtime.n8nPostCommitTimeoutMs,
      n8nPostCommitBaseRetrySeconds: runtime.n8nPostCommitBaseRetrySeconds,
    },
    policy: {
      pcapCandidateFromRow: pcapPolicy.pcapCandidateFromRow,
      normalizePcapRequest: pcapPolicy.normalizePcapRequest,
      pcapRetentionError: pcapPolicy.pcapRetentionError,
      pcapRequestFromRow: pcapPolicy.pcapRequestFromRow,
      classifyPcapOutcome: pcapPolicy.classifyPcapOutcome,
      readCaptureLossThreshold: () => (
        foundation.socAnalysisPolicy.read().pcap_capture_loss_threshold_percent
      ),
      readPcapThreshold: () => (
        foundation.socAnalysisPolicy.read().soc_analyst_pcap_min_severity
      ),
      matchesAnalysis: (level) => foundation.socAnalysisPolicy.matchesAnalysis(level),
      severityRank: foundation.severityRank,
      compactCorrelationCandidates,
      enrichmentRecord,
      groupKeyFromRow: foundation.alertGroupService.alertGroupKeyFromRow,
      groupIdFromKey: foundation.alertGroupId,
      supportedAgentRoles: foundation.supportedAgentRoles,
    },
    services: {
      pipelineMetrics: mutableRuntimeOwners.pipelineMetrics,
      pcapTransferRepository: mutableRuntimeOwners.pcapTransferRepository,
      durableJobs: mutableRuntimeOwners.durableJobs,
      authorizedCampaignForAlertId: (alertId) => (
        applicationOwners.authorizedCampaignPersistence.campaignForAlertId(alertId)
      ),
      enrichAlert: foundation.enrichmentOrchestrator.enrichAlert,
      indexAlertObservables: (alert, row) => (
        applicationOwners.authorizedCampaignPersistence.indexObservables(alert, row)
      ),
      signalAiWorkers,
      requestJson: foundation.enrichmentProviderClient.requestJson,
    },
    serialization: {
      safeString,
      parseJsonObject,
      jsonText: serialization.jsonText,
      canonicalJsonText: serialization.canonicalJsonText,
      normalizeTimestampValue: serialization.normalizeTimestampValue,
      nowUtc: serialization.nowUtc,
    },
  });
  const validIncidentCaseId = analystReviewDefinitions.validIncidentCaseId;
  const controlledRuntimeReleaseId = () => {
    const releaseId = platform.env.ONION_SENTINEL_RELEASE_ID;
    return typeof releaseId === 'string' && releaseIdPattern.test(releaseId)
      ? releaseId : '';
  };
  const incidentReanalysisReleaseId = () => {
    const candidate = safeString(
      platform.env.ONION_SENTINEL_RELEASE_ID || 'unversioned',
      100,
    ).replace(/[^A-Za-z0-9._:-]+/g, '-').replace(/^-+|-+$/g, '');
    return candidate || 'unversioned';
  };
  const controlledIncident = createControlledIncidentComposition({
    persistence: {get, all, run},
    identity: {
      safeString,
      validCaseId: validIncidentCaseId,
      validPinnedStableGroupKey,
      stableGroupIdPattern,
      representativeAlertIdPattern,
      dispatchIdPattern,
      cohortIdPattern,
      releaseIdPattern,
      controlledRoutePattern,
      controlledRouteModelIdentity,
      requestHasOwnField,
      identityConflict: incidentIdentityConflict,
    },
    runtime: {
      controlledEvaluationMode: runtime.controlledEvaluationMode,
      runtimeReleaseId: runtime.runtimeReleaseIdValue,
      controlledRuntimeReleaseId,
      incidentReanalysisReleaseId,
      aiAnalysisLeaseSeconds: runtime.aiAnalysisLeaseSeconds,
      nowUtc: serialization.nowUtc,
      randomUuid: platform.randomUUID,
      sha256Text: platform.sha256Text,
      warn: platform.warn,
    },
    durable: {
      available: () => Boolean(mutableRuntimeOwners.durableJobs()),
      owner: mutableRuntimeOwners.durableJobs,
      pipelineMetrics: mutableRuntimeOwners.pipelineMetrics,
      enqueue: (...args) => mutableRuntimeOwners.durableJobs().enqueue(...args),
      retirePendingExact: (ownerOptions) => (
        mutableRuntimeOwners.durableJobs().retirePendingExact(ownerOptions)
      ),
      reconcileAuthorizedActivity: () => (
        applicationOwners.authorizedCampaignPersistence.reconcileBacklog()
      ),
      recordMetric: (...args) => mutableRuntimeOwners.pipelineMetrics().record(...args),
      signalAiWorkers,
    },
    transaction: {withWriteGate, withTransaction},
    drains: {
      drainEnrichmentJobs: evidenceProcessing.durableBackgroundDrains.drainEnrichment,
      drainPostCommitJobs: evidenceProcessing.durableBackgroundDrains.drainPostCommit,
    },
    serialization: {
      parseJsonObject,
      jsonText: serialization.jsonText,
      canonicalJsonText: serialization.canonicalJsonText,
      parseProjectTimestamp: serialization.parseProjectTimestamp,
      formatProjectTimestamp: serialization.formatProjectTimestamp,
    },
  });
  const aiAnalysisAcceptance = evidenceProcessing.createAiAcceptance({
    bindingAuthority: controlledIncident.incidentReanalysisBindingService.bindingAuthority,
    analysisCompletion: controlledIncident.incidentAnalysisCompletion,
  });
  const applicationRuntimePorts = createApplicationRuntimePorts({
    mutable: mutableRuntimeOwners,
    domain: {
      enrichmentCache: foundation.enrichmentCache,
      pcapRequestRepository: evidenceProcessing.pcapRequestRepository,
      resolveDashboardAlertGroup: controlledIncident.manualAnalysisDispatch.resolveDashboardAlertGroup,
      randomUUID: platform.randomUUID,
      rebuildGroupSummariesUnlocked: foundation.alertGroupService.rebuildAlertGroupSummariesUnlocked,
      queueIncidentResponseForGroup: controlledIncident.manualAnalysisDispatch.queueIncidentResponseForGroup,
      persistStableIdentity: startupCompatibility.persistStableIdentity,
      refreshGroupSummary: foundation.alertGroupService.refreshAlertGroupSummary,
      queueNotification: foundation.notificationService.queueTelegramNotification,
      signalAiWorkers,
      drainNotificationOutbox: foundation.notificationService.drainTelegramOutbox,
      drainEnrichmentJobs: evidenceProcessing.durableBackgroundDrains.drainEnrichment,
      drainPostCommitJobs: evidenceProcessing.durableBackgroundDrains.drainPostCommit,
    },
    lifecycle: {
      reconcileRecoveredIncidentAttempts: controlledIncident.incidentReanalysisRecovery.reconcile,
      backfillStableGroupIdentity: startupCompatibility.backfillStableGroupIdentity,
      rebuildAlertGroupSummaries: foundation.alertGroupService.rebuildAlertGroupSummaries,
      refreshGroupAliases: foundation.alertGroupService.refreshGroupAliases,
    },
  });
  applicationOwners = createApplicationComposition({
    database: {get, all, run, withWriteGate, withTransaction, ensureColumn: startupCompatibility.ensureColumn},
    schema: {
      controlledEvaluationMode: runtime.controlledEvaluationMode,
      sqliteBusyTimeoutMs: foundation.sqliteBusyTimeoutMs,
      allowedJournalModes: foundation.allowedJournalModes,
      sqliteJournalMode: foundation.sqliteJournalMode,
      allowedSynchronousModes: foundation.allowedSynchronousModes,
      sqliteSynchronous: foundation.sqliteSynchronous,
      allowedTempStoreModes: foundation.allowedTempStoreModes,
      sqliteTempStore: foundation.sqliteTempStore,
      alertGroupKeySql: foundation.alertGroupKeySql,
    },
    policy: {
      authorizedActivityPolicy: runtime.authorizedActivityPolicy,
      matchAuthorizedActivity,
      integerField,
      stableGroupKey,
      stableGroupId,
      buildAlertObservables,
      extractAlertIndicators: foundation.indicatorExtraction.extractAlertIndicators,
      createAnalystReviewProjection: analystReviewDefinitions.createAnalystReviewProjection,
      safeString,
      conservativeReviewerTelemetry: foundation.reviewerPolicy.conservativeReviewerTelemetry,
      reviewerAutomationAuthorization: foundation.reviewerPolicy.reviewerAutomationAuthorization,
      reviewerFailureStatuses,
      validAnalystGroupId: analystReviewDefinitions.validAnalystGroupId,
      validIncidentCaseId,
      analystAdjudicationOutcomes,
      analystAdjudicationConfidences,
      analystEventStatuses,
      analystDetectionValidities,
      analystActivityDispositions,
      analystHandlingValues,
      analystVerdictContradictions,
      analystAdjudicationTextMaxLength: runtime.analystAdjudicationTextMaxLength,
      analystStatusReasonMaxLength: runtime.analystStatusReasonMaxLength,
      findSuppressRule: foundation.scoringPolicy.findSuppressRule,
      nestedField,
      suppressionKey: foundation.scoringPolicy.suppressionKey,
      ruleName: foundation.scoringPolicy.ruleName,
      scoreAlert: foundation.scoringPolicy.scoreAlert,
      enrichmentRecord,
      scoringRulesName: platform.path.basename(runtime.scoringRulesPath),
      readSocAnalysisPolicy: () => foundation.socAnalysisPolicy.read(),
      matchesPcap: (level) => foundation.socAnalysisPolicy.matchesPcap(level),
      matchesIncident: (level) => foundation.socAnalysisPolicy.matchesIncident(level),
      matchesAnalysis: (level) => foundation.socAnalysisPolicy.matchesAnalysis(level),
      groupKeyFromRow: foundation.alertGroupService.alertGroupKeyFromRow,
      groupIdFromKey: foundation.alertGroupId,
      currentGroupKey: foundation.alertGroupService.currentAlertGroupKey,
      findDropRule: foundation.scoringPolicy.findDropRule,
      pcapRequestDefaultWindowSeconds: runtime.pcapRequestDefaultWindowSeconds,
      severityRank: foundation.severityRank,
      postCommitMaxAttempts: runtime.n8nPostCommitMaxAttempts,
      hasUsableExternalIntel: foundation.indicatorExtraction.hasUsableExternalIntel,
      enrichmentMaxAttempts: runtime.enrichmentWorkerMaxAttempts,
    },
    services: applicationRuntimePorts.services,
    lifecycle: applicationRuntimePorts.lifecycle,
    serialization: {
      nowUtc: serialization.nowUtc,
      parseJsonObject,
      jsonText: serialization.jsonText,
      normalizeTimestampValue: serialization.normalizeTimestampValue,
    },
  });
  const initDb = startupCompatibility.createSchemaInitializer({
    alertStoreSchemaFoundation: applicationOwners.alertStoreSchemaFoundation,
    incidentAnalysisSchema: applicationOwners.incidentAnalysisSchema,
    aiReviewSchema: applicationOwners.aiReviewSchema,
    notificationEnrichmentSchema: applicationOwners.notificationEnrichmentSchema,
    pcapSchema: applicationOwners.pcapSchema,
    startupPersistenceOrchestrator: applicationOwners.startupPersistenceOrchestrator,
  });

  return {
    applicationOwners,
    controlledIncident,
    evidenceProcessing,
    mutableRuntimeOwners,
    aiAnalysisAcceptance,
    initDb,
    requestHasOwnField,
    incidentIdentityConflict,
  };
}

module.exports = {createApplicationGraphRuntime};
