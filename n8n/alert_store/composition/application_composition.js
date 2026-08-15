'use strict';

const {createControlledEvaluationSchema} = require('../lib/controlled_evaluation_schema');
const {
  createAlertStoreSchemaFoundation,
} = require('../services/alert_store_schema_foundation');
const {
  createAlertStoreSchemaVersion,
} = require('../services/alert_store_schema_version');
const {createIncidentAnalysisSchema} = require('../services/incident_analysis_schema');
const {createAiReviewSchema} = require('../services/ai_review_schema');
const {
  createNotificationEnrichmentSchema,
} = require('../services/notification_enrichment_schema');
const {createPcapSchema} = require('../services/pcap_schema');
const {
  createStartupPersistenceOrchestrator,
} = require('../services/startup_persistence_orchestrator');
const {
  createAuthorizedCampaignPersistence,
} = require('../services/authorized_campaign_persistence');
const {createAnalystDecisionPersistence} = require('../services/analyst_decision_persistence');
const {createSuppressionPersistence} = require('../services/suppression_persistence');
const {createRescorePersistence} = require('../services/rescore_persistence');
const {createAutomaticResponseRouting} = require('../services/automatic_response_routing');
const {createAlertPersistence} = require('../services/alert_persistence');
const {createPostCommitPayload} = require('../services/post_commit_payload');
const {createAlertIngestOrchestrator} = require('../services/alert_ingest_orchestrator');

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} application composition section is required`);
  }
  return section;
}

function createApplicationComposition(options = {}) {
  const database = requireSection(options, 'database');
  const schema = requireSection(options, 'schema');
  const policy = requireSection(options, 'policy');
  const services = requireSection(options, 'services');
  const lifecycle = requireSection(options, 'lifecycle');
  const serialization = requireSection(options, 'serialization');
  const {get, all, run, withWriteGate, withTransaction, ensureColumn} = database;
  const {nowUtc, parseJsonObject, jsonText, normalizeTimestampValue} = serialization;

  const controlledEvaluationSchema = createControlledEvaluationSchema({
    all,
    get,
    initializeDurableJobs: lifecycle.initializeDurableJobs,
    initializePipelineMetrics: lifecycle.initializePipelineMetrics,
  });
  const alertStoreSchemaVersion = createAlertStoreSchemaVersion({run, get});
  const alertStoreSchemaFoundation = createAlertStoreSchemaFoundation({
    run,
    ensureColumn,
    assertControlledSchema: controlledEvaluationSchema.assertSchema,
    controlledEvaluationMode: schema.controlledEvaluationMode,
    sqliteBusyTimeoutMs: schema.sqliteBusyTimeoutMs,
    allowedJournalModes: schema.allowedJournalModes,
    sqliteJournalMode: schema.sqliteJournalMode,
    allowedSynchronousModes: schema.allowedSynchronousModes,
    sqliteSynchronous: schema.sqliteSynchronous,
    allowedTempStoreModes: schema.allowedTempStoreModes,
    sqliteTempStore: schema.sqliteTempStore,
    alertGroupKeySql: schema.alertGroupKeySql,
  });
  const incidentAnalysisSchema = createIncidentAnalysisSchema({run, ensureColumn});
  const aiReviewSchema = createAiReviewSchema({run, ensureColumn});
  const notificationEnrichmentSchema = createNotificationEnrichmentSchema({
    run,
    nowUtc,
    installEnrichmentCache: services.installEnrichmentCache,
  });
  const pcapSchema = createPcapSchema({
    run,
    ensureColumn,
    backfillOutcomes: services.backfillPcapOutcomes,
  });

  const authorizedCampaignPersistence = createAuthorizedCampaignPersistence({
    all,
    get,
    run,
    withImmediateTransaction: withTransaction,
    policy: policy.authorizedActivityPolicy,
    matchAuthorizedActivity: policy.matchAuthorizedActivity,
    parseJsonObject,
    normalizeTimestampValue,
    nowUtc,
    jsonText,
    integerField: policy.integerField,
    completePendingJobs: services.completePendingJobs,
    stableGroupKey: policy.stableGroupKey,
    stableGroupId: policy.stableGroupId,
    buildAlertObservables: policy.buildAlertObservables,
    extractAlertIndicators: policy.extractAlertIndicators,
  });
  const analystReviewProjection = policy.createAnalystReviewProjection({
    get,
    all,
    resolveDashboardAlertGroup: services.resolveDashboardAlertGroup,
    safeString: policy.safeString,
    parseJsonObject,
    conservativeReviewerTelemetry: policy.conservativeReviewerTelemetry,
    reviewerAutomationAuthorization: policy.reviewerAutomationAuthorization,
    reviewerFailureStatuses: policy.reviewerFailureStatuses,
  });
  const analystDecisionPersistence = createAnalystDecisionPersistence({
    get,
    all,
    run,
    withWriteGate,
    reviewState: analystReviewProjection.reviewState,
    validGroupId: policy.validAnalystGroupId,
    validCaseId: policy.validIncidentCaseId,
    safeString: policy.safeString,
    adjudicationOutcomes: policy.analystAdjudicationOutcomes,
    adjudicationConfidences: policy.analystAdjudicationConfidences,
    eventStatuses: policy.analystEventStatuses,
    detectionValidities: policy.analystDetectionValidities,
    activityDispositions: policy.analystActivityDispositions,
    handlingValues: policy.analystHandlingValues,
    verdictContradictions: policy.analystVerdictContradictions,
    adjudicationTextMaxLength: policy.analystAdjudicationTextMaxLength,
    statusReasonMaxLength: policy.analystStatusReasonMaxLength,
    nowUtc,
    randomUUID: services.randomUUID,
    jsonText,
  });
  const suppressionPersistence = createSuppressionPersistence({
    findSuppressRule: policy.findSuppressRule,
    stableGroupId: policy.stableGroupId,
    nestedField: policy.nestedField,
    pendingHumanReview: analystReviewProjection.pendingHumanReview,
    suppressionKey: policy.suppressionKey,
    ruleName: policy.ruleName,
    get,
    run,
  });
  const rescorePersistence = createRescorePersistence({
    all,
    run,
    scoreAlert: policy.scoreAlert,
    nestedField: policy.nestedField,
    integerField: policy.integerField,
    jsonText,
    enrichmentRecord: policy.enrichmentRecord,
    rebuildGroupSummaries: services.rebuildGroupSummaries,
    scoringRulesName: policy.scoringRulesName,
  });
  const automaticResponseRouting = createAutomaticResponseRouting({
    nestedField: policy.nestedField,
    readPolicy: policy.readSocAnalysisPolicy,
    matchesPcap: policy.matchesPcap,
    matchesIncident: policy.matchesIncident,
    groupKeyFromRow: policy.groupKeyFromRow,
    groupIdFromKey: policy.groupIdFromKey,
    get,
    run,
    parseJsonObject,
    jsonText,
    nowUtc,
    createPcapRequest: services.createPcapRequest,
    pcapRequestDefaultWindowSeconds: policy.pcapRequestDefaultWindowSeconds,
    queueIncidentResponseForGroup: services.queueIncidentResponseForGroup,
    severityRank: policy.severityRank,
  });
  const alertPersistence = createAlertPersistence({
    currentGroupKey: policy.currentGroupKey,
    nowUtc,
    findDropRule: policy.findDropRule,
    nestedField: policy.nestedField,
    ruleName: policy.ruleName,
    normalizeTimestampValue,
    integerField: policy.integerField,
    jsonText,
    enrichmentRecord: policy.enrichmentRecord,
    run,
    get,
    applySuppression: suppressionPersistence.apply,
    persistStableIdentity: services.persistStableIdentity,
    indexObservables: authorizedCampaignPersistence.indexObservables,
    recordCampaign: authorizedCampaignPersistence.recordCampaign,
    groupKeyFromRow: policy.groupKeyFromRow,
    refreshGroupSummary: services.refreshGroupSummary,
    queueAutomaticPcap: automaticResponseRouting.queuePcap,
    queueAutomaticIncident: automaticResponseRouting.queueIncident,
  });
  const postCommitPayload = createPostCommitPayload({
    nowUtc,
    nestedField: policy.nestedField,
  });
  const alertIngestOrchestrator = createAlertIngestOrchestrator({
    scoreAlert: policy.scoreAlert,
    withWriteGate,
    withTransaction,
    storeUnlocked: alertPersistence.store,
    queueNotification: services.queueNotification,
    nowUtc,
    buildPostCommitPayload: postCommitPayload.build,
    enqueueJob: services.enqueueJob,
    recordMetric: services.recordMetric,
    severityRank: policy.severityRank,
    postCommitMaxAttempts: policy.postCommitMaxAttempts,
    hasUsableExternalIntel: policy.hasUsableExternalIntel,
    nestedField: policy.nestedField,
    enrichmentMaxAttempts: policy.enrichmentMaxAttempts,
    groupKeyFromRow: policy.groupKeyFromRow,
    groupIdFromKey: policy.groupIdFromKey,
    matchesAnalysis: policy.matchesAnalysis,
    signalAiWorkers: services.signalAiWorkers,
    drainNotificationOutbox: services.drainNotificationOutbox,
    drainEnrichmentJobs: services.drainEnrichmentJobs,
    drainPostCommitJobs: services.drainPostCommitJobs,
  });
  const startupPersistenceOrchestrator = createStartupPersistenceOrchestrator({
    initializeDurableJobs: lifecycle.initializeDurableJobs,
    installDurableJobs: lifecycle.installDurableJobs,
    initializePostgresShadowOutbox: lifecycle.initializePostgresShadowOutbox,
    installPostgresShadowOutbox: lifecycle.installPostgresShadowOutbox,
    initializePostgresShadowProjector: lifecycle.initializePostgresShadowProjector,
    reconcileRecoveredIncidentAttempts: lifecycle.reconcileRecoveredIncidentAttempts,
    initializePipelineMetrics: lifecycle.initializePipelineMetrics,
    installPipelineMetrics: lifecycle.installPipelineMetrics,
    backfillStableGroupIdentity: lifecycle.backfillStableGroupIdentity,
    backfillAuthorizedActivityCampaigns: authorizedCampaignPersistence.backfillCampaigns,
    reconcileAuthorizedActivityBacklog: authorizedCampaignPersistence.reconcileBacklog,
    backfillAlertObservables: authorizedCampaignPersistence.backfillObservables,
    rebuildAlertGroupSummaries: lifecycle.rebuildAlertGroupSummaries,
    refreshGroupAliases: lifecycle.refreshGroupAliases,
  });

  return {
    aiReviewSchema,
    alertIngestOrchestrator,
    alertPersistence,
    alertStoreSchemaFoundation,
    alertStoreSchemaVersion,
    analystDecisionPersistence,
    analystReviewProjection,
    authorizedCampaignPersistence,
    automaticResponseRouting,
    controlledEvaluationSchema,
    incidentAnalysisSchema,
    notificationEnrichmentSchema,
    pcapSchema,
    rescorePersistence,
    startupPersistenceOrchestrator,
    suppressionPersistence,
  };
}

module.exports = {createApplicationComposition};
