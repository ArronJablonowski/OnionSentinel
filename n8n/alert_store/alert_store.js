// alert-store is the policy and persistence layer for Security Onion alerts.
//
// n8n calls POST /alert with one normalized alert at a time. This service then
// scores, deduplicates, applies hard drops and TTL suppressions, stores the
// result in SQLite, and sends Telegram notifications when policy allows.
//
// First troubleshooting checks:
//   1. GET /health from inside the n8n Docker network.
//   2. Inspect /data/alerts.sqlite3 for alert/filter state.
//   3. Inspect /app/config/scoring_rules.json for tuning rules.
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const analystReviewDefinitions = require('./services/analyst_review_projection');
const {
  createControlledIncidentComposition,
} = require('./composition/controlled_incident_composition');
const {createApplicationComposition} = require('./composition/application_composition');
const {
  createRuntimeFoundationComposition,
} = require('./composition/runtime_foundation_composition');
const {
  createMutableRuntimeOwners,
} = require('./composition/mutable_runtime_owners');
const {
  createEvidenceProcessingComposition,
} = require('./composition/evidence_processing_composition');
const {
  createStartupPersistenceCompatibility,
} = require('./composition/startup_persistence_compatibility');
const {
  createApplicationRuntimePorts,
} = require('./composition/application_runtime_ports');
const {
  createHttpApplicationRuntime,
} = require('./composition/http_application_runtime');
const {createPcapPolicy} = require('./lib/pcap_policy');
const {createProjectSerialization} = require('./lib/project_serialization');
const {createRuntimeConfiguration} = require('./lib/runtime_configuration');
const {
  isRelayHeartbeat,
  nestedField,
  integerField,
  nonNegativeIntegerField,
  enrichmentRecord,
  normalizeTriageLevel,
  safeString,
  parseJsonObject,
} = require('./lib/alert_value_normalization');
const {
  analystAdjudicationOutcomes,
  analystAdjudicationConfidences,
  analystEventStatuses,
  analystDetectionValidities,
  analystActivityDispositions,
  analystHandlingValues,
  reviewerFailureStatuses,
  analystVerdictContradictions,
} = require('./lib/analyst_review_policy');
const {
  loadAuthorizedActivityPolicy,
  matchAuthorizedActivity,
} = require('./lib/authorized_activity_policy');
const {
  stableGroupKey,
  stableGroupId,
  validPinnedStableGroupKey,
} = require('./lib/group_identity');
const {buildAlertObservables, compactCorrelationCandidates} = require('./lib/correlation_context');
const {requestJson: boundedRequestJson} = require('./lib/http_json_client');
let sqlite3;
try {
  // Host-native launchd deployments install sqlite3 beside this script.
  sqlite3 = require('sqlite3');
} catch (error) {
  // The Docker proxy is preferred for n8n reachability, but this fallback keeps
  // older container-based DR deployments bootable.
  sqlite3 = require('/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3');
}
const {
  formatProjectTimestamp,
  parseProjectTimestamp,
  nowUtc,
  normalizeTimestampValue,
  jsonText,
  canonicalJsonText,
} = createProjectSerialization();

// Runtime values come from docker-compose.yml and .env. Keep real tokens in
// .env only; this DR repo stores placeholders and source code.
const runtimeConfiguration = createRuntimeConfiguration({
  env: process.env,
  fs,
  path,
  os,
  dirname: __dirname,
  getuid: typeof process.getuid === 'function' ? () => process.getuid() : null,
  loadAuthorizedActivityPolicy,
});
const {
  dbPath,
  scoringRulesPath,
  authorizedActivityPolicyPath,
  authorizedActivityPolicy,
  postgresShadowEnabled,
  postgresShadowBatchSize,
  controlledEvaluationMode,
  runtimeReleaseIdValue,
  maxRequestBytes,
  enrichmentTimeoutMs,
  enrichmentWorkerMaxAttempts,
  pcapRequestMaxWindowSeconds,
  pcapRequestDefaultWindowSeconds,
  pcapClaimLeaseSeconds,
  pcapCaptureRetentionSeconds,
  pcapPriorityMaxWaitSeconds,
  pcapTransferMaxAttempts,
  pcapTransferMaxRetrySeconds,
  pipelineEventRetentionHours,
  n8nPostCommitUrl,
  n8nPostCommitToken,
  n8nPostCommitTimeoutMs,
  n8nPostCommitMaxAttempts,
  n8nPostCommitBaseRetrySeconds,
  aiAnalysisLeaseSeconds,
  pcapAnalysisWakePath,
  analystStatusReasonMaxLength,
  analystAdjudicationTextMaxLength,
} = runtimeConfiguration;
const runtimeFoundation = createRuntimeFoundationComposition({
  runtime: runtimeConfiguration,
  platform: {
    fs,
    path,
    processApi: process,
    sqlite3,
    crypto,
    createPostgresPool: (config) => {
      const {Pool} = require('pg');
      return new Pool(config);
    },
  },
  serialization: {
    nowUtc,
    normalizeTimestampValue,
    formatProjectTimestamp,
    parseProjectTimestamp,
  },
  normalization: {
    nestedField,
    integerField,
    nonNegativeIntegerField,
    normalizeTriageLevel,
    safeString,
    parseJsonObject,
  },
  network: {boundedRequestJson, isRelayHeartbeat},
});
const {
  alertGroupId,
  alertGroupKeySql,
  alertGroupService,
  allowedJournalModes,
  allowedSynchronousModes,
  allowedTempStoreModes,
  applicationLogger,
  beaconPersistence,
  diskWriteAdmission,
  enrichmentCache,
  enrichmentOrchestrator,
  enrichmentProviderClient,
  enrichmentScheduler,
  indicatorExtraction,
  notificationService,
  postRequestAdmission,
  postgresAuxiliaryStores,
  requestAuthorization,
  reviewerPolicy,
  scoringPolicy,
  serviceMetrics,
  severityRank,
  socAnalysisPolicy,
  sqliteBusyTimeoutMs,
  sqliteJournalMode,
  sqliteRuntime,
  sqliteSynchronous,
  sqliteTempStore,
  supportedAgentRoles,
  workerWakeSignaling,
} = runtimeFoundation;
const {
  reviewerAutomationAuthorization,
  conservativeReviewerTelemetry,
} = reviewerPolicy;
const {
  ruleName,
  findDropRule,
  suppressionKey,
  findSuppressRule,
  scoreAlert,
} = scoringPolicy;
const {
  extractAlertIndicators,
  hasUsableExternalIntel,
} = indicatorExtraction;
const {requestJson} = enrichmentProviderClient;
const {
  database: db,
  run,
  get,
  all,
  withWriteGate: withSqliteWriteGate,
  withImmediateTransaction,
} = sqliteRuntime;
const {
  queueTelegramNotification,
  drainTelegramOutbox,
  telegramOutboxSnapshot,
} = notificationService;
const {
  refreshGroupAliases,
  alertGroupKeyFromRow,
  currentAlertGroupKey,
  refreshAlertGroupSummary,
  rebuildAlertGroupSummariesUnlocked,
  rebuildAlertGroupSummaries,
} = alertGroupService;
const {
  enrichAlert,
  cachedInvestigationEnrichment,
  queryInvestigationEnrichment,
} = enrichmentOrchestrator;

function diskCapacitySnapshot(additionalBytes = 0) {
  return diskWriteAdmission.diskCapacitySnapshot(additionalBytes);
}

function assertDiskWriteAdmission(label, additionalBytes = maxRequestBytes) {
  return diskWriteAdmission.assertDiskWriteAdmission(label, additionalBytes);
}

async function signalWorker(wakePath, eventName) {
  return workerWakeSignaling.signalWorker(wakePath, eventName);
}

async function signalAiWorkers(eventName) {
  return workerWakeSignaling.signalAiWorkers(eventName);
}

function writeN8nBeacon(stage, alert = {}, result = null, error = null) {
  return beaconPersistence.writeBeacon(stage, alert, result, error);
}

const startupPersistenceCompatibility = createStartupPersistenceCompatibility({
  database: {
    db,
    run,
    all,
    withTransaction: withImmediateTransaction,
  },
  identity: {stableGroupKey, stableGroupId},
  serialization: {parseJsonObject},
});
const {
  ensureColumn,
  persistStableIdentity,
  backfillStableGroupIdentity,
} = startupPersistenceCompatibility;

async function authorizedCampaignForAlertId(alertId) {
  return authorizedCampaignPersistence.campaignForAlertId(alertId);
}

async function reconcileAuthorizedActivityBacklog() {
  return authorizedCampaignPersistence.reconcileBacklog();
}

async function indexAlertObservables(alert, row) {
  return authorizedCampaignPersistence.indexObservables(alert, row);
}

async function recordAiAnalysisResult(payload) {
  return aiAnalysisAcceptance.record(payload);
}

function validAnalystGroupId(value) {
  return analystReviewDefinitions.validAnalystGroupId(value);
}

function validIncidentCaseId(value) {
  return analystReviewDefinitions.validIncidentCaseId(value);
}

async function stableGroupHasPendingHumanReview(stableId) {
  return analystReviewProjection.pendingHumanReview(stableId);
}

async function analystAdjudicationSnapshot(searchParams) {
  return analystReviewProjection.adjudicationSnapshot(searchParams);
}

async function recordAnalystAdjudication(payload) {
  return analystDecisionPersistence.recordAdjudication(payload);
}

async function updateIncidentCaseStatus(payload) {
  return analystDecisionPersistence.updateIncidentCaseStatus(payload);
}

async function analystStatusSnapshot() {
  return analystDecisionPersistence.statusSnapshot();
}

async function updateAnalystStatus(payload) {
  return analystDecisionPersistence.updateStatus(payload);
}

const cohortIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const stableGroupIdPattern = /^[a-f0-9]{20}$/;
const dispatchIdPattern = /^[a-f0-9]{64}$/;
const releaseIdPattern = /^[a-f0-9]{40}$/;
const representativeAlertIdPattern = /^[A-Za-z0-9._:@=-]{1,256}$/;
const controlledRoutePattern = /^codex-cli:(?:gpt-5\.5|gpt-5\.6-(?:sol|terra|luna)):(?:low|medium|high|xhigh)$/;
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

function controlledRuntimeReleaseId() {
  const releaseId = process.env.ONION_SENTINEL_RELEASE_ID;
  return (
    typeof releaseId === 'string'
    && releaseIdPattern.test(releaseId)
  ) ? releaseId : '';
}

function manualDispatchIdentity(payload) {
  return manualDispatchIdentityOwner.normalize(payload);
}
async function resolveDashboardAlertGroup(dashboardGroupId, identity = {}) {
  return manualAnalysisDispatch.resolveDashboardAlertGroup(dashboardGroupId, identity);
}

async function requestAiReanalysis(payload) {
  return manualAnalysisDispatch.requestAiReanalysis(payload);
}

async function requestIncidentEscalation(payload) {
  return manualAnalysisDispatch.requestIncidentEscalation(payload);
}

async function queueIncidentResponseForGroup(options) {
  return manualAnalysisDispatch.queueIncidentResponseForGroup(options);
}

function incidentReanalysisReleaseId() {
  const candidate = safeString(
    process.env.ONION_SENTINEL_RELEASE_ID || 'unversioned',
    100,
  ).replace(/[^A-Za-z0-9._:-]+/g, '-').replace(/^-+|-+$/g, '');
  return candidate || 'unversioned';
}

async function drainEnrichmentJobs() {
  return durableBackgroundDrains.drainEnrichment();
}

function n8nPostCommitResult(body) {
  return durableBackgroundDrains.postCommitResult(body);
}

async function drainN8nPostCommitJobs() {
  return durableBackgroundDrains.drainPostCommit();
}

async function storeAlertUnlocked(alert) {
  return alertPersistence.store(alert);
}

async function applySuppressionPolicy(alert, now) {
  return suppressionPersistence.apply(alert, now);
}

const {
  pcapOutcomes,
  pcapCandidateFromRow,
  normalizePcapRequest,
  pcapRetentionError,
  pcapRequestFromRow,
  classifyPcapOutcome,
} = createPcapPolicy({
  safeString,
  parseJsonObject,
  nestedField,
  integerField,
  normalizeTimestampValue,
  defaultWindowSeconds: pcapRequestDefaultWindowSeconds,
  maxWindowSeconds: pcapRequestMaxWindowSeconds,
  captureRetentionSeconds: pcapCaptureRetentionSeconds,
});
const mutableRuntimeOwners = createMutableRuntimeOwners({
  database: {get, all, run, withWriteGate: withSqliteWriteGate},
  runtime: {
    nowUtc,
    aiAnalysisLeaseSeconds,
    postgresShadowEnabled,
    controlledEvaluationMode,
    postgresShadowBatchSize,
    diskCapacitySnapshot,
    pipelineEventRetentionHours,
    pcapClaimLeaseSeconds,
    pcapTransferMaxAttempts,
    pcapTransferMaxRetrySeconds,
  },
  pcap: {
    safeString,
    nonNegativeIntegerField,
    formatProjectTimestamp,
    pcapRequestFromRow,
    classifyPcapOutcome,
    pcapOutcomes,
  },
  platform: {
    env: process.env,
    console,
    createPostgresPool: (options) => {
      const {Pool} = require('pg');
      return new Pool(options);
    },
  },
});
const evidenceProcessing = createEvidenceProcessingComposition({
  database: {
    get,
    all,
    run,
    withWriteTransaction: (task) => (
      withSqliteWriteGate(() => withImmediateTransaction(task))
    ),
  },
  runtime: {
    pcapPriorityMaxWaitSeconds,
    pcapCaptureRetentionSeconds,
    enrichmentTimeoutMs,
    n8nPostCommitUrl,
    n8nPostCommitToken,
    n8nPostCommitTimeoutMs,
    n8nPostCommitBaseRetrySeconds,
  },
  policy: {
    pcapCandidateFromRow,
    normalizePcapRequest,
    pcapRetentionError,
    pcapRequestFromRow,
    classifyPcapOutcome,
    readCaptureLossThreshold: () => (
      socAnalysisPolicy.read().pcap_capture_loss_threshold_percent
    ),
    matchesAnalysis: (level) => socAnalysisPolicy.matchesAnalysis(level),
    severityRank,
    compactCorrelationCandidates,
    enrichmentRecord,
    groupKeyFromRow: alertGroupKeyFromRow,
    groupIdFromKey: alertGroupId,
    supportedAgentRoles,
  },
  services: {
    pipelineMetrics: mutableRuntimeOwners.pipelineMetrics,
    pcapTransferRepository: mutableRuntimeOwners.pcapTransferRepository,
    durableJobs: mutableRuntimeOwners.durableJobs,
    authorizedCampaignForAlertId,
    enrichAlert,
    indexAlertObservables,
    signalAiWorkers,
    requestJson,
  },
  serialization: {
    safeString,
    parseJsonObject,
    jsonText,
    canonicalJsonText,
    normalizeTimestampValue,
    nowUtc,
  },
});
const {
  aiReviewRepository,
  pcapRequestRepository,
  pcapAnalysisCompletion,
  durableBackgroundDrains,
} = evidenceProcessing;
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
    controlledEvaluationMode,
    runtimeReleaseId: runtimeReleaseIdValue,
    controlledRuntimeReleaseId,
    incidentReanalysisReleaseId,
    aiAnalysisLeaseSeconds,
    nowUtc,
    randomUuid: () => crypto.randomUUID(),
    sha256Text: (value) => crypto.createHash('sha256').update(value).digest('hex'),
    warn: (...args) => console.warn(...args),
  },
  durable: {
    available: () => Boolean(mutableRuntimeOwners.durableJobs()),
    owner: mutableRuntimeOwners.durableJobs,
    pipelineMetrics: mutableRuntimeOwners.pipelineMetrics,
    enqueue: (...args) => mutableRuntimeOwners.durableJobs().enqueue(...args),
    retirePendingExact: (options) => (
      mutableRuntimeOwners.durableJobs().retirePendingExact(options)
    ),
    reconcileAuthorizedActivity: reconcileAuthorizedActivityBacklog,
    recordMetric: (...args) => mutableRuntimeOwners.pipelineMetrics().record(...args),
    signalAiWorkers,
  },
  transaction: {
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
  },
  drains: {
    drainEnrichmentJobs: durableBackgroundDrains.drainEnrichment,
    drainPostCommitJobs: durableBackgroundDrains.drainPostCommit,
  },
  serialization: {
    parseJsonObject,
    jsonText,
    canonicalJsonText,
    parseProjectTimestamp,
    formatProjectTimestamp,
  },
});
const {
  incidentAnalysisCompletion,
  incidentReanalysisBindingService,
  incidentReanalysisJobOwnership,
  incidentReanalysisRecovery,
  manualAnalysisDispatch,
  manualDispatchIdentityOwner,
} = controlledIncident;
const aiAnalysisAcceptance = evidenceProcessing.createAiAcceptance({
  bindingAuthority: incidentReanalysisBindingService.bindingAuthority,
  analysisCompletion: incidentAnalysisCompletion,
});
const applicationRuntimePorts = createApplicationRuntimePorts({
  mutable: mutableRuntimeOwners,
  domain: {
    enrichmentCache,
    pcapRequestRepository,
    resolveDashboardAlertGroup,
    randomUUID: crypto.randomUUID,
    rebuildGroupSummariesUnlocked: rebuildAlertGroupSummariesUnlocked,
    queueIncidentResponseForGroup,
    persistStableIdentity,
    refreshGroupSummary: refreshAlertGroupSummary,
    queueNotification: queueTelegramNotification,
    signalAiWorkers,
    drainNotificationOutbox: drainTelegramOutbox,
    drainEnrichmentJobs,
    drainPostCommitJobs: drainN8nPostCommitJobs,
  },
  lifecycle: {
    reconcileRecoveredIncidentAttempts: incidentReanalysisRecovery.reconcile,
    backfillStableGroupIdentity,
    rebuildAlertGroupSummaries,
    refreshGroupAliases,
  },
});
const applicationOwners = createApplicationComposition({
  database: {
    get,
    all,
    run,
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
    ensureColumn,
  },
  schema: {
    controlledEvaluationMode,
    sqliteBusyTimeoutMs,
    allowedJournalModes,
    sqliteJournalMode,
    allowedSynchronousModes,
    sqliteSynchronous,
    allowedTempStoreModes,
    sqliteTempStore,
    alertGroupKeySql,
  },
  policy: {
    authorizedActivityPolicy,
    matchAuthorizedActivity,
    integerField,
    stableGroupKey,
    stableGroupId,
    buildAlertObservables,
    extractAlertIndicators,
    createAnalystReviewProjection: analystReviewDefinitions.createAnalystReviewProjection,
    safeString,
    conservativeReviewerTelemetry,
    reviewerAutomationAuthorization,
    reviewerFailureStatuses,
    validAnalystGroupId,
    validIncidentCaseId,
    analystAdjudicationOutcomes,
    analystAdjudicationConfidences,
    analystEventStatuses,
    analystDetectionValidities,
    analystActivityDispositions,
    analystHandlingValues,
    analystVerdictContradictions,
    analystAdjudicationTextMaxLength,
    analystStatusReasonMaxLength,
    findSuppressRule,
    nestedField,
    suppressionKey,
    ruleName,
    scoreAlert,
    enrichmentRecord,
    scoringRulesName: path.basename(scoringRulesPath),
    readSocAnalysisPolicy: () => socAnalysisPolicy.read(),
    matchesPcap: (level) => socAnalysisPolicy.matchesPcap(level),
    matchesIncident: (level) => socAnalysisPolicy.matchesIncident(level),
    matchesAnalysis: (level) => socAnalysisPolicy.matchesAnalysis(level),
    groupKeyFromRow: alertGroupKeyFromRow,
    groupIdFromKey: alertGroupId,
    currentGroupKey: currentAlertGroupKey,
    findDropRule,
    pcapRequestDefaultWindowSeconds,
    severityRank,
    postCommitMaxAttempts: n8nPostCommitMaxAttempts,
    hasUsableExternalIntel,
    enrichmentMaxAttempts: enrichmentWorkerMaxAttempts,
  },
  services: applicationRuntimePorts.services,
  lifecycle: applicationRuntimePorts.lifecycle,
  serialization: {nowUtc, parseJsonObject, jsonText, normalizeTimestampValue},
});
const {
  aiReviewSchema,
  alertPersistence,
  alertStoreSchemaFoundation,
  analystDecisionPersistence,
  analystReviewProjection,
  authorizedCampaignPersistence,
  incidentAnalysisSchema,
  notificationEnrichmentSchema,
  pcapSchema,
  startupPersistenceOrchestrator,
  suppressionPersistence,
} = applicationOwners;
const initDb = startupPersistenceCompatibility.createSchemaInitializer({
  alertStoreSchemaFoundation,
  incidentAnalysisSchema,
  aiReviewSchema,
  notificationEnrichmentSchema,
  pcapSchema,
  startupPersistenceOrchestrator,
});
const httpApplicationRuntime = createHttpApplicationRuntime({
  runtime: runtimeConfiguration,
  platform: {
    httpCreateServer: (listener) => require('http').createServer(listener),
    processLike: process,
    consoleLike: console,
    dateNow: Date.now,
    randomUUID: crypto.randomUUID,
    monotonicNow: process.hrtime.bigint,
    setIntervalFn: setInterval,
    setTimeoutFn: setTimeout,
  },
  database: {
    db,
    get,
    all,
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
    sqliteRuntime,
  },
  foundation: runtimeFoundation,
  application: applicationOwners,
  controlled: controlledIncident,
  evidence: {...evidenceProcessing, aiAnalysisAcceptance},
  mutable: mutableRuntimeOwners,
  startup: {initDb},
  serialization: {
    nowUtc,
    safeString,
    isRelayHeartbeat,
    incidentIdentityConflict,
    requestHasOwnField,
  },
});

httpApplicationRuntime.run();
