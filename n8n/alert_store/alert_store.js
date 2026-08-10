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
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {createRequestDispatcher} = require('./lib/http_dispatch');
const analystReviewDefinitions = require('./services/analyst_review_projection');
const {createServiceRuntimeLifecycle} = require('./services/service_runtime_lifecycle');
const {createHttpRequestBoundary} = require('./services/http_request_boundary');
const {createRouteComposition} = require('./composition/route_composition');
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
const {configureHttpServer, readJsonObject} = require('./lib/http_runtime');
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
  host,
  port,
  postgresShadowEnabled,
  postgresShadowIntervalMs,
  postgresShadowBatchSize,
  assetPostgresEnabled,
  softwarePostgresEnabled,
  acHunterPostgresEnabled,
  controlledEvaluationMode,
  runtimeReleaseIdValue,
  maxRequestBytes,
  httpRequestTimeoutMs,
  httpHeadersTimeoutMs,
  httpKeepAliveTimeoutMs,
  httpMaxRequestsPerSocket,
  httpMaxConnections,
  telegramOutboxIntervalMs,
  telegramOutboxAutostart,
  enrichmentCacheCleanupIntervalMs,
  enrichmentTimeoutMs,
  enrichmentWorkerIntervalMs,
  enrichmentWorkerMaxAttempts,
  pcapRequestMaxWindowSeconds,
  pcapRequestDefaultWindowSeconds,
  pcapClaimLeaseSeconds,
  pcapCaptureRetentionSeconds,
  pcapPriorityMaxWaitSeconds,
  pcapTransferMaxAttempts,
  pcapTransferMaxRetrySeconds,
  pipelineEventRetentionHours,
  pipelineDiskSampleIntervalMs,
  n8nPostCommitUrl,
  n8nPostCommitToken,
  n8nPostCommitIntervalMs,
  n8nPostCommitTimeoutMs,
  n8nPostCommitMaxAttempts,
  n8nPostCommitBaseRetrySeconds,
  durableJobRecoveryIntervalMs,
  aiAnalysisLeaseSeconds,
  pcapAnalysisWakePath,
  analystStatusReasonMaxLength,
  analystAdjudicationTextMaxLength,
} = runtimeConfiguration;
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
} = createRuntimeFoundationComposition({
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

async function storeAlert(rawAlert) {
  return alertIngestOrchestrator.store(rawAlert);
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

async function rescoreAlertsUnlocked() {
  return rescorePersistence.rescore();
}

async function rescoreAlerts() {
  // Maintenance writes must not interleave with multi-statement ingestion.
  return withSqliteWriteGate(rescoreAlertsUnlocked);
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
const {
  controlledEvaluationLeases,
  controlledJobTransitionAuthority,
  controlledResultAdmissionAuthority,
  controlledRetirementCommandOwner,
  durableJobRecovery,
  durableJobTransitionExecutor,
  incidentAnalysisCompletion,
  incidentReanalysisBindingService,
  incidentReanalysisJobOwnership,
  incidentReanalysisRecovery,
  incidentReanalysisRequestOwner,
  manualAnalysisDispatch,
  manualDispatchIdentityOwner,
} = createControlledIncidentComposition({
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
const aiAnalysisAcceptance = evidenceProcessing.createAiAcceptance({
  bindingAuthority: incidentReanalysisBindingService.bindingAuthority,
  analysisCompletion: incidentAnalysisCompletion,
});
const {
  aiReviewSchema,
  alertIngestOrchestrator,
  alertPersistence,
  alertStoreSchemaFoundation,
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
} = createApplicationComposition({
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
  services: {
    installEnrichmentCache: () => enrichmentCache.install(),
    backfillPcapOutcomes: () => pcapRequestRepository.backfillOutcomes(),
    completePendingJobs: (...args) => (
      mutableRuntimeOwners.durableJobs().completePendingByDedupeKeys(...args)
    ),
    resolveDashboardAlertGroup,
    randomUUID: crypto.randomUUID,
    rebuildGroupSummaries: rebuildAlertGroupSummariesUnlocked,
    createPcapRequest: (...args) => pcapRequestRepository.createRequest(...args),
    queueIncidentResponseForGroup,
    persistStableIdentity,
    refreshGroupSummary: refreshAlertGroupSummary,
    queueNotification: queueTelegramNotification,
    enqueueJob: (...args) => mutableRuntimeOwners.durableJobs().enqueue(...args),
    recordMetric: (...args) => mutableRuntimeOwners.pipelineMetrics().record(...args),
    signalAiWorkers,
    drainNotificationOutbox: drainTelegramOutbox,
    drainEnrichmentJobs,
    drainPostCommitJobs: drainN8nPostCommitJobs,
  },
  lifecycle: {
    initializeDurableJobs: mutableRuntimeOwners.initializeDurableJobs,
    installDurableJobs: () => mutableRuntimeOwners.durableJobs().install(),
    initializePostgresShadowOutbox: mutableRuntimeOwners.initializePostgresShadowOutbox,
    installPostgresShadowOutbox: () => mutableRuntimeOwners.postgresShadowOutbox().install(),
    initializePostgresShadowProjector: mutableRuntimeOwners.initializePostgresShadowProjector,
    reconcileRecoveredIncidentAttempts: incidentReanalysisRecovery.reconcile,
    initializePipelineMetrics: mutableRuntimeOwners.initializePipelineMetrics,
    installPipelineMetrics: () => mutableRuntimeOwners.pipelineMetrics().install(),
    backfillStableGroupIdentity,
    rebuildAlertGroupSummaries,
    refreshGroupAliases,
  },
  serialization: {nowUtc, parseJsonObject, jsonText, normalizeTimestampValue},
});
const initDb = startupPersistenceCompatibility.createSchemaInitializer({
  alertStoreSchemaFoundation,
  incidentAnalysisSchema,
  aiReviewSchema,
  notificationEnrichmentSchema,
  pcapSchema,
  startupPersistenceOrchestrator,
});
async function maybeQueueAutomaticPcapRequest(alert, storedRow, inserted, suppression, campaign = null) {
  return automaticResponseRouting.queuePcap(
    alert, storedRow, inserted, suppression, campaign,
  );
}

async function maybeQueueAutomaticIncidentResponse(alert, storedRow, inserted, suppression, campaign = null) {
  return automaticResponseRouting.queueIncident(
    alert, storedRow, inserted, suppression, campaign,
  );
}

function readJsonBody(request, includeBodySha256 = false) {
  return readJsonObject(request, {
    maxBytes: maxRequestBytes,
    includeBodySha256,
  });
}

function sendJson(response, code, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  });
  response.end(body);
}

async function capturePipelineDiskSample() {
  const pipelineMetrics = mutableRuntimeOwners.pipelineMetrics();
  if (!pipelineMetrics) return;
  const pageCount = await get('PRAGMA page_count');
  const pageSize = await get('PRAGMA page_size');
  const sqliteBytes = Number(pageCount?.page_count || 0) * Number(pageSize?.page_size || 0);
  await withSqliteWriteGate(() => pipelineMetrics.captureDiskSample(sqliteBytes));
}

const controlledEvaluationRequests = new Set([
  'GET /health',
  'POST /ai/request',
  'POST /analysis/result',
  'POST /controlled-evaluations/retire',
  'POST /incidents/reanalyze',
  'POST /jobs/status',
]);

const modularRoutes = createRouteComposition({
  http: {readJsonBody, sendJson},
  transaction: {
    withWriteGate: withSqliteWriteGate,
    withTransaction: withImmediateTransaction,
  },
  inventory: {
    requireAcHunterStore: postgresAuxiliaryStores.requireAcHunterStore,
    requireSoftwareStore: postgresAuxiliaryStores.requireSoftwareStore,
    requireAssetStore: postgresAuxiliaryStores.requireAssetStore,
    authorizeWrite: requestAuthorization.requireAssetWrite,
  },
  health: {
    get,
    all,
    runtime: () => ({
      controlledEvaluationMode,
      controlledEvaluationLeases,
      controlledRoutes: controlledEvaluationRequests,
      runtimeReleaseId: runtimeReleaseIdValue,
      host,
      port,
      activeSqliteWrites: sqliteRuntime.activeWrites(),
      telegramOutboxSnapshot,
      enrichmentScheduler,
      enrichmentCache,
      authorizedActivityPolicyPath,
      authorizedActivityPolicyCount: authorizedActivityPolicy.policies.length,
      authorizedCampaignReconciliation: authorizedCampaignPersistence.reconciliationState(),
      diskCapacitySnapshot,
      ...mutableRuntimeOwners.snapshot(),
      postgresShadowEnabled,
      ...postgresAuxiliaryStores.state(),
      serviceMetrics,
      postRequestAdmission,
      nowUtc,
    }),
  },
  analystState: {
    analystStatusSnapshot,
    updateAnalystStatus,
    analystAdjudicationSnapshot,
    recordAnalystAdjudication,
    updateIncidentCaseStatus,
  },
  durableJob: {
    safeString,
    controlledTransitionAdmission: controlledJobTransitionAuthority.admit,
    transitionJobStatus: durableJobTransitionExecutor.transition,
    applyControlledTransition: controlledJobTransitionAuthority.apply,
    completePendingByDedupeKeys: (...args) => (
      mutableRuntimeOwners.durableJobs().completePendingByDedupeKeys(...args)
    ),
  },
  analysisRequest: {
    controlledEvaluationMode: () => controlledEvaluationMode,
    identityConflict: incidentIdentityConflict,
    requestAiReanalysis,
    requestIncidentEscalation,
    requestIncidentReanalysis: incidentReanalysisRequestOwner.request,
    retireControlledEvaluation: controlledRetirementCommandOwner.retire,
    signalAiWorkers,
  },
  analysisResult: {
    controlledEvaluationMode: () => controlledEvaluationMode,
    requestHasOwnField,
    identityConflict: incidentIdentityConflict,
    controlledResultAdmission: controlledResultAdmissionAuthority.admit,
    recordAnalysisResult: recordAiAnalysisResult,
    transitionJobStatus: durableJobTransitionExecutor.transition,
    applyControlledResultAdmission: controlledResultAdmissionAuthority.apply,
  },
  pcap: {
    createRequest: (...args) => pcapRequestRepository.createRequest(...args),
    listRequests: (...args) => pcapRequestRepository.listRequests(...args),
    claimRequest: (...args) => mutableRuntimeOwners.pcapTransferRepository().claimRequest(...args),
    completeRequest: (...args) => mutableRuntimeOwners.pcapTransferRepository().completeRequest(...args),
    updateTransferProgress: (...args) => (
      mutableRuntimeOwners.pcapTransferRepository().updateTransferProgress(...args)
    ),
    retryRequest: (...args) => mutableRuntimeOwners.pcapTransferRepository().retryRequest(...args),
    completeAnalysis: (...args) => pcapAnalysisCompletion.complete(...args),
    requeueRequests: (...args) => pcapRequestRepository.requeueRequests(...args),
    signalPcapWorker: (reason) => signalWorker(pcapAnalysisWakePath, reason),
    signalAiWorkers,
  },
  enrichment: {
    assertDiskWriteAdmission,
    enrichAlert,
    cachedInvestigationEnrichment,
    queryInvestigationEnrichment,
    authorizeInvestigation: requestAuthorization.requireAssetWrite,
  },
  maintenance: {rescore: rescoreAlerts, refreshGroups: rebuildAlertGroupSummaries},
  alertIngest: {
    metrics: serviceMetrics,
    now: Date.now,
    readJsonBody,
    writeBeacon: writeN8nBeacon,
    isRelayHeartbeat,
    assertDiskWriteAdmission,
    storeAlert,
  },
});

function controlledEvaluationRequestAuthorized(request) {
  return requestAuthorization.controlledEvaluationAuthorized(request);
}

const httpRequestBoundary = createHttpRequestBoundary({
  controlledEvaluationMode,
  controlledRequests: controlledEvaluationRequests,
  isShutdownStarted: () => serviceRuntimeLifecycle.isShutdownStarted(),
  controlledRequestAuthorized: controlledEvaluationRequestAuthorized,
  routeRegistry: modularRoutes,
  sendJson,
  serviceMetrics,
  writeBeacon: writeN8nBeacon,
});

async function handleRequest(request, response) {
  return httpRequestBoundary.handle(request, response);
}

const dispatchRequest = createRequestDispatcher({
  handleRequest,
  postRequestAdmission,
  logger: applicationLogger,
  sendJson,
  randomUUID: crypto.randomUUID,
  monotonicNow: process.hrtime.bigint,
});

const serviceRuntimeLifecycle = createServiceRuntimeLifecycle({
  initDb,
  initializePostgresAssetStore: postgresAuxiliaryStores.initializeAssetStore,
  initializePostgresSoftwareStore: postgresAuxiliaryStores.initializeSoftwareStore,
  initializePostgresAcHunterStore: postgresAuxiliaryStores.initializeAcHunterStore,
  getPostgresStoreState: () => postgresAuxiliaryStores.state(),
  applicationLogger,
  databaseLogFields: {
    database_path: dbPath,
    postgres_shadow_enabled: postgresShadowEnabled,
    asset_postgres_enabled: assetPostgresEnabled,
    software_postgres_enabled: softwarePostgresEnabled,
    ac_hunter_postgres_enabled: acHunterPostgresEnabled,
  },
  httpCreateServer: (listener) => http.createServer(listener),
  configureHttpServer,
  dispatchRequest,
  sendJson,
  httpConfiguration: {
    requestTimeoutMs: httpRequestTimeoutMs,
    headersTimeoutMs: httpHeadersTimeoutMs,
    keepAliveTimeoutMs: httpKeepAliveTimeoutMs,
    maxRequestsPerSocket: httpMaxRequestsPerSocket,
    maxConnections: httpMaxConnections,
  },
  host,
  port,
  dbPath,
  controlledEvaluationMode,
  processLike: process,
  consoleLike: console,
  database: db,
  waitForSqliteWrites: () => sqliteRuntime.waitForWrites(),
  getActiveSqliteWrites: () => sqliteRuntime.activeWrites(),
  setIntervalFn: setInterval,
  setTimeoutFn: setTimeout,
  workers: {
    telegram: {
      enabled: telegramOutboxAutostart,
      intervalMs: telegramOutboxIntervalMs,
      drain: drainTelegramOutbox,
    },
    enrichment: {intervalMs: enrichmentWorkerIntervalMs, drain: drainEnrichmentJobs},
    enrichmentCache: {intervalMs: enrichmentCacheCleanupIntervalMs, prune: () => enrichmentCache.prune()},
    n8nPostCommit: {intervalMs: n8nPostCommitIntervalMs, drain: drainN8nPostCommitJobs},
    durableRecovery: {intervalMs: durableJobRecoveryIntervalMs, recover: durableJobRecovery.recover},
    pipelineDisk: {intervalMs: pipelineDiskSampleIntervalMs, capture: capturePipelineDiskSample},
    postgresShadow: {
      enabled: () => Boolean(mutableRuntimeOwners.postgresShadowProjector()),
      intervalMs: postgresShadowIntervalMs,
      drain: () => mutableRuntimeOwners.postgresShadowProjector().drain(),
    },
    pipelineMetrics: {
      intervalMs: 60 * 60 * 1000,
      prune: () => mutableRuntimeOwners.pipelineMetrics().prune(),
      withWriteGate: withSqliteWriteGate,
    },
  },
});

serviceRuntimeLifecycle.run();
