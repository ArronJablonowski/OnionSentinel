'use strict';

const {createControlledJobIdentity} = require('../lib/controlled_job_identity');
const controlledRetirementDefinitions = require('../lib/controlled_retirement_identity');
const {createControlledRetirementProjections} = require('../lib/controlled_retirement_projections');
const {createManualDispatchIdentity} = require('../lib/manual_dispatch_identity');
const {createControlledJobTransition} = require('../services/controlled_job_transition');
const {createControlledResultAdmission} = require('../services/controlled_result_admission');
const {createDurableJobRecovery} = require('../services/durable_job_recovery');
const {
  createDurableJobTransitionExecutor,
} = require('../services/durable_job_transition_executor');
const {
  createControlledRetirementCompletedMember,
} = require('../services/controlled_retirement_completed_member');
const {
  createControlledRetirementTargetMember,
} = require('../services/controlled_retirement_target_member');
const {
  createControlledRetirementCensus,
} = require('../services/controlled_retirement_census');
const {
  createControlledRetirementReplay,
} = require('../services/controlled_retirement_replay');
const {
  createControlledRetirementCommand,
} = require('../services/controlled_retirement_command');
const {
  createIncidentReanalysisFrozenDispatch,
} = require('../services/incident_reanalysis_frozen_dispatch');
const {
  createAlertGroupAliasResolution,
} = require('../services/alert_group_alias_resolution');
const {
  createIncidentDurableJobPersistence,
} = require('../services/incident_durable_job_persistence');
const {
  createIncidentReanalysisRequest,
} = require('../services/incident_reanalysis_request');
const {
  createIncidentReanalysisJobOwnership,
} = require('../services/incident_reanalysis_job_ownership');
const {
  createIncidentReanalysisAttemptLifecycle,
} = require('../services/incident_reanalysis_attempt_lifecycle');
const {
  createIncidentReanalysisRecovery,
} = require('../services/incident_reanalysis_recovery');
const {
  createIncidentReanalysisRunPersistence,
} = require('../services/incident_reanalysis_run_persistence');
const {createIncidentAnalysisCompletion} = require('../services/incident_analysis_completion');
const {
  createIncidentReanalysisBindingService,
} = require('../services/incident_reanalysis_binding');
const {createManualAnalysisDispatch} = require('../services/manual_analysis_dispatch');

function requireSection(options, name) {
  const section = options && options[name];
  if (!section || typeof section !== 'object') {
    throw new Error(`${name} controlled incident composition section is required`);
  }
  return section;
}

function createControlledIncidentComposition(options = {}) {
  const persistence = requireSection(options, 'persistence');
  const identity = requireSection(options, 'identity');
  const runtime = requireSection(options, 'runtime');
  const durable = requireSection(options, 'durable');
  const transaction = requireSection(options, 'transaction');
  const drains = requireSection(options, 'drains');
  const serialization = requireSection(options, 'serialization');
  const {get, all, run} = persistence;
  const {
    safeString,
    validCaseId,
    validPinnedStableGroupKey,
    stableGroupIdPattern,
    representativeAlertIdPattern,
    dispatchIdPattern,
    cohortIdPattern,
    releaseIdPattern,
    controlledRoutePattern,
    controlledRouteModelIdentity,
    requestHasOwnField,
    identityConflict,
  } = identity;
  const {
    controlledEvaluationMode,
    runtimeReleaseId,
    controlledRuntimeReleaseId,
    incidentReanalysisReleaseId,
    aiAnalysisLeaseSeconds,
    nowUtc,
    randomUuid,
    sha256Text,
  } = runtime;
  const {parseJsonObject, jsonText, canonicalJsonText} = serialization;

  const incidentReanalysisRunPersistence = createIncidentReanalysisRunPersistence({
    get, all, run, nowUtc,
  });
  const incidentReanalysisJobOwnership = createIncidentReanalysisJobOwnership({
    safeString,
    validCaseId,
    get,
    all,
    run,
    nowUtc,
    sha256Text,
    refreshRun: incidentReanalysisRunPersistence.refresh,
  });
  const incidentReanalysisAttemptLifecycle = createIncidentReanalysisAttemptLifecycle({
    jobPayload: incidentReanalysisJobOwnership.jobPayload,
    safeString,
    validCaseId,
    attemptId: incidentReanalysisJobOwnership.attemptId,
    closeStale: incidentReanalysisJobOwnership.closeStale,
    get,
    run,
    nowUtc,
    refreshRun: incidentReanalysisRunPersistence.refresh,
  });
  const incidentReanalysisRecovery = createIncidentReanalysisRecovery({
    durableJobsAvailable: durable.available,
    all,
    get,
    run,
    retireCompleted: incidentReanalysisJobOwnership.retireCompleted,
    retireSuperseded: incidentReanalysisJobOwnership.retireSuperseded,
    attemptId: incidentReanalysisJobOwnership.attemptId,
    beginAttempt: incidentReanalysisAttemptLifecycle.begin,
    safeString,
    jobPayload: incidentReanalysisJobOwnership.jobPayload,
    validCaseId,
    nowUtc,
    refreshRun: incidentReanalysisRunPersistence.refresh,
  });
  const incidentReanalysisBindingService = createIncidentReanalysisBindingService({
    get,
    run,
    safeString,
    parseProjectTimestamp: serialization.parseProjectTimestamp,
    formatProjectTimestamp: serialization.formatProjectTimestamp,
    nowUtc,
    incidentAnalysisProvider: incidentReanalysisJobOwnership.analysisProvider,
    refreshIncidentReanalysisRun: incidentReanalysisRunPersistence.refresh,
  });
  const incidentAnalysisCompletion = createIncidentAnalysisCompletion({
    get,
    run,
    safeString,
    jsonText,
    nowUtc,
    bindIncidentReanalysisResult: incidentReanalysisBindingService.bindResult,
  });

  const controlledJobIdentity = createControlledJobIdentity({
    requestHasOwnField,
    identityConflict,
    validPinnedStableGroupKey,
    representativeAlertIdPattern,
    dispatchIdPattern,
    controlledRoutePattern,
    controlledRouteModelIdentity,
  });
  const controlledJobTransitionAuthority = createControlledJobTransition({
    controlledEvaluationMode,
    safeString,
    identityConflict,
    stableGroupIdPattern,
    parseClaimIdentity: controlledJobIdentity.parseClaim,
    all,
    get,
    incidentReanalysisJobPayload: incidentReanalysisJobOwnership.jobPayload,
    validPinnedStableGroupKey,
    cohortIdPattern,
    dispatchIdPattern,
    representativeAlertIdPattern,
    controlledRuntimeReleaseId,
    controlledRoutePattern,
    controlledRouteModelIdentity,
    incidentReanalysisAttemptId: incidentReanalysisJobOwnership.attemptId,
  });
  const controlledEvaluationLeases = controlledJobTransitionAuthority.leases;
  const controlledResultAdmissionAuthority = createControlledResultAdmission({
    controlledEvaluationMode,
    safeString,
    identityConflict,
    claimLeaseKey: controlledJobTransitionAuthority.leaseKey,
    get,
    incidentReanalysisJobPayload: incidentReanalysisJobOwnership.jobPayload,
    parseJsonObject,
    canonicalJsonText,
    controlledRoutePattern,
    controlledRouteModelIdentity,
    cohortIdPattern,
    dispatchIdPattern,
    representativeAlertIdPattern,
    stableGroupIdPattern,
    validPinnedStableGroupKey,
    releaseIdPattern,
    runtimeReleaseId,
    incidentReanalysisAttemptId: incidentReanalysisJobOwnership.attemptId,
    retireLease: controlledJobTransitionAuthority.retireLease,
  });
  const durableJobRecovery = createDurableJobRecovery({
    durableJobs: durable.owner,
    withWriteGate: transaction.withWriteGate,
    withTransaction: transaction.withTransaction,
    reconcileIncidentAttempts: incidentReanalysisRecovery.reconcile,
    reconcileAuthorizedActivity: durable.reconcileAuthorizedActivity,
    nowUtc,
    warn: runtime.warn,
    signalAiWorkers: durable.signalAiWorkers,
    drainEnrichmentJobs: drains.drainEnrichmentJobs,
    drainPostCommitJobs: drains.drainPostCommitJobs,
  });
  const durableJobTransitionExecutor = createDurableJobTransitionExecutor({
    controlledEvaluationMode,
    parseClaimIdentity: controlledJobIdentity.parseClaim,
    stableGroupIdPattern,
    identityConflict,
    get,
    run,
    safeString,
    incidentReanalysisJobPayload: incidentReanalysisJobOwnership.jobPayload,
    controlledRuntimeReleaseId,
    incidentReanalysisAttemptId: incidentReanalysisJobOwnership.attemptId,
    aiAnalysisLeaseSeconds,
    nowUtc,
    durableJobs: durable.owner,
    pipelineMetrics: durable.pipelineMetrics,
    retireCompletedIncidentReanalysisJob: incidentReanalysisJobOwnership.retireCompleted,
    retireSupersededIncidentReanalysisJob: incidentReanalysisJobOwnership.retireSuperseded,
    updateIncidentReanalysisProgress: incidentReanalysisAttemptLifecycle.update,
    signalAiWorkers: durable.signalAiWorkers,
  });

  const retirementIdentity = controlledRetirementDefinitions.createControlledRetirementIdentity({
    controlledEvaluationMode,
    safeString,
    validIncidentCaseId: validCaseId,
    cohortIdPattern,
    dispatchIdPattern,
    releaseIdPattern,
    representativeAlertIdPattern,
    stableGroupIdPattern,
    validPinnedStableGroupKey,
    controlledRuntimeReleaseId,
  });
  const retirementProjections = createControlledRetirementProjections({
    rawSha256: retirementIdentity.rawSha256,
    sha256: retirementIdentity.sha256,
    safeString,
    parseTimestamp: serialization.parseProjectTimestamp,
  });
  const completedMember = createControlledRetirementCompletedMember({
    all,
    get,
    parseJsonObject,
    incidentAnalysisProvider: incidentReanalysisJobOwnership.analysisProvider,
    completedJobLifecycleValid: retirementProjections.completedLifecycleValid,
    projectCompleted: retirementProjections.completed,
    conflict: retirementIdentity.conflict,
  });
  const targetMember = createControlledRetirementTargetMember({
    all,
    safeString,
    projectJob: retirementProjections.job,
    projectRun: retirementProjections.run,
    projectRunCase: retirementProjections.runCase,
    projectAttempt: retirementProjections.attempt,
    projectError: retirementProjections.error,
    rawSha256: retirementIdentity.rawSha256,
    conflict: retirementIdentity.conflict,
  });
  const census = createControlledRetirementCensus({
    all,
    orderedDispatches: retirementProjections.orderedDispatches,
    parseJobPayload: incidentReanalysisJobOwnership.jobPayload,
    validIncidentCaseId: validCaseId,
    stableGroupIdPattern,
    validPinnedStableGroupKey,
    representativeAlertIdPattern,
    parseJsonObject,
    projectCompleted: completedMember.project,
    projectTarget: targetMember.project,
    conflict: retirementIdentity.conflict,
  });
  const replay = createControlledRetirementReplay({
    all,
    get,
    eventType: controlledRetirementDefinitions.EVENT_TYPE,
    receiptFields: controlledRetirementDefinitions.RECEIPT_FIELDS,
    receiptSchema: controlledRetirementDefinitions.RECEIPT_SCHEMA,
    dispatchIdPattern,
    parseJsonObject,
    canonicalJsonText: retirementIdentity.canonicalJsonText,
    sha256: retirementIdentity.sha256,
    projectJob: retirementProjections.job,
    projectCensus: census.project,
    conflict: retirementIdentity.conflict,
  });
  const controlledRetirementCommandOwner = createControlledRetirementCommand({
    normalizeIdentity: retirementIdentity.normalize,
    sha256: retirementIdentity.sha256,
    replay: replay.replay,
    validatePostState: replay.validatePostState,
    projectCensus: census.project,
    get,
    all,
    run,
    parseJobPayload: incidentReanalysisJobOwnership.jobPayload,
    projectJob: retirementProjections.job,
    parseJsonObject,
    leaseKey: controlledJobTransitionAuthority.leaseKey,
    hasLease: (key) => controlledEvaluationLeases.has(key),
    nowUtc,
    retirePendingExact: durable.retirePendingExact,
    refreshRun: incidentReanalysisRunPersistence.refresh,
    receiptSchema: controlledRetirementDefinitions.RECEIPT_SCHEMA,
    eventType: controlledRetirementDefinitions.EVENT_TYPE,
    canonicalJsonText: retirementIdentity.canonicalJsonText,
    validateReceipt: replay.validateReceipt,
    conflict: retirementIdentity.conflict,
  });

  const manualDispatchIdentityOwner = createManualDispatchIdentity({
    hasOwnField: requestHasOwnField,
    stableGroupIdPattern,
    validPinnedStableGroupKey,
    cohortIdPattern,
    dispatchIdPattern,
    releaseIdPattern,
    controlledRoutePattern,
    controlledRouteModelIdentity,
    representativeAlertIdPattern,
    runtimeReleaseId: controlledRuntimeReleaseId,
    conflict: identityConflict,
  });
  const incidentDurableJobPersistence = createIncidentDurableJobPersistence({
    get, run, conflict: identityConflict,
  });
  const manualAnalysisDispatch = createManualAnalysisDispatch({
    get,
    run,
    safeString,
    normalizeIdentity: manualDispatchIdentityOwner.normalize,
    conflict: identityConflict,
    rejectProcessingJob: incidentDurableJobPersistence.rejectProcessing,
    enqueueJob: durable.enqueue,
    recordMetric: durable.recordMetric,
    nowUtc,
    jsonText,
    sha256Text,
  });
  const alertGroupAliasResolution = createAlertGroupAliasResolution({
    all, conflict: identityConflict,
  });
  const frozenDispatch = createIncidentReanalysisFrozenDispatch({
    get,
    all,
    run,
    parseJsonObject,
    loadAliases: alertGroupAliasResolution.loadSnapshot,
    resolveCanonicalIdentity: alertGroupAliasResolution.resolve,
    rejectProcessingJob: incidentDurableJobPersistence.rejectProcessing,
    jsonText,
    conflict: identityConflict,
  });
  const incidentReanalysisRequestOwner = createIncidentReanalysisRequest({
    validCaseId,
    normalizeIdentity: manualDispatchIdentityOwner.normalize,
    controlledEvaluationMode,
    safeString,
    replayFrozen: (...args) => frozenDispatch.replay(...args),
    bindFrozen: (...args) => frozenDispatch.bind(...args),
    releaseId: incidentReanalysisReleaseId,
    nowUtc,
    randomUuid,
    all,
    get,
    run,
    supersedeCase: incidentReanalysisRunPersistence.supersedeCase,
    retirePendingJobs: incidentDurableJobPersistence.retirePendingIncident,
    enqueueJob: durable.enqueue,
    jsonText,
    recordMetric: durable.recordMetric,
    refreshRun: incidentReanalysisRunPersistence.refresh,
    conflict: identityConflict,
  });

  return {
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
  };
}

module.exports = {createControlledIncidentComposition};
