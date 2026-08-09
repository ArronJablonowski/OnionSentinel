'use strict';

const crypto = require('crypto');

const EXPECTED_IDENTITY_FIELDS = Object.freeze([
  'job_id', 'job_type', 'lease_token', 'cohort_id', 'dispatch_id',
  'representative_alert_id', 'stable_group_id', 'stable_group_key',
  'agent_role', 'reanalysis_attempt_id', 'release_id',
  'expected_assigned_route', 'expected_reviewer_route', 'reviewer_required',
]);

function createControlledResultAdmission({
  controlledEvaluationMode,
  safeString,
  identityConflict,
  claimLeaseKey,
  get,
  incidentReanalysisJobPayload,
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
  incidentReanalysisAttemptId,
  retireLease,
}) {
  for (const [name, value] of Object.entries({
    safeString, identityConflict, claimLeaseKey, get, incidentReanalysisJobPayload,
    parseJsonObject, canonicalJsonText, controlledRouteModelIdentity,
    validPinnedStableGroupKey, incidentReanalysisAttemptId, retireLease,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  for (const [name, value] of Object.entries({
    controlledRoutePattern, cohortIdPattern, dispatchIdPattern,
    representativeAlertIdPattern, stableGroupIdPattern, releaseIdPattern,
  })) {
    if (!(value instanceof RegExp)) throw new TypeError(`${name} must be a RegExp`);
  }

  function claimDigest(identity) {
    const canonical = Object.fromEntries(
      Object.keys(identity).sort().map((key) => [key, identity[key]]),
    );
    return crypto.createHash('sha256').update(JSON.stringify(canonical), 'utf8').digest('hex');
  }

  function normalizedIdentity(payload) {
    const identity = payload?.controlled_job;
    if (
      !identity || typeof identity !== 'object' || Array.isArray(identity)
      || Object.keys(identity).sort().join('\0')
        !== [...EXPECTED_IDENTITY_FIELDS].sort().join('\0')
    ) {
      throw identityConflict('controlled evaluation result identity is incomplete');
    }
    return {
      identity,
      jobId: Number(identity.job_id),
      jobType: safeString(identity.job_type, 64),
      leaseToken: safeString(identity.lease_token, 128),
      cohortId: safeString(identity.cohort_id, 64),
      dispatchId: safeString(identity.dispatch_id, 64),
      representativeAlertId: safeString(identity.representative_alert_id, 256),
      stableGroupId: safeString(identity.stable_group_id, 64),
      stableGroupKey: identity.stable_group_key,
      agentRole: safeString(identity.agent_role, 64).toLowerCase(),
      reanalysisAttemptId: safeString(identity.reanalysis_attempt_id, 80).toLowerCase(),
      releaseId: safeString(identity.release_id, 40).toLowerCase(),
      expectedAssignedRoute: safeString(identity.expected_assigned_route, 256),
      expectedReviewerRoute: safeString(identity.expected_reviewer_route, 256),
      analysisId: safeString(payload?.analysis_id, 128).toLowerCase(),
      claimDigest: claimDigest(identity),
    };
  }

  function validIdentity(payload, value) {
    const {identity} = value;
    const expectedRole = {
      ai_analysis: 'soc-analyst',
      incident_response_analysis: 'incident-responder',
    }[value.jobType];
    return (
      typeof identity.job_id === 'number' && Number.isSafeInteger(value.jobId) && value.jobId >= 1
      && typeof identity.job_type === 'string' && identity.job_type === value.jobType
      && typeof identity.lease_token === 'string' && identity.lease_token === value.leaseToken
      && typeof identity.cohort_id === 'string' && identity.cohort_id === value.cohortId
      && typeof identity.dispatch_id === 'string' && identity.dispatch_id === value.dispatchId
      && typeof identity.representative_alert_id === 'string'
      && identity.representative_alert_id === value.representativeAlertId
      && typeof identity.stable_group_id === 'string'
      && identity.stable_group_id === value.stableGroupId
      && typeof identity.agent_role === 'string' && identity.agent_role === value.agentRole
      && typeof identity.reanalysis_attempt_id === 'string'
      && identity.reanalysis_attempt_id === value.reanalysisAttemptId
      && typeof identity.release_id === 'string' && identity.release_id === value.releaseId
      && typeof identity.expected_assigned_route === 'string'
      && identity.expected_assigned_route === value.expectedAssignedRoute
      && typeof identity.expected_reviewer_route === 'string'
      && identity.expected_reviewer_route === value.expectedReviewerRoute
      && controlledRoutePattern.test(value.expectedAssignedRoute)
      && controlledRoutePattern.test(value.expectedReviewerRoute)
      && controlledRouteModelIdentity(value.expectedAssignedRoute)
        !== controlledRouteModelIdentity(value.expectedReviewerRoute)
      && identity.reviewer_required === true
      && typeof payload?.analysis_id === 'string' && payload.analysis_id === value.analysisId
      && /^[a-z0-9_-]{8,128}$/.test(value.analysisId)
      && expectedRole && value.agentRole === expectedRole
      && cohortIdPattern.test(value.cohortId) && dispatchIdPattern.test(value.dispatchId)
      && representativeAlertIdPattern.test(value.representativeAlertId)
      && stableGroupIdPattern.test(value.stableGroupId)
      && validPinnedStableGroupKey(value.stableGroupKey)
      && releaseIdPattern.test(value.releaseId) && value.releaseId === runtimeReleaseId
      && (value.jobType !== 'ai_analysis' || !value.reanalysisAttemptId)
      && (value.jobType !== 'incident_response_analysis'
        || /^ira-[a-f0-9]{40}$/.test(value.reanalysisAttemptId))
      && safeString(payload?.alert_id, 1024) === value.representativeAlertId
      && safeString(payload?.agent_role, 64).toLowerCase() === value.agentRole
      && safeString(payload?.reanalysis_attempt_id, 80).toLowerCase()
        === value.reanalysisAttemptId
      && payload?.response?._analysis_evaluation_memory_frozen === true
      && payload?.response?._analysis_controlled_claim_sha256 === value.claimDigest
      && payload?.response?._analysis_model_route === value.expectedAssignedRoute
      && payload?.response?._second_opinion?.status === 'completed'
      && payload?.response?._second_opinion?.model_route === value.expectedReviewerRoute
      && payload?.response?._second_opinion?.response?._analysis_model_route
        === value.expectedReviewerRoute
    );
  }

  function durableJobMatches(current, payload, value) {
    return (
      Number(current?.id || 0) === value.jobId
      && Number(current?.rerun_requested || 0) === 0
      && payload.cohort_id === value.cohortId && payload.dispatch_id === value.dispatchId
      && payload.release_id === value.releaseId
      && payload.expected_assigned_route === value.expectedAssignedRoute
      && payload.expected_reviewer_route === value.expectedReviewerRoute
      && payload.reviewer_required === true
      && payload.alert_id === value.representativeAlertId
      && payload.representative_alert_id === value.representativeAlertId
      && payload.group_id === value.stableGroupId
      && payload.stable_group_id === value.stableGroupId
      && payload.stable_group_key === value.stableGroupKey
      && payload.agent_role === value.agentRole
    );
  }

  async function replayAdmission(payload, value, current, accepted) {
    const acceptedResponse = parseJsonObject(accepted.response_json);
    if (
      accepted.group_id !== value.stableGroupId
      || accepted.alert_id !== value.representativeAlertId
      || accepted.agent_role !== value.agentRole
      || acceptedResponse._analysis_controlled_claim_sha256 !== value.claimDigest
      || canonicalJsonText(acceptedResponse) !== canonicalJsonText(payload?.response || {})
    ) {
      throw identityConflict('controlled evaluation committed result replay changed');
    }
    const terminal = current.status === 'completed'
      && !current.lease_token && !current.lease_expires_at;
    const needsCompletion = current.status === 'processing'
      && current.lease_token === value.leaseToken;
    if (!terminal && !needsCompletion) {
      throw identityConflict('controlled evaluation result replay does not match its durable job');
    }
    return {idempotentReplay: true, completeRequired: needsCompletion};
  }

  async function validateNewResult(value, current, currentPayload) {
    if (current?.status !== 'processing' || current?.lease_token !== value.leaseToken) {
      throw identityConflict('controlled evaluation result does not own its durable lease');
    }
    const currentAlert = await get(
      `SELECT stable_group_id, stable_group_key
       FROM alerts WHERE alert_id = ? LIMIT 1`,
      [value.representativeAlertId],
    );
    if (
      currentAlert?.stable_group_id !== value.stableGroupId
      || currentAlert?.stable_group_key !== value.stableGroupKey
    ) {
      throw identityConflict('controlled evaluation representative alert changed before result commit');
    }
    if (value.jobType !== 'incident_response_analysis') return;
    const attempt = await get(
      `SELECT attempt_id, run_id, case_id, group_id, status
       FROM incident_reanalysis_attempts WHERE attempt_id = ?`,
      [value.reanalysisAttemptId],
    );
    if (
      value.reanalysisAttemptId !== incidentReanalysisAttemptId(value.leaseToken)
      || attempt?.status !== 'running' || attempt?.group_id !== value.stableGroupId
      || attempt?.run_id !== currentPayload.reanalysis_run_id
      || attempt?.case_id !== currentPayload.case_id
    ) {
      throw identityConflict('controlled evaluation incident attempt does not own the lease');
    }
  }

  async function admit(payload) {
    if (!controlledEvaluationMode) return null;
    const value = normalizedIdentity(payload);
    if (!validIdentity(payload, value)) {
      throw identityConflict('controlled evaluation result identity is invalid');
    }
    const key = claimLeaseKey(value.jobType, value.stableGroupId);
    const current = await get(
      `SELECT id, status, lease_token, lease_expires_at, rerun_requested,
              payload_json
       FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?`,
      [value.jobType, value.stableGroupId],
    );
    const currentPayload = incidentReanalysisJobPayload(current);
    if (!durableJobMatches(current, currentPayload, value)) {
      throw identityConflict('controlled evaluation durable job changed before result commit');
    }
    const accepted = await get(
      `SELECT group_id, alert_id, agent_role, response_json
       FROM ai_analysis_runs WHERE analysis_id = ?`,
      [value.analysisId],
    );
    let state = {idempotentReplay: false, completeRequired: true};
    if (accepted) state = await replayAdmission(payload, value, current, accepted);
    else await validateNewResult(value, current, currentPayload);
    return {
      key, analysisId: value.analysisId, jobType: value.jobType,
      stableGroupId: value.stableGroupId, leaseToken: value.leaseToken, ...state,
    };
  }

  function apply(admission) {
    if (!controlledEvaluationMode || !admission) return;
    retireLease(admission.key);
  }

  return {claimDigest, admit, apply};
}

module.exports = {createControlledResultAdmission};
