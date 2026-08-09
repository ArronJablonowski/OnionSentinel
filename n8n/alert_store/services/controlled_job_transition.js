'use strict';

function createControlledJobTransition({
  controlledEvaluationMode,
  safeString,
  identityConflict,
  stableGroupIdPattern,
  parseClaimIdentity,
  all,
  get,
  incidentReanalysisJobPayload,
  validPinnedStableGroupKey,
  cohortIdPattern,
  dispatchIdPattern,
  representativeAlertIdPattern,
  controlledRuntimeReleaseId,
  controlledRoutePattern,
  controlledRouteModelIdentity,
  incidentReanalysisAttemptId,
}) {
  for (const [name, value] of Object.entries({
    safeString,
    identityConflict,
    parseClaimIdentity,
    all,
    get,
    incidentReanalysisJobPayload,
    validPinnedStableGroupKey,
    controlledRuntimeReleaseId,
    controlledRouteModelIdentity,
    incidentReanalysisAttemptId,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  for (const [name, value] of Object.entries({
    stableGroupIdPattern,
    cohortIdPattern,
    dispatchIdPattern,
    representativeAlertIdPattern,
    controlledRoutePattern,
  })) {
    if (!(value instanceof RegExp)) throw new TypeError(`${name} must be a RegExp`);
  }
  const leases = new Map();

  function leaseKey(jobType, dedupeKey) {
    return `${jobType}\0${dedupeKey}`;
  }

  function normalizeTransition(payload) {
    const jobType = safeString(payload?.job_type, 64);
    const dedupeKey = safeString(payload?.dedupe_key, 256);
    const status = safeString(payload?.status, 32).toLowerCase();
    const leaseToken = safeString(payload?.lease_token, 128);
    if (
      typeof payload?.job_type !== 'string'
      || payload.job_type !== jobType
      || typeof payload?.dedupe_key !== 'string'
      || payload.dedupe_key !== dedupeKey
      || typeof payload?.status !== 'string'
      || payload.status !== status
      || typeof payload?.lease_token !== 'string'
      || payload.lease_token !== leaseToken
      || !['ai_analysis', 'incident_response_analysis'].includes(jobType)
      || !stableGroupIdPattern.test(dedupeKey)
      || !['processing', 'completed', 'failed'].includes(status)
    ) {
      throw identityConflict('controlled evaluation job transition is not allowed');
    }
    return {jobType, dedupeKey, status, leaseToken, key: leaseKey(jobType, dedupeKey)};
  }

  async function admitClaim(transition, exactClaim) {
    if (!exactClaim) {
      throw identityConflict('controlled evaluation requires one exact unowned job claim');
    }
    const processing = await all(
      `SELECT id, job_type, dedupe_key
       FROM durable_jobs
       WHERE status = 'processing'
         AND job_type IN ('ai_analysis', 'incident_response_analysis')
       ORDER BY id ASC LIMIT 2`,
    );
    if (
      processing.length > 1
      || processing.some((job) => (
        Number(job.id || 0) !== exactClaim.jobId
        || job.job_type !== transition.jobType
        || job.dedupe_key !== transition.dedupeKey
      ))
    ) {
      throw identityConflict('controlled evaluation requires one exact unowned job claim');
    }
    return {action: 'claim', key: transition.key, exactClaim};
  }

  function validOwnedJob(current, payload, transition, expectedRole) {
    const currentLeaseExpiry = Date.parse(
      String(current?.lease_expires_at || '').replace('  ', 'T'),
    );
    return (
      Number.isSafeInteger(Number(current?.id))
      && Number(current.id) >= 1
      && current?.status === 'processing'
      && current?.lease_token === transition.leaseToken
      && Number(current?.rerun_requested || 0) === 0
      && Number.isFinite(currentLeaseExpiry)
      && payload.alert_id === payload.representative_alert_id
      && payload.group_id === transition.dedupeKey
      && payload.stable_group_id === transition.dedupeKey
      && validPinnedStableGroupKey(payload.stable_group_key)
      && cohortIdPattern.test(String(payload.cohort_id || ''))
      && dispatchIdPattern.test(String(payload.dispatch_id || ''))
      && representativeAlertIdPattern.test(String(payload.representative_alert_id || ''))
      && payload.release_id === controlledRuntimeReleaseId()
      && payload.agent_role === expectedRole
      && controlledRoutePattern.test(String(payload.expected_assigned_route || ''))
      && controlledRoutePattern.test(String(payload.expected_reviewer_route || ''))
      && controlledRouteModelIdentity(payload.expected_assigned_route)
        !== controlledRouteModelIdentity(payload.expected_reviewer_route)
      && payload.reviewer_required === true
    );
  }

  async function validateRepresentative(payload, dedupeKey) {
    const representative = await get(
      `SELECT stable_group_id, stable_group_key
       FROM alerts WHERE alert_id = ? LIMIT 1`,
      [payload.representative_alert_id],
    );
    if (
      representative?.stable_group_id !== dedupeKey
      || representative?.stable_group_key !== payload.stable_group_key
    ) {
      throw identityConflict('controlled evaluation lease representative changed');
    }
  }

  async function validateIncidentAttempt(transition, payload) {
    if (transition.jobType !== 'incident_response_analysis') return '';
    const attemptId = incidentReanalysisAttemptId(transition.leaseToken);
    const attempt = await get(
      `SELECT attempt_id, run_id, case_id, group_id, status
       FROM incident_reanalysis_attempts WHERE attempt_id = ?`,
      [attemptId],
    );
    if (
      attempt?.status !== 'running'
      || attempt?.group_id !== transition.dedupeKey
      || attempt?.run_id !== payload.reanalysis_run_id
      || attempt?.case_id !== payload.case_id
    ) {
      throw identityConflict('controlled evaluation incident attempt does not own the lease');
    }
    return attemptId;
  }

  async function admitOwned(transition, exactClaim) {
    if (exactClaim) {
      throw identityConflict('controlled evaluation lease transition cannot repeat claim identity');
    }
    if (!transition.leaseToken) {
      throw identityConflict('controlled evaluation transition does not own the active lease');
    }
    const current = await get(
      `SELECT id, status, lease_token, lease_expires_at, rerun_requested,
              payload_json
       FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?`,
      [transition.jobType, transition.dedupeKey],
    );
    const payload = incidentReanalysisJobPayload(current);
    const expectedRole = transition.jobType === 'incident_response_analysis'
      ? 'incident-responder' : 'soc-analyst';
    if (!validOwnedJob(current, payload, transition, expectedRole)) {
      throw identityConflict('controlled evaluation lease is no longer active');
    }
    await validateRepresentative(payload, transition.dedupeKey);
    const reanalysisAttemptId = await validateIncidentAttempt(transition, payload);
    if (transition.status === 'completed') {
      throw identityConflict('controlled evaluation job cannot complete before its bound result');
    }
    return {
      action: transition.status,
      key: transition.key,
      owned: {
        jobId: Number(current.id),
        jobType: transition.jobType,
        dedupeKey: transition.dedupeKey,
        leaseToken: transition.leaseToken,
        cohortId: String(payload.cohort_id || ''),
        dispatchId: String(payload.dispatch_id || ''),
        releaseId: String(payload.release_id || ''),
        representativeAlertId: String(payload.representative_alert_id || ''),
        stableGroupId: String(payload.stable_group_id || ''),
        stableGroupKey: payload.stable_group_key,
        agentRole: expectedRole,
        expectedAssignedRoute: payload.expected_assigned_route,
        expectedReviewerRoute: payload.expected_reviewer_route,
        reviewerRequired: true,
        reanalysisAttemptId,
        resultCommitted: false,
        analysisId: '',
      },
    };
  }

  async function admit(payload) {
    if (!controlledEvaluationMode) return null;
    const transition = normalizeTransition(payload);
    const exactClaim = parseClaimIdentity(payload);
    if (transition.status === 'processing' && !transition.leaseToken) {
      return admitClaim(transition, exactClaim);
    }
    return admitOwned(transition, exactClaim);
  }

  function apply(admission, transition) {
    if (!controlledEvaluationMode || !admission || !transition?.updated) return;
    if (admission.action === 'claim') {
      const claim = transition.claim;
      const payload = claim?.payload;
      if (
        !claim || !payload || !transition.leaseToken
        || Number(claim.job_id || 0) !== admission.exactClaim.jobId
      ) {
        throw identityConflict('controlled evaluation claim receipt is incomplete');
      }
      leases.clear();
      leases.set(admission.key, {
        jobId: Number(claim.job_id),
        jobType: String(claim.job_type || ''),
        dedupeKey: String(claim.dedupe_key || ''),
        leaseToken: String(transition.leaseToken),
        cohortId: String(payload.cohort_id || ''),
        dispatchId: String(payload.dispatch_id || ''),
        releaseId: String(payload.release_id || ''),
        representativeAlertId: String(payload.representative_alert_id || ''),
        stableGroupId: String(payload.stable_group_id || ''),
        stableGroupKey: String(payload.stable_group_key || ''),
        agentRole: String(payload.agent_role || ''),
        expectedAssignedRoute: String(payload.expected_assigned_route || ''),
        expectedReviewerRoute: String(payload.expected_reviewer_route || ''),
        reviewerRequired: payload.reviewer_required === true,
        reanalysisAttemptId: String(claim.reanalysis_attempt_id || ''),
        resultCommitted: false,
        analysisId: '',
      });
      return;
    }
    if (admission.action === 'processing') {
      leases.clear();
      leases.set(admission.key, admission.owned);
      return;
    }
    if (['completed', 'failed'].includes(admission.action)) leases.delete(admission.key);
  }

  function retireLease(key) {
    leases.delete(key);
  }

  return {leases, leaseKey, admit, apply, retireLease};
}

module.exports = {createControlledJobTransition};
