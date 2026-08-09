'use strict';

function createDurableJobTransitionExecutor({
  controlledEvaluationMode,
  parseClaimIdentity,
  stableGroupIdPattern,
  identityConflict,
  get,
  run,
  safeString,
  incidentReanalysisJobPayload,
  controlledRuntimeReleaseId,
  incidentReanalysisAttemptId,
  aiAnalysisLeaseSeconds,
  nowUtc,
  nowMs = () => Date.now(),
  durableJobs,
  pipelineMetrics,
  retireCompletedIncidentReanalysisJob,
  retireSupersededIncidentReanalysisJob,
  updateIncidentReanalysisProgress,
  signalAiWorkers,
}) {
  for (const [name, value] of Object.entries({
    parseClaimIdentity, identityConflict, get, run, safeString,
    incidentReanalysisJobPayload, controlledRuntimeReleaseId,
    incidentReanalysisAttemptId, nowUtc, nowMs, durableJobs, pipelineMetrics,
    retireCompletedIncidentReanalysisJob, retireSupersededIncidentReanalysisJob,
    updateIncidentReanalysisProgress, signalAiWorkers,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!(stableGroupIdPattern instanceof RegExp)) {
    throw new TypeError('stableGroupIdPattern must be a RegExp');
  }

  function validateExactRequest(jobType, resolvedKey, status, leaseToken) {
    if (
      status !== 'processing' || leaseToken
      || !['ai_analysis', 'incident_response_analysis'].includes(jobType)
      || !stableGroupIdPattern.test(resolvedKey)
    ) {
      throw identityConflict('controlled durable job claim is not valid for this transition');
    }
  }

  function validateExactPayload(jobType, resolvedKey, claim, payload) {
    const runtimeReleaseId = controlledRuntimeReleaseId();
    const expectedRole = jobType === 'incident_response_analysis'
      ? 'incident-responder' : 'soc-analyst';
    if (
      payload.alert_id !== claim.representativeAlertId
      || payload.representative_alert_id !== claim.representativeAlertId
      || payload.group_id !== resolvedKey || payload.stable_group_id !== resolvedKey
      || payload.stable_group_key !== claim.stableGroupKey
      || payload.dispatch_id !== claim.dispatchId
      || payload.expected_assigned_route !== claim.expectedAssignedRoute
      || payload.expected_reviewer_route !== claim.expectedReviewerRoute
      || payload.reviewer_required !== claim.reviewerRequired
      || !runtimeReleaseId || payload.release_id !== runtimeReleaseId
      || typeof payload.agent_role !== 'string' || payload.agent_role !== expectedRole
    ) {
      throw identityConflict('controlled durable job payload changed before it could be claimed');
    }
  }

  async function replayProcessingClaim(jobType, resolvedKey, candidate, payload) {
    const replayLeaseToken = safeString(candidate.lease_token, 128);
    if (!replayLeaseToken) {
      throw identityConflict('controlled durable job processing lease is incomplete');
    }
    const replayLeaseExpiry = new Date(
      nowMs() + aiAnalysisLeaseSeconds * 1000,
    ).toISOString();
    const replayed = await run(
      `UPDATE durable_jobs
       SET lease_expires_at = ?, updated_at = ?
       WHERE id = ? AND status = 'processing' AND lease_token = ?
         AND rerun_requested = 0`,
      [replayLeaseExpiry, nowUtc(), candidate.id, replayLeaseToken],
    );
    if (Number(replayed.changes || 0) !== 1) {
      throw identityConflict('controlled durable job changed before its claim could be replayed');
    }
    const claim = {
      job_id: Number(candidate.id), job_type: jobType,
      dedupe_key: resolvedKey, payload,
    };
    if (jobType === 'incident_response_analysis') {
      const attempt = await get(
        `SELECT attempt_id, run_id, case_id
         FROM incident_reanalysis_attempts WHERE attempt_id = ?`,
        [incidentReanalysisAttemptId(replayLeaseToken)],
      );
      claim.reanalysis_attempt_id = attempt?.attempt_id || null;
      claim.reanalysis_run_id = attempt?.run_id || null;
      claim.case_id = attempt?.case_id || null;
    }
    return {
      updated: true, resolvedKey, leaseToken: replayLeaseToken,
      claim, idempotentClaim: true,
    };
  }

  async function exactClaimState(jobType, resolvedKey, status, leaseToken, exactClaim) {
    validateExactRequest(jobType, resolvedKey, status, leaseToken);
    const candidate = await get(
      `SELECT id, job_type, dedupe_key, payload_json, status, rerun_requested,
              attempt_count, lease_token, lease_expires_at
       FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?`,
      [jobType, resolvedKey],
    );
    if (
      !candidate || Number(candidate.id || 0) !== exactClaim.jobId
      || !['pending', 'processing'].includes(candidate.status)
      || Number(candidate.rerun_requested || 0) !== 0
    ) {
      throw identityConflict('controlled durable job changed before it could be claimed');
    }
    const payload = incidentReanalysisJobPayload(candidate);
    validateExactPayload(jobType, resolvedKey, exactClaim, payload);
    const representative = await get(
      `SELECT stable_group_id, stable_group_key
       FROM alerts WHERE alert_id = ? LIMIT 1`,
      [exactClaim.representativeAlertId],
    );
    if (
      representative?.stable_group_id !== resolvedKey
      || representative?.stable_group_key !== exactClaim.stableGroupKey
    ) {
      throw identityConflict('controlled durable job representative changed before it could be claimed');
    }
    const replay = candidate.status === 'processing'
      ? await replayProcessingClaim(jobType, resolvedKey, candidate, payload) : null;
    return {candidate, replay};
  }

  async function retireCompletedIncidentCandidate(jobType, resolvedKey, status, leaseToken) {
    if (jobType !== 'incident_response_analysis' || status !== 'processing' || leaseToken) {
      return null;
    }
    const candidate = await get(
      `SELECT id, job_type, dedupe_key, payload_json, status
       FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?`,
      [jobType, resolvedKey],
    );
    if (candidate && (
      await retireCompletedIncidentReanalysisJob(candidate)
      || await retireSupersededIncidentReanalysisJob(candidate)
    )) {
      return {updated: false, resolvedKey, leaseToken: null, retiredCompleted: true, claim: null};
    }
    return null;
  }

  async function transitionWithAlias({
    queue, jobType, dedupeKey, resolvedKey, status, error,
    leaseToken, retryable, exactClaim, exactCandidate,
  }) {
    let transition = await queue.transition(
      jobType, resolvedKey, status, error, leaseToken, retryable,
      exactClaim ? {
        expectedJobId: exactClaim.jobId,
        expectedPayloadJson: exactCandidate.payload_json,
      } : {},
    );
    let updated = Boolean(transition?.updated);
    if (exactClaim && !updated) {
      throw identityConflict('controlled durable job changed before it could be claimed');
    }
    if (!exactClaim && !updated && ['ai_analysis', 'incident_response_analysis'].includes(jobType)) {
      const alias = await get(
        'SELECT stable_group_id FROM alert_group_alias WHERE legacy_group_id = ?',
        [dedupeKey],
      );
      if (alias?.stable_group_id) {
        resolvedKey = String(alias.stable_group_id);
        transition = await queue.transition(
          jobType, resolvedKey, status, error, leaseToken, retryable,
        );
        updated = Boolean(transition?.updated);
      }
    }
    return {transition, updated, resolvedKey};
  }

  async function applyIncidentEffects({job, status, error, leaseToken, transition, resolvedKey, claim}) {
    const progressLeaseToken = leaseToken || transition?.leaseToken || '';
    const progress = await updateIncidentReanalysisProgress({
      job, requestedStatus: status, error, leaseToken: progressLeaseToken,
      groupId: resolvedKey, newLease: status === 'processing' && !leaseToken,
    });
    if (
      status === 'completed' && job?.status === 'pending'
      && await retireSupersededIncidentReanalysisJob({
        ...job, job_type: 'incident_response_analysis', dedupe_key: resolvedKey,
      })
    ) job.status = 'completed';
    if (status === 'processing' && job?.status === 'processing') {
      claim = {...claim, reanalysis_attempt_id: progress?.attempt_id || null,
        reanalysis_run_id: progress?.run_id || null, case_id: progress?.case_id || null};
    }
    const agentStatus = {pending: 'queued', processing: 'analyzing',
      completed: 'analyzed', failed: 'failed'}[job?.status] || 'queued';
    const caseRow = await get(
      'SELECT case_id FROM incident_response_cases WHERE group_id = ?', [resolvedKey],
    );
    if (caseRow?.case_id) {
      await run(
        `UPDATE incident_response_cases
         SET agent_status = ?, latest_error = ?, updated_at = ? WHERE case_id = ?`,
        [agentStatus, job?.status === 'failed' ? safeString(error, 1000) : null,
          nowUtc(), caseRow.case_id],
      );
    }
    if (status === 'completed' && job?.status === 'pending') {
      void signalAiWorkers('incident-response-rerun-pending');
    }
    return claim;
  }

  async function applyUpdatedEffects({jobType, resolvedKey, status, error,
    leaseToken, transition, exactClaim}) {
    const job = await get(
      `SELECT id, dedupe_key, status, attempt_count, updated_at, last_completed_at,
              payload_json, last_error
       FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?`,
      [jobType, resolvedKey],
    );
    const metrics = pipelineMetrics();
    const eventType = status === 'processing' ? 'started' : status;
    if (metrics) await metrics.record(jobType, eventType, resolvedKey, {
      eventKey: `${jobType}:${eventType}:${resolvedKey}:${job?.attempt_count || 0}:${job?.last_completed_at || job?.updated_at || nowUtc()}`,
    });
    if (jobType === 'ai_analysis' && status === 'completed' && job?.status === 'pending') {
      void signalAiWorkers('ai-rerun-pending');
    }
    let claim = null;
    if (['ai_analysis', 'incident_response_analysis'].includes(jobType)
      && status === 'processing' && job?.status === 'processing') {
      claim = {...(exactClaim ? {job_id: Number(job.id || 0)} : {}),
        job_type: jobType, dedupe_key: resolvedKey,
        payload: incidentReanalysisJobPayload(job)};
    }
    if (jobType === 'incident_response_analysis') {
      claim = await applyIncidentEffects({job, status, error, leaseToken,
        transition, resolvedKey, claim});
    }
    if (controlledEvaluationMode && status === 'completed' && job?.status !== 'completed') {
      throw identityConflict('controlled evaluation completion unexpectedly queued another run');
    }
    return claim;
  }

  async function transition(jobType, dedupeKey, status, error = '', leaseToken = '',
    retryable = true, requestedClaimIdentity = null) {
    let resolvedKey = dedupeKey;
    const exactClaim = controlledEvaluationMode
      ? parseClaimIdentity(requestedClaimIdentity) : null;
    let exactCandidate = null;
    if (exactClaim) {
      const exact = await exactClaimState(jobType, resolvedKey, status, leaseToken, exactClaim);
      if (exact.replay) return exact.replay;
      exactCandidate = exact.candidate;
    } else {
      const retired = await retireCompletedIncidentCandidate(jobType, resolvedKey, status, leaseToken);
      if (retired) return retired;
    }
    const queue = durableJobs();
    const state = await transitionWithAlias({queue, jobType, dedupeKey, resolvedKey,
      status, error, leaseToken, retryable, exactClaim, exactCandidate});
    resolvedKey = state.resolvedKey;
    const claim = state.updated ? await applyUpdatedEffects({jobType, resolvedKey,
      status, error, leaseToken, transition: state.transition, exactClaim}) : null;
    return {updated: state.updated, resolvedKey,
      leaseToken: state.transition?.leaseToken || null, claim};
  }

  return {transition};
}

module.exports = {createDurableJobTransitionExecutor};
