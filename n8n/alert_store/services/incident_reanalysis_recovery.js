'use strict';

function createIncidentReanalysisRecovery({
  durableJobsAvailable,
  all,
  get,
  run,
  retireCompleted,
  retireSuperseded,
  attemptId,
  beginAttempt,
  safeString,
  jobPayload,
  validCaseId,
  nowUtc,
  refreshRun,
}) {
  const functions = {durableJobsAvailable, all, get, run, retireCompleted,
    retireSuperseded, attemptId, beginAttempt, safeString, jobPayload,
    validCaseId, nowUtc, refreshRun};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function retireSatisfiedJobs() {
    let reconciled = 0;
    const jobs = await all(
      `SELECT id, job_type, dedupe_key, payload_json, status
       FROM durable_jobs
       WHERE job_type = 'incident_response_analysis'
         AND status IN ('pending', 'processing')`,
    );
    for (const job of jobs) {
      if (await retireCompleted(job) || await retireSuperseded(job)) reconciled += 1;
    }
    return reconciled;
  }

  async function repairMissingAttempts(affectedCases) {
    let reconciled = 0;
    const jobs = await all(
      `SELECT dedupe_key, payload_json, status, attempt_count, lease_token, last_error
       FROM durable_jobs
       WHERE job_type = 'incident_response_analysis' AND status = 'processing'`,
    );
    for (const job of jobs) {
      const currentAttemptId = attemptId(job.lease_token);
      if (!currentAttemptId) continue;
      const currentAttempt = await get(
        `SELECT 1 AS present FROM incident_reanalysis_attempts
         WHERE attempt_id = ?`,
        [currentAttemptId],
      );
      if (currentAttempt) continue;
      const groupId = safeString(job.dedupe_key, 64).toLowerCase();
      const repaired = await beginAttempt(job, job.lease_token, groupId);
      if (repaired) {
        affectedCases.set(repaired.case_id, {group_id: groupId, latest_error: ''});
        reconciled += 1;
      }
    }
    return reconciled;
  }

  async function successorState(attempt) {
    const currentCase = await get(
      'SELECT group_id FROM incident_response_cases WHERE case_id = ?',
      [attempt.case_id],
    );
    const newerRunCase = await get(
      `SELECT 1 AS present
       FROM incident_reanalysis_run_cases
       WHERE case_id = ? AND run_id != ? AND status != 'skipped'
         AND rowid > COALESCE((
           SELECT rowid FROM incident_reanalysis_run_cases
           WHERE run_id = ? AND case_id = ?
         ), 0)
       LIMIT 1`,
      [attempt.case_id, attempt.run_id, attempt.run_id, attempt.case_id],
    );
    const currentCaseGroup = safeString(currentCase?.group_id, 64).toLowerCase();
    const migratedToSuccessor = Boolean(currentCaseGroup
      && currentCaseGroup !== safeString(attempt.group_id, 64).toLowerCase()
      && newerRunCase);
    return {currentCaseGroup, migratedToSuccessor};
  }

  function durableState(attempt, migratedToSuccessor) {
    const currentPayload = jobPayload(attempt);
    const durableOwnsSameRun = !migratedToSuccessor
      && safeString(currentPayload?.reanalysis_run_id, 80) === attempt.run_id
      && validCaseId(currentPayload?.case_id) === attempt.case_id;
    const durableCompleted = attempt.durable_status === 'completed' && durableOwnsSameRun;
    const latestError = durableCompleted
      ? null
      : migratedToSuccessor
        ? 'Worker lease expired after stable identity migrated to a successor run'
        : safeString(attempt.last_error || 'worker lease expired before completion', 1000);
    const retryOwnsSameRun = attempt.durable_status === 'pending' && durableOwnsSameRun;
    const caseStatus = durableCompleted ? 'completed' : retryOwnsSameRun ? 'queued' : 'failed';
    return {caseStatus, durableCompleted, latestError};
  }

  async function closeRunningAttempt(attempt, affectedCases, affectedRuns) {
    const ownsCurrentLease = attempt.durable_status === 'processing'
      && attemptId(attempt.lease_token) === attempt.attempt_id;
    if (ownsCurrentLease) return false;
    const updatedAt = nowUtc();
    const successor = await successorState(attempt);
    const state = durableState(attempt, successor.migratedToSuccessor);
    await run(
      `UPDATE incident_reanalysis_attempts
       SET status = ?, latest_error = ?, completed_at = ?, updated_at = ?
       WHERE attempt_id = ? AND status = 'running'`,
      [state.durableCompleted ? 'completed' : 'failed', state.latestError,
        updatedAt, updatedAt, attempt.attempt_id],
    );
    await run(
      `UPDATE incident_reanalysis_run_cases
       SET status = ?, latest_error = ?,
           completed_at = CASE WHEN ? = 'queued' THEN NULL ELSE ? END,
           latest_attempt_id = ?, updated_at = ?
       WHERE run_id = ? AND case_id = ?
         AND status NOT IN ('completed', 'skipped')`,
      [state.caseStatus, state.latestError, state.caseStatus, updatedAt,
        attempt.attempt_id, updatedAt, attempt.run_id, attempt.case_id],
    );
    if (successor.migratedToSuccessor && attempt.durable_status === 'pending') {
      await run(
        `UPDATE durable_jobs
         SET status = 'completed', lease_expires_at = NULL, lease_token = NULL,
             last_error = NULL, completed_at = COALESCE(completed_at, ?),
             last_completed_at = COALESCE(last_completed_at, ?),
             processing_started_at = NULL, rerun_requested = 0, updated_at = ?
         WHERE job_type = 'incident_response_analysis'
           AND dedupe_key = ? AND status = 'pending' AND payload_json = ?`,
        [updatedAt, updatedAt, updatedAt,
          safeString(attempt.group_id, 64).toLowerCase(), String(attempt.payload_json || '')],
      );
    }
    affectedCases.set(attempt.case_id, {
      group_id: successor.migratedToSuccessor
        ? successor.currentCaseGroup : safeString(attempt.group_id, 64).toLowerCase(),
      latest_error: state.latestError,
    });
    affectedRuns.add(String(attempt.run_id || ''));
    return true;
  }

  async function reconcileRunningAttempts(affectedCases) {
    const attempts = await all(
      `SELECT a.attempt_id, a.run_id, a.case_id, a.group_id,
              d.status AS durable_status, d.payload_json,
              d.lease_token, d.last_error
       FROM incident_reanalysis_attempts AS a
       LEFT JOIN durable_jobs AS d
         ON d.job_type = 'incident_response_analysis'
        AND d.dedupe_key = a.group_id
       WHERE a.status = 'running'`,
    );
    const affectedRuns = new Set();
    let reconciled = 0;
    for (const attempt of attempts) {
      if (await closeRunningAttempt(attempt, affectedCases, affectedRuns)) reconciled += 1;
    }
    for (const runId of affectedRuns) await refreshRun(runId);
    return reconciled;
  }

  async function publishCases(affectedCases) {
    for (const [caseId, affected] of affectedCases.entries()) {
      const currentJob = await get(
        `SELECT status, payload_json, last_error
         FROM durable_jobs
         WHERE job_type = 'incident_response_analysis' AND dedupe_key = ?`,
        [affected.group_id],
      );
      const currentPayload = jobPayload(currentJob);
      const currentCaseId = validCaseId(currentPayload?.case_id);
      const durableOwnsCase = !currentCaseId || currentCaseId === caseId;
      const agentStatus = durableOwnsCase ? ({pending: 'queued', processing: 'analyzing',
        completed: 'analyzed', failed: 'failed'}[currentJob?.status] || 'failed') : 'failed';
      const latestError = agentStatus === 'failed'
        ? safeString(currentJob?.last_error || affected.latest_error
          || 'worker lease expired before completion', 1000)
        : null;
      await run(
        `UPDATE incident_response_cases
         SET agent_status = ?, latest_error = ?, updated_at = ?
         WHERE case_id = ?`,
        [agentStatus, latestError, nowUtc(), caseId],
      );
    }
  }

  async function reconcile() {
    if (!durableJobsAvailable()) return 0;
    const affectedCases = new Map();
    let reconciled = await retireSatisfiedJobs();
    reconciled += await repairMissingAttempts(affectedCases);
    reconciled += await reconcileRunningAttempts(affectedCases);
    await publishCases(affectedCases);
    return reconciled;
  }

  return {reconcile};
}

module.exports = {createIncidentReanalysisRecovery};
