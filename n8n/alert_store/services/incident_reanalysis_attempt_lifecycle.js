'use strict';

function createIncidentReanalysisAttemptLifecycle({
  jobPayload,
  safeString,
  validCaseId,
  attemptId,
  closeStale,
  get,
  run,
  nowUtc,
  refreshRun,
}) {
  for (const [name, value] of Object.entries({jobPayload, safeString, validCaseId,
    attemptId, closeStale, get, run, nowUtc, refreshRun})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function begin(job, leaseToken, groupId) {
    const payload = jobPayload(job);
    const runId = safeString(payload?.reanalysis_run_id, 80);
    const caseId = validCaseId(payload?.case_id);
    const immutableAttemptId = attemptId(leaseToken);
    if (!immutableAttemptId) return null;
    if (!runId || !caseId) {
      await closeStale(safeString(groupId, 64).toLowerCase(), '', '', nowUtc());
      return null;
    }
    const runCase = await get(
      `SELECT group_id, status
       FROM incident_reanalysis_run_cases
       WHERE run_id = ? AND case_id = ?`,
      [runId, caseId],
    );
    if (!runCase || !['queued', 'running', 'failed'].includes(String(runCase.status || ''))) {
      return null;
    }
    const boundGroupId = safeString(runCase.group_id || groupId, 64).toLowerCase();
    if (!boundGroupId || (groupId && boundGroupId !== groupId)) return null;
    const updatedAt = nowUtc();
    await closeStale(boundGroupId, runId, caseId, updatedAt);
    await run(
      `INSERT INTO incident_reanalysis_attempts (
         attempt_id, run_id, case_id, group_id, durable_attempt_count,
         status, started_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, 'running', ?, ?)
       ON CONFLICT(attempt_id) DO NOTHING`,
      [immutableAttemptId, runId, caseId, boundGroupId,
        Math.max(0, Number(job?.attempt_count || 0)), updatedAt, updatedAt],
    );
    await run(
      `UPDATE incident_reanalysis_run_cases
       SET status = 'running', skip_reason = NULL, latest_error = NULL,
           started_at = COALESCE(started_at, ?), completed_at = NULL,
           latest_attempt_id = ?, updated_at = ?
       WHERE run_id = ? AND case_id = ?
         AND status IN ('queued', 'running', 'failed')`,
      [updatedAt, immutableAttemptId, updatedAt, runId, caseId],
    );
    await refreshRun(runId);
    return {attempt_id: immutableAttemptId, run_id: runId, case_id: caseId};
  }

  async function heartbeat(leaseToken) {
    const immutableAttemptId = attemptId(leaseToken);
    if (!immutableAttemptId) return null;
    const updatedAt = nowUtc();
    await run(
      `UPDATE incident_reanalysis_attempts
       SET updated_at = ?
       WHERE attempt_id = ? AND status = 'running'`,
      [updatedAt, immutableAttemptId],
    );
    return get(
      `SELECT attempt_id, run_id, case_id
       FROM incident_reanalysis_attempts WHERE attempt_id = ?`,
      [immutableAttemptId],
    );
  }

  async function finish(job, requestedStatus, error, leaseToken) {
    const immutableAttemptId = attemptId(leaseToken);
    if (!immutableAttemptId) return null;
    const attempt = await get(
      `SELECT attempt_id, run_id, case_id, status
       FROM incident_reanalysis_attempts WHERE attempt_id = ?`,
      [immutableAttemptId],
    );
    if (!attempt) return null;
    const updatedAt = nowUtc();
    if (requestedStatus === 'completed') {
      await run(
        `UPDATE incident_reanalysis_attempts
         SET status = 'completed', latest_error = NULL,
             completed_at = COALESCE(completed_at, ?), updated_at = ?
         WHERE attempt_id = ?`,
        [updatedAt, updatedAt, immutableAttemptId],
      );
      await run(
        `UPDATE incident_reanalysis_run_cases
         SET status = 'completed', latest_error = NULL,
             completed_at = COALESCE(completed_at, ?),
             latest_attempt_id = ?, updated_at = ?
         WHERE run_id = ? AND case_id = ? AND status != 'skipped'`,
        [updatedAt, immutableAttemptId, updatedAt, attempt.run_id, attempt.case_id],
      );
    } else if (requestedStatus === 'failed') {
      const latestError = safeString(error || job?.last_error || 'analysis attempt failed', 1000);
      await run(
        `UPDATE incident_reanalysis_attempts
         SET status = CASE WHEN status = 'completed' THEN status ELSE 'failed' END,
             latest_error = CASE WHEN status = 'completed' THEN latest_error ELSE ? END,
             completed_at = CASE WHEN status = 'completed' THEN completed_at ELSE ? END,
             updated_at = ?
         WHERE attempt_id = ?`,
        [latestError, updatedAt, updatedAt, immutableAttemptId],
      );
      if (attempt.status !== 'completed') {
        const currentPayload = jobPayload(job);
        const retryOwnsSameRun = job?.status === 'pending'
          && safeString(currentPayload?.reanalysis_run_id, 80) === attempt.run_id
          && validCaseId(currentPayload?.case_id) === attempt.case_id;
        const caseStatus = retryOwnsSameRun ? 'queued' : 'failed';
        await run(
          `UPDATE incident_reanalysis_run_cases
           SET status = ?, latest_error = ?,
               completed_at = CASE WHEN ? = 'queued' THEN NULL ELSE ? END,
               latest_attempt_id = ?, updated_at = ?
           WHERE run_id = ? AND case_id = ?
             AND status NOT IN ('completed', 'skipped')`,
          [caseStatus, latestError, caseStatus, updatedAt, immutableAttemptId,
            updatedAt, attempt.run_id, attempt.case_id],
        );
      }
    }
    await refreshRun(attempt.run_id);
    return attempt;
  }

  async function queue(job) {
    const payload = jobPayload(job);
    const runId = safeString(payload?.reanalysis_run_id, 80);
    const caseId = validCaseId(payload?.case_id);
    if (!runId || !caseId) return null;
    const updatedAt = nowUtc();
    await run(
      `UPDATE incident_reanalysis_run_cases
       SET status = 'queued', latest_error = NULL, completed_at = NULL, updated_at = ?
       WHERE run_id = ? AND case_id = ? AND status = 'failed'`,
      [updatedAt, runId, caseId],
    );
    await refreshRun(runId);
    return {run_id: runId, case_id: caseId};
  }

  async function update({job, requestedStatus, error = '', leaseToken = '',
    groupId = '', newLease = false}) {
    if (requestedStatus === 'processing') {
      return newLease ? begin(job, leaseToken, groupId) : heartbeat(leaseToken);
    }
    if (['completed', 'failed'].includes(requestedStatus)) {
      return finish(job, requestedStatus, error, leaseToken);
    }
    if (requestedStatus === 'pending') return queue(job);
    return null;
  }

  return {begin, finish, heartbeat, queue, update};
}

module.exports = {createIncidentReanalysisAttemptLifecycle};
