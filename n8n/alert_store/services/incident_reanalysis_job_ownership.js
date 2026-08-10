'use strict';

function createIncidentReanalysisJobOwnership({
  safeString,
  validCaseId,
  get,
  all,
  run,
  nowUtc,
  sha256Text,
  refreshRun,
}) {
  for (const [name, value] of Object.entries({safeString, validCaseId, get, all,
    run, nowUtc, sha256Text, refreshRun})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function jobPayload(job) {
    if (!job?.payload_json) return {};
    try {
      const payload = JSON.parse(job.payload_json);
      return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
    } catch (_) {
      return {};
    }
  }

  function jobBinding(job) {
    const payload = jobPayload(job);
    if (payload?.manual_reanalysis !== true) return null;
    const runId = safeString(payload?.reanalysis_run_id, 80);
    const caseId = validCaseId(payload?.case_id);
    return runId && caseId ? {payload, runId, caseId} : null;
  }

  async function retireCompleted(job) {
    const binding = jobBinding(job);
    if (!binding) return false;
    const completed = await get(
      `SELECT analysis_id
       FROM incident_reanalysis_run_cases
       WHERE run_id = ? AND case_id = ?
         AND status = 'completed' AND analysis_id IS NOT NULL`,
      [binding.runId, binding.caseId],
    );
    if (!completed?.analysis_id) return false;
    const updatedAt = nowUtc();
    const result = await run(
      `UPDATE durable_jobs
       SET status = 'completed', lease_expires_at = NULL, lease_token = NULL,
           last_error = NULL, completed_at = COALESCE(completed_at, ?),
           last_completed_at = COALESCE(last_completed_at, ?),
           processing_started_at = NULL, rerun_requested = 0, updated_at = ?
       WHERE id = ? AND job_type = 'incident_response_analysis'
         AND status IN ('pending', 'processing') AND payload_json = ?`,
      [updatedAt, updatedAt, updatedAt, Number(job.id || 0), String(job.payload_json || '')],
    );
    return Number(result.changes || 0) === 1;
  }

  async function retireSuperseded(job) {
    if (job?.status !== 'pending') return false;
    const binding = jobBinding(job);
    if (!binding) return false;
    const superseded = await get(
      `SELECT 1 AS present
       FROM incident_reanalysis_run_cases
       WHERE run_id = ? AND case_id = ? AND status = 'skipped'`,
      [binding.runId, binding.caseId],
    );
    if (!superseded) return false;
    const updatedAt = nowUtc();
    const result = await run(
      `UPDATE durable_jobs
       SET status = 'completed', lease_expires_at = NULL, lease_token = NULL,
           last_error = NULL, completed_at = COALESCE(completed_at, ?),
           last_completed_at = COALESCE(last_completed_at, ?),
           processing_started_at = NULL, rerun_requested = 0, updated_at = ?
       WHERE id = ? AND job_type = 'incident_response_analysis'
         AND status = 'pending' AND payload_json = ?`,
      [updatedAt, updatedAt, updatedAt, Number(job.id || 0), String(job.payload_json || '')],
    );
    return Number(result.changes || 0) === 1;
  }

  function attemptId(leaseToken) {
    const token = safeString(leaseToken, 128);
    return token ? `ira-${sha256Text(token).slice(0, 40)}` : '';
  }

  function analysisProvider(modelPath, observedProvider = '') {
    const observed = safeString(observedProvider, 100).toLowerCase();
    if (observed) return observed;
    const route = safeString(modelPath, 100).toLowerCase();
    if (route === 'frontier-codex-cli') return 'codex-cli';
    if (route === 'hermes-agent') return 'openai-codex';
    if (route === 'openclaw') return 'openclaw';
    if (route === 'ollama') return 'ollama';
    return route;
  }

  async function closeStale(groupId, currentRunId, currentCaseId, updatedAt) {
    const stale = await all(
      `SELECT attempt_id, run_id, case_id
       FROM incident_reanalysis_attempts
       WHERE group_id = ? AND status = 'running'`,
      [groupId],
    );
    if (!stale.length) return;
    const staleError = 'Prior durable processing lease ended before completion';
    const affectedRuns = new Set();
    for (const attempt of stale) {
      await run(
        `UPDATE incident_reanalysis_attempts
         SET status = 'failed', latest_error = ?, completed_at = ?, updated_at = ?
         WHERE attempt_id = ? AND status = 'running'`,
        [staleError, updatedAt, updatedAt, attempt.attempt_id],
      );
      if (attempt.run_id === currentRunId && attempt.case_id === currentCaseId) continue;
      await run(
        `UPDATE incident_reanalysis_run_cases
         SET status = 'failed', latest_error = ?, completed_at = ?, updated_at = ?
         WHERE run_id = ? AND case_id = ?
           AND status NOT IN ('completed', 'skipped')`,
        [staleError, updatedAt, updatedAt, attempt.run_id, attempt.case_id],
      );
      affectedRuns.add(String(attempt.run_id || ''));
    }
    for (const runId of affectedRuns) await refreshRun(runId);
  }

  return {analysisProvider, attemptId, closeStale, jobPayload, retireCompleted, retireSuperseded};
}

module.exports = {createIncidentReanalysisJobOwnership};
