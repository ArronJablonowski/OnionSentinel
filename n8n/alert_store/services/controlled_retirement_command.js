'use strict';

function createControlledRetirementCommand({
  normalizeIdentity,
  sha256,
  replay,
  validatePostState,
  projectCensus,
  get,
  all,
  run,
  parseJobPayload,
  projectJob,
  parseJsonObject,
  leaseKey,
  hasLease,
  nowUtc,
  retirePendingExact,
  refreshRun,
  receiptSchema,
  eventType,
  canonicalJsonText,
  validateReceipt,
  conflict,
}) {
  const functions = {
    normalizeIdentity, sha256, replay, validatePostState, projectCensus,
    get, all, run, parseJobPayload, projectJob, parseJsonObject, leaseKey,
    hasLease, nowUtc, retirePendingExact, refreshRun, canonicalJsonText,
    validateReceipt, conflict,
  };
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function loadPreState(identity) {
    const job = await get('SELECT * FROM durable_jobs WHERE id = ?', [identity.job_id]);
    const jobPayload = parseJobPayload(job);
    const jobBefore = projectJob(job);
    const runRow = await get(
      'SELECT * FROM incident_reanalysis_runs WHERE run_id = ?',
      [identity.reanalysis_run_id],
    );
    const runReceipt = parseJsonObject(runRow?.controlled_receipt_json);
    const runCase = await get(
      `SELECT * FROM incident_reanalysis_run_cases
       WHERE run_id = ? AND case_id = ?`,
      [identity.reanalysis_run_id, identity.case_id],
    );
    const attempts = await all(
      `SELECT * FROM incident_reanalysis_attempts
       WHERE run_id = ? AND case_id = ? ORDER BY started_at, attempt_id`,
      [identity.reanalysis_run_id, identity.case_id],
    );
    const incident = await get(
      'SELECT * FROM incident_response_cases WHERE case_id = ?',
      [identity.case_id],
    );
    const priorAnalysis = identity.expected_prior_analysis_id
      ? await get(
        `SELECT analysis_id, group_id, agent_role
         FROM ai_analysis_runs WHERE analysis_id = ?`,
        [identity.expected_prior_analysis_id],
      )
      : null;
    return {job, jobPayload, jobBefore, runRow, runReceipt, runCase,
      attempts, attempt: attempts[0], incident, priorAnalysis};
  }

  function preStateChanged(identity, state) {
    const {job, jobPayload, jobBefore, runRow, runReceipt, runCase,
      attempts, attempt, incident, priorAnalysis} = state;
    return !job || job.job_type !== 'incident_response_analysis'
      || job.dedupe_key !== identity.stable_group_id
      || jobBefore.payload_sha256 !== identity.expected_job_payload_sha256
      || job.status !== 'pending'
      || Number(job.attempt_count || 0) !== identity.expected_attempt_count
      || job.lease_token !== null || job.lease_expires_at !== null
      || Number(job.rerun_requested || 0) !== 0
      || !job.processing_started_at || !job.last_error
      || jobPayload.agent_role !== 'incident-responder'
      || jobPayload.manual_reanalysis !== true
      || jobPayload.cohort_id !== identity.cohort_id
      || jobPayload.dispatch_id !== identity.dispatch_id
      || jobPayload.release_id !== identity.retired_release_id
      || jobPayload.reanalysis_release_id !== identity.retired_release_id
      || jobPayload.reanalysis_run_id !== identity.reanalysis_run_id
      || jobPayload.case_id !== identity.case_id
      || jobPayload.group_id !== identity.stable_group_id
      || jobPayload.stable_group_id !== identity.stable_group_id
      || jobPayload.stable_group_key !== identity.stable_group_key
      || jobPayload.alert_id !== identity.representative_alert_id
      || jobPayload.representative_alert_id !== identity.representative_alert_id
      || !runRow || runRow.release_id !== identity.retired_release_id
      || runRow.scope !== 'single_case' || runRow.status !== 'queued'
      || Number(runRow.total_count || 0) !== 1 || runRow.completed_at !== null
      || runRow.controlled_dispatch_id !== identity.dispatch_id
      || runReceipt.ok !== true || runReceipt.case_id !== identity.case_id
      || runReceipt.cohort_id !== identity.cohort_id
      || runReceipt.dispatch_id !== identity.dispatch_id
      || runReceipt.release_id !== identity.retired_release_id
      || runReceipt.representative_alert_id !== identity.representative_alert_id
      || runReceipt.stable_group_id !== identity.stable_group_id
      || runReceipt.stable_group_key !== identity.stable_group_key
      || !runCase || runCase.group_id !== identity.stable_group_id
      || runCase.representative_alert_id !== identity.representative_alert_id
      || runCase.status !== 'queued'
      || runCase.latest_attempt_id !== identity.expected_attempt_id
      || runCase.analysis_id !== null || attempts.length !== 1 || !attempt
      || attempt.attempt_id !== identity.expected_attempt_id
      || attempt.run_id !== identity.reanalysis_run_id
      || attempt.case_id !== identity.case_id || attempt.group_id !== identity.stable_group_id
      || Number(attempt.durable_attempt_count || 0) !== identity.expected_attempt_count
      || attempt.status !== 'failed' || attempt.analysis_id !== null
      || !attempt.started_at || !attempt.completed_at || !incident
      || incident.group_id !== identity.stable_group_id
      || incident.representative_alert_id !== identity.representative_alert_id
      || incident.agent_status !== 'queued'
      || String(incident.latest_analysis_id || '') !== identity.expected_prior_analysis_id
      || (identity.expected_prior_analysis_id && (!priorAnalysis
        || priorAnalysis.group_id !== identity.stable_group_id
        || priorAnalysis.agent_role !== 'incident-responder'))
      || hasLease(leaseKey('incident_response_analysis', identity.stable_group_id));
  }

  async function applyRetirement(identity, state, retirementId, retiredAt, skipReason) {
    const retired = await retirePendingExact({
      jobId: identity.job_id,
      jobType: 'incident_response_analysis',
      dedupeKey: identity.stable_group_id,
      payloadJson: String(state.job.payload_json),
      attemptCount: identity.expected_attempt_count,
      retiredAt,
    });
    if (!retired) {
      throw conflict('controlled evaluation pending job changed during retirement');
    }
    const retiredCase = await run(
      `UPDATE incident_reanalysis_run_cases
       SET status = 'skipped', skip_reason = ?, latest_error = NULL,
           completed_at = ?, updated_at = ?
       WHERE run_id = ? AND case_id = ? AND group_id = ?
         AND status = 'queued' AND latest_attempt_id = ?
         AND analysis_id IS NULL`,
      [skipReason, retiredAt, retiredAt, identity.reanalysis_run_id,
        identity.case_id, identity.stable_group_id, identity.expected_attempt_id],
    );
    if (Number(retiredCase.changes || 0) !== 1) {
      throw conflict('controlled evaluation run case changed during retirement');
    }
    const refreshedRun = await refreshRun(identity.reanalysis_run_id);
    if (!refreshedRun || refreshedRun.status !== 'partial'
      || Number(refreshedRun.total_count || 0) !== 1) {
      throw conflict('controlled evaluation run did not retire as partial');
    }
    const caseAgentStatus = identity.expected_prior_analysis_id ? 'analyzed' : 'failed';
    const updatedIncident = await run(
      `UPDATE incident_response_cases
       SET agent_status = ?, latest_error = ?, updated_at = ?
       WHERE case_id = ? AND group_id = ? AND representative_alert_id = ?
         AND agent_status = 'queued'
         AND COALESCE(latest_analysis_id, '') = ?`,
      [caseAgentStatus, caseAgentStatus === 'failed' ? skipReason : null, retiredAt,
        identity.case_id, identity.stable_group_id, identity.representative_alert_id,
        identity.expected_prior_analysis_id],
    );
    if (Number(updatedIncident.changes || 0) !== 1) {
      throw conflict('controlled evaluation incident case changed during retirement');
    }
    return caseAgentStatus;
  }

  async function sealReceipt(identity, state, lineageBefore, retirementId, retiredAt,
    skipReason, caseAgentStatus) {
    const jobAfter = await get('SELECT * FROM durable_jobs WHERE id = ?', [identity.job_id]);
    const lineageAfter = await projectCensus(identity, 'retired');
    const receipt = {
      schema: receiptSchema,
      ok: true,
      status: 'retired',
      idempotent: true,
      retirement_id: retirementId,
      retired_at: retiredAt,
      identity,
      skip_reason: skipReason,
      case_agent_status: caseAgentStatus,
      target_before: lineageBefore.members[identity.member_rank - 1],
      target_after: lineageAfter.members[identity.member_rank - 1],
      lineage_before_sha256: sha256(lineageBefore),
      lineage_after_sha256: sha256(lineageAfter),
      job_before_sha256: sha256(state.jobBefore),
      job_after_sha256: sha256(projectJob(jobAfter)),
      security_onion_access: 'none',
      security_onion_writes_allowed: false,
      model_invocations: 0,
      worker_wake_signaled: false,
    };
    receipt.receipt_sha256 = sha256(receipt);
    const sealedReceiptText = canonicalJsonText(receipt);
    const sealedReceipt = JSON.parse(sealedReceiptText);
    const inserted = await run(
      `INSERT INTO incident_response_events (
         case_id, event_type, actor, detail_json, created_at
       ) VALUES (?, ?, ?, ?, ?)`,
      [identity.case_id, eventType,
        `controlled-retirement:${identity.replacement_release_id.slice(0, 12)}`,
        sealedReceiptText, retiredAt],
    );
    if (Number(inserted.changes || 0) !== 1) {
      throw conflict('controlled evaluation retirement receipt was not recorded');
    }
    validateReceipt(sealedReceipt, identity, retirementId);
    await validatePostState(identity, sealedReceipt);
    return sealedReceipt;
  }

  async function retire(payload) {
    const identity = normalizeIdentity(payload);
    const retirementId = sha256(identity);
    const replayed = await replay(identity, retirementId);
    if (replayed) {
      await validatePostState(identity, replayed);
      return replayed;
    }
    const lineageBefore = await projectCensus(identity, 'pending');
    const state = await loadPreState(identity);
    if (preStateChanged(identity, state)) {
      throw conflict('controlled evaluation retirement pre-state changed');
    }
    const retiredAt = nowUtc();
    const skipReason = `Administratively retired controlled evaluation ${identity.cohort_id} `
      + `rank ${identity.member_rank} after its failed sole attempt; `
      + `no analysis was credited (${retirementId}).`;
    const caseAgentStatus = await applyRetirement(
      identity, state, retirementId, retiredAt, skipReason,
    );
    return sealReceipt(identity, state, lineageBefore, retirementId, retiredAt,
      skipReason, caseAgentStatus);
  }

  return {retire};
}

module.exports = {createControlledRetirementCommand};
