'use strict';

function createControlledRetirementReplay({
  all,
  get,
  eventType,
  receiptFields,
  receiptSchema,
  dispatchIdPattern,
  parseJsonObject,
  canonicalJsonText,
  sha256,
  projectJob,
  projectCensus,
  conflict,
}) {
  const functions = {
    all,
    get,
    parseJsonObject,
    canonicalJsonText,
    sha256,
    projectJob,
    projectCensus,
    conflict,
  };
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!Array.isArray(receiptFields)) throw new TypeError('receiptFields must be an array');
  if (!dispatchIdPattern || typeof dispatchIdPattern.test !== 'function') {
    throw new TypeError('dispatchIdPattern must be a pattern');
  }

  function validateReceipt(receipt, identity, retirementId) {
    if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
      throw conflict('controlled evaluation retirement receipt is malformed');
    }
    const receiptSha256 = receipt.receipt_sha256;
    const unsigned = {...receipt};
    delete unsigned.receipt_sha256;
    const suppliedFields = Object.keys(receipt).sort();
    if (suppliedFields.length !== receiptFields.length
      || suppliedFields.some((field, index) => field !== receiptFields[index])
      || receipt.schema !== receiptSchema
      || receipt.ok !== true
      || receipt.status !== 'retired'
      || receipt.idempotent !== true
      || receipt.retirement_id !== retirementId
      || !receipt.target_before
      || typeof receipt.target_before !== 'object'
      || Array.isArray(receipt.target_before)
      || !receipt.target_after
      || typeof receipt.target_after !== 'object'
      || Array.isArray(receipt.target_after)
      || canonicalJsonText(receipt.identity) !== canonicalJsonText(identity)
      || !dispatchIdPattern.test(String(receipt.lineage_before_sha256 || ''))
      || !dispatchIdPattern.test(String(receipt.lineage_after_sha256 || ''))
      || !dispatchIdPattern.test(String(receiptSha256 || ''))
      || sha256(unsigned) !== receiptSha256) {
      throw conflict('controlled evaluation retirement receipt identity changed');
    }
    return receipt;
  }

  async function replay(identity, retirementId) {
    const rows = await all(
      `SELECT id, detail_json
       FROM incident_response_events
       WHERE case_id = ? AND event_type = ?
       ORDER BY id ASC LIMIT 101`,
      [identity.case_id, eventType],
    );
    if (rows.length > 100) {
      throw conflict('controlled evaluation retirement event scan exceeded its bound');
    }
    const lineage = [];
    for (const row of rows) {
      const receipt = parseJsonObject(row.detail_json);
      const receiptIdentity = receipt.identity || {};
      if (receiptIdentity.cohort_id === identity.cohort_id
        || receiptIdentity.dispatch_id === identity.dispatch_id
        || receiptIdentity.reanalysis_run_id === identity.reanalysis_run_id
        || Number(receiptIdentity.job_id || 0) === identity.job_id) {
        if (canonicalJsonText(receipt) !== row.detail_json) {
          throw conflict('controlled evaluation retirement receipt is not canonical');
        }
        lineage.push(receipt);
      }
    }
    if (!lineage.length) return null;
    if (lineage.length !== 1 || lineage[0].retirement_id !== retirementId) {
      throw conflict('controlled evaluation retirement lineage is ambiguous');
    }
    return validateReceipt(lineage[0], identity, retirementId);
  }

  async function loadPostState(identity) {
    const job = await get('SELECT * FROM durable_jobs WHERE id = ?', [identity.job_id]);
    const runRow = await get(
      'SELECT * FROM incident_reanalysis_runs WHERE run_id = ?',
      [identity.reanalysis_run_id],
    );
    const runCase = await get(
      `SELECT * FROM incident_reanalysis_run_cases
       WHERE run_id = ? AND case_id = ?`,
      [identity.reanalysis_run_id, identity.case_id],
    );
    const attempt = await get(
      'SELECT * FROM incident_reanalysis_attempts WHERE attempt_id = ?',
      [identity.expected_attempt_id],
    );
    const incident = await get(
      'SELECT * FROM incident_response_cases WHERE case_id = ?',
      [identity.case_id],
    );
    return {job, runRow, runCase, attempt, incident};
  }

  function postStateChanged(identity, receipt, state, afterProjection) {
    const {job, runRow, runCase, attempt, incident} = state;
    return !job
      || job.job_type !== 'incident_response_analysis'
      || job.dedupe_key !== identity.stable_group_id
      || afterProjection.payload_sha256 !== identity.expected_job_payload_sha256
      || job.status !== 'completed'
      || Number(job.attempt_count || 0) !== identity.expected_attempt_count
      || job.lease_token !== null || job.lease_expires_at !== null
      || job.last_error !== null || job.processing_started_at !== null
      || Number(job.rerun_requested || 0) !== 0
      || job.completed_at !== receipt.retired_at
      || job.last_completed_at !== receipt.retired_at
      || job.updated_at !== receipt.retired_at
      || sha256(afterProjection) !== receipt.job_after_sha256
      || !runRow || runRow.release_id !== identity.retired_release_id
      || runRow.scope !== 'single_case' || runRow.status !== 'partial'
      || Number(runRow.total_count || 0) !== 1
      || runRow.controlled_dispatch_id !== identity.dispatch_id || !runRow.completed_at
      || !runCase || runCase.group_id !== identity.stable_group_id
      || runCase.representative_alert_id !== identity.representative_alert_id
      || runCase.status !== 'skipped' || runCase.skip_reason !== receipt.skip_reason
      || runCase.latest_error !== null
      || runCase.latest_attempt_id !== identity.expected_attempt_id
      || runCase.analysis_id !== null
      || !attempt || attempt.run_id !== identity.reanalysis_run_id
      || attempt.case_id !== identity.case_id || attempt.group_id !== identity.stable_group_id
      || Number(attempt.durable_attempt_count || 0) !== identity.expected_attempt_count
      || attempt.status !== 'failed' || attempt.analysis_id !== null || !attempt.completed_at
      || !incident || incident.group_id !== identity.stable_group_id
      || incident.representative_alert_id !== identity.representative_alert_id
      || String(incident.latest_analysis_id || '') !== identity.expected_prior_analysis_id
      || incident.agent_status !== receipt.case_agent_status
      || (receipt.case_agent_status === 'analyzed' && incident.latest_error !== null)
      || (receipt.case_agent_status === 'failed' && incident.latest_error !== receipt.skip_reason);
  }

  async function validatePostState(identity, receipt) {
    const state = await loadPostState(identity);
    const afterProjection = projectJob(state.job);
    if (postStateChanged(identity, receipt, state, afterProjection)) {
      throw conflict('controlled evaluation retirement post-state changed');
    }
    const lineageAfter = await projectCensus(identity, 'retired');
    if (sha256(lineageAfter) !== receipt.lineage_after_sha256
      || canonicalJsonText(lineageAfter.members[identity.member_rank - 1])
        !== canonicalJsonText(receipt.target_after)) {
      throw conflict('controlled evaluation retirement post-lineage changed');
    }
  }

  return {replay, validatePostState, validateReceipt};
}

module.exports = {createControlledRetirementReplay};
