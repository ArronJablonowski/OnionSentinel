'use strict';

function createControlledRetirementProjections({rawSha256, sha256, safeString, parseTimestamp}) {
  for (const [name, value] of Object.entries({rawSha256, sha256, safeString, parseTimestamp})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  const error = (value) => {
    if (value === null || value === undefined) return {raw_sha256: null, normalized_sha256: null};
    const raw = String(value), normalized = safeString(raw, 1000);
    return {raw_sha256: rawSha256(raw), normalized_sha256: normalized ? rawSha256(normalized) : null};
  };
  const job = (row) => { const payloadJson = String(row?.payload_json || ''); return {
    id: Number(row?.id || 0), job_type: String(row?.job_type || ''), dedupe_key: String(row?.dedupe_key || ''),
    payload_sha256: rawSha256(payloadJson), status: String(row?.status || ''), priority: Number(row?.priority || 0),
    attempt_count: Number(row?.attempt_count || 0), max_attempts: Number(row?.max_attempts || 0),
    next_attempt_at: row?.next_attempt_at ?? null, lease_expires_at: row?.lease_expires_at ?? null,
    lease_token_present: Boolean(row?.lease_token), last_error_sha256: row?.last_error ? rawSha256(row.last_error) : null,
    created_at: row?.created_at ?? null, updated_at: row?.updated_at ?? null,
    completed_at: row?.completed_at ?? null, last_completed_at: row?.last_completed_at ?? null,
    requested_at: row?.requested_at ?? null, processing_started_at: row?.processing_started_at ?? null,
    rerun_requested: Number(row?.rerun_requested || 0)}; };
  const orderedDispatches = (identity) => [...identity.completed_dispatch_ids, identity.dispatch_id,
    ...identity.absent_dispatch_ids].map((dispatchId, index) => ({rank: index + 1, dispatch_id: dispatchId,
      expected_state: index + 1 < identity.member_rank ? 'completed'
        : (index + 1 === identity.member_rank ? 'target' : 'absent')}));
  const run = (row, receipt) => ({run_id: String(row?.run_id || ''), release_id: String(row?.release_id || ''),
    scope: String(row?.scope || ''), status: String(row?.status || ''), requested_by: row?.requested_by ?? null,
    reason_sha256: row?.reason == null ? null : rawSha256(row.reason), total_count: Number(row?.total_count || 0),
    created_at: row?.created_at ?? null, updated_at: row?.updated_at ?? null,
    completed_at: row?.completed_at ?? null, controlled_dispatch_id: row?.controlled_dispatch_id ?? null,
    controlled_receipt_sha256: sha256(receipt || {})});
  const runCase = (row) => ({run_id: String(row?.run_id || ''), case_id: String(row?.case_id || ''),
    group_id: String(row?.group_id || ''), dashboard_group_id: String(row?.dashboard_group_id || ''),
    representative_alert_id: String(row?.representative_alert_id || ''), status: String(row?.status || ''),
    skip_reason_sha256: row?.skip_reason == null ? null : rawSha256(row.skip_reason), latest_error: error(row?.latest_error),
    queued_at: row?.queued_at ?? null, started_at: row?.started_at ?? null, completed_at: row?.completed_at ?? null,
    latest_attempt_id: row?.latest_attempt_id ?? null, analysis_id: row?.analysis_id ?? null,
    executed_model: row?.executed_model ?? null, executed_provider: row?.executed_provider ?? null,
    executed_model_path: row?.executed_model_path ?? null, result_generated_at: row?.result_generated_at ?? null,
    updated_at: row?.updated_at ?? null});
  const attempt = (row) => ({attempt_id: String(row?.attempt_id || ''), run_id: String(row?.run_id || ''),
    case_id: String(row?.case_id || ''), group_id: String(row?.group_id || ''),
    durable_attempt_count: Number(row?.durable_attempt_count || 0), status: String(row?.status || ''),
    latest_error: error(row?.latest_error), analysis_id: row?.analysis_id ?? null,
    executed_model: row?.executed_model ?? null, executed_provider: row?.executed_provider ?? null,
    executed_model_path: row?.executed_model_path ?? null, result_generated_at: row?.result_generated_at ?? null,
    started_at: row?.started_at ?? null, completed_at: row?.completed_at ?? null, updated_at: row?.updated_at ?? null});
  const primary = (row) => ({analysis_id: String(row?.analysis_id || ''), group_id: String(row?.group_id || ''),
    alert_id: String(row?.alert_id || ''), agent_role: String(row?.agent_role || ''), generated_at: row?.generated_at ?? null,
    model: row?.model ?? null, model_path: row?.model_path ?? null, detection_outcome: row?.detection_outcome ?? null,
    bluf_sha256: row?.bluf == null ? null : rawSha256(row.bluf), summary_sha256: row?.summary == null ? null : rawSha256(row.summary),
    confidence: row?.confidence ?? null, artifact_path: row?.artifact_path ?? null, evidence_hash: row?.evidence_hash ?? null,
    response_sha256: rawSha256(row?.response_json || ''), created_at: row?.created_at ?? null});
  const reviewer = (row) => ({analysis_id: String(row?.analysis_id || ''), group_id: String(row?.group_id || ''),
    alert_id: String(row?.alert_id || ''), agent_role: String(row?.agent_role || ''), trigger: row?.trigger ?? null,
    status: String(row?.status || ''), reviewer_error: error(row?.reviewer_error), primary_model: row?.primary_model ?? null,
    primary_model_path: row?.primary_model_path ?? null, primary_outcome: row?.primary_outcome ?? null,
    primary_confidence: row?.primary_confidence ?? null, reviewer_model: row?.reviewer_model ?? null,
    reviewer_model_path: row?.reviewer_model_path ?? null,
    reviewer_model_route: row?.reviewer_model_route ?? null,
    reviewer_outcome: row?.reviewer_outcome ?? null,
    reviewer_confidence: row?.reviewer_confidence ?? null, agreement: row?.agreement ?? null,
    material_disagreement: Number(row?.material_disagreement || 0), disputed_fields_sha256: rawSha256(row?.disputed_fields_json || ''),
    comparison_sha256: rawSha256(row?.comparison_json || ''), reviewer_runtime_seconds: row?.reviewer_runtime_seconds == null
      ? null : String(row.reviewer_runtime_seconds), memory_candidates_promoted: Number(row?.memory_candidates_promoted || 0),
    generated_at: row?.generated_at ?? null, created_at: row?.created_at ?? null, updated_at: row?.updated_at ?? null});
  const completedLifecycleValid = (value) => { const times = ['requested_at', 'processing_started_at', 'completed_at',
    'last_completed_at', 'updated_at'].map((key) => parseTimestamp(value?.[key]));
    return Boolean(times.every(Boolean) && times.every((time, index) => !index || times[index - 1].getTime() <= time.getTime())); };
  function completed({member, job: jobRow, jobPayload, runRow, runReceipt, runCase: runCaseRow,
    attempt: attemptRow, analysis, reviewer: reviewerRow, incident}) { return {
    rank: member.rank, dispatch_id: member.dispatch_id, state: 'completed', job: job(jobRow), run: run(runRow, runReceipt),
    run_case: runCase(runCaseRow), attempt: attempt(attemptRow), primary: primary(analysis), reviewer: reviewer(reviewerRow),
    case: {case_id: String(incident.case_id || ''), group_id: String(incident.group_id || ''),
      dashboard_group_id: String(incident.dashboard_group_id || ''), representative_alert_id: String(incident.representative_alert_id || ''),
      agent_status: String(incident.agent_status || ''), latest_analysis_id: incident.latest_analysis_id ?? null,
      latest_model: incident.latest_model ?? null, latest_generated_at: incident.latest_generated_at ?? null,
      latest_error: error(incident.latest_error), updated_at: incident.updated_at ?? null},
    stable_group_key: String(jobPayload.stable_group_key || '')}; }
  return {job, orderedDispatches, error, run, runCase, attempt, primary, reviewer, completedLifecycleValid, completed};
}
module.exports = {createControlledRetirementProjections};
