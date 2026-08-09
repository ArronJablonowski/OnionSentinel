'use strict';

function createControlledRetirementCompletedMember({
  all, get, parseJsonObject, incidentAnalysisProvider,
  completedJobLifecycleValid, projectCompleted, conflict,
}) {
  for (const [name, value] of Object.entries({all, get, parseJsonObject,
    incidentAnalysisProvider, completedJobLifecycleValid, projectCompleted, conflict})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function load(runRow, jobPayload) {
    const runCases = await all(
      `SELECT * FROM incident_reanalysis_run_cases
       WHERE run_id = ? ORDER BY case_id LIMIT 3`, [runRow.run_id]);
    const attempts = await all(
      `SELECT * FROM incident_reanalysis_attempts
       WHERE run_id = ? ORDER BY started_at, attempt_id LIMIT 3`, [runRow.run_id]);
    const runCase = runCases[0], attempt = attempts[0];
    const analysis = runCase?.analysis_id
      ? await get('SELECT * FROM ai_analysis_runs WHERE analysis_id = ?', [runCase.analysis_id]) : null;
    const reviewer = runCase?.analysis_id
      ? await get('SELECT * FROM ai_second_opinion_runs WHERE analysis_id = ?', [runCase.analysis_id]) : null;
    const incident = jobPayload.case_id
      ? await get('SELECT * FROM incident_response_cases WHERE case_id = ?', [jobPayload.case_id]) : null;
    return {runCases, attempts, runCase, attempt, analysis, reviewer, incident};
  }

  function validJobRun(identity, member, job, jobPayload, runRow, runReceipt) {
    return job.status === 'completed' && Number(job.attempt_count || 0) === 1
      && job.lease_token === null && job.lease_expires_at === null && job.last_error === null
      && Number(job.rerun_requested || 0) === 0 && completedJobLifecycleValid(job)
      && runRow && runRow.release_id === identity.retired_release_id
      && runRow.scope === 'single_case' && runRow.status === 'completed'
      && Number(runRow.total_count || 0) === 1
      && runRow.controlled_dispatch_id === member.dispatch_id && Boolean(runRow.completed_at)
      && runReceipt.ok === true && runReceipt.run_id === runRow.run_id
      && runReceipt.case_id === jobPayload.case_id && runReceipt.cohort_id === identity.cohort_id
      && runReceipt.dispatch_id === member.dispatch_id
      && runReceipt.release_id === identity.retired_release_id && runReceipt.scope === 'single_case'
      && Number(runReceipt.total_count || 0) === 1
      && runReceipt.representative_alert_id === jobPayload.representative_alert_id
      && runReceipt.stable_group_id === jobPayload.stable_group_id
      && runReceipt.stable_group_key === jobPayload.stable_group_key;
  }

  function validRunCaseAttempt(jobPayload, runRow, lineage, primaryProvider) {
    const {runCases, attempts, runCase, attempt, analysis} = lineage;
    return runCases.length === 1 && runCase && runCase.case_id === jobPayload.case_id
      && runCase.group_id === jobPayload.stable_group_id
      && runCase.dashboard_group_id === jobPayload.dashboard_group_id
      && runCase.representative_alert_id === jobPayload.representative_alert_id
      && runCase.status === 'completed' && runCase.skip_reason === null && runCase.latest_error === null
      && Boolean(runCase.latest_attempt_id) && Boolean(runCase.analysis_id) && Boolean(runCase.completed_at)
      && runCase.executed_model === analysis?.model && runCase.executed_provider === primaryProvider
      && runCase.executed_model_path === analysis?.model_path && attempts.length === 1 && attempt
      && attempt.attempt_id === runCase.latest_attempt_id && attempt.run_id === runRow.run_id
      && attempt.case_id === jobPayload.case_id && attempt.group_id === jobPayload.stable_group_id
      && Number(attempt.durable_attempt_count || 0) === 1 && attempt.status === 'completed'
      && attempt.latest_error === null && attempt.analysis_id === runCase.analysis_id
      && Boolean(attempt.completed_at) && attempt.executed_model === analysis?.model
      && attempt.executed_provider === primaryProvider && attempt.executed_model_path === analysis?.model_path;
  }

  function validAnalysisReviewerIncident(jobPayload, lineage) {
    const {runCase, attempt, analysis, reviewer, incident} = lineage;
    const runtime = reviewer?.reviewer_runtime_seconds;
    return analysis && analysis.group_id === jobPayload.stable_group_id
      && analysis.alert_id === jobPayload.representative_alert_id
      && analysis.agent_role === 'incident-responder' && Boolean(analysis.generated_at)
      && Boolean(analysis.response_json) && runCase.result_generated_at === analysis.generated_at
      && attempt.result_generated_at === analysis.generated_at && reviewer
      && reviewer.group_id === jobPayload.stable_group_id
      && reviewer.alert_id === jobPayload.representative_alert_id
      && reviewer.agent_role === 'incident-responder' && reviewer.status === 'completed'
      && !Boolean(reviewer.reviewer_error) && reviewer.generated_at === analysis.generated_at
      && reviewer.primary_model === analysis.model && reviewer.primary_model_path === analysis.model_path
      && reviewer.primary_outcome === analysis.detection_outcome
      && reviewer.primary_confidence === analysis.confidence && Boolean(reviewer.reviewer_model)
      && (runtime == null || (Number.isFinite(Number(runtime)) && Number(runtime) >= 0))
      && incident && incident.group_id === jobPayload.stable_group_id
      && incident.dashboard_group_id === jobPayload.dashboard_group_id
      && incident.representative_alert_id === jobPayload.representative_alert_id
      && incident.agent_status === 'analyzed' && incident.latest_analysis_id === analysis.analysis_id
      && incident.latest_model === analysis.model && incident.latest_generated_at === analysis.generated_at;
  }

  async function project(identity, member, job, jobPayload, runRow, runReceipt) {
    const lineage = await load(runRow, jobPayload);
    const response = parseJsonObject(lineage.analysis?.response_json);
    const primaryProvider = incidentAnalysisProvider(lineage.analysis?.model_path, response._analysis_provider);
    if (!validJobRun(identity, member, job, jobPayload, runRow, runReceipt)
      || !validRunCaseAttempt(jobPayload, runRow, lineage, primaryProvider)
      || !validAnalysisReviewerIncident(jobPayload, lineage)) {
      throw conflict(`controlled evaluation rank ${member.rank} is not one exact completed primary-and-reviewer lineage`);
    }
    return projectCompleted({member, job, jobPayload, runRow, runReceipt,
      runCase: lineage.runCase, attempt: lineage.attempt, analysis: lineage.analysis,
      reviewer: lineage.reviewer, incident: lineage.incident});
  }
  return {project};
}
module.exports = {createControlledRetirementCompletedMember};
