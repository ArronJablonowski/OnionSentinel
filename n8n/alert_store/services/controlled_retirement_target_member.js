'use strict';

function createControlledRetirementTargetMember({
  all,
  safeString,
  projectJob,
  projectRun,
  projectRunCase,
  projectAttempt,
  projectError,
  rawSha256,
  conflict,
}) {
  const dependencies = {
    all,
    safeString,
    projectJob,
    projectRun,
    projectRunCase,
    projectAttempt,
    projectError,
    rawSha256,
    conflict,
  };
  for (const [name, value] of Object.entries(dependencies)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function load(runRow) {
    const runCases = await all(
      `SELECT * FROM incident_reanalysis_run_cases
       WHERE run_id = ? ORDER BY case_id LIMIT 3`,
      [runRow.run_id],
    );
    const attempts = await all(
      `SELECT * FROM incident_reanalysis_attempts
       WHERE run_id = ? ORDER BY started_at, attempt_id LIMIT 3`,
      [runRow.run_id],
    );
    return {runCases, attempts, runCase: runCases[0], attempt: attempts[0]};
  }

  function exactLineage(identity, jobPayload, runRow, lineage) {
    const {runCases, attempts, runCase, attempt} = lineage;
    return runCases.length === 1 && runCase
      && runCase.run_id === runRow.run_id
      && runCase.case_id === identity.case_id
      && runCase.group_id === identity.stable_group_id
      && runCase.dashboard_group_id === jobPayload.dashboard_group_id
      && runCase.representative_alert_id === identity.representative_alert_id
      && runCase.latest_attempt_id === identity.expected_attempt_id
      && runCase.analysis_id === null && Boolean(runCase.started_at)
      && attempts.length === 1 && attempt
      && attempt.attempt_id === identity.expected_attempt_id
      && attempt.run_id === identity.reanalysis_run_id
      && attempt.case_id === identity.case_id
      && attempt.group_id === identity.stable_group_id
      && Number(attempt.durable_attempt_count || 0) === identity.expected_attempt_count
      && attempt.status === 'failed' && attempt.analysis_id === null
      && Boolean(attempt.started_at) && Boolean(attempt.completed_at);
  }

  function exactState(targetState, job, runCase, errors) {
    const pending = targetState === 'pending';
    return Boolean(errors.attempt)
      && (!pending || (
        runCase.status === 'queued' && runCase.completed_at === null
        && Boolean(job.processing_started_at) && Boolean(errors.job) && Boolean(errors.runCase)
        && errors.job === errors.runCase && errors.job === errors.attempt
      ))
      && (pending || (
        runCase.status === 'skipped' && Boolean(runCase.completed_at)
        && job.last_error === null && runCase.latest_error === null
      ));
  }

  async function project(identity, member, targetState, job, jobPayload, runRow, runReceipt) {
    const lineage = await load(runRow);
    const errors = {
      job: safeString(job.last_error, 1000),
      runCase: safeString(lineage.runCase?.latest_error, 1000),
      attempt: safeString(lineage.attempt?.latest_error, 1000),
    };
    if (!exactLineage(identity, jobPayload, runRow, lineage)
      || !exactState(targetState, job, lineage.runCase, errors)) {
      throw conflict('controlled evaluation target failure lineage is contradictory');
    }
    return {
      rank: member.rank,
      dispatch_id: member.dispatch_id,
      state: targetState,
      job: projectJob(job),
      run: projectRun(runRow, runReceipt),
      run_case: projectRunCase(lineage.runCase),
      attempt: projectAttempt(lineage.attempt),
      failure: {
        job: projectError(job.last_error),
        run_case: projectError(lineage.runCase.latest_error),
        attempt: projectError(lineage.attempt.latest_error),
        normalized_sha256: rawSha256(errors.attempt),
      },
      case_id: identity.case_id,
      stable_group_id: identity.stable_group_id,
      stable_group_key: identity.stable_group_key,
      representative_alert_id: identity.representative_alert_id,
    };
  }

  return {project};
}

module.exports = {createControlledRetirementTargetMember};
