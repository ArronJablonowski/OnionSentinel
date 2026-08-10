'use strict';

function createControlledRetirementCensus({
  all,
  orderedDispatches,
  parseJobPayload,
  validIncidentCaseId,
  stableGroupIdPattern,
  validPinnedStableGroupKey,
  representativeAlertIdPattern,
  parseJsonObject,
  projectCompleted,
  projectTarget,
  conflict,
}) {
  const functions = {
    all,
    orderedDispatches,
    parseJobPayload,
    validIncidentCaseId,
    validPinnedStableGroupKey,
    parseJsonObject,
    projectCompleted,
    projectTarget,
    conflict,
  };
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  for (const [name, value] of Object.entries({stableGroupIdPattern,
    representativeAlertIdPattern})) {
    if (!value || typeof value.test !== 'function') throw new TypeError(`${name} must be a pattern`);
  }

  async function loadRows(identity, dispatchIds, placeholders, rowLimit) {
    const jobs = await all(
      `SELECT * FROM durable_jobs
       WHERE job_type = 'incident_response_analysis'
         AND (
           CASE WHEN json_valid(payload_json)
             THEN json_extract(payload_json, '$.cohort_id')
             ELSE NULL
           END = ?
           OR CASE WHEN json_valid(payload_json)
             THEN json_extract(payload_json, '$.dispatch_id')
             ELSE NULL
           END IN (${placeholders})
         )
       ORDER BY id ASC LIMIT ?`,
      [identity.cohort_id, ...dispatchIds, rowLimit],
    );
    const runRows = await all(
      `SELECT * FROM incident_reanalysis_runs
       WHERE controlled_dispatch_id IN (${placeholders})
          OR (
            controlled_receipt_json IS NOT NULL
            AND CASE WHEN json_valid(controlled_receipt_json)
              THEN json_extract(controlled_receipt_json, '$.cohort_id')
              ELSE NULL
            END = ?
          )
       ORDER BY created_at, run_id LIMIT ?`,
      [...dispatchIds, identity.cohort_id, rowLimit],
    );
    return {jobs, runRows};
  }

  function indexJobs(identity, dispatchIds, jobs) {
    const indexed = new Map();
    for (const job of jobs) {
      const jobPayload = parseJobPayload(job);
      const dispatchId = jobPayload.dispatch_id;
      if (job.job_type !== 'incident_response_analysis'
        || Number(job.priority || 0) !== 1200
        || Number(job.max_attempts || 0) !== 12
        || jobPayload.agent_role !== 'incident-responder'
        || jobPayload.manual_reanalysis !== true
        || jobPayload.cohort_id !== identity.cohort_id
        || !dispatchIds.includes(dispatchId)
        || jobPayload.release_id !== identity.retired_release_id
        || jobPayload.reanalysis_release_id !== identity.retired_release_id
        || !/^irr-[a-z0-9-]{1,64}$/.test(String(jobPayload.reanalysis_run_id || ''))
        || !validIncidentCaseId(jobPayload.case_id)
        || validIncidentCaseId(jobPayload.case_id) !== jobPayload.case_id
        || typeof jobPayload.dashboard_group_id !== 'string'
        || !jobPayload.dashboard_group_id
        || !stableGroupIdPattern.test(String(jobPayload.stable_group_id || ''))
        || jobPayload.group_id !== jobPayload.stable_group_id
        || job.dedupe_key !== jobPayload.stable_group_id
        || !validPinnedStableGroupKey(jobPayload.stable_group_key)
        || !representativeAlertIdPattern.test(String(jobPayload.representative_alert_id || ''))
        || jobPayload.alert_id !== jobPayload.representative_alert_id
        || indexed.has(dispatchId)) {
        throw conflict('controlled evaluation cohort job census is ambiguous');
      }
      indexed.set(dispatchId, {job, jobPayload});
    }
    return indexed;
  }

  function indexRuns(identity, dispatchIds, runRows) {
    const indexed = new Map();
    for (const runRow of runRows) {
      const runReceipt = parseJsonObject(runRow.controlled_receipt_json);
      const dispatchId = String(runRow.controlled_dispatch_id || '');
      if (!dispatchIds.includes(dispatchId)
        || runRow.release_id !== identity.retired_release_id
        || runReceipt.ok !== true
        || runReceipt.cohort_id !== identity.cohort_id
        || runReceipt.dispatch_id !== dispatchId
        || runReceipt.release_id !== identity.retired_release_id
        || indexed.has(dispatchId)) {
        throw conflict('controlled evaluation cohort run census is ambiguous');
      }
      indexed.set(dispatchId, {runRow, runReceipt});
    }
    return indexed;
  }

  function bindingChanged(jobPayload, runRow, runReceipt) {
    return jobPayload.reanalysis_run_id !== runRow.run_id
      || runReceipt.run_id !== runRow.run_id
      || runReceipt.case_id !== jobPayload.case_id
      || runReceipt.representative_alert_id !== jobPayload.representative_alert_id
      || runReceipt.stable_group_id !== jobPayload.stable_group_id
      || runReceipt.stable_group_key !== jobPayload.stable_group_key;
  }

  function targetChanged(identity, member, targetState, job, jobPayload, runRow) {
    const expectedJobStatus = targetState === 'pending' ? 'pending' : 'completed';
    const expectedRunStatus = targetState === 'pending' ? 'queued' : 'partial';
    return member.rank !== identity.member_rank
      || member.dispatch_id !== identity.dispatch_id
      || Number(job.id || 0) !== identity.job_id
      || jobPayload.case_id !== identity.case_id
      || jobPayload.reanalysis_run_id !== identity.reanalysis_run_id
      || jobPayload.stable_group_id !== identity.stable_group_id
      || jobPayload.stable_group_key !== identity.stable_group_key
      || jobPayload.representative_alert_id !== identity.representative_alert_id
      || runRow.run_id !== identity.reanalysis_run_id
      || job.status !== expectedJobStatus
      || Number(job.attempt_count || 0) !== identity.expected_attempt_count
      || runRow.status !== expectedRunStatus
      || Number(runRow.total_count || 0) !== 1;
  }

  async function projectMember(identity, targetState, member, jobsByDispatch, runsByDispatch) {
    const jobBinding = jobsByDispatch.get(member.dispatch_id);
    const runBinding = runsByDispatch.get(member.dispatch_id);
    if (member.expected_state === 'absent') {
      if (jobBinding || runBinding) {
        throw conflict(`controlled evaluation rank ${member.rank} is not absent`);
      }
      return {rank: member.rank, dispatch_id: member.dispatch_id, state: 'absent'};
    }
    if (!jobBinding || !runBinding) {
      throw conflict(`controlled evaluation rank ${member.rank} lineage is missing`);
    }
    const {job, jobPayload} = jobBinding;
    const {runRow, runReceipt} = runBinding;
    if (bindingChanged(jobPayload, runRow, runReceipt)) {
      throw conflict(`controlled evaluation rank ${member.rank} job/run binding changed`);
    }
    if (member.expected_state === 'completed') {
      return projectCompleted(identity, member, job, jobPayload, runRow, runReceipt);
    }
    if (targetChanged(identity, member, targetState, job, jobPayload, runRow)) {
      throw conflict('controlled evaluation target rank census changed');
    }
    return projectTarget(identity, member, targetState, job, jobPayload, runRow, runReceipt);
  }

  async function project(identity, targetState) {
    if (!['pending', 'retired'].includes(targetState)) {
      throw conflict('controlled evaluation retirement census state is invalid');
    }
    const members = orderedDispatches(identity);
    const dispatchIds = members.map((member) => member.dispatch_id);
    const placeholders = dispatchIds.map(() => '?').join(', ');
    const rowLimit = identity.cohort_size + 2;
    const {jobs, runRows} = await loadRows(identity, dispatchIds, placeholders, rowLimit);
    if (jobs.length !== identity.member_rank || runRows.length !== identity.member_rank
      || jobs.length >= rowLimit || runRows.length >= rowLimit) {
      throw conflict('controlled evaluation cohort job/run census is not exact');
    }
    const jobsByDispatch = indexJobs(identity, dispatchIds, jobs);
    const runsByDispatch = indexRuns(identity, dispatchIds, runRows);
    const projection = {
      cohort_id: identity.cohort_id,
      cohort_size: identity.cohort_size,
      release_id: identity.retired_release_id,
      target_rank: identity.member_rank,
      members: [],
    };
    for (const member of members) {
      projection.members.push(
        await projectMember(identity, targetState, member, jobsByDispatch, runsByDispatch),
      );
    }
    return projection;
  }

  return {project};
}

module.exports = {createControlledRetirementCensus};
