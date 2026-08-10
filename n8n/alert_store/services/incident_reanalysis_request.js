'use strict';

function createIncidentReanalysisRequest({
  validCaseId,
  normalizeIdentity,
  controlledEvaluationMode,
  safeString,
  replayFrozen,
  bindFrozen,
  releaseId,
  nowUtc,
  randomUuid,
  all,
  get,
  run,
  supersedeCase,
  retirePendingJobs,
  enqueueJob,
  jsonText,
  recordMetric,
  refreshRun,
  conflict,
}) {
  const functions = {validCaseId, normalizeIdentity, safeString, replayFrozen,
    bindFrozen, releaseId, nowUtc, randomUuid, all, get, run, supersedeCase,
    retirePendingJobs, enqueueJob, jsonText, recordMetric, refreshRun, conflict};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function httpError(message, statusCode) {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
  }

  async function loadCases(caseId) {
    return caseId
      ? all(
        `SELECT c.*, CASE WHEN a.alert_id IS NULL THEN 0 ELSE 1 END AS representative_exists,
                a.stable_group_id AS representative_group_id,
                a.stable_group_key AS representative_group_key
         FROM incident_response_cases AS c
         LEFT JOIN alerts AS a ON a.alert_id = c.representative_alert_id
         WHERE c.case_id = ?`,
        [caseId],
      )
      : all(
        `SELECT c.*, CASE WHEN a.alert_id IS NULL THEN 0 ELSE 1 END AS representative_exists,
                a.stable_group_id AS representative_group_id,
                a.stable_group_key AS representative_group_key
         FROM incident_response_cases AS c
         LEFT JOIN alerts AS a ON a.alert_id = c.representative_alert_id
         ORDER BY c.escalated_at ASC, c.case_id ASC`,
      );
  }

  async function prepare(payload, requestedCaseId) {
    const caseId = requestedCaseId ? validCaseId(requestedCaseId) : '';
    if (requestedCaseId && !caseId) throw httpError('valid incident case_id is required', 400);
    const identity = normalizeIdentity(payload);
    const controlledIdentitySupplied = Boolean(identity.representativeAlertIdSupplied
      || identity.stableGroupIdSupplied || identity.stableGroupKeySupplied || identity.cohortId);
    const controlledIncidentDispatch = Boolean(controlledEvaluationMode && identity.cohortId);
    if (!caseId && controlledIdentitySupplied) {
      throw httpError('frozen dispatch identity is supported only for single-case reanalysis', 409);
    }
    const requestedBy = safeString(payload?.requested_by || 'dashboard', 100);
    const reason = safeString(payload?.reason || (caseId
      ? 'Analyst requested fresh Incident Responder analysis'
      : 'Analyst requested fresh analysis of all incident cases'), 1000);
    if (caseId && controlledIncidentDispatch) {
      const replay = await replayFrozen(identity, caseId, requestedBy, reason);
      if (replay) return {replay};
    }
    const context = {
      identity,
      controlledIdentitySupplied,
      controlledIncidentDispatch,
      caseId,
      requestedBy,
      reason,
      releaseId: releaseId(),
      requestedAt: nowUtc(),
      runId: `irr-${randomUuid()}`,
      scope: caseId ? 'single_case' : 'all_cases',
    };
    context.cases = await loadCases(caseId);
    if (caseId && !context.cases.length) throw httpError('incident case not found', 404);
    if (caseId && controlledIdentitySupplied) {
      await bindFrozen(identity, caseId, context.cases[0], context.requestedAt, requestedBy);
    }
    return context;
  }

  function normalizeCase(incident) {
    const storedCaseId = validCaseId(incident.case_id);
    const storedGroupId = safeString(incident.group_id, 64).toLowerCase();
    const representativeGroupId = safeString(incident.representative_group_id, 64).toLowerCase();
    const groupId = representativeGroupId || storedGroupId;
    const dashboardGroupId = safeString(incident.dashboard_group_id, 64).toLowerCase();
    const representativeAlertId = safeString(incident.representative_alert_id, 256);
    let skipReason = '';
    if (!storedCaseId) skipReason = 'Stored case identifier is invalid';
    else if (!groupId) skipReason = 'Stored stable group identifier is missing';
    else if (!representativeAlertId || !Number(incident.representative_exists || 0)) {
      skipReason = 'Stored representative alert no longer exists';
    }
    return {storedCaseId, storedGroupId, representativeGroupId, groupId,
      dashboardGroupId, representativeAlertId, skipReason,
      identityDrift: Boolean(representativeGroupId && representativeGroupId !== storedGroupId)};
  }

  async function recordSkipped(context, incident, normalized) {
    await run(
      `INSERT INTO incident_reanalysis_run_cases (
         run_id, case_id, group_id, dashboard_group_id,
         representative_alert_id, status, skip_reason, completed_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, 'skipped', ?, ?, ?)`,
      [context.runId, String(incident.case_id || ''), normalized.groupId,
        normalized.dashboardGroupId, normalized.representativeAlertId,
        normalized.skipReason, context.requestedAt, context.requestedAt],
    );
  }

  async function migrateIdentity(context, incident, normalized) {
    if (!normalized.identityDrift) return;
    const conflictingCase = await get(
      `SELECT case_id FROM incident_response_cases
       WHERE group_id = ? AND case_id != ?`,
      [normalized.representativeGroupId, normalized.storedCaseId],
    );
    if (conflictingCase) {
      throw httpError('representative alert identity now belongs to another incident case', 409);
    }
    await run(
      `UPDATE incident_response_cases
       SET group_id = ?, updated_at = ?
       WHERE case_id = ? AND group_id = ?`,
      [normalized.representativeGroupId, context.requestedAt,
        normalized.storedCaseId, normalized.storedGroupId],
    );
    const representativeGroupKey = safeString(incident.representative_group_key, 2048);
    if (normalized.storedGroupId && representativeGroupKey) {
      await run(
        `INSERT INTO alert_group_alias (
           legacy_group_id, stable_group_id, stable_group_key, updated_at
         ) VALUES (?, ?, ?, ?)
         ON CONFLICT(legacy_group_id) DO UPDATE SET
           stable_group_id = excluded.stable_group_id,
           stable_group_key = excluded.stable_group_key,
           updated_at = excluded.updated_at`,
        [normalized.storedGroupId, normalized.representativeGroupId,
          representativeGroupKey, context.requestedAt],
      );
    }
  }

  async function retirePriorOwnership(context, incident, normalized) {
    const controlledLegacyJobGroupId = safeString(
      incident.controlled_legacy_job_group_id, 64,
    ).toLowerCase();
    if (controlledLegacyJobGroupId) {
      await retirePendingJobs([controlledLegacyJobGroupId], context.requestedAt);
    }
    if (normalized.identityDrift && normalized.storedGroupId) {
      await run(
        `UPDATE durable_jobs
         SET status = 'completed', lease_expires_at = NULL, lease_token = NULL,
             last_error = NULL, completed_at = COALESCE(completed_at, ?),
             last_completed_at = COALESCE(last_completed_at, ?),
             processing_started_at = NULL, rerun_requested = 0, updated_at = ?
         WHERE job_type = 'incident_response_analysis'
           AND dedupe_key = ? AND status = 'pending'`,
        [context.requestedAt, context.requestedAt, context.requestedAt,
          normalized.storedGroupId],
      );
    }
  }

  function jobPayload(context, normalized) {
    const {identity} = context;
    return {
      agent_role: 'incident-responder',
      case_id: normalized.storedCaseId,
      alert_id: normalized.representativeAlertId,
      group_id: normalized.groupId,
      dashboard_group_id: normalized.dashboardGroupId,
      ...(identity.representativeAlertIdSupplied
        ? {representative_alert_id: normalized.representativeAlertId} : {}),
      ...(identity.stableGroupIdSupplied ? {stable_group_id: normalized.groupId} : {}),
      ...(identity.stableGroupKeySupplied ? {stable_group_key: identity.stableGroupKey} : {}),
      ...(identity.cohortId ? {
        cohort_id: identity.cohortId,
        dispatch_id: identity.dispatchId,
        release_id: identity.releaseId,
        expected_assigned_route: identity.expectedAssignedRoute,
        expected_reviewer_route: identity.expectedReviewerRoute,
        reviewer_required: identity.reviewerRequired,
      } : {}),
      reanalysis_run_id: context.runId,
      reanalysis_release_id: context.releaseId,
      manual_reanalysis: true,
      requested_by: context.requestedBy,
      requested_at: context.requestedAt,
      reason: context.reason,
      related_limit: 500,
      pcap_analysis_limit: 25,
    };
  }

  async function enqueueCase(context, normalized) {
    await run(
      `INSERT INTO incident_reanalysis_run_cases (
         run_id, case_id, group_id, dashboard_group_id,
         representative_alert_id, status, queued_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)`,
      [context.runId, normalized.storedCaseId, normalized.groupId,
        normalized.dashboardGroupId, normalized.representativeAlertId,
        context.requestedAt, context.requestedAt],
    );
    await enqueueJob(
      'incident_response_analysis', normalized.groupId,
      jobPayload(context, normalized), {priority: 1200, maxAttempts: 12},
    );
    await run(
      `UPDATE incident_response_cases
       SET agent_status = 'queued', latest_error = NULL, updated_at = ?
       WHERE case_id = ?`,
      [context.requestedAt, normalized.storedCaseId],
    );
    await run(
      `INSERT INTO incident_response_events (
         case_id, event_type, actor, detail_json, created_at
       ) VALUES (?, 'reanalysis_queued', ?, ?, ?)`,
      [normalized.storedCaseId, context.requestedBy, jsonText({
        run_id: context.runId,
        release_id: context.releaseId,
        ...(context.identity.representativeAlertIdSupplied
          ? {representative_alert_id: normalized.representativeAlertId} : {}),
        ...(context.identity.stableGroupIdSupplied
          ? {stable_group_id: normalized.groupId} : {}),
        ...(context.identity.stableGroupKeySupplied
          ? {stable_group_key: context.identity.stableGroupKey} : {}),
        ...(context.identity.cohortId ? {
          cohort_id: context.identity.cohortId,
          dispatch_id: context.identity.dispatchId,
          expected_assigned_route: context.identity.expectedAssignedRoute,
          expected_reviewer_route: context.identity.expectedReviewerRoute,
          reviewer_required: context.identity.reviewerRequired,
        } : {}),
        reason: context.reason,
      }), context.requestedAt],
    );
    await recordMetric('incident_response_analysis', 'enqueued', normalized.groupId, {
      eventKey: `incident_response_analysis:reanalysis:${context.runId}:${normalized.storedCaseId}`,
    });
  }

  async function processCase(context, incident) {
    const normalized = normalizeCase(incident);
    if (normalized.skipReason) return recordSkipped(context, incident, normalized);
    await migrateIdentity(context, incident, normalized);
    await supersedeCase(normalized.storedCaseId, context.runId, context.requestedAt);
    await retirePriorOwnership(context, incident, normalized);
    return enqueueCase(context, normalized);
  }

  async function sealReceipt(context) {
    const {identity} = context;
    const receipt = {
      ok: true,
      ...(await refreshRun(context.runId)),
      ...(identity.representativeAlertIdSupplied
        ? {representative_alert_id: identity.representativeAlertId} : {}),
      ...(identity.stableGroupIdSupplied ? {stable_group_id: identity.stableGroupId} : {}),
      ...(identity.stableGroupKeySupplied ? {stable_group_key: identity.stableGroupKey} : {}),
      ...(identity.cohortId ? {
        ...(context.controlledIncidentDispatch ? {case_id: context.caseId} : {}),
        cohort_id: identity.cohortId,
        dispatch_id: identity.dispatchId,
        release_id: identity.releaseId,
        expected_assigned_route: identity.expectedAssignedRoute,
        expected_reviewer_route: identity.expectedReviewerRoute,
        reviewer_required: identity.reviewerRequired,
      } : {}),
    };
    if (context.controlledIncidentDispatch) {
      const storedReceipt = await run(
        `UPDATE incident_reanalysis_runs
         SET controlled_receipt_json = ?
         WHERE run_id = ? AND controlled_dispatch_id = ?
           AND controlled_receipt_json IS NULL`,
        [jsonText(receipt), context.runId, identity.dispatchId],
      );
      if (Number(storedReceipt.changes || 0) !== 1) {
        throw conflict('controlled incident dispatch receipt could not be sealed');
      }
    }
    return receipt;
  }

  async function request(payload, requestedCaseId = '') {
    const context = await prepare(payload, requestedCaseId);
    if (context.replay) return context.replay;
    await run(
      `INSERT INTO incident_reanalysis_runs (
         run_id, release_id, scope, status, requested_by, reason,
         total_count, created_at, updated_at, controlled_dispatch_id
       ) VALUES (?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?)`,
      [context.runId, context.releaseId, context.scope, context.requestedBy,
        context.reason, context.cases.length, context.requestedAt, context.requestedAt,
        context.controlledIncidentDispatch ? context.identity.dispatchId : null],
    );
    for (const incident of context.cases) await processCase(context, incident);
    return sealReceipt(context);
  }

  return {request};
}

module.exports = {createIncidentReanalysisRequest};
