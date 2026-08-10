'use strict';

function createManualAnalysisDispatch({
  get, run, safeString, normalizeIdentity, conflict, rejectProcessingJob,
  enqueueJob, recordMetric, nowUtc, jsonText, sha256Text,
}) {
  for (const [name, value] of Object.entries({
    get, run, safeString, normalizeIdentity, conflict, rejectProcessingJob,
    enqueueJob, recordMetric, nowUtc, jsonText, sha256Text,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function resolveDashboardAlertGroup(dashboardGroupId, identity = {}) {
    let representative = await get(
      `SELECT a.alert_id, a.stable_group_id, a.stable_group_key
       FROM alert_group_summary AS g
       JOIN alerts AS a ON a.alert_id = g.representative_alert_id
       WHERE g.group_id = ?`,
      [dashboardGroupId],
    );
    if (!representative) {
      representative = await get(
        `SELECT a.alert_id, a.stable_group_id, a.stable_group_key
         FROM alert_group_alias AS ga
         JOIN alerts AS a ON a.stable_group_id = ga.stable_group_id
         WHERE ga.legacy_group_id = ?
         ORDER BY replace(replace(COALESCE(NULLIF(a.last_seen, ''), NULLIF(a.timestamp, ''), NULLIF(a.first_seen, '')), 'T', ' '), 'Z', '') DESC,
                  a.alert_id DESC LIMIT 1`,
        [dashboardGroupId],
      );
    }
    if (!representative) return null;

    const resolvedStableGroupId = typeof representative.stable_group_id === 'string'
      ? representative.stable_group_id : '';
    const resolvedStableGroupKey = typeof representative.stable_group_key === 'string'
      ? representative.stable_group_key : '';
    if (identity.stableGroupIdSupplied && identity.stableGroupId !== resolvedStableGroupId) {
      const error = new Error('requested stable_group_id no longer matches the dashboard group');
      error.statusCode = 409;
      throw error;
    }
    if (identity.stableGroupKeySupplied && identity.stableGroupKey !== resolvedStableGroupKey) {
      throw conflict('requested stable_group_key no longer matches the dashboard group');
    }
    if (!identity.representativeAlertIdSupplied) return representative;

    const pinned = await get(
      `SELECT alert_id, stable_group_id, stable_group_key
       FROM alerts WHERE alert_id = ? LIMIT 1`,
      [identity.representativeAlertId],
    );
    const pinnedStableGroupId = typeof pinned?.stable_group_id === 'string'
      ? pinned.stable_group_id : '';
    const pinnedStableGroupKey = typeof pinned?.stable_group_key === 'string'
      ? pinned.stable_group_key : '';
    if (
      !pinned?.alert_id
      || !resolvedStableGroupId
      || pinnedStableGroupId !== resolvedStableGroupId
      || (identity.stableGroupIdSupplied && pinnedStableGroupId !== identity.stableGroupId)
      || (resolvedStableGroupKey && pinnedStableGroupKey !== resolvedStableGroupKey)
      || (identity.stableGroupKeySupplied && pinnedStableGroupKey !== identity.stableGroupKey)
    ) {
      const error = new Error(
        'requested representative_alert_id no longer belongs to the dashboard group',
      );
      error.statusCode = 409;
      throw error;
    }
    return pinned;
  }

  async function requestAiReanalysis(payload) {
    const dashboardGroupId = safeString(payload?.group_id, 64).toLowerCase();
    if (!/^[a-f0-9]{12}$/.test(dashboardGroupId)) {
      const error = new Error('valid dashboard group_id is required');
      error.statusCode = 400;
      throw error;
    }
    const identity = normalizeIdentity(payload);
    const representative = await resolveDashboardAlertGroup(dashboardGroupId, identity);
    const stableGroupId = safeString(representative?.stable_group_id, 64).toLowerCase();
    if (!representative?.alert_id || !stableGroupId) {
      const error = new Error('SOC alert group was not found');
      error.statusCode = 404;
      throw error;
    }
    const requestedRelatedLimit = Number(payload?.related_limit ?? 250);
    const requestedPcapLimit = Number(payload?.pcap_analysis_limit ?? 8);
    if (!Number.isFinite(requestedRelatedLimit) || !Number.isFinite(requestedPcapLimit)) {
      const error = new Error('AI analysis queue limits must be finite numbers');
      error.statusCode = 400;
      throw error;
    }
    const relatedLimit = Math.max(1, Math.min(500, Math.trunc(requestedRelatedLimit)));
    const pcapAnalysisLimit = Math.max(1, Math.min(25, Math.trunc(requestedPcapLimit)));
    const requestedBy = safeString(payload?.requested_by || 'dashboard', 100);
    const requestedAt = nowUtc();
    if (identity.cohortId) await rejectProcessingJob('ai_analysis', [stableGroupId]);
    await enqueueJob('ai_analysis', stableGroupId, {
      alert_id: representative.alert_id,
      group_id: stableGroupId,
      dashboard_group_id: dashboardGroupId,
      ...(identity.representativeAlertIdSupplied
        ? {representative_alert_id: representative.alert_id} : {}),
      ...(identity.stableGroupIdSupplied ? {stable_group_id: stableGroupId} : {}),
      ...(identity.stableGroupKeySupplied ? {stable_group_key: identity.stableGroupKey} : {}),
      ...(identity.cohortId ? {
        cohort_id: identity.cohortId,
        dispatch_id: identity.dispatchId,
        release_id: identity.releaseId,
        expected_assigned_route: identity.expectedAssignedRoute,
        expected_reviewer_route: identity.expectedReviewerRoute,
        reviewer_required: identity.reviewerRequired,
        agent_role: 'soc-analyst',
      } : {}),
      manual_reanalysis: true,
      requested_by: requestedBy,
      requested_at: requestedAt,
      reason: safeString(payload?.reason || 'SOC analyst requested fresh AI analysis', 500),
      related_limit: relatedLimit,
      pcap_analysis_limit: pcapAnalysisLimit,
    }, {priority: 1000, maxAttempts: 12});
    await recordMetric('ai_analysis', 'enqueued', stableGroupId, {
      eventKey: `ai_analysis:manual:${stableGroupId}:${requestedAt}`,
    });
    return {
      ok: true,
      status: 'queued',
      group_id: dashboardGroupId,
      queue_group_id: stableGroupId,
      representative_alert_id: representative.alert_id,
      ...(identity.stableGroupIdSupplied ? {stable_group_id: stableGroupId} : {}),
      ...(identity.stableGroupKeySupplied ? {stable_group_key: identity.stableGroupKey} : {}),
      ...(identity.cohortId ? {
        cohort_id: identity.cohortId,
        dispatch_id: identity.dispatchId,
        release_id: identity.releaseId,
        expected_assigned_route: identity.expectedAssignedRoute,
        expected_reviewer_route: identity.expectedReviewerRoute,
        reviewer_required: identity.reviewerRequired,
      } : {}),
      requested_at: requestedAt,
    };
  }

  async function requestIncidentEscalation(payload) {
    const dashboardGroupId = safeString(payload?.group_id, 64).toLowerCase();
    if (!/^[a-f0-9]{12}$/.test(dashboardGroupId)) {
      const error = new Error('valid dashboard group_id is required');
      error.statusCode = 400;
      throw error;
    }
    const identity = normalizeIdentity(payload);
    const representative = await resolveDashboardAlertGroup(dashboardGroupId, identity);
    const stableGroupId = safeString(representative?.stable_group_id, 64).toLowerCase();
    if (!representative?.alert_id || !stableGroupId) {
      const error = new Error('SOC alert group was not found');
      error.statusCode = 404;
      throw error;
    }
    return queueIncidentResponseForGroup({
      dashboardGroupId,
      representative,
      requestedBy: payload?.requested_by || 'dashboard',
      reason: payload?.reason || 'Escalated from SOC Alerts for incident response',
      relatedLimit: payload?.related_limit ?? 250,
      pcapAnalysisLimit: payload?.pcap_analysis_limit ?? 25,
      manualReanalysis: false,
      eventType: 'escalated',
      priority: 1100,
      cohortId: identity.cohortId,
      dispatchId: identity.dispatchId,
      releaseId: identity.releaseId,
      expectedAssignedRoute: identity.expectedAssignedRoute,
      expectedReviewerRoute: identity.expectedReviewerRoute,
      reviewerRequired: identity.reviewerRequired,
      representativeAlertIdPinned: identity.representativeAlertIdSupplied,
      stableGroupIdPinned: identity.stableGroupIdSupplied,
      stableGroupKey: identity.stableGroupKey,
      stableGroupKeyPinned: identity.stableGroupKeySupplied,
    });
  }

  async function queueIncidentResponseForGroup({
    dashboardGroupId, representative, requestedBy = 'dashboard',
    reason = 'Escalated from SOC Alerts for incident response', relatedLimit = 250,
    pcapAnalysisLimit = 25, manualReanalysis = false, eventType = 'escalated',
    priority = 1100, cohortId = '', dispatchId = '', releaseId = '',
    expectedAssignedRoute = '', expectedReviewerRoute = '', reviewerRequired = false,
    representativeAlertIdPinned = false, stableGroupIdPinned = false,
    stableGroupKey = '', stableGroupKeyPinned = false,
  }) {
    const stableGroupId = safeString(representative?.stable_group_id, 64).toLowerCase();
    if (!representative?.alert_id || !stableGroupId) {
      const error = new Error('resolved SOC alert group is missing its stable identity');
      error.statusCode = 409;
      throw error;
    }
    const requestedRelatedLimit = Number(relatedLimit);
    const requestedPcapLimit = Number(pcapAnalysisLimit);
    if (!Number.isFinite(requestedRelatedLimit) || !Number.isFinite(requestedPcapLimit)) {
      const error = new Error('Incident response queue limits must be finite numbers');
      error.statusCode = 400;
      throw error;
    }
    const requestedAt = nowUtc();
    const actor = safeString(requestedBy, 100);
    const normalizedReason = safeString(reason, 1000);
    const caseId = `ir-${sha256Text(stableGroupId).slice(0, 16)}`;
    if (cohortId) {
      await rejectProcessingJob('incident_response_analysis', [stableGroupId]);
    }
    await run(
      `INSERT INTO incident_response_cases (
         case_id, group_id, dashboard_group_id, representative_alert_id, status,
         agent_status, escalated_at, updated_at, escalated_by, reason
       ) VALUES (?, ?, ?, ?, 'open', 'queued', ?, ?, ?, ?)
       ON CONFLICT(group_id) DO UPDATE SET
         dashboard_group_id = excluded.dashboard_group_id,
         representative_alert_id = excluded.representative_alert_id,
         status = CASE WHEN incident_response_cases.status = 'resolved' THEN 'open' ELSE incident_response_cases.status END,
         agent_status = 'queued', updated_at = excluded.updated_at,
         escalated_by = excluded.escalated_by, reason = excluded.reason,
         resolution_reason = CASE WHEN incident_response_cases.status = 'resolved' THEN NULL ELSE incident_response_cases.resolution_reason END,
         resolved_at = CASE WHEN incident_response_cases.status = 'resolved' THEN NULL ELSE incident_response_cases.resolved_at END,
         resolved_by = CASE WHEN incident_response_cases.status = 'resolved' THEN NULL ELSE incident_response_cases.resolved_by END,
         latest_error = NULL`,
      [caseId, stableGroupId, dashboardGroupId, representative.alert_id,
        requestedAt, requestedAt, actor, normalizedReason],
    );
    const incident = await get(
      'SELECT case_id, escalated_at FROM incident_response_cases WHERE group_id = ?',
      [stableGroupId],
    );
    await run(
      `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [incident.case_id, safeString(eventType, 64), actor, jsonText({
        dashboard_group_id: dashboardGroupId,
        ...(representativeAlertIdPinned
          ? {representative_alert_id: representative.alert_id} : {}),
        ...(stableGroupIdPinned ? {stable_group_id: stableGroupId} : {}),
        ...(stableGroupKeyPinned ? {stable_group_key: stableGroupKey} : {}),
        ...(cohortId ? {
          cohort_id: cohortId, dispatch_id: dispatchId, release_id: releaseId,
          expected_assigned_route: expectedAssignedRoute,
          expected_reviewer_route: expectedReviewerRoute,
          reviewer_required: reviewerRequired,
        } : {}),
        reason: normalizedReason,
      }), requestedAt],
    );
    await enqueueJob('incident_response_analysis', stableGroupId, {
      agent_role: 'incident-responder', case_id: incident.case_id,
      alert_id: representative.alert_id, group_id: stableGroupId,
      dashboard_group_id: dashboardGroupId,
      ...(representativeAlertIdPinned
        ? {representative_alert_id: representative.alert_id} : {}),
      ...(stableGroupIdPinned ? {stable_group_id: stableGroupId} : {}),
      ...(stableGroupKeyPinned ? {stable_group_key: stableGroupKey} : {}),
      ...(cohortId ? {
        cohort_id: cohortId, dispatch_id: dispatchId, release_id: releaseId,
        expected_assigned_route: expectedAssignedRoute,
        expected_reviewer_route: expectedReviewerRoute,
        reviewer_required: reviewerRequired,
      } : {}),
      manual_reanalysis: Boolean(manualReanalysis), requested_by: actor,
      requested_at: requestedAt, reason: normalizedReason,
      related_limit: Math.max(1, Math.min(500, Math.trunc(requestedRelatedLimit))),
      pcap_analysis_limit: Math.max(1, Math.min(25, Math.trunc(requestedPcapLimit))),
    }, {priority: Math.max(0, Number(priority) || 0), maxAttempts: 12});
    await recordMetric('incident_response_analysis', 'enqueued', stableGroupId, {
      eventKey: `incident_response_analysis:${manualReanalysis ? 'manual' : 'automatic'}:${stableGroupId}:${requestedAt}`,
    });
    return {
      ok: true, status: 'queued', case_id: incident.case_id,
      group_id: dashboardGroupId, queue_group_id: stableGroupId,
      representative_alert_id: representative.alert_id,
      ...(stableGroupIdPinned ? {stable_group_id: stableGroupId} : {}),
      ...(stableGroupKeyPinned ? {stable_group_key: stableGroupKey} : {}),
      ...(cohortId ? {
        cohort_id: cohortId, dispatch_id: dispatchId, release_id: releaseId,
        expected_assigned_route: expectedAssignedRoute,
        expected_reviewer_route: expectedReviewerRoute,
        reviewer_required: reviewerRequired,
      } : {}),
      escalated_at: incident.escalated_at,
      requested_at: requestedAt,
    };
  }

  return {
    resolveDashboardAlertGroup,
    requestAiReanalysis,
    requestIncidentEscalation,
    queueIncidentResponseForGroup,
  };
}

module.exports = {createManualAnalysisDispatch};
