'use strict';

const HUMAN_REVIEW_STATUSES = new Set([
  'disputed_pending_human',
  'review_required_failed',
  'review_completed_not_authorized',
]);

function publicError(message, statusCode) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

function createAnalystDecisionPersistence({
  get, all, run, withWriteGate, reviewState, validGroupId, validCaseId,
  safeString, adjudicationOutcomes, adjudicationConfidences, eventStatuses,
  detectionValidities, activityDispositions, handlingValues, verdictContradictions,
  adjudicationTextMaxLength, statusReasonMaxLength, nowUtc, randomUUID, jsonText,
}) {
  const functions = {get, all, run, withWriteGate, reviewState, validGroupId,
    validCaseId, safeString, verdictContradictions, nowUtc, randomUUID, jsonText};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function verdictFactors(payload) {
    const definitions = [
      ['event_status', eventStatuses],
      ['detection_validity', detectionValidities],
      ['activity_disposition', activityDispositions],
      ['handling', handlingValues],
    ];
    const factors = {};
    for (const [field, allowed] of definitions) {
      const value = safeString(payload?.[field], 64).toLowerCase();
      if (value && !allowed.has(value)) throw publicError(`invalid ${field}`, 400);
      factors[field] = value || null;
    }
    return factors;
  }

  function duplicateIdentity(payload) {
    const raw = payload?.duplicate_of;
    if (raw !== null && raw !== undefined && typeof raw !== 'string') {
      throw publicError('duplicate_of must be a string identifier or null', 400);
    }
    const duplicateOf = raw === null || raw === undefined ? null : safeString(raw, 256);
    if (raw !== null && raw !== undefined && !duplicateOf) {
      throw publicError('duplicate_of must be a non-empty identifier or null', 400);
    }
    return duplicateOf;
  }

  async function adjudicationRequest(payload) {
    const dashboardGroupId = validGroupId(payload?.group_id);
    if (!dashboardGroupId) throw publicError('valid dashboard group_id is required', 400);
    const caseId = payload?.case_id ? validCaseId(payload.case_id) : '';
    if (payload?.case_id && !caseId) throw publicError('valid incident case_id is required', 400);
    const review = await reviewState({dashboardGroupId, caseId});
    if (!review.analysis_id) throw publicError('no current analysis is available to adjudicate', 409);
    const requestedId = safeString(payload?.analysis_id, 160);
    if (requestedId && requestedId !== review.analysis_id) {
      throw publicError('analysis changed; refresh before adjudicating', 409);
    }
    const outcome = safeString(payload?.outcome_override, 100).toLowerCase();
    if (!adjudicationOutcomes.has(outcome)) {
      throw publicError('valid outcome_override is required', 400);
    }
    const confidence = safeString(payload?.confidence, 16).toLowerCase();
    if (!adjudicationConfidences.has(confidence)) {
      throw publicError('confidence must be low, medium, or high', 400);
    }
    const rationale = safeString(payload?.rationale, adjudicationTextMaxLength);
    const reviewer = safeString(payload?.reviewer, 100);
    if (!rationale || !reviewer) throw publicError('rationale and reviewer are required', 400);
    const factors = verdictFactors(payload);
    const duplicateOf = duplicateIdentity(payload);
    const contradictions = verdictContradictions(outcome, {...factors, duplicate_of: duplicateOf});
    if (contradictions.length) {
      throw publicError(
        `outcome_override conflicts with explicit verdict factors: ${contradictions.join('; ')}`,
        400,
      );
    }
    if (payload?.resolve_case !== undefined && typeof payload.resolve_case !== 'boolean') {
      throw publicError('resolve_case must be a JSON boolean', 400);
    }
    const resolveCase = payload?.resolve_case === true;
    const caseResolutionReason = safeString(payload?.case_resolution_reason, 2000);
    if (resolveCase && (!caseId || !caseResolutionReason)) {
      throw publicError('case_id and case_resolution_reason are required to resolve a case', 400);
    }
    return {dashboardGroupId, caseId, review, outcome, confidence, rationale, reviewer,
      evidenceGap: safeString(payload?.evidence_gap, adjudicationTextMaxLength),
      nextAction: safeString(payload?.next_action, adjudicationTextMaxLength), factors,
      duplicateOf, resolveCase, caseResolutionReason};
  }

  async function recordAdjudication(payload) {
    const request = await adjudicationRequest(payload);
    const createdAt = nowUtc();
    const adjudicationId = `adj-${randomUUID()}`;
    await run(
      `INSERT INTO analyst_adjudications (
         adjudication_id, dashboard_group_id, stable_group_id, case_id, analysis_id,
         outcome_override, confidence, rationale, evidence_gap, next_action,
         reviewer, event_status, detection_validity, activity_disposition,
         handling, duplicate_of, case_resolution_reason, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [adjudicationId, request.dashboardGroupId, request.review.stable_group_id,
        request.caseId || null, request.review.analysis_id, request.outcome,
        request.confidence, request.rationale, request.evidenceGap, request.nextAction,
        request.reviewer, request.factors.event_status, request.factors.detection_validity,
        request.factors.activity_disposition, request.factors.handling,
        request.duplicateOf, request.caseResolutionReason, createdAt],
    );
    if (request.caseId) {
      await run(
        `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
         VALUES (?, 'analyst_adjudicated', ?, ?, ?)`,
        [request.caseId, request.reviewer, jsonText({adjudication_id: adjudicationId,
          analysis_id: request.review.analysis_id, outcome_override: request.outcome,
          confidence: request.confidence, ...request.factors,
          duplicate_of: request.duplicateOf, resolve_case: request.resolveCase}), createdAt],
      );
    }
    if (request.resolveCase) {
      await run(
        `UPDATE incident_response_cases
         SET status = 'resolved', resolution_reason = ?, resolved_at = ?,
             resolved_by = ?, updated_at = ? WHERE case_id = ?`,
        [request.caseResolutionReason, createdAt, request.reviewer, createdAt, request.caseId],
      );
      await run(
        `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
         VALUES (?, 'resolved', ?, ?, ?)`,
        [request.caseId, request.reviewer, jsonText({reason: request.caseResolutionReason,
          adjudication_id: adjudicationId}), createdAt],
      );
    }
    return {ok: true, adjudication_id: adjudicationId,
      review: await reviewState({dashboardGroupId: request.dashboardGroupId,
        caseId: request.caseId})};
  }

  async function updateIncidentCaseStatus(payload) {
    const caseId = validCaseId(payload?.case_id);
    if (!caseId) throw publicError('valid incident case_id is required', 400);
    const status = safeString(payload?.status, 32).toLowerCase();
    if (!['open', 'in_progress', 'resolved'].includes(status)) {
      throw publicError('invalid incident case status', 400);
    }
    const incident = await get(
      'SELECT case_id, dashboard_group_id, status FROM incident_response_cases WHERE case_id = ?',
      [caseId],
    );
    if (!incident) throw publicError('incident case not found', 404);
    const actor = safeString(payload?.updated_by || 'dashboard', 100);
    const reason = safeString(payload?.resolution_reason, 2000);
    if (status === 'resolved') {
      if (!reason) throw publicError('resolution_reason is required', 400);
      const review = await reviewState({dashboardGroupId: incident.dashboard_group_id, caseId});
      if (HUMAN_REVIEW_STATUSES.has(review.final_status)) {
        throw publicError(
          'required independent review needs explicit analyst adjudication before resolution',
          409,
        );
      }
    }
    const updatedAt = nowUtc();
    await run(
      `UPDATE incident_response_cases
       SET status = ?, resolution_reason = ?, resolved_at = ?, resolved_by = ?, updated_at = ?
       WHERE case_id = ?`,
      [status, status === 'resolved' ? reason : null,
        status === 'resolved' ? updatedAt : null, status === 'resolved' ? actor : null,
        updatedAt, caseId],
    );
    await run(
      `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
       VALUES (?, ?, ?, ?, ?)`,
      [caseId, status === 'resolved' ? 'resolved' : 'status_changed', actor,
        jsonText({from: incident.status, to: status, resolution_reason: reason}), updatedAt],
    );
    return {ok: true, case_id: caseId, status, updated_at: updatedAt,
      review: await reviewState({dashboardGroupId: incident.dashboard_group_id, caseId})};
  }

  async function statusSnapshotUnlocked() {
    const rows = await all(`
      SELECT state.group_id, state.group_key, state.status, state.repeat_count,
             state.reason, state.updated_at, state.updated_by,
             COALESCE(summary.total_seen_count, summary.raw_alert_count,
               state.repeat_count, 0) AS current_count
      FROM analyst_alert_group_state AS state
      LEFT JOIN alert_group_summary AS summary ON summary.group_id = state.group_id
      WHERE state.status IN ('acknowledged', 'suppressed')
    `);
    const expired = new Set(rows.filter((row) => row.status === 'acknowledged'
      && Number(row.current_count || 0) > Number(row.repeat_count || 0))
      .map((row) => row.group_id));
    for (const groupId of expired) {
      await run('DELETE FROM analyst_alert_group_state WHERE group_id = ?', [groupId]);
    }
    const statuses = {};
    for (const row of rows) {
      if (expired.has(row.group_id)) continue;
      statuses[row.group_id] = {status: row.status,
        repeat_count: Number(row.repeat_count || 0), reason: row.reason || '',
        updated_at: row.updated_at, updated_by: row.updated_by || '',
        group_key: row.group_key || ''};
    }
    return {ok: true, statuses,
      acknowledged: Object.keys(statuses).filter((id) => statuses[id].status === 'acknowledged'),
      suppressed: Object.keys(statuses).filter((id) => statuses[id].status === 'suppressed')};
  }

  async function statusSnapshot() {
    return withWriteGate(statusSnapshotUnlocked);
  }

  async function updateStatus(payload) {
    return withWriteGate(async () => {
      const groupId = validGroupId(payload?.id);
      if (!groupId) throw new Error('invalid analyst alert group id');
      const status = String(payload?.status || '').trim().toLowerCase();
      if (!['open', 'acknowledged', 'suppressed'].includes(status)) {
        throw new Error('invalid analyst alert status');
      }
      const summary = await get(
        'SELECT group_key, raw_alert_count, total_seen_count FROM alert_group_summary WHERE group_id = ?',
        [groupId],
      );
      if (!summary) throw new Error('analyst alert group not found');
      let repeatCount = Math.max(0, Number.parseInt(payload?.repeat_count, 10) || 0);
      if (status === 'acknowledged' && repeatCount <= 0) {
        repeatCount = Math.max(
          Number(summary.raw_alert_count || 0),
          Number(summary.total_seen_count || 0),
        );
      }
      const reason = String(payload?.reason || '').trim().slice(0, statusReasonMaxLength);
      if (status === 'suppressed' && !reason) throw new Error('suppression reason is required');
      if (status === 'suppressed') {
        const review = await reviewState({dashboardGroupId: groupId});
        if (HUMAN_REVIEW_STATUSES.has(review.final_status)) {
          throw publicError(
            'required independent review needs explicit analyst adjudication before suppression',
            409,
          );
        }
      }
      if (status === 'open') {
        await run('DELETE FROM analyst_alert_group_state WHERE group_id = ?', [groupId]);
      } else {
        await run(
          `INSERT INTO analyst_alert_group_state (
             group_id, group_key, status, repeat_count, reason, updated_at, updated_by
           ) VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(group_id) DO UPDATE SET
             group_key = excluded.group_key, status = excluded.status,
             repeat_count = excluded.repeat_count, reason = excluded.reason,
             updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
          [groupId, summary.group_key || '', status, repeatCount, reason, nowUtc(),
            String(payload?.updated_by || 'dashboard').trim().slice(0, 80)],
        );
      }
      return statusSnapshotUnlocked();
    });
  }

  return {recordAdjudication, updateIncidentCaseStatus, statusSnapshot, updateStatus};
}

module.exports = {HUMAN_REVIEW_STATUSES, createAnalystDecisionPersistence};
