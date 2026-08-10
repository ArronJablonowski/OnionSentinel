'use strict';

function validAnalystGroupId(value) {
  const groupId = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{12}$/.test(groupId) ? groupId : '';
}

function validIncidentCaseId(value) {
  const caseId = String(value || '').trim().toLowerCase();
  return /^ir-[a-z0-9_-]{1,64}$/.test(caseId) ? caseId : '';
}

function createAnalystReviewProjection({
  get,
  all,
  resolveDashboardAlertGroup,
  safeString,
  parseJsonObject,
  conservativeReviewerTelemetry,
  reviewerAutomationAuthorization,
  reviewerFailureStatuses,
}) {
  const functions = {get, all, resolveDashboardAlertGroup, safeString, parseJsonObject,
    conservativeReviewerTelemetry, reviewerAutomationAuthorization};
  for (const [name, value] of Object.entries(functions)) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!(reviewerFailureStatuses instanceof Set)) {
    throw new TypeError('reviewerFailureStatuses must be a Set');
  }

  async function pendingHumanReview(stableId) {
    const groupId = safeString(stableId, 64).toLowerCase();
    if (!groupId) return false;
    const analysis = await get(
      `SELECT analysis_id, response_json
       FROM ai_analysis_runs
       WHERE (
           group_id = ?
           OR group_id IN (
             SELECT legacy_group_id FROM alert_group_alias WHERE stable_group_id = ?))
         AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = 'soc-analyst'
       ORDER BY generated_at DESC, created_at DESC LIMIT 1`,
      [groupId, groupId],
    );
    const analysisId = safeString(analysis?.analysis_id, 160);
    if (!analysisId) return false;
    const secondOpinion = await get(
      `SELECT status, material_disagreement, reviewer_confidence
       FROM ai_second_opinion_runs WHERE analysis_id = ?`,
      [analysisId],
    );
    const reviewer = conservativeReviewerTelemetry(analysis?.response_json, secondOpinion);
    const authorization = reviewerAutomationAuthorization(
      analysis?.response_json,
      reviewer.reviewer_confidence,
    );
    const required = reviewer.material_disagreement
      || reviewerFailureStatuses.has(reviewer.status)
      || (reviewer.status === 'completed' && authorization.authorized === false);
    if (!required) return false;
    const adjudication = await get(
      `SELECT adjudication_id
       FROM analyst_adjudications
       WHERE (
           stable_group_id = ?
           OR stable_group_id IN (
             SELECT legacy_group_id FROM alert_group_alias WHERE stable_group_id = ?))
         AND analysis_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT 1`,
      [groupId, groupId, analysisId],
    );
    return !adjudication;
  }

  async function resolveIdentity(dashboardGroupId, stableGroupId, caseId) {
    const dashboardId = validAnalystGroupId(dashboardGroupId);
    if (!dashboardId) {
      const error = new Error('valid dashboard group id is required');
      error.statusCode = 400;
      throw error;
    }
    let stableId = safeString(stableGroupId, 64).toLowerCase();
    let resolvedCase = null;
    if (caseId) {
      const normalizedCaseId = validIncidentCaseId(caseId);
      if (!normalizedCaseId) {
        const error = new Error('valid incident case id is required');
        error.statusCode = 400;
        throw error;
      }
      resolvedCase = await get(
        `SELECT case_id, group_id, dashboard_group_id, latest_analysis_id, status
         FROM incident_response_cases WHERE case_id = ?`,
        [normalizedCaseId],
      );
      if (!resolvedCase || resolvedCase.dashboard_group_id !== dashboardId) {
        const error = new Error('incident case does not belong to the requested alert group');
        error.statusCode = 404;
        throw error;
      }
      stableId = safeString(resolvedCase.group_id, 64).toLowerCase();
    }
    if (!stableId) {
      const representative = await resolveDashboardAlertGroup(dashboardId);
      stableId = safeString(representative?.stable_group_id, 64).toLowerCase();
    }
    if (!stableId) {
      const error = new Error('SOC alert group was not found');
      error.statusCode = 404;
      throw error;
    }
    return {dashboardId, stableId, resolvedCase};
  }

  async function analysisFor(identity) {
    let analysis = null;
    if (identity.resolvedCase?.latest_analysis_id) {
      analysis = await get(
        `SELECT analysis_id, generated_at, detection_outcome, confidence, response_json
         FROM ai_analysis_runs
         WHERE analysis_id = ?
           AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = 'incident-responder'`,
        [identity.resolvedCase.latest_analysis_id],
      );
    }
    if (!analysis) {
      const role = identity.resolvedCase ? 'incident-responder' : 'soc-analyst';
      analysis = await get(
        `SELECT analysis_id, generated_at, detection_outcome, confidence, response_json
         FROM ai_analysis_runs
         WHERE (
             group_id = ?
             OR group_id IN (
               SELECT legacy_group_id FROM alert_group_alias WHERE stable_group_id = ?))
           AND COALESCE(NULLIF(agent_role, ''), 'soc-analyst') = ?
         ORDER BY generated_at DESC, created_at DESC LIMIT 1`,
        [identity.stableId, identity.stableId, role],
      );
    }
    return analysis;
  }

  function finalStatus(adjudication, reviewer, authorization) {
    if (adjudication) return 'adjudicated';
    if (reviewer.material_disagreement) return 'disputed_pending_human';
    if (reviewerFailureStatuses.has(reviewer.status)) return 'review_required_failed';
    if (reviewer.status === 'completed' && authorization.authorized === false) {
      return 'review_completed_not_authorized';
    }
    if (reviewer.status === 'completed' && reviewer.agreement === 'agreement') {
      return 'model_consensus';
    }
    if (reviewer.status === 'completed') return 'reviewer_advisory';
    return 'unreviewed';
  }

  async function reviewState({dashboardGroupId, stableGroupId = '', caseId = ''} = {}) {
    const identity = await resolveIdentity(dashboardGroupId, stableGroupId, caseId);
    const analysis = await analysisFor(identity);
    const analysisId = safeString(analysis?.analysis_id, 160);
    const secondOpinion = analysisId ? await get(
      `SELECT status, primary_outcome, primary_confidence, reviewer_outcome,
              reviewer_confidence, agreement, material_disagreement,
              disputed_fields_json, reviewer_error, generated_at
       FROM ai_second_opinion_runs WHERE analysis_id = ?`,
      [analysisId],
    ) : null;
    const adjudication = analysisId ? await get(
      `SELECT adjudication_id, outcome_override, confidence, rationale,
              evidence_gap, next_action, reviewer, event_status,
              detection_validity, activity_disposition, handling, duplicate_of,
              case_resolution_reason, created_at
       FROM analyst_adjudications
       WHERE ${identity.resolvedCase ? 'case_id' : 'stable_group_id'} = ? AND analysis_id = ?
       ORDER BY created_at DESC, rowid DESC LIMIT 1`,
      [identity.resolvedCase ? identity.resolvedCase.case_id : identity.stableId, analysisId],
    ) : null;
    const primaryResponse = parseJsonObject(analysis?.response_json);
    const reviewer = conservativeReviewerTelemetry(primaryResponse, secondOpinion);
    const authorization = reviewerAutomationAuthorization(
      primaryResponse,
      reviewer.reviewer_confidence,
    );
    const primaryOutcome = secondOpinion?.primary_outcome || analysis?.detection_outcome || '';
    const primaryConfidence = secondOpinion?.primary_confidence || analysis?.confidence || '';
    return {
      dashboard_group_id: identity.dashboardId,
      stable_group_id: identity.stableId,
      case_id: identity.resolvedCase?.case_id || null,
      case_status: identity.resolvedCase?.status || null,
      analysis_id: analysisId,
      analysis_generated_at: analysis?.generated_at || null,
      primary_outcome: primaryOutcome,
      primary_confidence: primaryConfidence,
      effective_outcome: adjudication?.outcome_override || primaryOutcome,
      effective_confidence: adjudication?.confidence || primaryConfidence,
      primary_event_status: safeString(primaryResponse.event_status, 64),
      primary_detection_validity: safeString(primaryResponse.detection_validity, 64),
      primary_activity_disposition: safeString(primaryResponse.activity_disposition, 64),
      primary_handling: safeString(primaryResponse.handling, 64),
      primary_duplicate_of: primaryResponse.duplicate_of ?? null,
      reviewer_status: reviewer.status || 'not_requested',
      reviewer_error: reviewer.reviewer_error,
      reviewer_outcome: reviewer.reviewer_outcome,
      reviewer_confidence: reviewer.reviewer_confidence,
      automation_authorization: authorization,
      agreement: reviewer.agreement,
      material_disagreement: reviewer.material_disagreement,
      disputed_fields: reviewer.disputed_fields,
      final_status: finalStatus(adjudication, reviewer, authorization),
      adjudication: adjudication || null,
    };
  }

  async function adjudicationSnapshot(searchParams) {
    const dashboardGroupId = validAnalystGroupId(searchParams.get('group_id'));
    if (!dashboardGroupId) {
      const error = new Error('valid dashboard group_id is required');
      error.statusCode = 400;
      throw error;
    }
    const requestedCaseId = String(searchParams.get('case_id') || '').trim();
    const caseId = validIncidentCaseId(requestedCaseId);
    if (requestedCaseId && !caseId) {
      const error = new Error('valid incident case_id is required');
      error.statusCode = 400;
      throw error;
    }
    const review = await reviewState({dashboardGroupId, caseId});
    const requested = Number(searchParams.get('limit') || 25);
    const limit = Math.max(1, Math.min(100, Number.isFinite(requested) ? Math.trunc(requested) : 25));
    const history = await all(
      `SELECT adjudication_id, dashboard_group_id, stable_group_id, case_id,
              analysis_id, outcome_override, confidence, rationale, evidence_gap,
              next_action, reviewer, event_status, detection_validity,
              activity_disposition, handling, duplicate_of,
              case_resolution_reason, created_at
       FROM analyst_adjudications
       WHERE ${caseId ? 'case_id' : 'stable_group_id'} = ?
       ORDER BY created_at DESC, rowid DESC LIMIT ?`,
      [caseId || review.stable_group_id, limit],
    );
    return {ok: true, review, history};
  }

  return {pendingHumanReview, reviewState, adjudicationSnapshot};
}

module.exports = {validAnalystGroupId, validIncidentCaseId, createAnalystReviewProjection};
