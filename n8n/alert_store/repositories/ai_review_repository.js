'use strict';

function createAiReviewRepository({run, safeString, jsonText, nowUtc}) {
  for (const [name, value] of Object.entries({run, safeString, jsonText, nowUtc})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function recordSecondOpinion({
    analysisId,
    groupId,
    alertId,
    agentRole,
    generatedAt,
    model,
    modelPath,
    response,
  }) {
    const secondOpinion = response._second_opinion && typeof response._second_opinion === 'object'
      ? response._second_opinion
      : null;
    if (!secondOpinion) return false;
    const reviewer = secondOpinion.response && typeof secondOpinion.response === 'object'
      ? secondOpinion.response
      : {};
    const comparison = secondOpinion.comparison && typeof secondOpinion.comparison === 'object'
      ? secondOpinion.comparison
      : {};
    const memoryWriteback = secondOpinion.memory_writeback && typeof secondOpinion.memory_writeback === 'object'
      ? secondOpinion.memory_writeback
      : {};
    const runtime = Number(secondOpinion.runtime_seconds);
    const now = nowUtc();
    await run(
      `INSERT INTO ai_second_opinion_runs (
         analysis_id, group_id, alert_id, agent_role, trigger, status, reviewer_error,
         primary_model, primary_model_path, primary_outcome, primary_confidence,
         reviewer_model, reviewer_model_path, reviewer_outcome, reviewer_confidence,
         agreement, material_disagreement, disputed_fields_json, comparison_json,
         reviewer_runtime_seconds, memory_candidates_promoted, generated_at,
         created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(analysis_id) DO UPDATE SET
         group_id = excluded.group_id, alert_id = excluded.alert_id,
         agent_role = excluded.agent_role, trigger = excluded.trigger,
         status = excluded.status, reviewer_error = excluded.reviewer_error,
         primary_model = excluded.primary_model, primary_model_path = excluded.primary_model_path,
         primary_outcome = excluded.primary_outcome, primary_confidence = excluded.primary_confidence,
         reviewer_model = excluded.reviewer_model, reviewer_model_path = excluded.reviewer_model_path,
         reviewer_outcome = excluded.reviewer_outcome, reviewer_confidence = excluded.reviewer_confidence,
         agreement = excluded.agreement, material_disagreement = excluded.material_disagreement,
         disputed_fields_json = excluded.disputed_fields_json, comparison_json = excluded.comparison_json,
         reviewer_runtime_seconds = excluded.reviewer_runtime_seconds,
         memory_candidates_promoted = excluded.memory_candidates_promoted,
         generated_at = excluded.generated_at, updated_at = excluded.updated_at`,
      [
        analysisId, groupId, alertId, agentRole,
        safeString(secondOpinion.trigger, 1000),
        safeString(secondOpinion.status || 'unknown', 32),
        safeString(secondOpinion.error, 1000),
        safeString(model || response._analysis_model, 200),
        safeString(modelPath || response._analysis_model_path, 100),
        safeString(response.detection_outcome, 100),
        safeString(response.confidence, 16).toLowerCase(),
        safeString(reviewer._analysis_model || secondOpinion.model_route, 200),
        safeString(reviewer._analysis_model_path, 100),
        safeString(reviewer.detection_outcome, 100),
        safeString(reviewer.confidence, 16).toLowerCase(),
        safeString(comparison.agreement, 64),
        comparison.material_disagreement ? 1 : 0,
        jsonText(Array.isArray(comparison.disputed_fields) ? comparison.disputed_fields : []),
        jsonText(comparison),
        Number.isFinite(runtime) && runtime >= 0 ? runtime : null,
        Math.max(0, Number(memoryWriteback.accepted) || 0),
        generatedAt, now, now,
      ],
    );
    return true;
  }

  async function recordDisagreementAdjudication({
    analysisId,
    groupId,
    alertId,
    agentRole,
    generatedAt,
    response,
  }) {
    const adjudication = (
      response._disagreement_adjudication
      && typeof response._disagreement_adjudication === 'object'
      && !Array.isArray(response._disagreement_adjudication)
    ) ? response._disagreement_adjudication : null;
    if (!adjudication) return false;
    const adjudicatorResponse = (
      adjudication.response
      && typeof adjudication.response === 'object'
      && !Array.isArray(adjudication.response)
    ) ? adjudication.response : {};
    const runtime = Number(adjudication.runtime_seconds);
    const score = Number(adjudicatorResponse.confidence_score);
    const now = nowUtc();
    await run(
      `INSERT INTO ai_disagreement_adjudication_runs (
         analysis_id, group_id, alert_id, agent_role, status, mode,
         adjudicator_error, model_route, decision, confidence, confidence_score,
         resolved_fields_json, remaining_disagreements_json, evidence_used_json,
         rationale, additional_evidence_needed_json, adjudicator_runtime_seconds,
         automation_authorized, human_adjudication_required, generated_at,
         created_at, updated_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(analysis_id) DO UPDATE SET
         group_id = excluded.group_id, alert_id = excluded.alert_id,
         agent_role = excluded.agent_role, status = excluded.status, mode = excluded.mode,
         adjudicator_error = excluded.adjudicator_error, model_route = excluded.model_route,
         decision = excluded.decision, confidence = excluded.confidence,
         confidence_score = excluded.confidence_score,
         resolved_fields_json = excluded.resolved_fields_json,
         remaining_disagreements_json = excluded.remaining_disagreements_json,
         evidence_used_json = excluded.evidence_used_json, rationale = excluded.rationale,
         additional_evidence_needed_json = excluded.additional_evidence_needed_json,
         adjudicator_runtime_seconds = excluded.adjudicator_runtime_seconds,
         automation_authorized = excluded.automation_authorized,
         human_adjudication_required = excluded.human_adjudication_required,
         generated_at = excluded.generated_at, updated_at = excluded.updated_at`,
      [
        analysisId, groupId, alertId, agentRole,
        safeString(adjudication.status || 'unknown', 32),
        safeString(adjudication.mode || 'shadow', 32),
        safeString(adjudication.error, 2000),
        safeString(adjudication.model_route, 200),
        safeString(adjudicatorResponse.decision || adjudication.decision, 64),
        safeString(adjudicatorResponse.confidence, 16).toLowerCase(),
        Number.isFinite(score) && score >= 0 && score <= 1 ? score : null,
        jsonText(Array.isArray(adjudicatorResponse.resolved_fields) ? adjudicatorResponse.resolved_fields : []),
        jsonText(Array.isArray(adjudicatorResponse.remaining_disagreements) ? adjudicatorResponse.remaining_disagreements : []),
        jsonText(Array.isArray(adjudicatorResponse.evidence_used) ? adjudicatorResponse.evidence_used : []),
        safeString(adjudicatorResponse.rationale, 4000),
        jsonText(Array.isArray(adjudicatorResponse.additional_evidence_needed)
          ? adjudicatorResponse.additional_evidence_needed : []),
        Number.isFinite(runtime) && runtime >= 0 ? runtime : null,
        0,
        1,
        generatedAt, now, now,
      ],
    );
    return true;
  }

  return {recordSecondOpinion, recordDisagreementAdjudication};
}

module.exports = {createAiReviewRepository};
