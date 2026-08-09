'use strict';

const crypto = require('crypto');

function createAiAnalysisAcceptance({
  get,
  run,
  safeString,
  jsonText,
  nowUtc,
  parseJsonObject,
  canonicalJsonText,
  normalizeTimestampValue,
  supportedAgentRoles,
  incidentReanalysisBindingAuthority,
  aiReviewRepository,
  incidentAnalysisCompletion,
  aiCorrelationRepository,
}) {
  for (const [name, value] of Object.entries({
    get, run, safeString, jsonText, nowUtc, parseJsonObject, canonicalJsonText,
    normalizeTimestampValue, incidentReanalysisBindingAuthority,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!supportedAgentRoles || typeof supportedAgentRoles.has !== 'function') {
    throw new TypeError('supportedAgentRoles must provide has()');
  }
  for (const [name, owner, method] of [
    ['aiReviewRepository', aiReviewRepository, 'recordSecondOpinion'],
    ['aiReviewRepository', aiReviewRepository, 'recordDisagreementAdjudication'],
    ['incidentAnalysisCompletion', incidentAnalysisCompletion, 'complete'],
    ['aiCorrelationRepository', aiCorrelationRepository, 'recordCorrelations'],
  ]) {
    if (!owner || typeof owner[method] !== 'function') {
      throw new TypeError(`${name}.${method} must be a function`);
    }
  }

  function normalizedResult(payload, alertRow) {
    const response = payload?.response && typeof payload.response === 'object'
      ? payload.response : {};
    const requestedAgentRole = safeString(payload?.agent_role || 'soc-analyst', 64).toLowerCase();
    const canonicalResponse = canonicalJsonText(response);
    return {
      alertId: safeString(payload?.alert_id, 1024),
      analysisId: safeString(payload?.analysis_id, 128).toLowerCase(),
      groupId: alertRow.stable_group_id,
      response,
      generatedAt: safeString(payload?.generated_at, 64) || nowUtc(),
      agentRole: supportedAgentRoles.has(requestedAgentRole) ? requestedAgentRole : 'soc-analyst',
      model: safeString(payload?.model || response._analysis_model, 200),
      modelPath: safeString(payload?.model_path || response._analysis_model_path, 100),
      detectionOutcome: safeString(response.detection_outcome, 100),
      bluf: safeString(response.bluf, 4000),
      summary: safeString(response.summary, 8000),
      confidence: safeString(response.confidence, 16).toLowerCase(),
      artifactPath: safeString(payload?.artifact_path, 2048),
      evidenceHash: safeString(payload?.evidence_hash, 128).toLowerCase(),
      responseJson: jsonText(response),
      storedResponseSha256: crypto.createHash('sha256').update(canonicalResponse).digest('hex'),
    };
  }

  function immutableChangedFields(accepted, value) {
    const existingResponse = parseJsonObject(accepted.response_json);
    const comparisons = {
      group_id: [safeString(accepted.group_id, 64), value.groupId],
      alert_id: [safeString(accepted.alert_id, 1024), value.alertId],
      agent_role: [safeString(accepted.agent_role, 64), value.agentRole],
      generated_at: [
        normalizeTimestampValue(accepted.generated_at),
        normalizeTimestampValue(value.generatedAt),
      ],
      model: [safeString(accepted.model, 200), value.model],
      model_path: [safeString(accepted.model_path, 100), value.modelPath],
      detection_outcome: [safeString(accepted.detection_outcome, 100), value.detectionOutcome],
      bluf: [safeString(accepted.bluf, 4000), value.bluf],
      summary: [safeString(accepted.summary, 8000), value.summary],
      confidence: [safeString(accepted.confidence, 16).toLowerCase(), value.confidence],
      artifact_path: [safeString(accepted.artifact_path, 2048), value.artifactPath],
      evidence_hash: [safeString(accepted.evidence_hash, 128).toLowerCase(), value.evidenceHash],
      response_json: [canonicalJsonText(existingResponse), canonicalJsonText(value.response)],
    };
    return Object.entries(comparisons)
      .filter(([, values]) => values[0] !== values[1])
      .map(([field]) => field);
  }

  async function replayBinding(payload, analysisId) {
    const existingAttempt = await get(
      `SELECT attempt_id, run_id, case_id, started_at,
              rowid AS attempt_order
       FROM incident_reanalysis_attempts WHERE analysis_id = ?`,
      [analysisId],
    );
    const hasAttemptField = Object.prototype.hasOwnProperty.call(
      payload || {},
      'reanalysis_attempt_id',
    );
    const suppliedAttemptId = safeString(payload?.reanalysis_attempt_id, 80).toLowerCase();
    if (suppliedAttemptId && !/^ira-[a-f0-9]{40}$/.test(suppliedAttemptId)) {
      const error = new Error('reanalysis_attempt_id is invalid');
      error.statusCode = 400;
      throw error;
    }
    if (
      (existingAttempt && hasAttemptField && suppliedAttemptId !== existingAttempt.attempt_id)
      || (!existingAttempt && suppliedAttemptId)
    ) {
      const error = new Error(
        'analysis_id replay does not match its immutable reanalysis attempt',
      );
      error.statusCode = 409;
      throw error;
    }
    return existingAttempt
      ? incidentReanalysisBindingAuthority(existingAttempt)
      : null;
  }

  function responseEnvelope(value, state, idempotent = false) {
    const binding = state.incidentReanalysisBinding;
    return {
      ok: true,
      status: 'analysis_indexed',
      ...(idempotent ? {idempotent: true} : {}),
      analysis_id: value.analysisId,
      stored_response_sha256: value.storedResponseSha256,
      group_id: value.groupId,
      correlations: Number(state.correlations || 0),
      second_opinion_recorded: Boolean(state.secondOpinionRecorded),
      disagreement_adjudication_recorded: Boolean(state.disagreementAdjudicationRecorded),
      reanalysis_run_id: binding?.run_id || null,
      reanalysis_attempt_id: binding?.attempt_id || null,
      reanalysis_authoritative: binding ? binding.authoritative !== false : null,
    };
  }

  async function replayResult(payload, value, accepted) {
    const changedFields = immutableChangedFields(accepted, value);
    if (changedFields.length) {
      const error = new Error(
        `analysis_id already exists with different immutable fields: ${changedFields.join(', ')}`,
      );
      error.statusCode = 409;
      throw error;
    }
    const incidentReanalysisBinding = await replayBinding(payload, value.analysisId);
    const secondOpinionRow = await get(
      'SELECT 1 AS present FROM ai_second_opinion_runs WHERE analysis_id = ?',
      [value.analysisId],
    );
    const adjudicationRow = await get(
      'SELECT 1 AS present FROM ai_disagreement_adjudication_runs WHERE analysis_id = ?',
      [value.analysisId],
    );
    const correlationRow = await get(
      'SELECT COUNT(*) AS count FROM alert_correlations WHERE analysis_id = ?',
      [value.analysisId],
    );
    return responseEnvelope(value, {
      correlations: Number(correlationRow?.count || 0),
      secondOpinionRecorded: Boolean(secondOpinionRow),
      disagreementAdjudicationRecorded: Boolean(adjudicationRow),
      incidentReanalysisBinding,
    }, true);
  }

  async function insertPrimary(value) {
    await run(
      `INSERT INTO ai_analysis_runs (
         analysis_id, group_id, alert_id, agent_role, generated_at, model, model_path,
         detection_outcome, bluf, summary, confidence, artifact_path,
         evidence_hash, response_json, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(analysis_id) DO NOTHING`,
      [
        value.analysisId, value.groupId, value.alertId, value.agentRole, value.generatedAt,
        value.model, value.modelPath, value.detectionOutcome, value.bluf, value.summary,
        value.confidence, value.artifactPath, value.evidenceHash, value.responseJson, nowUtc(),
      ],
    );
  }

  async function record(payload) {
    const alertId = safeString(payload?.alert_id, 1024);
    const analysisId = safeString(payload?.analysis_id, 128).toLowerCase();
    if (!alertId || !analysisId || !/^[a-z0-9_-]{8,128}$/.test(analysisId)) {
      throw new Error('analysis_id and alert_id are required');
    }
    const alertRow = await get(
      'SELECT alert_id, stable_group_id, stable_group_key FROM alerts WHERE alert_id = ?',
      [alertId],
    );
    if (!alertRow) throw new Error('analysis alert_id not found');
    const value = normalizedResult(payload, alertRow);
    if (!value.groupId) throw new Error('analysis alert has no stable group identity');
    const accepted = await get(
      `SELECT analysis_id, group_id, alert_id, agent_role, generated_at, model,
              model_path, detection_outcome, bluf, summary, confidence,
              artifact_path, evidence_hash, response_json
       FROM ai_analysis_runs WHERE analysis_id = ?`,
      [analysisId],
    );
    if (accepted) return replayResult(payload, value, accepted);
    await insertPrimary(value);
    const secondOpinionRecorded = await aiReviewRepository.recordSecondOpinion({
      analysisId, groupId: value.groupId, alertId, agentRole: value.agentRole,
      generatedAt: value.generatedAt, model: payload?.model, modelPath: payload?.model_path,
      response: value.response,
    });
    const disagreementAdjudicationRecorded = await aiReviewRepository
      .recordDisagreementAdjudication({
        analysisId, groupId: value.groupId, alertId, agentRole: value.agentRole,
        generatedAt: value.generatedAt, response: value.response,
      });
    const incidentReanalysisBinding = await incidentAnalysisCompletion.complete({
      agentRole: value.agentRole, groupId: value.groupId, analysisId,
      payload, response: value.response, generatedAt: value.generatedAt,
    });
    const correlations = await aiCorrelationRepository.recordCorrelations({
      groupId: value.groupId, analysisId,
      assessment: value.response.correlation_assessment,
      candidates: payload?.correlation_candidates,
    });
    return responseEnvelope(value, {
      correlations, secondOpinionRecorded, disagreementAdjudicationRecorded,
      incidentReanalysisBinding,
    });
  }

  return {record};
}

module.exports = {createAiAnalysisAcceptance};
