'use strict';

function createIncidentAnalysisCompletion({
  get,
  run,
  safeString,
  jsonText,
  nowUtc,
  bindIncidentReanalysisResult,
}) {
  for (const [name, value] of Object.entries({
    get, run, safeString, jsonText, nowUtc, bindIncidentReanalysisResult,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function complete({agentRole, groupId, analysisId, payload, response, generatedAt}) {
    if (agentRole !== 'incident-responder') return null;
    const executedModel = safeString(payload?.model || response._analysis_model, 200);
    const executedModelPath = safeString(payload?.model_path || response._analysis_model_path, 100);
    const executedProvider = safeString(payload?.provider || response._analysis_provider, 100);
    const binding = await bindIncidentReanalysisResult({
      groupId,
      analysisId,
      model: executedModel,
      modelPath: executedModelPath,
      provider: executedProvider,
      expectedAttemptId: safeString(payload?.reanalysis_attempt_id, 80).toLowerCase(),
      allowLegacyFallback: !Object.prototype.hasOwnProperty.call(
        payload || {},
        'reanalysis_attempt_id',
      ),
      analysisStartedAt: safeString(payload?.analysis_started_at, 64),
      generatedAt,
    });
    const caseRow = await get(
      'SELECT case_id FROM incident_response_cases WHERE group_id = ?',
      [groupId],
    );
    if (!caseRow?.case_id) return binding;
    const updatedAt = nowUtc();
    if (!binding || binding.authoritative !== false) {
      await run(
        `UPDATE incident_response_cases
         SET agent_status = 'analyzed', latest_analysis_id = ?, latest_model = ?,
             latest_generated_at = ?, latest_error = NULL, updated_at = ?
         WHERE case_id = ?`,
        [analysisId, executedModel, generatedAt, updatedAt, caseRow.case_id],
      );
    }
    await run(
      `INSERT INTO incident_response_events (case_id, event_type, actor, detail_json, created_at)
       VALUES (?, 'analysis_completed', 'incident-responder', ?, ?)`,
      [
        caseRow.case_id,
        jsonText({
          analysis_id: analysisId,
          generated_at: generatedAt,
          reanalysis_run_id: binding?.run_id || null,
          reanalysis_attempt_id: binding?.attempt_id || null,
          authoritative: binding?.authoritative !== false,
        }),
        updatedAt,
      ],
    );
    return binding;
  }

  return {complete};
}

module.exports = {createIncidentAnalysisCompletion};
