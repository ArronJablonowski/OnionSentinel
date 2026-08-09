'use strict';

function createIncidentReanalysisBindingService({
  get,
  run,
  safeString,
  parseProjectTimestamp,
  formatProjectTimestamp,
  nowUtc,
  incidentAnalysisProvider,
  refreshIncidentReanalysisRun,
}) {
  for (const [name, value] of Object.entries({
    get,
    run,
    safeString,
    parseProjectTimestamp,
    formatProjectTimestamp,
    nowUtc,
    incidentAnalysisProvider,
    refreshIncidentReanalysisRun,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function bindingAuthority(attempt) {
    if (!attempt?.attempt_id || !attempt?.case_id || !attempt?.started_at) {
      return {
        attempt_id: attempt?.attempt_id || null,
        run_id: attempt?.run_id || null,
        case_id: attempt?.case_id || null,
        authoritative: true,
      };
    }
    const newerAttempt = await get(
      `SELECT 1 AS present
       FROM incident_reanalysis_attempts
       WHERE case_id = ? AND attempt_id != ?
         AND (
           julianday(replace(started_at, '  ', 'T'))
             > julianday(replace(?, '  ', 'T'))
           OR (
             julianday(replace(started_at, '  ', 'T'))
               = julianday(replace(?, '  ', 'T'))
             AND rowid > ?
           )
         )
       LIMIT 1`,
      [
        attempt.case_id,
        attempt.attempt_id,
        attempt.started_at,
        attempt.started_at,
        Number(attempt.attempt_order || 0),
      ],
    );
    const newerRunCase = await get(
      `SELECT 1 AS present
       FROM incident_reanalysis_run_cases
       WHERE case_id = ? AND run_id != ? AND status != 'skipped'
         AND rowid > COALESCE((
           SELECT rowid FROM incident_reanalysis_run_cases
           WHERE run_id = ? AND case_id = ?
         ), 0)
       LIMIT 1`,
      [attempt.case_id, attempt.run_id, attempt.run_id, attempt.case_id],
    );
    return {
      attempt_id: attempt.attempt_id,
      run_id: attempt.run_id,
      case_id: attempt.case_id,
      authoritative: !newerAttempt && !newerRunCase,
    };
  }

  async function resolveSuppliedAttempt({suppliedAttemptId, groupId, analysisId}) {
    if (!/^ira-[a-f0-9]{40}$/.test(suppliedAttemptId)) {
      const error = new Error('reanalysis_attempt_id is invalid');
      error.statusCode = 400;
      throw error;
    }
    const attempt = await get(
      `SELECT attempt_id, run_id, case_id, group_id, started_at, analysis_id,
              rowid AS attempt_order
       FROM incident_reanalysis_attempts
       WHERE attempt_id = ?`,
      [suppliedAttemptId],
    );
    let strictCaseIdentityMatch = false;
    if (attempt && safeString(attempt.group_id, 64).toLowerCase() !== groupId) {
      strictCaseIdentityMatch = Boolean(await get(
        `SELECT 1 AS present
         FROM incident_response_cases AS c
         JOIN alerts AS a ON a.alert_id = c.representative_alert_id
         WHERE c.case_id = ? AND c.group_id = ? AND a.stable_group_id = ?`,
        [attempt.case_id, groupId, groupId],
      ));
    }
    if (!attempt || (
      safeString(attempt.group_id, 64).toLowerCase() !== groupId
      && !strictCaseIdentityMatch
    )) {
      const error = new Error('reanalysis_attempt_id does not match the analyzed alert group');
      error.statusCode = 409;
      throw error;
    }
    if (attempt.analysis_id) {
      if (attempt.analysis_id === analysisId) {
        return {binding: await bindingAuthority(attempt)};
      }
      const error = new Error('reanalysis attempt is already bound to another analysis');
      error.statusCode = 409;
      throw error;
    }
    return {attempt};
  }

  async function resolveLegacyAttempt({groupId, analysisId, analysisStartedAt, generatedAt}) {
    const existing = await get(
      `SELECT attempt_id, run_id, case_id, started_at,
              rowid AS attempt_order
       FROM incident_reanalysis_attempts WHERE analysis_id = ? AND group_id = ?`,
      [analysisId, groupId],
    );
    if (existing) return {binding: await bindingAuthority(existing)};
    const parsedAnalysisStartedAt = parseProjectTimestamp(analysisStartedAt);
    const parsedGeneratedAt = parseProjectTimestamp(generatedAt);
    const attemptCutoff = parsedAnalysisStartedAt
      ? formatProjectTimestamp(parsedAnalysisStartedAt)
      : parsedGeneratedAt ? formatProjectTimestamp(parsedGeneratedAt) : nowUtc();
    const attempt = await get(
      `SELECT attempt_id, run_id, case_id, started_at,
              rowid AS attempt_order
       FROM incident_reanalysis_attempts
       WHERE group_id = ? AND analysis_id IS NULL
         AND status IN ('running', 'completed', 'failed')
         AND julianday(replace(started_at, '  ', 'T'))
             <= julianday(replace(?, '  ', 'T'))
         AND (
           status = 'running'
           OR (
             completed_at IS NOT NULL
             AND julianday(replace(?, '  ', 'T'))
                 <= julianday(replace(completed_at, '  ', 'T'))
           )
         )
       ORDER BY julianday(replace(started_at, '  ', 'T')) DESC, rowid DESC
       LIMIT 1`,
      [groupId, attemptCutoff, attemptCutoff],
    );
    return {attempt};
  }

  async function completeAttempt({attempt, analysisId, model, modelPath, provider, generatedAt}) {
    const executedModel = safeString(model, 200);
    const executedModelPath = safeString(modelPath, 100);
    const executedProvider = incidentAnalysisProvider(executedModelPath, provider);
    const updatedAt = nowUtc();
    const bound = await run(
      `UPDATE incident_reanalysis_attempts
       SET status = 'completed', latest_error = NULL, analysis_id = ?,
           executed_model = ?, executed_provider = ?, executed_model_path = ?,
           result_generated_at = ?, completed_at = ?, updated_at = ?
       WHERE attempt_id = ? AND analysis_id IS NULL`,
      [
        analysisId, executedModel, executedProvider, executedModelPath,
        generatedAt, updatedAt, updatedAt, attempt.attempt_id,
      ],
    );
    if (Number(bound.changes || 0) !== 1) return null;
    const newerAttempt = await get(
      `SELECT 1 AS present
       FROM incident_reanalysis_attempts
       WHERE run_id = ? AND case_id = ? AND attempt_id != ?
         AND status = 'running'
         AND (
           julianday(replace(started_at, '  ', 'T'))
             > julianday(replace(?, '  ', 'T'))
           OR (
             julianday(replace(started_at, '  ', 'T'))
               = julianday(replace(?, '  ', 'T'))
             AND rowid > ?
           )
         )
       LIMIT 1`,
      [
        attempt.run_id, attempt.case_id, attempt.attempt_id,
        attempt.started_at, attempt.started_at, Number(attempt.attempt_order || 0),
      ],
    );
    if (!newerAttempt) {
      await run(
        `UPDATE incident_reanalysis_run_cases
         SET status = 'completed', latest_error = NULL, completed_at = ?,
             latest_attempt_id = ?, analysis_id = ?, executed_model = ?,
             executed_provider = ?, executed_model_path = ?,
             result_generated_at = ?, updated_at = ?
         WHERE run_id = ? AND case_id = ? AND status != 'skipped'`,
        [
          updatedAt, attempt.attempt_id, analysisId, executedModel,
          executedProvider, executedModelPath, generatedAt, updatedAt,
          attempt.run_id, attempt.case_id,
        ],
      );
    }
    await refreshIncidentReanalysisRun(attempt.run_id);
    return bindingAuthority(attempt);
  }

  async function bindResult({
    groupId,
    analysisId,
    model,
    modelPath,
    provider,
    expectedAttemptId,
    allowLegacyFallback,
    analysisStartedAt,
    generatedAt,
  }) {
    if (!groupId || !analysisId) return null;
    const suppliedAttemptId = safeString(expectedAttemptId, 80).toLowerCase();
    let resolved;
    if (suppliedAttemptId) {
      resolved = await resolveSuppliedAttempt({suppliedAttemptId, groupId, analysisId});
    } else if (allowLegacyFallback) {
      resolved = await resolveLegacyAttempt({
        groupId, analysisId, analysisStartedAt, generatedAt,
      });
    } else {
      return null;
    }
    if (resolved.binding) return resolved.binding;
    if (!resolved.attempt) return null;
    return completeAttempt({
      attempt: resolved.attempt, analysisId, model, modelPath, provider, generatedAt,
    });
  }

  return {bindingAuthority, bindResult};
}

module.exports = {createIncidentReanalysisBindingService};
