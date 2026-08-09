'use strict';

function createAiCorrelationRepository({
  get,
  run,
  safeString,
  jsonText,
  nowUtc,
  compactCorrelationCandidates,
}) {
  for (const [name, value] of Object.entries({
    get, run, safeString, jsonText, nowUtc, compactCorrelationCandidates,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  function normalizeAssessment(value) {
    const assessment = value && typeof value === 'object' ? value : {};
    const relatedGroups = Array.isArray(assessment.related_groups)
      ? assessment.related_groups.map((item) => {
        if (typeof item === 'string') return safeString(item, 64).toLowerCase();
        return safeString(item?.group_id, 64).toLowerCase();
      }).filter(Boolean).slice(0, 20)
      : [];
    return {
      correlation_found: Boolean(assessment.correlation_found),
      confidence: safeString(assessment.confidence, 16).toLowerCase(),
      related_groups: new Set(relatedGroups),
      attack_chain_hypothesis: safeString(assessment.attack_chain_hypothesis, 2000),
    };
  }

  async function recordCorrelations({groupId, analysisId, assessment: value, candidates: valueCandidates}) {
    const assessment = normalizeAssessment(value);
    const candidates = compactCorrelationCandidates(valueCandidates);
    let correlations = 0;
    for (const candidate of candidates) {
      if (candidate.group_id === groupId) continue;
      const relatedExists = await get(
        'SELECT 1 AS present FROM alerts WHERE stable_group_id = ? LIMIT 1',
        [candidate.group_id],
      );
      if (!relatedExists) continue;
      const modelRelated = assessment.related_groups.has(candidate.group_id);
      await run(
        `INSERT INTO alert_correlations (
           source_group_id, related_group_id, analysis_id, correlation_score,
           reasons_json, shared_observables_json, model_status, model_confidence,
           model_hypothesis, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(source_group_id, related_group_id) DO UPDATE SET
           analysis_id = excluded.analysis_id,
           correlation_score = excluded.correlation_score,
           reasons_json = excluded.reasons_json,
           shared_observables_json = excluded.shared_observables_json,
           model_status = excluded.model_status,
           model_confidence = excluded.model_confidence,
           model_hypothesis = excluded.model_hypothesis,
           updated_at = excluded.updated_at`,
        [
          groupId,
          candidate.group_id,
          analysisId,
          candidate.score,
          jsonText(candidate.reasons),
          jsonText(candidate.shared_observables),
          modelRelated ? 'model-related' : 'candidate',
          modelRelated ? assessment.confidence : null,
          modelRelated ? assessment.attack_chain_hypothesis : null,
          nowUtc(),
          nowUtc(),
        ],
      );
      correlations += 1;
    }
    return correlations;
  }

  return {normalizeAssessment, recordCorrelations};
}

module.exports = {createAiCorrelationRepository};
