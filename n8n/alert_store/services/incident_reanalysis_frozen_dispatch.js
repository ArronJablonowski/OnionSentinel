'use strict';

function createIncidentReanalysisFrozenDispatch({
  get,
  all,
  run,
  parseJsonObject,
  loadAliases,
  resolveCanonicalIdentity,
  rejectProcessingJob,
  jsonText,
  conflict,
}) {
  for (const [name, value] of Object.entries({get, all, run, parseJsonObject,
    loadAliases, resolveCanonicalIdentity, rejectProcessingJob, jsonText, conflict})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function replay(identity, caseId, requestedBy, reason) {
    const priorDispatch = await get(
      `SELECT controlled_receipt_json
       FROM incident_reanalysis_runs
       WHERE controlled_dispatch_id = ?`,
      [identity.dispatchId],
    );
    if (!priorDispatch) return null;
    const receipt = parseJsonObject(priorDispatch.controlled_receipt_json);
    if (receipt.ok !== true
      || receipt.case_id !== caseId
      || receipt.cohort_id !== identity.cohortId
      || receipt.dispatch_id !== identity.dispatchId
      || receipt.release_id !== identity.releaseId
      || receipt.expected_assigned_route !== identity.expectedAssignedRoute
      || receipt.expected_reviewer_route !== identity.expectedReviewerRoute
      || receipt.reviewer_required !== identity.reviewerRequired
      || receipt.representative_alert_id !== identity.representativeAlertId
      || receipt.stable_group_id !== identity.stableGroupId
      || receipt.stable_group_key !== identity.stableGroupKey
      || receipt.requested_by !== requestedBy
      || receipt.reason !== reason) {
      throw conflict('controlled incident dispatch identity was already used');
    }
    return receipt;
  }

  async function loadContext(identity, incident) {
    const storedGroupId = typeof incident.group_id === 'string' ? incident.group_id : '';
    const storedRepresentativeAlertId = typeof incident.representative_alert_id === 'string'
      ? incident.representative_alert_id : '';
    const representativeGroupId = typeof incident.representative_group_id === 'string'
      ? incident.representative_group_id : '';
    const aliases = await loadAliases();
    const caseIdentity = resolveCanonicalIdentity(storedGroupId, aliases);
    const requestedStableIdentity = identity.stableGroupIdSupplied
      ? resolveCanonicalIdentity(identity.stableGroupId, aliases) : caseIdentity;
    if (requestedStableIdentity.stableGroupId !== caseIdentity.stableGroupId
      || (identity.stableGroupIdSupplied
        && identity.stableGroupId !== requestedStableIdentity.stableGroupId)) {
      throw conflict('requested stable_group_id no longer matches the incident case');
    }
    const targetRepresentativeAlertId = identity.representativeAlertIdSupplied
      ? identity.representativeAlertId : storedRepresentativeAlertId;
    const targetRepresentative = await get(
      `SELECT alert_id, stable_group_id, stable_group_key
       FROM alerts WHERE alert_id = ? LIMIT 1`,
      [targetRepresentativeAlertId],
    );
    if (!targetRepresentative?.alert_id) {
      throw conflict('requested representative_alert_id no longer matches the incident case');
    }
    return {storedGroupId, storedRepresentativeAlertId, representativeGroupId,
      aliases, caseIdentity, requestedStableIdentity, targetRepresentativeAlertId,
      targetRepresentative};
  }

  function validateTarget(identity, incident, context) {
    const {caseIdentity, requestedStableIdentity, representativeGroupId,
      targetRepresentative, targetRepresentativeAlertId, aliases} = context;
    const targetRepresentativeGroupId = typeof targetRepresentative.stable_group_id === 'string'
      ? targetRepresentative.stable_group_id.trim().toLowerCase() : '';
    const targetIdentity = resolveCanonicalIdentity(targetRepresentativeGroupId, aliases);
    if (targetIdentity.stableGroupId !== caseIdentity.stableGroupId
      || (identity.stableGroupIdSupplied
        && targetIdentity.stableGroupId !== requestedStableIdentity.stableGroupId)
      || targetRepresentativeGroupId !== targetIdentity.stableGroupId) {
      throw conflict('requested representative_alert_id no longer matches the incident case');
    }
    const targetRepresentativeGroupKey = typeof targetRepresentative.stable_group_key === 'string'
      ? targetRepresentative.stable_group_key : '';
    const canonicalAliasGroupKeys = [caseIdentity.stableGroupKey,
      requestedStableIdentity.stableGroupKey].filter(Boolean);
    if (targetRepresentativeGroupKey
      && canonicalAliasGroupKeys.some((groupKey) => groupKey !== targetRepresentativeGroupKey)) {
      throw conflict('requested representative_alert_id has an incompatible stable group key');
    }
    if (identity.stableGroupKeySupplied
      && targetRepresentativeGroupKey !== identity.stableGroupKey) {
      throw conflict('requested stable_group_key no longer matches the incident case');
    }
    if (representativeGroupId === targetRepresentativeGroupId
      && Number(incident.representative_exists || 0)
      && typeof incident.representative_group_key === 'string'
      && incident.representative_group_key && targetRepresentativeGroupKey
      && incident.representative_group_key !== targetRepresentativeGroupKey) {
      throw conflict('requested representative_alert_id has an incompatible stable group key');
    }
    return {targetIdentity, targetRepresentativeAlertId, targetRepresentativeGroupKey};
  }

  async function proveExclusiveCase(caseId, aliases, targetIdentity) {
    const otherCases = await all(
      `SELECT case_id, group_id FROM incident_response_cases
       WHERE case_id != ?`,
      [caseId],
    );
    for (const otherCase of otherCases) {
      const otherIdentity = resolveCanonicalIdentity(String(otherCase.group_id || ''), aliases);
      if (otherIdentity.stableGroupId === targetIdentity.stableGroupId) {
        throw conflict('requested stable_group_id belongs to another incident case');
      }
    }
  }

  async function persistRebind(identity, caseId, requestedAt, requestedBy, context, target) {
    const {storedGroupId, storedRepresentativeAlertId} = context;
    const targetGroupId = target.targetIdentity.stableGroupId;
    if (storedGroupId === targetGroupId
      && storedRepresentativeAlertId === target.targetRepresentativeAlertId) return;
    const updated = await run(
      `UPDATE incident_response_cases
       SET group_id = ?, representative_alert_id = ?, updated_at = ?
       WHERE case_id = ? AND group_id = ? AND representative_alert_id = ?`,
      [targetGroupId, target.targetRepresentativeAlertId, requestedAt, caseId,
        storedGroupId, storedRepresentativeAlertId],
    );
    if (Number(updated.changes || 0) !== 1) {
      throw conflict('incident case identity changed during frozen dispatch validation');
    }
    await run(
      `INSERT INTO incident_response_events (
         case_id, event_type, actor, detail_json, created_at
       ) VALUES (?, 'reanalysis_basis_rebound', ?, ?, ?)`,
      [caseId, requestedBy, jsonText({
        previous_group_id: storedGroupId,
        previous_representative_alert_id: storedRepresentativeAlertId,
        group_id: targetGroupId,
        representative_alert_id: target.targetRepresentativeAlertId,
        ...(identity.stableGroupKeySupplied ? {stable_group_key: identity.stableGroupKey} : {}),
        ...(identity.cohortId ? {
          cohort_id: identity.cohortId,
          dispatch_id: identity.dispatchId,
          release_id: identity.releaseId,
          expected_assigned_route: identity.expectedAssignedRoute,
          expected_reviewer_route: identity.expectedReviewerRoute,
          reviewer_required: identity.reviewerRequired,
        } : {}),
      }), requestedAt],
    );
  }

  async function bind(identity, caseId, incident, requestedAt, requestedBy) {
    const context = await loadContext(identity, incident);
    const target = validateTarget(identity, incident, context);
    await proveExclusiveCase(caseId, context.aliases, target.targetIdentity);
    const targetGroupId = target.targetIdentity.stableGroupId;
    if (identity.cohortId) {
      await rejectProcessingJob(
        'incident_response_analysis',
        [context.storedGroupId, targetGroupId],
      );
    }
    await persistRebind(identity, caseId, requestedAt, requestedBy, context, target);
    incident.group_id = targetGroupId;
    incident.representative_alert_id = target.targetRepresentativeAlertId;
    incident.representative_exists = 1;
    incident.representative_group_id = targetGroupId;
    incident.representative_group_key = target.targetRepresentativeGroupKey;
    incident.controlled_legacy_job_group_id = context.storedGroupId
      && context.storedGroupId !== targetGroupId ? context.storedGroupId : '';
    return incident;
  }

  return {bind, replay};
}

module.exports = {createIncidentReanalysisFrozenDispatch};
