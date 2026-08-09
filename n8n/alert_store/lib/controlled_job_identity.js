'use strict';

function createControlledJobIdentity({
  requestHasOwnField,
  identityConflict,
  validPinnedStableGroupKey,
  representativeAlertIdPattern,
  dispatchIdPattern,
  controlledRoutePattern,
  controlledRouteModelIdentity,
}) {
  for (const [name, value] of Object.entries({
    requestHasOwnField,
    identityConflict,
    validPinnedStableGroupKey,
    controlledRouteModelIdentity,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  for (const [name, value] of Object.entries({
    representativeAlertIdPattern, dispatchIdPattern, controlledRoutePattern,
  })) {
    if (!(value instanceof RegExp)) throw new TypeError(`${name} must be a RegExp`);
  }

  function parseClaim(value) {
    if (!value || typeof value !== 'object') return null;
    const supplied = [
      'expected_job_id',
      'expected_representative_alert_id',
      'expected_dispatch_id',
      'expected_stable_group_key',
      'expected_assigned_route',
      'expected_reviewer_route',
      'reviewer_required',
    ].filter((field) => requestHasOwnField(value, field));
    if (!supplied.length) return null;
    if (supplied.length !== 7) {
      throw identityConflict('controlled durable job claim identity is incomplete');
    }
    const jobId = Number(value.expected_job_id);
    const representativeAlertId = value.expected_representative_alert_id;
    const dispatchId = value.expected_dispatch_id;
    const stableGroupKey = value.expected_stable_group_key;
    const expectedAssignedRoute = value.expected_assigned_route;
    const expectedReviewerRoute = value.expected_reviewer_route;
    if (!Number.isSafeInteger(jobId) || jobId < 1) {
      throw identityConflict('controlled durable job claim ID is invalid');
    }
    if (
      typeof representativeAlertId !== 'string'
      || !representativeAlertIdPattern.test(representativeAlertId)
    ) {
      throw identityConflict('controlled durable job representative identity is invalid');
    }
    if (typeof dispatchId !== 'string' || !dispatchIdPattern.test(dispatchId)) {
      throw identityConflict('controlled durable job dispatch identity is invalid');
    }
    if (!validPinnedStableGroupKey(stableGroupKey)) {
      throw identityConflict('controlled durable job stable group key is invalid');
    }
    if (
      typeof expectedAssignedRoute !== 'string'
      || typeof expectedReviewerRoute !== 'string'
      || !controlledRoutePattern.test(expectedAssignedRoute)
      || !controlledRoutePattern.test(expectedReviewerRoute)
      || controlledRouteModelIdentity(expectedAssignedRoute)
        === controlledRouteModelIdentity(expectedReviewerRoute)
      || value.reviewer_required !== true
    ) {
      throw identityConflict('controlled durable job route identity is invalid');
    }
    return {
      jobId,
      representativeAlertId,
      dispatchId,
      stableGroupKey,
      expectedAssignedRoute,
      expectedReviewerRoute,
      reviewerRequired: true,
    };
  }

  return {parseClaim};
}

module.exports = {createControlledJobIdentity};
