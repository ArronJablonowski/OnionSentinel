'use strict';

function createManualDispatchIdentity({
  hasOwnField,
  stableGroupIdPattern,
  validPinnedStableGroupKey,
  cohortIdPattern,
  dispatchIdPattern,
  releaseIdPattern,
  controlledRoutePattern,
  controlledRouteModelIdentity,
  representativeAlertIdPattern,
  runtimeReleaseId,
  conflict,
}) {
  for (const [name, value] of Object.entries({hasOwnField, validPinnedStableGroupKey,
    controlledRouteModelIdentity, runtimeReleaseId, conflict})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  const patterns = {stableGroupIdPattern, cohortIdPattern, dispatchIdPattern,
    releaseIdPattern, controlledRoutePattern, representativeAlertIdPattern};
  for (const [name, value] of Object.entries(patterns)) {
    if (!value || typeof value.test !== 'function') throw new TypeError(`${name} must be a pattern`);
  }

  function httpConflict(message) {
    const error = new Error(message);
    error.statusCode = 409;
    return error;
  }

  function supplied(payload) {
    return {
      representativeAlertId: hasOwnField(payload, 'representative_alert_id'),
      stableGroupId: hasOwnField(payload, 'stable_group_id'),
      stableGroupKey: hasOwnField(payload, 'stable_group_key'),
      cohortId: hasOwnField(payload, 'cohort_id'),
      dispatchId: hasOwnField(payload, 'dispatch_id'),
      releaseId: hasOwnField(payload, 'release_id'),
      expectedAssignedRoute: hasOwnField(payload, 'expected_assigned_route'),
      expectedReviewerRoute: hasOwnField(payload, 'expected_reviewer_route'),
      reviewerRequired: hasOwnField(payload, 'reviewer_required'),
    };
  }

  function stringValue(payload, field, isSupplied) {
    return isSupplied && typeof payload[field] === 'string' ? payload[field] : '';
  }

  function normalize(payload) {
    const fields = supplied(payload);
    const representativeAlertId = stringValue(
      payload, 'representative_alert_id', fields.representativeAlertId,
    );
    const stableGroupId = stringValue(payload, 'stable_group_id', fields.stableGroupId);
    const stableGroupKey = stringValue(payload, 'stable_group_key', fields.stableGroupKey);
    const cohortId = stringValue(payload, 'cohort_id', fields.cohortId);
    const dispatchId = stringValue(payload, 'dispatch_id', fields.dispatchId);
    const releaseId = stringValue(payload, 'release_id', fields.releaseId);
    const expectedAssignedRoute = stringValue(
      payload, 'expected_assigned_route', fields.expectedAssignedRoute,
    );
    const expectedReviewerRoute = stringValue(
      payload, 'expected_reviewer_route', fields.expectedReviewerRoute,
    );
    if (fields.stableGroupId
      && (typeof payload.stable_group_id !== 'string'
        || !stableGroupIdPattern.test(stableGroupId))) {
      throw httpConflict('requested stable_group_id is invalid');
    }
    if (fields.stableGroupKey && !validPinnedStableGroupKey(payload.stable_group_key)) {
      throw httpConflict('requested stable_group_key is invalid');
    }
    if (fields.cohortId !== fields.dispatchId
      || (fields.cohortId && !fields.releaseId)
      || (fields.cohortId && (!fields.expectedAssignedRoute
        || !fields.expectedReviewerRoute || !fields.reviewerRequired))
      || (!fields.cohortId && (fields.expectedAssignedRoute
        || fields.expectedReviewerRoute || fields.reviewerRequired))) {
      throw httpConflict('controlled cohort identity and route contract must be supplied together');
    }
    if (fields.cohortId
      && (typeof payload.cohort_id !== 'string'
        || typeof payload.dispatch_id !== 'string'
        || typeof payload.release_id !== 'string'
        || !cohortIdPattern.test(cohortId)
        || !dispatchIdPattern.test(dispatchId)
        || !releaseIdPattern.test(releaseId))) {
      throw httpConflict('cohort dispatch identity is invalid');
    }
    if (fields.cohortId) {
      if (typeof payload.expected_assigned_route !== 'string'
        || typeof payload.expected_reviewer_route !== 'string'
        || !controlledRoutePattern.test(expectedAssignedRoute)
        || !controlledRoutePattern.test(expectedReviewerRoute)
        || controlledRouteModelIdentity(expectedAssignedRoute)
          === controlledRouteModelIdentity(expectedReviewerRoute)
        || payload.reviewer_required !== true) {
        throw conflict('controlled cohort route contract is invalid');
      }
      const deployedReleaseId = runtimeReleaseId();
      if (!deployedReleaseId) {
        throw conflict('controlled cohort dispatch requires an exact deployed runtime release');
      }
      if (releaseId !== deployedReleaseId) {
        throw conflict('controlled cohort dispatch release_id does not match the deployed runtime');
      }
    }
    if (fields.cohortId && (!fields.representativeAlertId
      || !fields.stableGroupId || !fields.stableGroupKey)) {
      throw httpConflict(
        'cohort dispatch requires representative_alert_id, stable_group_id, and stable_group_key pins',
      );
    }
    if (fields.representativeAlertId
      && (typeof payload.representative_alert_id !== 'string'
        || !representativeAlertIdPattern.test(representativeAlertId))) {
      throw httpConflict('requested representative_alert_id is invalid');
    }
    return {
      representativeAlertIdSupplied: fields.representativeAlertId,
      stableGroupIdSupplied: fields.stableGroupId,
      stableGroupKeySupplied: fields.stableGroupKey,
      representativeAlertId,
      stableGroupId,
      stableGroupKey,
      cohortId,
      dispatchId,
      releaseId,
      expectedAssignedRoute,
      expectedReviewerRoute,
      reviewerRequired: payload?.reviewer_required === true,
    };
  }

  return {normalize};
}

module.exports = {createManualDispatchIdentity};
