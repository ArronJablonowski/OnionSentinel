'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createManualDispatchIdentity} = require('../lib/manual_dispatch_identity');

function owner(release = 'release-1') {
  return createManualDispatchIdentity({
    hasOwnField: (value, field) => Object.prototype.hasOwnProperty.call(value || {}, field),
    stableGroupIdPattern: /^group-/,
    validPinnedStableGroupKey: (value) => value === 'key-1',
    cohortIdPattern: /^cohort-/,
    dispatchIdPattern: /^(dispatch-|release-)/,
    releaseIdPattern: /^release-/,
    controlledRoutePattern: /^route:/,
    controlledRouteModelIdentity: (value) => value.split(':')[1],
    representativeAlertIdPattern: /^alert-/,
    runtimeReleaseId: () => release,
    conflict: (message) => Object.assign(new Error(message), {statusCode: 409}),
  });
}

function controlledPayload() {
  return {
    representative_alert_id: 'alert-1',
    stable_group_id: 'group-1',
    stable_group_key: 'key-1',
    cohort_id: 'cohort-1',
    dispatch_id: 'dispatch-1',
    release_id: 'release-1',
    expected_assigned_route: 'route:primary',
    expected_reviewer_route: 'route:reviewer',
    reviewer_required: true,
  };
}

test('normalizes an exact controlled dispatch contract', () => {
  const value = owner().normalize(controlledPayload());
  assert.equal(value.cohortId, 'cohort-1');
  assert.equal(value.reviewerRequired, true);
  assert.equal(value.stableGroupIdSupplied, true);
});

test('allows an unpinned ordinary manual dispatch', () => {
  assert.deepEqual(owner().normalize({}), {
    representativeAlertIdSupplied: false,
    stableGroupIdSupplied: false,
    stableGroupKeySupplied: false,
    representativeAlertId: '',
    stableGroupId: '',
    stableGroupKey: '',
    cohortId: '',
    dispatchId: '',
    releaseId: '',
    expectedAssignedRoute: '',
    expectedReviewerRoute: '',
    reviewerRequired: false,
  });
});

test('rejects a partial controlled route contract', () => {
  const value = controlledPayload();
  delete value.expected_reviewer_route;
  assert.throws(() => owner().normalize(value), /must be supplied together/);
});

test('rejects identical primary and reviewer model identities', () => {
  const value = controlledPayload();
  value.expected_reviewer_route = 'route:primary';
  assert.throws(() => owner().normalize(value), /route contract is invalid/);
});

test('rejects a release that differs from the deployed runtime', () => {
  assert.throws(
    () => owner('release-2').normalize(controlledPayload()),
    /release_id does not match/,
  );
});
