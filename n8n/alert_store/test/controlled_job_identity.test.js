'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createControlledJobIdentity} = require('../lib/controlled_job_identity');

function conflict(message) {
  const error = new Error(message);
  error.statusCode = 409;
  return error;
}

function parser() {
  return createControlledJobIdentity({
    requestHasOwnField: (value, field) => Object.prototype.hasOwnProperty.call(value, field),
    identityConflict: conflict,
    validPinnedStableGroupKey: (value) => /^key:[a-z]+$/.test(String(value || '')),
    representativeAlertIdPattern: /^alert-[a-z0-9]+$/,
    dispatchIdPattern: /^dispatch-[a-z0-9]+$/,
    controlledRoutePattern: /^route:[a-z0-9-]+$/,
    controlledRouteModelIdentity: (value) => String(value).split(':')[1],
  }).parseClaim;
}

const valid = {
  expected_job_id: 7,
  expected_representative_alert_id: 'alert-one',
  expected_dispatch_id: 'dispatch-one',
  expected_stable_group_key: 'key:group',
  expected_assigned_route: 'route:primary',
  expected_reviewer_route: 'route:reviewer',
  reviewer_required: true,
};

test('absent claim fields remain an optional null identity', () => {
  const parse = parser();
  assert.equal(parse(null), null);
  assert.equal(parse({status: 'processing'}), null);
});

test('partial identity is rejected before interpreting values', () => {
  const parse = parser();
  assert.throws(() => parse({expected_job_id: 7}), (error) => (
    error.statusCode === 409
    && error.message === 'controlled durable job claim identity is incomplete'
  ));
});

test('valid identity preserves exact claim fields and normalized numeric job ID', () => {
  const parse = parser();
  assert.deepEqual(parse({...valid, expected_job_id: '7'}), {
    jobId: 7,
    representativeAlertId: 'alert-one',
    dispatchId: 'dispatch-one',
    stableGroupKey: 'key:group',
    expectedAssignedRoute: 'route:primary',
    expectedReviewerRoute: 'route:reviewer',
    reviewerRequired: true,
  });
});

test('invalid job, representative, dispatch, and stable group identities retain errors', () => {
  const parse = parser();
  for (const [field, value, message] of [
    ['expected_job_id', 0, 'controlled durable job claim ID is invalid'],
    ['expected_representative_alert_id', 'bad', 'controlled durable job representative identity is invalid'],
    ['expected_dispatch_id', 'bad', 'controlled durable job dispatch identity is invalid'],
    ['expected_stable_group_key', 'bad', 'controlled durable job stable group key is invalid'],
  ]) {
    assert.throws(() => parse({...valid, [field]: value}), (error) => error.message === message);
  }
});

test('route identity requires distinct valid models and mandatory reviewer', () => {
  const parse = parser();
  for (const override of [
    {expected_assigned_route: 'bad'},
    {expected_reviewer_route: 'bad'},
    {expected_reviewer_route: 'route:primary'},
    {reviewer_required: false},
  ]) {
    assert.throws(() => parse({...valid, ...override}), (error) => (
      error.message === 'controlled durable job route identity is invalid'
    ));
  }
});
