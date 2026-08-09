'use strict';

const assert = require('node:assert/strict');
const crypto = require('crypto');
const test = require('node:test');
const {createRequestAuthorization} = require('../lib/request_authorization');

function authorization(overrides = {}) {
  return createRequestAuthorization({
    assetWriteToken: 'asset-secret',
    evaluationToken: 'a'.repeat(64),
    controlledEvaluationMode: true,
    timingSafeEqual: crypto.timingSafeEqual,
    ...overrides,
  });
}

test('asset write authorization requires an exact string token', () => {
  const owner = authorization();
  assert.equal(owner.assetWriteAuthorized({headers: {}}), false);
  assert.equal(owner.assetWriteAuthorized({headers: {
    'x-onion-sentinel-asset-token': 'asset-secret-extra',
  }}), false);
  assert.equal(owner.assetWriteAuthorized({headers: {
    'x-onion-sentinel-asset-token': 'asset-secret',
  }}), true);
});

test('asset write authorization failure retains its public 403 contract', () => {
  const owner = authorization();
  assert.throws(() => owner.requireAssetWrite({headers: {}}), (error) => (
    error.statusCode === 403 && error.message === 'asset-store write authorization failed'
  ));
  assert.doesNotThrow(() => owner.requireAssetWrite({headers: {
    'x-onion-sentinel-asset-token': 'asset-secret',
  }}));
});

test('controlled evaluation authorization is bypassed only when mode is disabled', () => {
  const owner = authorization({controlledEvaluationMode: false});
  assert.equal(owner.controlledEvaluationAuthorized({headers: {}}), true);
});

test('controlled evaluation token requires lowercase 64-hex shape and exact value', () => {
  const owner = authorization();
  for (const supplied of [undefined, 'a'.repeat(63), 'A'.repeat(64), 'b'.repeat(64)]) {
    assert.equal(owner.controlledEvaluationAuthorized({headers: {
      'x-onion-sentinel-evaluation-token': supplied,
    }}), false);
  }
  assert.equal(owner.controlledEvaluationAuthorized({headers: {
    'x-onion-sentinel-evaluation-token': 'a'.repeat(64),
  }}), true);
});

test('length mismatch short-circuits before timingSafeEqual', () => {
  let comparisons = 0;
  const owner = authorization({
    timingSafeEqual: () => {
      comparisons += 1;
      return true;
    },
  });
  assert.equal(owner.assetWriteAuthorized({headers: {
    'x-onion-sentinel-asset-token': 'short',
  }}), false);
  assert.equal(comparisons, 0);
});
