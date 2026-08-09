'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {RETIREMENT_SCHEMA, createControlledRetirementIdentity} = require('../lib/controlled_retirement_identity');

function owner(mode = true) {
  return createControlledRetirementIdentity({
    controlledEvaluationMode: mode,
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    validIncidentCaseId: (value) => /^ir-[a-z]+$/.test(String(value)) ? value : '',
    cohortIdPattern: /^cohort-[a-z]+$/, dispatchIdPattern: /^[a-f0-9]{64}$/,
    releaseIdPattern: /^[a-f0-9]{40}$/, representativeAlertIdPattern: /^alert-[a-z]+$/,
    stableGroupIdPattern: /^[a-f0-9]{20}$/,
    validPinnedStableGroupKey: (value) => value === 'key:one',
    controlledRuntimeReleaseId: () => 'b'.repeat(40),
  });
}

function valid() {
  return {schema: RETIREMENT_SCHEMA, absent_dispatch_ids: ['3'.repeat(64)],
    case_id: 'ir-one', cohort_id: 'cohort-one', cohort_size: 3,
    completed_dispatch_ids: ['1'.repeat(64)], dispatch_id: '2'.repeat(64),
    expected_attempt_count: 1, expected_attempt_id: `ira-${'a'.repeat(40)}`,
    expected_job_payload_sha256: '4'.repeat(64), expected_prior_analysis_id: '',
    failure_attestation_sha256: '5'.repeat(64), job_id: 7,
    manifest_sha256: '6'.repeat(64), member_rank: 2,
    reanalysis_run_id: 'irr-run-1', reason: 'retire failed controlled member',
    replacement_release_id: 'b'.repeat(40), representative_alert_id: 'alert-one',
    retired_release_id: 'c'.repeat(40), stable_group_id: 'd'.repeat(20),
    stable_group_key: 'key:one', start_sha256: '7'.repeat(64)};
}

test('production mode rejects retirement with 403', () => {
  assert.throws(() => owner(false).normalize(valid()), (error) => error.statusCode === 403);
});

test('request field set is exact before identity parsing', () => {
  const value = valid(); delete value.reason;
  assert.throws(() => owner().normalize(value), (error) =>
    error.message === 'controlled evaluation retirement request fields are not exact');
});

test('valid cohort identity preserves ordered dispatch partitions', () => {
  const normalized = owner().normalize(valid());
  assert.equal(normalized.member_rank, 2);
  assert.deepEqual(normalized.completed_dispatch_ids, ['1'.repeat(64)]);
  assert.deepEqual(normalized.absent_dispatch_ids, ['3'.repeat(64)]);
});

test('duplicate dispatch IDs and changed runtime release fail closed', () => {
  const duplicate = valid(); duplicate.absent_dispatch_ids = [duplicate.dispatch_id];
  assert.throws(() => owner().normalize(duplicate), (error) =>
    error.message === 'controlled evaluation retirement identity is invalid');
  const release = valid(); release.replacement_release_id = 'c'.repeat(40);
  assert.throws(() => owner().normalize(release), (error) =>
    error.message === 'controlled evaluation retirement identity is invalid');
});

test('canonical hashing sorts objects and rejects non-finite or unsupported values', () => {
  const identity = owner();
  assert.equal(identity.canonicalJsonText({b: 1, a: [true]}), '{"a":[true],"b":1}');
  assert.equal(identity.sha256({b: 1, a: 2}), identity.sha256({a: 2, b: 1}));
  assert.throws(() => identity.canonicalJsonText({value: Infinity}), (error) =>
    error.message === 'controlled evaluation retirement JSON is not finite');
  assert.throws(() => identity.canonicalJsonText({value: undefined}), (error) =>
    error.message.includes('unsupported value'));
});
