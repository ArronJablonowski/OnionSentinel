'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createControlledResultAdmission} = require('../services/controlled_result_admission');

function conflict(message) { const error = new Error(message); error.statusCode = 409; return error; }

function harness({mode = true, getResults = []} = {}) {
  const retired = [];
  const pending = [...getResults];
  const owner = createControlledResultAdmission({
    controlledEvaluationMode: mode,
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    identityConflict: conflict,
    claimLeaseKey: (type, key) => `${type}\0${key}`,
    get: async () => pending.shift(),
    incidentReanalysisJobPayload: (row) => row?.payload || {},
    parseJsonObject: JSON.parse,
    canonicalJsonText: JSON.stringify,
    controlledRoutePattern: /^route:[a-z]+$/,
    controlledRouteModelIdentity: (value) => String(value).split(':')[1],
    cohortIdPattern: /^cohort-[a-z]+$/,
    dispatchIdPattern: /^dispatch-[a-z]+$/,
    representativeAlertIdPattern: /^alert-[a-z]+$/,
    stableGroupIdPattern: /^group-[a-z]+$/,
    validPinnedStableGroupKey: (value) => /^key:[a-z]+$/.test(String(value || '')),
    releaseIdPattern: /^release-[0-9]+$/,
    runtimeReleaseId: 'release-1',
    incidentReanalysisAttemptId: () => `ira-${'a'.repeat(40)}`,
    retireLease: (key) => retired.push(key),
  });
  return {owner, retired};
}

function validPackage(owner) {
  const controlled_job = {
    job_id: 7, job_type: 'ai_analysis', lease_token: 'lease-1',
    cohort_id: 'cohort-one', dispatch_id: 'dispatch-one',
    representative_alert_id: 'alert-one', stable_group_id: 'group-one',
    stable_group_key: 'key:group', agent_role: 'soc-analyst',
    reanalysis_attempt_id: '', release_id: 'release-1',
    expected_assigned_route: 'route:primary', expected_reviewer_route: 'route:reviewer',
    reviewer_required: true,
  };
  const response = {
    _analysis_evaluation_memory_frozen: true,
    _analysis_controlled_claim_sha256: owner.claimDigest(controlled_job),
    _analysis_model_route: 'route:primary',
    _second_opinion: {
      status: 'completed', model_route: 'route:reviewer',
      response: {_analysis_model_route: 'route:reviewer'},
    },
  };
  return {controlled_job, analysis_id: 'analysis-1', alert_id: 'alert-one',
    agent_role: 'soc-analyst', reanalysis_attempt_id: '', response};
}

function current(payload, overrides = {}) {
  return {id: 7, status: 'processing', lease_token: 'lease-1',
    lease_expires_at: '2026-08-09T13:00:00Z', rerun_requested: 0, payload, ...overrides};
}

function jobPayload() {
  return {cohort_id: 'cohort-one', dispatch_id: 'dispatch-one', release_id: 'release-1',
    expected_assigned_route: 'route:primary', expected_reviewer_route: 'route:reviewer',
    reviewer_required: true, alert_id: 'alert-one', representative_alert_id: 'alert-one',
    group_id: 'group-one', stable_group_id: 'group-one', stable_group_key: 'key:group',
    agent_role: 'soc-analyst'};
}

test('disabled mode bypasses admission and lease retirement', async () => {
  const env = harness({mode: false});
  assert.equal(await env.owner.admit({}), null);
  env.owner.apply({key: 'x'});
  assert.deepEqual(env.retired, []);
});

test('identity requires the exact field set and frozen claim-bound routes', async () => {
  const env = harness();
  await assert.rejects(env.owner.admit({controlled_job: {}}), (error) =>
    error.message === 'controlled evaluation result identity is incomplete');
  const value = validPackage(env.owner);
  value.response._analysis_evaluation_memory_frozen = false;
  await assert.rejects(env.owner.admit(value), (error) =>
    error.message === 'controlled evaluation result identity is invalid');
});

test('new result validates durable job and representative before admission', async () => {
  const probe = harness();
  const value = validPackage(probe.owner);
  const payload = jobPayload();
  const env = harness({getResults: [current(payload), undefined,
    {stable_group_id: 'group-one', stable_group_key: 'key:group'}]});
  const admitted = await env.owner.admit(value);
  assert.deepEqual(admitted, {key: 'ai_analysis\0group-one', analysisId: 'analysis-1',
    jobType: 'ai_analysis', stableGroupId: 'group-one', leaseToken: 'lease-1',
    idempotentReplay: false, completeRequired: true});
});

test('exact accepted replay is read-only and may finish a still-processing job', async () => {
  const probe = harness();
  const value = validPackage(probe.owner);
  const payload = jobPayload();
  const accepted = {group_id: 'group-one', alert_id: 'alert-one', agent_role: 'soc-analyst',
    response_json: JSON.stringify(value.response)};
  const env = harness({getResults: [current(payload), accepted]});
  const admitted = await env.owner.admit(value);
  assert.equal(admitted.idempotentReplay, true);
  assert.equal(admitted.completeRequired, true);
});

test('post-commit apply retires only the admitted lease key', () => {
  const env = harness();
  env.owner.apply(null);
  env.owner.apply({key: 'ai_analysis\0group-one'});
  assert.deepEqual(env.retired, ['ai_analysis\0group-one']);
});
