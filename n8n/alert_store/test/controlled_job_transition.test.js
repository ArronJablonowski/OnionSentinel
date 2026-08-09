'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createControlledJobTransition} = require('../services/controlled_job_transition');

function conflict(message) {
  const error = new Error(message);
  error.statusCode = 409;
  return error;
}

function harness({mode = true, getResults = [], allResults = [[]], exactClaim = null} = {}) {
  const gets = [];
  const alls = [];
  const pendingGets = [...getResults];
  const pendingAlls = [...allResults];
  const owner = createControlledJobTransition({
    controlledEvaluationMode: mode,
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    identityConflict: conflict,
    stableGroupIdPattern: /^group-[a-z]+$/,
    parseClaimIdentity: () => exactClaim,
    all: async (sql, params) => {
      alls.push({sql, params});
      return pendingAlls.shift() || [];
    },
    get: async (sql, params) => {
      gets.push({sql, params});
      return pendingGets.shift();
    },
    incidentReanalysisJobPayload: (row) => row?.payload || {},
    validPinnedStableGroupKey: (value) => /^key:[a-z]+$/.test(String(value || '')),
    cohortIdPattern: /^cohort-[a-z]+$/,
    dispatchIdPattern: /^dispatch-[a-z]+$/,
    representativeAlertIdPattern: /^alert-[a-z]+$/,
    controlledRuntimeReleaseId: () => 'release-1',
    controlledRoutePattern: /^route:[a-z]+$/,
    controlledRouteModelIdentity: (value) => String(value).split(':')[1],
    incidentReanalysisAttemptId: () => 'attempt-1',
  });
  return {alls, gets, owner};
}

const base = {
  job_type: 'ai_analysis',
  dedupe_key: 'group-one',
  status: 'processing',
  lease_token: '',
};

const payload = {
  alert_id: 'alert-one',
  representative_alert_id: 'alert-one',
  group_id: 'group-one',
  stable_group_id: 'group-one',
  stable_group_key: 'key:group',
  cohort_id: 'cohort-one',
  dispatch_id: 'dispatch-one',
  release_id: 'release-1',
  agent_role: 'soc-analyst',
  expected_assigned_route: 'route:primary',
  expected_reviewer_route: 'route:reviewer',
  reviewer_required: true,
};

test('disabled mode bypasses admission and mirror mutation', async () => {
  const env = harness({mode: false});
  assert.equal(await env.owner.admit({}), null);
  env.owner.apply({action: 'processing', key: 'key', owned: {}}, {updated: true});
  assert.equal(env.owner.leases.size, 0);
});

test('transition shape and exact unowned claim remain fail closed', async () => {
  const invalid = harness();
  await assert.rejects(invalid.owner.admit({...base, status: 'Processing'}), (error) => (
    error.message === 'controlled evaluation job transition is not allowed'
  ));
  const missingClaim = harness();
  await assert.rejects(missingClaim.owner.admit(base), (error) => (
    error.message === 'controlled evaluation requires one exact unowned job claim'
  ));
});

test('claim admission rejects unrelated processing jobs and accepts exact ownership', async () => {
  const claim = {jobId: 7};
  const conflictEnv = harness({exactClaim: claim, allResults: [[{
    id: 8, job_type: 'ai_analysis', dedupe_key: 'group-one',
  }]]});
  await assert.rejects(conflictEnv.owner.admit(base), (error) => (
    error.message === 'controlled evaluation requires one exact unowned job claim'
  ));
  const exact = harness({exactClaim: claim, allResults: [[{
    id: 7, job_type: 'ai_analysis', dedupe_key: 'group-one',
  }]]});
  assert.deepEqual(await exact.owner.admit(base), {
    action: 'claim', key: 'ai_analysis\0group-one', exactClaim: claim,
  });
});

test('active owned transition validates database lease and representative identity', async () => {
  const current = {
    id: 7,
    status: 'processing',
    lease_token: 'lease-1',
    lease_expires_at: '2026-08-09T12:30:00Z',
    rerun_requested: 0,
    payload,
  };
  const env = harness({getResults: [current, {
    stable_group_id: 'group-one', stable_group_key: 'key:group',
  }]});
  const admitted = await env.owner.admit({...base, lease_token: 'lease-1'});
  assert.equal(admitted.action, 'processing');
  assert.equal(admitted.owned.jobId, 7);
  assert.equal(admitted.owned.agentRole, 'soc-analyst');
  assert.equal(admitted.owned.resultCommitted, false);
});

test('completed transition is rejected before a result-bound completion', async () => {
  const current = {
    id: 7,
    status: 'processing',
    lease_token: 'lease-1',
    lease_expires_at: '2026-08-09T12:30:00Z',
    rerun_requested: 0,
    payload,
  };
  const env = harness({getResults: [current, {
    stable_group_id: 'group-one', stable_group_key: 'key:group',
  }]});
  await assert.rejects(env.owner.admit({...base, status: 'completed', lease_token: 'lease-1'}),
    (error) => error.message === 'controlled evaluation job cannot complete before its bound result');
});

test('post-commit mirror applies claim and heartbeat only after updated receipt', () => {
  const claim = {jobId: 7};
  const env = harness({exactClaim: claim});
  const admission = {action: 'claim', key: 'ai_analysis\0group-one', exactClaim: claim};
  env.owner.apply(admission, {updated: false});
  assert.equal(env.owner.leases.size, 0);
  assert.throws(() => env.owner.apply(admission, {updated: true}), (error) => (
    error.message === 'controlled evaluation claim receipt is incomplete'
  ));
  env.owner.apply(admission, {
    updated: true,
    leaseToken: 'lease-1',
    claim: {job_id: 7, job_type: 'ai_analysis', dedupe_key: 'group-one', payload},
  });
  assert.equal(env.owner.leases.get('ai_analysis\0group-one').leaseToken, 'lease-1');
  const owned = {jobId: 7};
  env.owner.apply({action: 'processing', key: 'key-2', owned}, {updated: true});
  assert.deepEqual(env.owner.leases.get('key-2'), owned);
  assert.equal(env.owner.leases.size, 1);
  env.owner.retireLease('key-2');
  assert.equal(env.owner.leases.size, 0);
});
