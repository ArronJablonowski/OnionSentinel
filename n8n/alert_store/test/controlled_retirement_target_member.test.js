'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createControlledRetirementTargetMember,
} = require('../services/controlled_retirement_target_member');

function fixture(targetState = 'pending') {
  const pending = targetState === 'pending';
  return {
    identity: {
      case_id: 'case-1',
      stable_group_id: 'group-1',
      stable_group_key: 'key-1',
      representative_alert_id: 'alert-1',
      expected_attempt_id: 'attempt-1',
      expected_attempt_count: 1,
      reanalysis_run_id: 'run-1',
    },
    member: {rank: 2, dispatch_id: 'dispatch-2'},
    targetState,
    job: {
      processing_started_at: pending ? 'time' : null,
      last_error: pending ? 'exact failure' : null,
    },
    jobPayload: {dashboard_group_id: 'dashboard-1'},
    runRow: {run_id: 'run-1'},
    runReceipt: {run_id: 'run-1'},
    runCase: {
      run_id: 'run-1',
      case_id: 'case-1',
      group_id: 'group-1',
      dashboard_group_id: 'dashboard-1',
      representative_alert_id: 'alert-1',
      latest_attempt_id: 'attempt-1',
      analysis_id: null,
      started_at: 'time',
      status: pending ? 'queued' : 'skipped',
      completed_at: pending ? null : 'time',
      latest_error: pending ? 'exact failure' : null,
    },
    attempt: {
      attempt_id: 'attempt-1',
      run_id: 'run-1',
      case_id: 'case-1',
      group_id: 'group-1',
      durable_attempt_count: 1,
      status: 'failed',
      analysis_id: null,
      started_at: 'time',
      completed_at: 'time',
      latest_error: 'exact failure',
    },
  };
}

function owner(value) {
  return createControlledRetirementTargetMember({
    all: async (sql) => (sql.includes('run_cases') ? [value.runCase] : [value.attempt]),
    safeString: (input) => String(input || '').trim(),
    projectJob: (input) => input,
    projectRun: (input, receipt) => ({input, receipt}),
    projectRunCase: (input) => input,
    projectAttempt: (input) => input,
    projectError: (input) => input,
    rawSha256: (input) => `sha:${input}`,
    conflict: (message) => new Error(message),
  });
}

test('projects one exact pending target failure lineage', async () => {
  const value = fixture('pending');
  const result = await owner(value).project(
    value.identity, value.member, value.targetState, value.job,
    value.jobPayload, value.runRow, value.runReceipt,
  );
  assert.equal(result.state, 'pending');
  assert.equal(result.failure.normalized_sha256, 'sha:exact failure');
});

test('projects one exact retired target failure lineage', async () => {
  const value = fixture('retired');
  const result = await owner(value).project(
    value.identity, value.member, value.targetState, value.job,
    value.jobPayload, value.runRow, value.runReceipt,
  );
  assert.equal(result.state, 'retired');
  assert.equal(result.run_case.status, 'skipped');
});

test('rejects mismatched pending failure provenance', async () => {
  const value = fixture('pending');
  value.runCase.latest_error = 'different failure';
  await assert.rejects(
    owner(value).project(
      value.identity, value.member, value.targetState, value.job,
      value.jobPayload, value.runRow, value.runReceipt,
    ),
    /target failure lineage is contradictory/,
  );
});

test('rejects duplicate durable attempts', async () => {
  const value = fixture('pending');
  const targetOwner = createControlledRetirementTargetMember({
    all: async (sql) => (sql.includes('run_cases')
      ? [value.runCase]
      : [value.attempt, {...value.attempt, attempt_id: 'attempt-2'}]),
    safeString: (input) => String(input || '').trim(),
    projectJob: (input) => input,
    projectRun: (input) => input,
    projectRunCase: (input) => input,
    projectAttempt: (input) => input,
    projectError: (input) => input,
    rawSha256: (input) => input,
    conflict: (message) => new Error(message),
  });
  await assert.rejects(
    targetOwner.project(
      value.identity, value.member, value.targetState, value.job,
      value.jobPayload, value.runRow, value.runReceipt,
    ),
    /target failure lineage is contradictory/,
  );
});
