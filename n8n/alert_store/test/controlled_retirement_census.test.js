'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createControlledRetirementCensus} = require('../services/controlled_retirement_census');

function fixture() {
  const identity = {
    cohort_id: 'cohort-1',
    cohort_size: 2,
    member_rank: 1,
    retired_release_id: 'release-1',
    dispatch_id: 'dispatch-1',
    job_id: 7,
    case_id: 'case-1',
    reanalysis_run_id: 'irr-run-1',
    stable_group_id: 'group-1',
    stable_group_key: 'key-1',
    representative_alert_id: 'alert-1',
    expected_attempt_count: 1,
  };
  const payload = {
    dispatch_id: 'dispatch-1',
    agent_role: 'incident-responder',
    manual_reanalysis: true,
    cohort_id: 'cohort-1',
    release_id: 'release-1',
    reanalysis_release_id: 'release-1',
    reanalysis_run_id: 'irr-run-1',
    case_id: 'case-1',
    dashboard_group_id: 'dashboard-1',
    stable_group_id: 'group-1',
    group_id: 'group-1',
    stable_group_key: 'key-1',
    representative_alert_id: 'alert-1',
    alert_id: 'alert-1',
  };
  const job = {
    id: 7,
    job_type: 'incident_response_analysis',
    priority: 1200,
    max_attempts: 12,
    dedupe_key: 'group-1',
    status: 'pending',
    attempt_count: 1,
    payload,
  };
  const receipt = {
    ok: true,
    cohort_id: 'cohort-1',
    dispatch_id: 'dispatch-1',
    release_id: 'release-1',
    run_id: 'irr-run-1',
    case_id: 'case-1',
    representative_alert_id: 'alert-1',
    stable_group_id: 'group-1',
    stable_group_key: 'key-1',
  };
  const runRow = {
    run_id: 'irr-run-1',
    release_id: 'release-1',
    controlled_dispatch_id: 'dispatch-1',
    controlled_receipt_json: JSON.stringify(receipt),
    status: 'queued',
    total_count: 1,
  };
  return {identity, job, receipt, runRow};
}

function owner(value, overrides = {}) {
  const members = [
    {rank: 1, dispatch_id: 'dispatch-1', expected_state: 'target'},
    {rank: 2, dispatch_id: 'dispatch-2', expected_state: 'absent'},
  ];
  let query = 0;
  return createControlledRetirementCensus({
    all: async () => (++query === 1 ? [value.job] : [value.runRow]),
    orderedDispatches: () => members,
    parseJobPayload: (job) => job.payload,
    validIncidentCaseId: (input) => input,
    stableGroupIdPattern: /^group-/,
    validPinnedStableGroupKey: (input) => input === 'key-1',
    representativeAlertIdPattern: /^alert-/,
    parseJsonObject: JSON.parse,
    projectCompleted: async () => ({state: 'completed'}),
    projectTarget: async (...args) => ({rank: args[1].rank, state: args[2]}),
    conflict: (message) => new Error(message),
    ...overrides,
  });
}

test('projects one exact target and proves the remaining member absent', async () => {
  const value = fixture();
  const result = await owner(value).project(value.identity, 'pending');
  assert.deepEqual(result.members, [
    {rank: 1, state: 'pending'},
    {rank: 2, dispatch_id: 'dispatch-2', state: 'absent'},
  ]);
});

test('rejects an invalid census target state before querying', async () => {
  const value = fixture();
  await assert.rejects(
    owner(value).project(value.identity, 'completed'),
    /retirement census state is invalid/,
  );
});

test('rejects changed job and run binding provenance', async () => {
  const value = fixture();
  value.receipt.case_id = 'case-other';
  value.runRow.controlled_receipt_json = JSON.stringify(value.receipt);
  await assert.rejects(
    owner(value).project(value.identity, 'pending'),
    /job\/run binding changed/,
  );
});

test('rejects an extra cohort job before projecting any member', async () => {
  const value = fixture();
  let query = 0;
  const targetOwner = owner(value, {
    all: async () => (++query === 1 ? [value.job, {...value.job, id: 8}] : [value.runRow]),
  });
  await assert.rejects(
    targetOwner.project(value.identity, 'pending'),
    /job\/run census is not exact/,
  );
});
