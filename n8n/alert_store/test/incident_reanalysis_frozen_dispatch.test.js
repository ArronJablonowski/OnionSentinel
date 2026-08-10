'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createIncidentReanalysisFrozenDispatch,
} = require('../services/incident_reanalysis_frozen_dispatch');

function identity() {
  return {
    representativeAlertIdSupplied: true,
    stableGroupIdSupplied: true,
    stableGroupKeySupplied: true,
    representativeAlertId: 'alert-1',
    stableGroupId: 'group-1',
    stableGroupKey: 'key-1',
    cohortId: 'cohort-1',
    dispatchId: 'dispatch-1',
    releaseId: 'release-1',
    expectedAssignedRoute: 'route-primary',
    expectedReviewerRoute: 'route-reviewer',
    reviewerRequired: true,
  };
}

function receipt() {
  return {
    ok: true,
    case_id: 'case-1',
    cohort_id: 'cohort-1',
    dispatch_id: 'dispatch-1',
    release_id: 'release-1',
    expected_assigned_route: 'route-primary',
    expected_reviewer_route: 'route-reviewer',
    reviewer_required: true,
    representative_alert_id: 'alert-1',
    stable_group_id: 'group-1',
    stable_group_key: 'key-1',
    requested_by: 'analyst',
    reason: 'reason',
  };
}

function owner({prior = null, otherCases = [], mutations = []} = {}) {
  return createIncidentReanalysisFrozenDispatch({
    get: async (sql) => (sql.includes('controlled_receipt_json')
      ? prior
      : {alert_id: 'alert-1', stable_group_id: 'group-1', stable_group_key: 'key-1'}),
    all: async () => otherCases,
    run: async (sql, params) => { mutations.push({sql, params}); return {changes: 1}; },
    parseJsonObject: JSON.parse,
    loadAliases: async () => new Map(),
    resolveCanonicalIdentity: (groupId) => ({stableGroupId: groupId, stableGroupKey: 'key-1'}),
    rejectProcessingJob: async () => undefined,
    jsonText: JSON.stringify,
    conflict: (message) => Object.assign(new Error(message), {statusCode: 409}),
  });
}

test('replays one exact controlled dispatch receipt', async () => {
  const value = receipt();
  const result = await owner({prior: {controlled_receipt_json: JSON.stringify(value)}})
    .replay(identity(), 'case-1', 'analyst', 'reason');
  assert.deepEqual(result, value);
});

test('rejects reuse of a dispatch with changed request provenance', async () => {
  const value = receipt();
  value.reason = 'other';
  await assert.rejects(
    owner({prior: {controlled_receipt_json: JSON.stringify(value)}})
      .replay(identity(), 'case-1', 'analyst', 'reason'),
    /dispatch identity was already used/,
  );
});

test('proves and retains an exact canonical frozen basis without writes', async () => {
  const mutations = [];
  const incident = {
    group_id: 'group-1',
    representative_alert_id: 'alert-1',
    representative_group_id: 'group-1',
    representative_group_key: 'key-1',
    representative_exists: 1,
  };
  const result = await owner({mutations}).bind(
    identity(), 'case-1', incident, 'time', 'analyst',
  );
  assert.equal(result.group_id, 'group-1');
  assert.equal(result.controlled_legacy_job_group_id, '');
  assert.equal(mutations.length, 0);
});

test('rejects a canonical group already owned by another case before writes', async () => {
  const mutations = [];
  await assert.rejects(
    owner({otherCases: [{case_id: 'case-2', group_id: 'group-1'}], mutations}).bind(
      identity(), 'case-1', {group_id: 'group-1', representative_alert_id: 'alert-1'},
      'time', 'analyst',
    ),
    /belongs to another incident case/,
  );
  assert.equal(mutations.length, 0);
});
