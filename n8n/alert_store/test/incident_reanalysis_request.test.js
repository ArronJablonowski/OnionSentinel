'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createIncidentReanalysisRequest} = require('../services/incident_reanalysis_request');

function owner(overrides = {}) {
  const mutations = [];
  const service = createIncidentReanalysisRequest({
    validCaseId: (value) => (/^case-/.test(String(value || '')) ? value : ''),
    normalizeIdentity: () => ({
      representativeAlertIdSupplied: false,
      stableGroupIdSupplied: false,
      stableGroupKeySupplied: false,
      cohortId: '',
    }),
    controlledEvaluationMode: true,
    safeString: (value) => String(value || '').trim(),
    replayFrozen: async () => null,
    bindFrozen: async () => undefined,
    releaseId: () => 'release-1',
    nowUtc: () => 'time',
    randomUuid: () => 'uuid-1',
    all: async () => [],
    get: async () => null,
    run: async (sql, params) => { mutations.push({sql, params}); return {changes: 1}; },
    supersedeCase: async () => undefined,
    retirePendingJobs: async () => undefined,
    enqueueJob: async () => undefined,
    jsonText: JSON.stringify,
    recordMetric: async () => undefined,
    refreshRun: async (runId) => ({run_id: runId, status: 'completed', total_count: 0}),
    conflict: (message) => Object.assign(new Error(message), {statusCode: 409}),
    ...overrides,
  });
  return {mutations, service};
}

test('rejects an invalid case identifier before normalization or writes', async () => {
  let normalized = 0;
  const {mutations, service} = owner({normalizeIdentity: () => { normalized += 1; return {}; }});
  await assert.rejects(service.request({}, 'bad'), (error) => error.statusCode === 400);
  assert.equal(normalized, 0);
  assert.equal(mutations.length, 0);
});

test('returns an exact frozen replay before release and run creation', async () => {
  const replay = {ok: true, dispatch_id: 'dispatch-1'};
  let releaseReads = 0;
  const {mutations, service} = owner({
    normalizeIdentity: () => ({
      representativeAlertIdSupplied: true,
      stableGroupIdSupplied: true,
      stableGroupKeySupplied: true,
      cohortId: 'cohort-1',
    }),
    replayFrozen: async () => replay,
    releaseId: () => { releaseReads += 1; return 'release-1'; },
  });
  assert.equal(await service.request({}, 'case-1'), replay);
  assert.equal(releaseReads, 0);
  assert.equal(mutations.length, 0);
});

test('rejects a missing requested incident case before run insertion', async () => {
  const {mutations, service} = owner();
  await assert.rejects(service.request({}, 'case-1'), (error) => error.statusCode === 404);
  assert.equal(mutations.length, 0);
});

test('creates and completes an empty all-cases reanalysis run', async () => {
  const {mutations, service} = owner();
  const result = await service.request({requested_by: 'analyst'});
  assert.deepEqual(result, {ok: true, run_id: 'irr-uuid-1', status: 'completed', total_count: 0});
  assert.equal(mutations.length, 1);
  assert.match(mutations[0].sql, /INSERT INTO incident_reanalysis_runs/);
});
