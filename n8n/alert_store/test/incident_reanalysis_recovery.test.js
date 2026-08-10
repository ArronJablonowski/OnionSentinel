'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createIncidentReanalysisRecovery} = require('../services/incident_reanalysis_recovery');

function owner(overrides = {}) {
  const writes = [];
  const service = createIncidentReanalysisRecovery({
    durableJobsAvailable: () => true,
    all: async () => [],
    get: async () => null,
    run: async (sql, params) => { writes.push({sql, params}); return {changes: 1}; },
    retireCompleted: async () => false,
    retireSuperseded: async () => false,
    attemptId: (lease) => (lease ? `attempt:${lease}` : ''),
    beginAttempt: async () => null,
    safeString: (value) => String(value || '').trim(),
    jobPayload: (job) => job?.payload || {},
    validCaseId: (value) => (/^case-/.test(String(value || '')) ? value : ''),
    nowUtc: () => 'time',
    refreshRun: async () => undefined,
    ...overrides,
  });
  return {service, writes};
}

test('does no recovery work before durable jobs are initialized', async () => {
  let reads = 0;
  const {service} = owner({durableJobsAvailable: () => false, all: async () => { reads += 1; return []; }});
  assert.equal(await service.reconcile(), 0);
  assert.equal(reads, 0);
});

test('retires already-satisfied jobs without launching replacement attempts', async () => {
  let query = 0;
  const {service, writes} = owner({
    all: async () => (++query === 1 ? [{id: 7}] : []),
    retireCompleted: async () => true,
  });
  assert.equal(await service.reconcile(), 1);
  assert.equal(writes.length, 0);
});

test('leaves the immutable attempt owning the current processing lease untouched', async () => {
  let query = 0;
  const attempt = {
    attempt_id: 'attempt:lease', run_id: 'run-1', case_id: 'case-1',
    group_id: 'group-1', durable_status: 'processing', lease_token: 'lease',
  };
  const {service, writes} = owner({
    all: async () => {
      query += 1;
      if (query < 3) return [];
      return [attempt];
    },
  });
  assert.equal(await service.reconcile(), 0);
  assert.equal(writes.length, 0);
});

test('repairs a missing current attempt and publishes queued ownership once', async () => {
  let query = 0;
  let getQuery = 0;
  const job = {dedupe_key: 'group-1', lease_token: 'lease'};
  const {service, writes} = owner({
    all: async () => {
      query += 1;
      if (query === 2) return [job];
      return [];
    },
    get: async () => {
      getQuery += 1;
      if (getQuery === 1) return null;
      return {status: 'pending', payload: {case_id: 'case-1'}};
    },
    beginAttempt: async () => ({case_id: 'case-1'}),
  });
  assert.equal(await service.reconcile(), 1);
  assert.equal(writes.length, 1);
  assert.equal(writes[0].params[0], 'queued');
});
