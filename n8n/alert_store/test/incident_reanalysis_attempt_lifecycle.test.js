'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createIncidentReanalysisAttemptLifecycle,
} = require('../services/incident_reanalysis_attempt_lifecycle');

function owner(overrides = {}) {
  const writes = [];
  const refreshes = [];
  const service = createIncidentReanalysisAttemptLifecycle({
    jobPayload: (job) => job?.payload || {},
    safeString: (value) => String(value || '').trim(),
    validCaseId: (value) => (/^case-/.test(String(value || '')) ? value : ''),
    attemptId: (lease) => (lease ? `attempt:${lease}` : ''),
    closeStale: async () => undefined,
    get: async () => null,
    run: async (sql, params) => { writes.push({sql, params}); return {changes: 1}; },
    nowUtc: () => 'time',
    refreshRun: async (runId) => refreshes.push(runId),
    ...overrides,
  });
  return {refreshes, service, writes};
}

const job = {
  attempt_count: 2,
  payload: {reanalysis_run_id: 'run-1', case_id: 'case-1'},
};

test('begins one immutable attempt and refreshes its run', async () => {
  const {refreshes, service, writes} = owner({
    get: async () => ({group_id: 'group-1', status: 'queued'}),
  });
  assert.deepEqual(await service.begin(job, 'lease', 'group-1'), {
    attempt_id: 'attempt:lease', run_id: 'run-1', case_id: 'case-1',
  });
  assert.equal(writes.length, 2);
  assert.deepEqual(refreshes, ['run-1']);
});

test('a normal escalation closes stale ownership without creating an attempt', async () => {
  const stale = [];
  const {service, writes} = owner({closeStale: async (...args) => stale.push(args)});
  assert.equal(await service.begin({payload: {}}, 'lease', 'group-1'), null);
  assert.equal(writes.length, 0);
  assert.deepEqual(stale, [['group-1', '', '', 'time']]);
});

test('failed retry returns its run case to queued', async () => {
  const attempt = {attempt_id: 'attempt:lease', run_id: 'run-1', case_id: 'case-1', status: 'running'};
  const {service, writes} = owner({get: async () => attempt});
  await service.finish({...job, status: 'pending'}, 'failed', 'failure', 'lease');
  assert.equal(writes.length, 2);
  assert.equal(writes[1].params[0], 'queued');
});

test('routes processing heartbeats and ignores unknown lifecycle states', async () => {
  const attempt = {attempt_id: 'attempt:lease', run_id: 'run-1', case_id: 'case-1'};
  const {service, writes} = owner({get: async () => attempt});
  assert.equal((await service.update({requestedStatus: 'processing', leaseToken: 'lease'})).run_id, 'run-1');
  assert.equal(await service.update({requestedStatus: 'unknown'}), null);
  assert.equal(writes.length, 1);
});
