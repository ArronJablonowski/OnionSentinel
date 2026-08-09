'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAnalysisResultService} = require('../services/analysis_result_service');

function harness({controlled = false, completeRequired = false, completed = true, failCommit = false} = {}) {
  const calls = [];
  const service = createAnalysisResultService({
    controlledEvaluationMode: () => controlled,
    requestHasOwnField: (payload, field) => Object.hasOwn(payload, field),
    identityConflict: (message) => Object.assign(new Error(message), {statusCode: 409}),
    withWriteGate: async (callback) => {
      calls.push('gate:begin');
      const result = await callback();
      calls.push('gate:end');
      return result;
    },
    withTransaction: async (callback) => {
      calls.push('transaction:begin');
      const result = await callback();
      if (failCommit) throw new Error('commit failed');
      calls.push('transaction:commit');
      return result;
    },
    controlledResultAdmission: async () => {
      calls.push('controlled:admit');
      return {
        completeRequired,
        jobType: 'ai_analysis',
        stableGroupId: 'stable-group',
        leaseToken: 'lease-1',
      };
    },
    recordAnalysisResult: async () => {
      calls.push('result:record');
      return {ok: true, analysis_id: 'analysis-1'};
    },
    transitionJobStatus: async (...args) => {
      calls.push({name: 'job:complete', args});
      return {updated: completed};
    },
    applyControlledResultAdmission: () => calls.push('controlled:apply'),
  });
  return {calls, service};
}

test('preserves submission provenance and applies mirror state only after commit', async () => {
  const env = harness();
  assert.deepEqual(await env.service.submit({__body_sha256: 'digest-1'}), {
    ok: true,
    analysis_id: 'analysis-1',
    submission_sha256: 'digest-1',
  });
  assert.deepEqual(env.calls, [
    'gate:begin', 'transaction:begin', 'controlled:admit', 'result:record',
    'transaction:commit', 'controlled:apply', 'gate:end',
  ]);
});

test('controlled result atomically completes its exact durable job', async () => {
  const env = harness({controlled: true, completeRequired: true});
  await env.service.submit({controlled_job: {job_id: 42}, __body_sha256: 'digest-2'});
  const completion = env.calls.find((item) => typeof item === 'object');
  assert.deepEqual(completion.args, [
    'ai_analysis', 'stable-group', 'completed', '', 'lease-1', true,
  ]);
  assert.ok(env.calls.indexOf(completion) < env.calls.indexOf('transaction:commit'));
  assert.ok(env.calls.indexOf('transaction:commit') < env.calls.indexOf('controlled:apply'));
});

test('rejects controlled identity outside controlled mode before acquiring the gate', async () => {
  const env = harness();
  await assert.rejects(env.service.submit({controlled_job: null}), (error) => (
    error.statusCode === 409 && /requires controlled evaluation mode/.test(error.message)
  ));
  assert.deepEqual(env.calls, []);
});

test('fails the transaction when exact controlled completion is rejected', async () => {
  const env = harness({controlled: true, completeRequired: true, completed: false});
  await assert.rejects(env.service.submit({controlled_job: {}}), (error) => (
    error.statusCode === 409 && /could not complete its exact job/.test(error.message)
  ));
  assert.equal(env.calls.includes('transaction:commit'), false);
  assert.equal(env.calls.includes('controlled:apply'), false);
});

test('a commit failure never applies process-local controlled state', async () => {
  const env = harness({failCommit: true});
  await assert.rejects(env.service.submit({}), /commit failed/);
  assert.equal(env.calls.includes('controlled:apply'), false);
});
