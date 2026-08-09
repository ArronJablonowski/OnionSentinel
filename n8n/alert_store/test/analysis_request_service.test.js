'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAnalysisRequestService} = require('../services/analysis_request_service');

function harness({controlled = false, failCommit = false} = {}) {
  const calls = [];
  const operation = (name) => async (...args) => {
    calls.push({name, args});
    return {operation: name};
  };
  const service = createAnalysisRequestService({
    controlledEvaluationMode: () => controlled,
    identityConflict: (message) => Object.assign(new Error(message), {statusCode: 409}),
    withWriteGate: async (callback) => {
      calls.push({name: 'gate:begin'});
      const result = await callback();
      calls.push({name: 'gate:end'});
      return result;
    },
    withTransaction: async (callback) => {
      calls.push({name: 'transaction:begin'});
      const result = await callback();
      if (failCommit) throw new Error('commit failed');
      calls.push({name: 'transaction:commit'});
      return result;
    },
    requestAiReanalysis: operation('requestAiReanalysis'),
    requestIncidentEscalation: operation('requestIncidentEscalation'),
    requestIncidentReanalysis: operation('requestIncidentReanalysis'),
    retireControlledEvaluation: operation('retireControlledEvaluation'),
    signalAiWorkers: async (reason) => calls.push({name: 'signal', args: [reason]}),
  });
  return {calls, service};
}

test('commits each request before emitting its exact worker signal', async () => {
  const cases = [
    ['requestAi', 'requestAiReanalysis', 'manual-ai-reanalysis'],
    ['escalateIncident', 'requestIncidentEscalation', 'incident-response-escalation'],
    ['reanalyzeIncident', 'requestIncidentReanalysis', 'incident-response-case-reanalysis'],
    ['reanalyzeAllIncidents', 'requestIncidentReanalysis', 'incident-response-bulk-reanalysis'],
  ];
  for (const [method, operation, reason] of cases) {
    const env = harness();
    const payload = {case_id: 'ir-one'};
    await env.service[method](payload);
    assert.deepEqual(env.calls.map(({name}) => name), [
      'gate:begin', 'transaction:begin', operation, 'transaction:commit', 'gate:end', 'signal',
    ]);
    assert.deepEqual(env.calls.at(-1).args, [reason]);
    if (method === 'reanalyzeIncident') {
      assert.deepEqual(env.calls[2].args, [payload, 'ir-one']);
    }
    if (method === 'reanalyzeAllIncidents') {
      assert.deepEqual(env.calls[2].args, [payload]);
    }
  }
});

test('retirement is transactional and does not wake workers', async () => {
  const env = harness();
  await env.service.retireEvaluation({job_id: 42});
  assert.deepEqual(env.calls.map(({name}) => name), [
    'gate:begin', 'transaction:begin', 'retireControlledEvaluation',
    'transaction:commit', 'gate:end',
  ]);
});

test('controlled AI and case reanalysis require a frozen cohort before writing', async () => {
  for (const method of ['requestAi', 'reanalyzeIncident']) {
    const env = harness({controlled: true});
    await assert.rejects(env.service[method]({}), (error) => (
      error.statusCode === 409 && /frozen cohort dispatch identity/.test(error.message)
    ));
    assert.deepEqual(env.calls, []);
  }
  const env = harness({controlled: true});
  await env.service.requestAi({cohort_id: 'cohort-1'});
  assert.equal(env.calls.some(({name}) => name === 'requestAiReanalysis'), true);
});

test('a failed commit never wakes AI workers', async () => {
  const env = harness({failCommit: true});
  await assert.rejects(env.service.requestAi({}), /commit failed/);
  assert.equal(env.calls.some(({name}) => name === 'signal'), false);
});
