'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createIncidentAnalysisCompletion} = require('../services/incident_analysis_completion');

function harness({binding = null, caseId = 'case-1'} = {}) {
  const binds = [];
  const runs = [];
  const service = createIncidentAnalysisCompletion({
    get: async () => (caseId ? {case_id: caseId} : undefined),
    run: async (sql, params) => runs.push({sql, params}),
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    jsonText: JSON.stringify,
    nowUtc: () => '2026-08-09  12:00:00Z',
    bindIncidentReanalysisResult: async (value) => {
      binds.push(value);
      return binding;
    },
  });
  return {binds, runs, service};
}

const request = {
  groupId: 'group-1',
  analysisId: 'analysis-1',
  generatedAt: '2026-08-09  11:59:00Z',
  response: {_analysis_model: 'response-model', _analysis_model_path: 'local'},
};

test('non-incident analyses have no reanalysis or case side effects', async () => {
  const env = harness();
  assert.equal(await env.service.complete({...request, agentRole: 'soc-analyst', payload: {}}), null);
  assert.equal(env.binds.length, 0);
  assert.equal(env.runs.length, 0);
});

test('authoritative completion updates case state then appends provenance event', async () => {
  const binding = {run_id: 'run-1', attempt_id: 'attempt-1', authoritative: true};
  const env = harness({binding});
  assert.equal(await env.service.complete({
    ...request,
    agentRole: 'incident-responder',
    payload: {model: 'payload-model', provider: 'ollama', reanalysis_attempt_id: ' ATTEMPT-1 '},
  }), binding);
  assert.equal(env.binds.length, 1);
  assert.deepEqual(env.binds[0], {
    groupId: 'group-1',
    analysisId: 'analysis-1',
    model: 'payload-model',
    modelPath: 'local',
    provider: 'ollama',
    expectedAttemptId: 'attempt-1',
    allowLegacyFallback: false,
    analysisStartedAt: '',
    generatedAt: '2026-08-09  11:59:00Z',
  });
  assert.equal(env.runs.length, 2);
  assert.match(env.runs[0].sql, /SET agent_status = 'analyzed'/);
  assert.match(env.runs[1].sql, /VALUES \(\?, 'analysis_completed', 'incident-responder'/);
  assert.deepEqual(JSON.parse(env.runs[1].params[1]), {
    analysis_id: 'analysis-1',
    generated_at: '2026-08-09  11:59:00Z',
    reanalysis_run_id: 'run-1',
    reanalysis_attempt_id: 'attempt-1',
    authoritative: true,
  });
});

test('non-authoritative completion preserves current case pointer but records history', async () => {
  const env = harness({binding: {run_id: 'run-old', attempt_id: 'attempt-old', authoritative: false}});
  await env.service.complete({...request, agentRole: 'incident-responder', payload: {}});
  assert.equal(env.runs.length, 1);
  assert.doesNotMatch(env.runs[0].sql, /UPDATE incident_response_cases/);
  assert.equal(JSON.parse(env.runs[0].params[1]).authoritative, false);
});

test('legacy unbound result remains case-authoritative and records null binding provenance', async () => {
  const env = harness({binding: null});
  await env.service.complete({...request, agentRole: 'incident-responder', payload: {}});
  assert.equal(env.binds[0].allowLegacyFallback, true);
  assert.equal(env.runs.length, 2);
  const detail = JSON.parse(env.runs[1].params[1]);
  assert.equal(detail.reanalysis_run_id, null);
  assert.equal(detail.reanalysis_attempt_id, null);
  assert.equal(detail.authoritative, true);
});

test('missing incident case returns durable binding without case writes', async () => {
  const binding = {run_id: 'run-1', attempt_id: 'attempt-1', authoritative: true};
  const env = harness({binding, caseId: ''});
  assert.equal(await env.service.complete({
    ...request, agentRole: 'incident-responder', payload: {},
  }), binding);
  assert.equal(env.runs.length, 0);
});
