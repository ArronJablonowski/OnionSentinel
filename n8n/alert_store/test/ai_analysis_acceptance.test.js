'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAiAnalysisAcceptance} = require('../services/ai_analysis_acceptance');

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function harness({getResults = [], binding = null, correlations = 2} = {}) {
  const gets = [];
  const runs = [];
  const calls = [];
  const pendingGets = [...getResults];
  const service = createAiAnalysisAcceptance({
    get: async (sql, params) => {
      gets.push({sql, params});
      return pendingGets.shift();
    },
    run: async (sql, params) => runs.push({sql, params}),
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    jsonText: JSON.stringify,
    nowUtc: () => '2026-08-09  12:00:00Z',
    parseJsonObject: (value) => {
      try { return JSON.parse(value); } catch { return {}; }
    },
    canonicalJsonText: canonical,
    normalizeTimestampValue: (value) => String(value || '')
      .replace('T', ' ')
      .replace('Z', '+00:00')
      .replace(/\s+/g, ' '),
    supportedAgentRoles: new Set(['soc-analyst', 'incident-responder']),
    incidentReanalysisBindingAuthority: async (attempt) => {
      calls.push(['authority', attempt]);
      return binding;
    },
    aiReviewRepository: {
      recordSecondOpinion: async (value) => {
        calls.push(['second', value]);
        return true;
      },
      recordDisagreementAdjudication: async (value) => {
        calls.push(['adjudication', value]);
        return false;
      },
    },
    incidentAnalysisCompletion: {
      complete: async (value) => {
        calls.push(['incident', value]);
        return binding;
      },
    },
    aiCorrelationRepository: {
      recordCorrelations: async (value) => {
        calls.push(['correlation', value]);
        return correlations;
      },
    },
  });
  return {calls, gets, runs, service};
}

const payload = {
  alert_id: 'alert-1',
  analysis_id: 'analysis-1',
  generated_at: '2026-08-09T11:59:00Z',
  model: 'model-1',
  model_path: 'local',
  artifact_path: '/evidence/result.json',
  evidence_hash: 'ABC123',
  response: {
    detection_outcome: 'true_positive',
    bluf: 'Summary',
    summary: 'Longer summary',
    confidence: 'HIGH',
    correlation_assessment: {correlation_found: true},
  },
};

function accepted(overrides = {}) {
  return {
    analysis_id: 'analysis-1',
    group_id: 'group-1',
    alert_id: 'alert-1',
    agent_role: 'soc-analyst',
    generated_at: '2026-08-09  11:59:00+00:00',
    model: 'model-1',
    model_path: 'local',
    detection_outcome: 'true_positive',
    bluf: 'Summary',
    summary: 'Longer summary',
    confidence: 'high',
    artifact_path: '/evidence/result.json',
    evidence_hash: 'abc123',
    response_json: JSON.stringify(payload.response),
    ...overrides,
  };
}

test('invalid identity is rejected before database access', async () => {
  const env = harness();
  await assert.rejects(env.service.record({alert_id: '', analysis_id: 'short'}), {
    message: 'analysis_id and alert_id are required',
  });
  assert.equal(env.gets.length, 0);
});

test('missing alert and missing stable group retain acceptance errors', async () => {
  const missing = harness({getResults: [undefined]});
  await assert.rejects(missing.service.record(payload), {message: 'analysis alert_id not found'});
  const ungrouped = harness({getResults: [{alert_id: 'alert-1'}, undefined]});
  await assert.rejects(ungrouped.service.record(payload), {
    message: 'analysis alert has no stable group identity',
  });
});

test('new acceptance persists primary before bounded downstream owners', async () => {
  const binding = {run_id: 'run-1', attempt_id: 'attempt-1', authoritative: true};
  const env = harness({getResults: [{alert_id: 'alert-1', stable_group_id: 'group-1'}, undefined], binding});
  const result = await env.service.record({...payload, agent_role: 'unknown-role'});
  assert.equal(env.runs.length, 1);
  assert.match(env.runs[0].sql, /ON CONFLICT\(analysis_id\) DO NOTHING/);
  assert.equal(env.runs[0].params[3], 'soc-analyst');
  assert.deepEqual(env.calls.map((item) => item[0]), [
    'second', 'adjudication', 'incident', 'correlation',
  ]);
  assert.equal(result.correlations, 2);
  assert.equal(result.second_opinion_recorded, true);
  assert.equal(result.disagreement_adjudication_recorded, false);
  assert.equal(result.reanalysis_authoritative, true);
  assert.equal(result.idempotent, undefined);
  assert.match(result.stored_response_sha256, /^[a-f0-9]{64}$/);
});

test('exact replay is read-only and reports durable related state', async () => {
  const binding = {run_id: 'run-1', attempt_id: 'attempt-1', authoritative: false};
  const env = harness({
    getResults: [
      {alert_id: 'alert-1', stable_group_id: 'group-1'},
      accepted(),
      {attempt_id: 'attempt-1'},
      {present: 1},
      undefined,
      {count: 4},
    ],
    binding,
  });
  const result = await env.service.record(payload);
  assert.equal(result.idempotent, true);
  assert.equal(result.correlations, 4);
  assert.equal(result.second_opinion_recorded, true);
  assert.equal(result.disagreement_adjudication_recorded, false);
  assert.equal(result.reanalysis_authoritative, false);
  assert.equal(env.runs.length, 0);
  assert.deepEqual(env.calls.map((item) => item[0]), ['authority']);
});

test('changed immutable replay is rejected before any secondary state reads', async () => {
  const env = harness({
    getResults: [{alert_id: 'alert-1', stable_group_id: 'group-1'}, accepted({model: 'other'})],
  });
  await assert.rejects(env.service.record(payload), (error) => (
    error.statusCode === 409 && error.message.includes('model')
  ));
  assert.equal(env.gets.length, 2);
  assert.equal(env.calls.length, 0);
});

test('replay rejects malformed or mismatched immutable attempt identity', async () => {
  const malformed = harness({
    getResults: [{alert_id: 'alert-1', stable_group_id: 'group-1'}, accepted(), undefined],
  });
  await assert.rejects(malformed.service.record({...payload, reanalysis_attempt_id: 'bad'}),
    (error) => error.statusCode === 400);
  const mismatch = harness({
    getResults: [
      {alert_id: 'alert-1', stable_group_id: 'group-1'},
      accepted(),
      {attempt_id: `ira-${'a'.repeat(40)}`},
    ],
  });
  await assert.rejects(mismatch.service.record({
    ...payload, reanalysis_attempt_id: `ira-${'b'.repeat(40)}`,
  }), (error) => error.statusCode === 409);
});
