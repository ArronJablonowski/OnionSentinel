'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createIncidentReanalysisBindingService} = require('../services/incident_reanalysis_binding');

function harness({getResults = [], runResults = []} = {}) {
  const gets = [];
  const runs = [];
  const refreshes = [];
  const pendingGets = [...getResults];
  const pendingRuns = [...runResults];
  const service = createIncidentReanalysisBindingService({
    get: async (sql, params) => {
      gets.push({sql, params});
      return pendingGets.shift();
    },
    run: async (sql, params) => {
      runs.push({sql, params});
      return pendingRuns.shift() || {changes: 1};
    },
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    parseProjectTimestamp: (value) => (value ? new Date(value) : null),
    formatProjectTimestamp: (value) => value.toISOString(),
    nowUtc: () => '2026-08-09  12:00:00Z',
    incidentAnalysisProvider: (modelPath, provider) => provider || `provider:${modelPath}`,
    refreshIncidentReanalysisRun: async (runId) => refreshes.push(runId),
  });
  return {gets, runs, refreshes, service};
}

const attempt = {
  attempt_id: `ira-${'a'.repeat(40)}`,
  run_id: 'run-1',
  case_id: 'case-1',
  group_id: 'group-1',
  started_at: '2026-08-09  11:00:00Z',
  attempt_order: 7,
  analysis_id: null,
};

test('incomplete historical binding identity remains authoritative without queries', async () => {
  const env = harness();
  assert.deepEqual(await env.service.bindingAuthority({attempt_id: 'legacy-attempt'}), {
    attempt_id: 'legacy-attempt', run_id: null, case_id: null, authoritative: true,
  });
  assert.equal(env.gets.length, 0);
});

test('newer attempt or run-case ownership makes an older binding non-authoritative', async () => {
  const env = harness({getResults: [{present: 1}, undefined]});
  const binding = await env.service.bindingAuthority(attempt);
  assert.equal(binding.authoritative, false);
  assert.equal(env.gets.length, 2);
  assert.deepEqual(env.gets[0].params, [
    'case-1', attempt.attempt_id, attempt.started_at, attempt.started_at, 7,
  ]);
});

test('strict attempt identity rejects malformed, missing, and already-bound mismatches', async () => {
  const malformed = harness();
  await assert.rejects(
    malformed.service.bindResult({groupId: 'group-1', analysisId: 'analysis-1', expectedAttemptId: 'bad'}),
    (error) => error.statusCode === 400,
  );
  const missing = harness({getResults: [undefined]});
  await assert.rejects(
    missing.service.bindResult({
      groupId: 'group-1', analysisId: 'analysis-1', expectedAttemptId: attempt.attempt_id,
    }),
    (error) => error.statusCode === 409,
  );
  const alreadyBound = harness({getResults: [{...attempt, analysis_id: 'analysis-old'}]});
  await assert.rejects(
    alreadyBound.service.bindResult({
      groupId: 'group-1', analysisId: 'analysis-new', expectedAttemptId: attempt.attempt_id,
    }),
    (error) => error.statusCode === 409,
  );
});

test('strict replay returns immutable binding without rewriting the attempt', async () => {
  const env = harness({getResults: [{...attempt, analysis_id: 'analysis-1'}, undefined, undefined]});
  const binding = await env.service.bindResult({
    groupId: 'group-1', analysisId: 'analysis-1', expectedAttemptId: attempt.attempt_id,
  });
  assert.equal(binding.attempt_id, attempt.attempt_id);
  assert.equal(binding.authoritative, true);
  assert.equal(env.runs.length, 0);
});

test('legacy fallback uses analysis start cutoff and safely returns no candidate', async () => {
  const env = harness({getResults: [undefined, undefined]});
  const binding = await env.service.bindResult({
    groupId: 'group-1',
    analysisId: 'analysis-1',
    allowLegacyFallback: true,
    analysisStartedAt: '2026-08-09T11:30:00Z',
    generatedAt: '2026-08-09T11:40:00Z',
  });
  assert.equal(binding, null);
  assert.deepEqual(env.gets[1].params, [
    'group-1', '2026-08-09T11:30:00.000Z', '2026-08-09T11:30:00.000Z',
  ]);
});

test('completion updates the exact attempt and run case before refreshing authority', async () => {
  const env = harness({
    getResults: [attempt, undefined, undefined, undefined],
    runResults: [{changes: 1}, {changes: 1}],
  });
  const binding = await env.service.bindResult({
    groupId: 'group-1',
    analysisId: 'analysis-1',
    model: 'model-1',
    modelPath: 'local',
    provider: 'ollama',
    expectedAttemptId: attempt.attempt_id,
    generatedAt: '2026-08-09  11:59:00Z',
  });
  assert.equal(binding.authoritative, true);
  assert.equal(env.runs.length, 2);
  assert.match(env.runs[0].sql, /WHERE attempt_id = \? AND analysis_id IS NULL/);
  assert.deepEqual(env.runs[0].params.slice(0, 5), [
    'analysis-1', 'model-1', 'ollama', 'local', '2026-08-09  11:59:00Z',
  ]);
  assert.match(env.runs[1].sql, /WHERE run_id = \? AND case_id = \? AND status != 'skipped'/);
  assert.deepEqual(env.refreshes, ['run-1']);
});

test('lost conditional bind performs no run-case or refresh side effects', async () => {
  const env = harness({getResults: [attempt], runResults: [{changes: 0}]});
  const binding = await env.service.bindResult({
    groupId: 'group-1', analysisId: 'analysis-1', expectedAttemptId: attempt.attempt_id,
  });
  assert.equal(binding, null);
  assert.equal(env.runs.length, 1);
  assert.deepEqual(env.refreshes, []);
});
