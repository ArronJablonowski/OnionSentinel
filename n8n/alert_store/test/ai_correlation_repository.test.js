'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {compactCorrelationCandidates} = require('../lib/correlation_context');
const {createAiCorrelationRepository} = require('../repositories/ai_correlation_repository');

function harness(existingGroups = []) {
  const calls = [];
  const existing = new Set(existingGroups);
  const repository = createAiCorrelationRepository({
    get: async (_sql, params) => (existing.has(params[0]) ? {present: 1} : undefined),
    run: async (sql, params) => calls.push({sql, params}),
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    jsonText: JSON.stringify,
    nowUtc: () => '2026-08-09  12:00:00Z',
    compactCorrelationCandidates,
  });
  return {calls, repository};
}

test('correlation assessment preserves bounded model linkage fields', () => {
  const {repository} = harness();
  const assessment = repository.normalizeAssessment({
    correlation_found: 1,
    confidence: ' HIGH ',
    related_groups: [' GROUP-A ', {group_id: 'Group-B'}, '', {other: 'ignored'}],
    attack_chain_hypothesis: ' staged activity ',
  });
  assert.equal(assessment.correlation_found, true);
  assert.equal(assessment.confidence, 'high');
  assert.deepEqual([...assessment.related_groups], ['group-a', 'group-b']);
  assert.equal(assessment.attack_chain_hypothesis, 'staged activity');
});

test('malformed assessment remains a bounded empty assessment', () => {
  const {repository} = harness();
  const assessment = repository.normalizeAssessment('not-an-object');
  assert.equal(assessment.correlation_found, false);
  assert.equal(assessment.confidence, '');
  assert.deepEqual([...assessment.related_groups], []);
  assert.equal(assessment.attack_chain_hypothesis, '');
});

test('correlations skip the source and unknown groups while preserving model status', async () => {
  const env = harness(['group-related', 'group-candidate']);
  const count = await env.repository.recordCorrelations({
    groupId: 'group-source',
    analysisId: 'analysis-1',
    assessment: {
      confidence: 'MEDIUM',
      related_groups: [{group_id: 'group-related'}],
      attack_chain_hypothesis: 'same campaign',
    },
    candidates: [
      {group_id: 'group-source', score: 99},
      {group_id: 'group-missing', score: 80},
      {group_id: 'group-related', score: 77, correlation_reasons: ['shared host']},
      {group_id: 'group-candidate', score: 41, shared_observables: [{type: 'IP', value: '192.0.2.1'}]},
    ],
  });
  assert.equal(count, 2);
  assert.equal(env.calls.length, 2);
  assert.match(env.calls[0].sql, /ON CONFLICT\(source_group_id, related_group_id\) DO UPDATE SET/);
  assert.deepEqual(env.calls[0].params.slice(0, 9), [
    'group-source', 'group-related', 'analysis-1', 77, '["shared host"]', '[]',
    'model-related', 'medium', 'same campaign',
  ]);
  assert.equal(env.calls[1].params[6], 'candidate');
  assert.equal(env.calls[1].params[7], null);
  assert.equal(env.calls[1].params[8], null);
});

test('invalid candidate packages create no persistence side effects', async () => {
  const env = harness(['group-related']);
  assert.equal(await env.repository.recordCorrelations({
    groupId: 'group-source', analysisId: 'analysis-1', assessment: {}, candidates: {},
  }), 0);
  assert.equal(env.calls.length, 0);
});
