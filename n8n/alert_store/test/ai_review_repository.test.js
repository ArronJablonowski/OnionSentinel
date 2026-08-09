'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAiReviewRepository} = require('../repositories/ai_review_repository');

function harness() {
  const calls = [];
  const repository = createAiReviewRepository({
    run: async (sql, params) => calls.push({sql, params}),
    safeString: (value, max) => String(value ?? '').trim().replace(/\s+/g, ' ').slice(0, max),
    jsonText: JSON.stringify,
    nowUtc: () => '2026-08-09  12:00:00Z',
  });
  return {calls, repository};
}

const identity = {
  analysisId: 'analysis-1',
  groupId: 'group-1',
  alertId: 'alert-1',
  agentRole: 'soc-analyst',
  generatedAt: '2026-08-09  11:59:00Z',
};

test('absent or invalid review envelopes remain no-op records', async () => {
  const env = harness();
  assert.equal(await env.repository.recordSecondOpinion({...identity, response: {}}), false);
  assert.equal(await env.repository.recordDisagreementAdjudication({
    ...identity, response: {_disagreement_adjudication: []},
  }), false);
  assert.equal(env.calls.length, 0);
});

test('second opinion preserves bounded reviewer, comparison, runtime, and memory telemetry', async () => {
  const env = harness();
  const recorded = await env.repository.recordSecondOpinion({
    ...identity,
    model: 'primary-model',
    modelPath: 'local',
    response: {
      detection_outcome: 'true_positive',
      confidence: 'HIGH',
      _second_opinion: {
        trigger: 'material review',
        status: 'completed',
        runtime_seconds: 1.5,
        model_route: 'review-route',
        response: {_analysis_model: 'reviewer', confidence: 'MEDIUM'},
        comparison: {agreement: 'partial', material_disagreement: true, disputed_fields: ['outcome']},
        memory_writeback: {accepted: 2},
      },
    },
  });
  assert.equal(recorded, true);
  const {sql, params} = env.calls[0];
  assert.match(sql, /ON CONFLICT\(analysis_id\) DO UPDATE SET/);
  assert.equal(params[7], 'primary-model');
  assert.equal(params[14], 'medium');
  assert.equal(params[16], 1);
  assert.equal(params[19], 1.5);
  assert.equal(params[20], 2);
});

test('invalid second-opinion runtime and arrays are normalized without widening schemas', async () => {
  const env = harness();
  await env.repository.recordSecondOpinion({
    ...identity,
    response: {_second_opinion: {
      runtime_seconds: -1,
      comparison: {disputed_fields: 'not-an-array'},
      memory_writeback: {accepted: -3},
    }},
  });
  const params = env.calls[0].params;
  assert.equal(params[17], '[]');
  assert.equal(params[19], null);
  assert.equal(params[20], 0);
});

test('adjudication remains human-required and never directly authorizes automation', async () => {
  const env = harness();
  const recorded = await env.repository.recordDisagreementAdjudication({
    ...identity,
    response: {_disagreement_adjudication: {
      status: 'completed',
      mode: 'active',
      model_route: 'adjudicator-route',
      runtime_seconds: 2,
      response: {
        decision: 'primary',
        confidence: 'HIGH',
        confidence_score: 0.8,
        resolved_fields: ['outcome'],
        remaining_disagreements: [],
        evidence_used: ['e1'],
        rationale: 'evidence-bound',
        additional_evidence_needed: [],
      },
    }},
  });
  assert.equal(recorded, true);
  const {sql, params} = env.calls[0];
  assert.match(sql, /automation_authorized = excluded\.automation_authorized/);
  assert.equal(params[10], 0.8);
  assert.equal(params[17], 0);
  assert.equal(params[18], 1);
});

test('out-of-range adjudicator scores and malformed lists are stored as bounded unknowns', async () => {
  const env = harness();
  await env.repository.recordDisagreementAdjudication({
    ...identity,
    response: {_disagreement_adjudication: {
      runtime_seconds: -2,
      response: {confidence_score: 4, resolved_fields: 'all'},
    }},
  });
  const params = env.calls[0].params;
  assert.equal(params[10], null);
  assert.equal(params[11], '[]');
  assert.equal(params[16], null);
});
