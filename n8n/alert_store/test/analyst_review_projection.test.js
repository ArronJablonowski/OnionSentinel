'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  validAnalystGroupId,
  validIncidentCaseId,
  createAnalystReviewProjection,
} = require('../services/analyst_review_projection');

function owner(overrides = {}) {
  const calls = [];
  const service = createAnalystReviewProjection({
    get: async (sql, params) => { calls.push({type: 'get', sql, params}); return null; },
    all: async (sql, params) => { calls.push({type: 'all', sql, params}); return []; },
    resolveDashboardAlertGroup: async () => ({stable_group_id: 'abcdef123456'}),
    safeString: (value, max) => String(value || '').trim().slice(0, max),
    parseJsonObject: (value) => {
      try { return typeof value === 'string' ? JSON.parse(value) : value || {}; } catch { return {}; }
    },
    conservativeReviewerTelemetry: (_response, second) => ({
      status: second?.status || 'not_requested',
      reviewer_error: second?.reviewer_error || '',
      reviewer_outcome: second?.reviewer_outcome || '',
      reviewer_confidence: second?.reviewer_confidence || '',
      agreement: second?.agreement || '',
      material_disagreement: Boolean(second?.material_disagreement),
      disputed_fields: [],
    }),
    reviewerAutomationAuthorization: (_response, confidence) => ({
      authorized: confidence === 'high', reason: confidence === 'high' ? 'approved' : 'denied',
    }),
    reviewerFailureStatuses: new Set(['failed', 'timed_out']),
    ...overrides,
  });
  return {calls, service};
}

test('normalizes only exact analyst group and incident case identifiers', () => {
  assert.equal(validAnalystGroupId(' ABCDEF123456 '), 'abcdef123456');
  assert.equal(validAnalystGroupId('abcdef'), '');
  assert.equal(validIncidentCaseId(' IR-Case_1 '), 'ir-case_1');
  assert.equal(validIncidentCaseId('case-1'), '');
});

test('pending human review stops before reviewer reads without a primary analysis', async () => {
  const {calls, service} = owner();
  assert.equal(await service.pendingHumanReview('abcdef123456'), false);
  assert.equal(calls.length, 1);
});

test('material disagreement remains pending until an analyst adjudication exists', async () => {
  let read = 0;
  const rows = [
    {analysis_id: 'analysis-1', response_json: '{}'},
    {status: 'completed', material_disagreement: 1, reviewer_confidence: 'high'},
    null,
  ];
  const {service} = owner({get: async () => rows[read++]});
  assert.equal(await service.pendingHumanReview('abcdef123456'), true);
});

test('analyst adjudication clears the pending human-review gate', async () => {
  let read = 0;
  const rows = [
    {analysis_id: 'analysis-1', response_json: '{}'},
    {status: 'failed', reviewer_confidence: ''},
    {adjudication_id: 'adj-1'},
  ];
  const {service} = owner({get: async () => rows[read++]});
  assert.equal(await service.pendingHumanReview('abcdef123456'), false);
});

test('review state rejects a case outside the requested dashboard identity', async () => {
  const {service} = owner({get: async () => ({
    case_id: 'ir-case-1', group_id: 'abcdef123456',
    dashboard_group_id: '111111111111', status: 'open',
  })});
  await assert.rejects(
    service.reviewState({dashboardGroupId: 'abcdef123456', caseId: 'ir-case-1'}),
    (error) => error.statusCode === 404,
  );
});

test('review state projects consensus only when reviewer automation is authorized', async () => {
  let read = 0;
  const rows = [
    {analysis_id: 'analysis-1', generated_at: 'time', detection_outcome: 'true_positive',
      confidence: 'medium', response_json: JSON.stringify({event_status: 'malicious'})},
    {status: 'completed', primary_outcome: 'true_positive', primary_confidence: 'medium',
      reviewer_outcome: 'true_positive', reviewer_confidence: 'high',
      agreement: 'agreement', material_disagreement: 0},
    null,
  ];
  const {service} = owner({get: async () => rows[read++]});
  const review = await service.reviewState({
    dashboardGroupId: 'abcdef123456', stableGroupId: 'abcdef123456',
  });
  assert.equal(review.final_status, 'model_consensus');
  assert.equal(review.primary_event_status, 'malicious');
  assert.equal(review.effective_outcome, 'true_positive');
});

test('history query caps analyst-controlled limits at 100', async () => {
  let read = 0;
  const rows = [null];
  const {calls, service} = owner({get: async (sql, params) => {
    calls.push({type: 'get', sql, params});
    return rows[read++] || null;
  }});
  const snapshot = await service.adjudicationSnapshot(
    new URLSearchParams({group_id: 'abcdef123456', limit: '10000'}),
  );
  assert.equal(snapshot.ok, true);
  const history = calls.find((call) => call.type === 'all');
  assert.deepEqual(history.params, ['abcdef123456', 100]);
});
