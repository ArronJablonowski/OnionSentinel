'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createAnalystDecisionPersistence,
} = require('../services/analyst_decision_persistence');

function owner(overrides = {}) {
  const events = [];
  const service = createAnalystDecisionPersistence({
    get: async () => null,
    all: async () => [],
    run: async (sql, params = []) => {
      events.push({sql: sql.replace(/\s+/g, ' ').trim(), params});
      return {changes: 1};
    },
    withWriteGate: async (task) => task(),
    reviewState: async () => ({analysis_id: 'analysis-1', stable_group_id: 'abcdef123456',
      final_status: 'model_consensus'}),
    validGroupId: (value) => /^[a-f0-9]{12}$/.test(String(value || '')) ? value : '',
    validCaseId: (value) => /^ir-[a-z0-9_-]+$/.test(String(value || '')) ? value : '',
    safeString: (value, max) => String(value || '').trim().slice(0, max),
    adjudicationOutcomes: new Set(['true_positive', 'false_positive']),
    adjudicationConfidences: new Set(['low', 'medium', 'high']),
    eventStatuses: new Set(['malicious', 'benign']),
    detectionValidities: new Set(['valid', 'invalid']),
    activityDispositions: new Set(['authorized', 'unauthorized']),
    handlingValues: new Set(['monitor', 'contain']),
    verdictContradictions: () => [],
    adjudicationTextMaxLength: 2000,
    statusReasonMaxLength: 500,
    nowUtc: () => '2026-08-10T00:00:00Z',
    randomUUID: () => 'uuid-1',
    jsonText: (value) => JSON.stringify(value),
    ...overrides,
  });
  return {events, service};
}

function validAdjudication(overrides = {}) {
  return {
    group_id: 'abcdef123456', analysis_id: 'analysis-1',
    outcome_override: 'true_positive', confidence: 'high',
    rationale: 'Validated evidence', reviewer: 'analyst',
    event_status: 'malicious', detection_validity: 'valid',
    activity_disposition: 'unauthorized', handling: 'contain',
    ...overrides,
  };
}

test('stale analysis identity fails closed before any adjudication write', async () => {
  const {events, service} = owner();
  await assert.rejects(
    service.recordAdjudication(validAdjudication({analysis_id: 'stale'})),
    (error) => error.statusCode === 409 && /analysis changed/.test(error.message),
  );
  assert.deepEqual(events, []);
});

test('factored verdict contradictions fail before persistence', async () => {
  const {events, service} = owner({
    verdictContradictions: () => ['true positive cannot be benign'],
  });
  await assert.rejects(
    service.recordAdjudication(validAdjudication()),
    (error) => error.statusCode === 400 && /conflicts/.test(error.message),
  );
  assert.deepEqual(events, []);
});

test('case adjudication records audit provenance before optional resolution', async () => {
  let review = 0;
  const {events, service} = owner({reviewState: async () => {
    review += 1;
    return {analysis_id: 'analysis-1', stable_group_id: 'abcdef123456',
      final_status: review === 1 ? 'disputed_pending_human' : 'adjudicated'};
  }});
  const result = await service.recordAdjudication(validAdjudication({
    case_id: 'ir-case-1', resolve_case: true, case_resolution_reason: 'Reviewed and closed',
  }));
  assert.equal(result.adjudication_id, 'adj-uuid-1');
  assert.deepEqual(events.map((event) => (
    event.sql.startsWith('INSERT INTO analyst_adjudications') ? 'adjudication'
      : event.sql.includes("'analyst_adjudicated'") ? 'audit'
        : event.sql.startsWith('UPDATE incident_response_cases') ? 'resolve'
          : event.sql.includes("'resolved'") ? 'resolved-event' : 'unknown'
  )), ['adjudication', 'audit', 'resolve', 'resolved-event']);
});

test('incident resolution is blocked while independent review is pending', async () => {
  const {events, service} = owner({
    get: async () => ({case_id: 'ir-case-1', dashboard_group_id: 'abcdef123456', status: 'open'}),
    reviewState: async () => ({final_status: 'review_required_failed'}),
  });
  await assert.rejects(
    service.updateIncidentCaseStatus({case_id: 'ir-case-1', status: 'resolved',
      resolution_reason: 'close'}),
    (error) => error.statusCode === 409,
  );
  assert.deepEqual(events, []);
});

test('status snapshot expires acknowledged groups after a new repeat', async () => {
  const rows = [
    {group_id: 'aaaaaaaaaaaa', status: 'acknowledged', repeat_count: 2, current_count: 3},
    {group_id: 'bbbbbbbbbbbb', status: 'suppressed', repeat_count: 1,
      current_count: 9, reason: 'approved suppression'},
  ];
  const {events, service} = owner({all: async () => rows});
  const snapshot = await service.statusSnapshot();
  assert.deepEqual(snapshot.acknowledged, []);
  assert.deepEqual(snapshot.suppressed, ['bbbbbbbbbbbb']);
  assert.equal(events.length, 1);
  assert(events[0].sql.startsWith('DELETE FROM analyst_alert_group_state'));
});

test('acknowledgement defaults repeat count to the highest current count', async () => {
  const {events, service} = owner({
    get: async () => ({group_key: 'key', raw_alert_count: 3, total_seen_count: 7}),
  });
  await service.updateStatus({id: 'abcdef123456', status: 'acknowledged', updated_by: 'analyst'});
  assert.equal(events.length, 1);
  assert(events[0].sql.startsWith('INSERT INTO analyst_alert_group_state'));
  assert.equal(events[0].params[3], 7);
});

test('suppression requires explicit rationale before review or writes', async () => {
  let reviews = 0;
  const {events, service} = owner({
    get: async () => ({group_key: 'key', raw_alert_count: 1, total_seen_count: 1}),
    reviewState: async () => { reviews += 1; return {final_status: 'model_consensus'}; },
  });
  await assert.rejects(
    service.updateStatus({id: 'abcdef123456', status: 'suppressed'}),
    /suppression reason is required/,
  );
  assert.equal(reviews, 0);
  assert.deepEqual(events, []);
});
