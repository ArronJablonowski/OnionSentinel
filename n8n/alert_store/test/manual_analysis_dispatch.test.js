'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');
const {safeString} = require('../lib/alert_value_normalization');
const {createManualAnalysisDispatch} = require('../services/manual_analysis_dispatch');

const emptyIdentity = {
  cohortId: '', dispatchId: '', releaseId: '', expectedAssignedRoute: '',
  expectedReviewerRoute: '', reviewerRequired: false,
  representativeAlertIdSupplied: false, stableGroupIdSupplied: false,
  stableGroupKey: '', stableGroupKeySupplied: false,
};
const representative = {alert_id: 'alert-1', stable_group_id: 'stable-group-id',
  stable_group_key: 'stable-group-key'};

function owner({gets = [], identity = emptyIdentity, get, run} = {}) {
  const events = [];
  const getValues = [...gets];
  const service = createManualAnalysisDispatch({
    get: get || (async (sql, params) => {
      events.push({name: 'get', sql, params});
      return getValues.shift() ?? null;
    }),
    run: run || (async (sql, params) => events.push({name: 'run', sql, params})),
    safeString,
    normalizeIdentity: (payload) => {
      events.push({name: 'identity', payload});
      return identity;
    },
    conflict: (message) => {
      const error = new Error(message);
      error.statusCode = 409;
      return error;
    },
    rejectProcessingJob: async (...args) => events.push({name: 'reject', args}),
    enqueueJob: async (...args) => events.push({name: 'enqueue', args}),
    recordMetric: async (...args) => events.push({name: 'metric', args}),
    nowUtc: () => '2026-08-10  02:00:00+00:00',
    jsonText: JSON.stringify,
    sha256Text: (value) => crypto.createHash('sha256').update(value).digest('hex'),
  });
  return {events, service};
}

test('dashboard resolution uses summary first and returns without legacy lookup', async () => {
  const {events, service} = owner({gets: [representative]});
  assert.equal(await service.resolveDashboardAlertGroup('abcdef123456'), representative);
  assert.equal(events.length, 1);
  assert.match(events[0].sql, /FROM alert_group_summary/);
  assert.deepEqual(events[0].params, ['abcdef123456']);
});

test('dashboard resolution falls back to legacy alias with deterministic representative order', async () => {
  const {events, service} = owner({gets: [null, representative]});
  assert.equal(await service.resolveDashboardAlertGroup('abcdef123456'), representative);
  assert.match(events[1].sql, /FROM alert_group_alias/);
  assert.match(events[1].sql, /a\.alert_id DESC LIMIT 1/);
});

test('stable group ID and key pins reject stale dashboard identity', async () => {
  const idOwner = owner({gets: [representative]});
  await assert.rejects(idOwner.service.resolveDashboardAlertGroup('abcdef123456', {
    stableGroupIdSupplied: true, stableGroupId: 'changed',
  }), (error) => error.statusCode === 409
    && error.message === 'requested stable_group_id no longer matches the dashboard group');
  const keyOwner = owner({gets: [representative]});
  await assert.rejects(keyOwner.service.resolveDashboardAlertGroup('abcdef123456', {
    stableGroupKeySupplied: true, stableGroupKey: 'changed',
  }), (error) => error.statusCode === 409
    && error.message === 'requested stable_group_key no longer matches the dashboard group');
});

test('representative pin must still belong to the resolved stable identity', async () => {
  const valid = owner({gets: [representative, {...representative, alert_id: 'pinned'}]});
  assert.equal((await valid.service.resolveDashboardAlertGroup('abcdef123456', {
    representativeAlertIdSupplied: true, representativeAlertId: 'pinned',
  })).alert_id, 'pinned');
  const invalid = owner({gets: [representative, {alert_id: 'pinned',
    stable_group_id: 'other', stable_group_key: 'other'}]});
  await assert.rejects(invalid.service.resolveDashboardAlertGroup('abcdef123456', {
    representativeAlertIdSupplied: true, representativeAlertId: 'pinned',
  }), (error) => error.statusCode === 409
    && error.message === 'requested representative_alert_id no longer belongs to the dashboard group');
});

test('manual AI rejects invalid or missing dashboard groups before queue writes', async () => {
  const invalid = owner();
  await assert.rejects(invalid.service.requestAiReanalysis({group_id: 'bad'}),
    (error) => error.statusCode === 400 && error.message === 'valid dashboard group_id is required');
  assert.deepEqual(invalid.events, []);
  const missing = owner({gets: [null, null]});
  await assert.rejects(missing.service.requestAiReanalysis({group_id: 'abcdef123456'}),
    (error) => error.statusCode === 404 && error.message === 'SOC alert group was not found');
  assert.equal(missing.events.some(({name}) => name === 'enqueue'), false);
});

test('manual AI rejects non-finite limits before durable enqueue', async () => {
  const {events, service} = owner({gets: [representative]});
  await assert.rejects(service.requestAiReanalysis({group_id: 'abcdef123456',
    related_limit: 'not-finite'}), (error) => error.statusCode === 400
    && error.message === 'AI analysis queue limits must be finite numbers');
  assert.equal(events.some(({name}) => name === 'enqueue'), false);
});

test('manual AI preserves clamps, durable options, metric order, and response', async () => {
  const {events, service} = owner({gets: [representative]});
  const result = await service.requestAiReanalysis({group_id: 'ABCDEF123456',
    related_limit: 999, pcap_analysis_limit: 0, requested_by: ' analyst ', reason: ' fresh '});
  const enqueue = events.find(({name}) => name === 'enqueue').args;
  assert.equal(enqueue[0], 'ai_analysis');
  assert.equal(enqueue[1], 'stable-group-id');
  assert.deepEqual(enqueue[2], {alert_id: 'alert-1', group_id: 'stable-group-id',
    dashboard_group_id: 'abcdef123456', manual_reanalysis: true, requested_by: 'analyst',
    requested_at: '2026-08-10  02:00:00+00:00', reason: 'fresh', related_limit: 500,
    pcap_analysis_limit: 1});
  assert.deepEqual(enqueue[3], {priority: 1000, maxAttempts: 12});
  assert.equal(events.at(-1).name, 'metric');
  assert.deepEqual(result, {ok: true, status: 'queued', group_id: 'abcdef123456',
    queue_group_id: 'stable-group-id', representative_alert_id: 'alert-1',
    requested_at: '2026-08-10  02:00:00+00:00'});
});

test('controlled SOC dispatch rejects processing work before enqueue and preserves identity', async () => {
  const identity = {...emptyIdentity, cohortId: 'cohort-1', dispatchId: 'dispatch-1',
    releaseId: 'release-1', expectedAssignedRoute: 'route-a',
    expectedReviewerRoute: 'route-b', reviewerRequired: true,
    representativeAlertIdSupplied: true, representativeAlertId: 'alert-1',
    stableGroupIdSupplied: true, stableGroupId: 'stable-group-id',
    stableGroupKeySupplied: true, stableGroupKey: 'stable-group-key'};
  const {events, service} = owner({gets: [representative, representative], identity});
  const result = await service.requestAiReanalysis({group_id: 'abcdef123456'});
  const rejectIndex = events.findIndex(({name}) => name === 'reject');
  const enqueueIndex = events.findIndex(({name}) => name === 'enqueue');
  assert.ok(rejectIndex >= 0 && rejectIndex < enqueueIndex);
  const payload = events[enqueueIndex].args[2];
  assert.equal(payload.agent_role, 'soc-analyst');
  assert.equal(payload.representative_alert_id, 'alert-1');
  assert.equal(payload.stable_group_id, 'stable-group-id');
  assert.equal(payload.stable_group_key, 'stable-group-key');
  assert.equal(result.reviewer_required, true);
});

test('incident queue rejects missing identity and non-finite limits before writes', async () => {
  const missing = owner();
  await assert.rejects(missing.service.queueIncidentResponseForGroup({
    dashboardGroupId: 'abcdef123456', representative: {},
  }), (error) => error.statusCode === 409
    && error.message === 'resolved SOC alert group is missing its stable identity');
  const invalid = owner();
  await assert.rejects(invalid.service.queueIncidentResponseForGroup({
    dashboardGroupId: 'abcdef123456', representative, relatedLimit: Infinity,
  }), (error) => error.statusCode === 400
    && error.message === 'Incident response queue limits must be finite numbers');
  assert.equal(invalid.events.some(({name}) => name === 'run'), false);
});

test('incident queue preserves case/event/job/metric order, pins, clamps, and lineage', async () => {
  const incident = {case_id: 'ir-existing', escalated_at: 'escalated-at'};
  const {events, service} = owner({gets: [incident]});
  const result = await service.queueIncidentResponseForGroup({
    dashboardGroupId: 'abcdef123456', representative, requestedBy: ' responder ',
    reason: ' investigate ', relatedLimit: 0, pcapAnalysisLimit: 99,
    manualReanalysis: true, eventType: 'manual_event', priority: -1,
    cohortId: 'cohort-1', dispatchId: 'dispatch-1', releaseId: 'release-1',
    expectedAssignedRoute: 'route-a', expectedReviewerRoute: 'route-b',
    reviewerRequired: true, representativeAlertIdPinned: true,
    stableGroupIdPinned: true, stableGroupKey: 'stable-group-key',
    stableGroupKeyPinned: true,
  });
  assert.deepEqual(events.map(({name}) => name),
    ['reject', 'run', 'get', 'run', 'enqueue', 'metric']);
  const caseParams = events[1].params;
  assert.equal(caseParams[0], `ir-${crypto.createHash('sha256')
    .update('stable-group-id').digest('hex').slice(0, 16)}`);
  assert.equal(caseParams.at(-2), 'responder');
  assert.equal(caseParams.at(-1), 'investigate');
  const detail = JSON.parse(events[3].params[3]);
  assert.equal(detail.representative_alert_id, 'alert-1');
  assert.equal(detail.stable_group_id, 'stable-group-id');
  assert.equal(detail.stable_group_key, 'stable-group-key');
  assert.equal(detail.cohort_id, 'cohort-1');
  const enqueue = events[4].args;
  assert.equal(enqueue[0], 'incident_response_analysis');
  assert.equal(enqueue[2].agent_role, 'incident-responder');
  assert.equal(enqueue[2].manual_reanalysis, true);
  assert.equal(enqueue[2].related_limit, 1);
  assert.equal(enqueue[2].pcap_analysis_limit, 25);
  assert.deepEqual(enqueue[3], {priority: 0, maxAttempts: 12});
  assert.match(events[5].args[3].eventKey, /incident_response_analysis:manual:/);
  assert.equal(result.case_id, 'ir-existing');
  assert.equal(result.stable_group_id, 'stable-group-id');
  assert.equal(result.stable_group_key, 'stable-group-key');
});

test('incident escalation keeps initial-analysis defaults and automatic lineage', async () => {
  const {events, service} = owner({gets: [representative,
    {case_id: 'ir-case', escalated_at: 'escalated-at'}]});
  const result = await service.requestIncidentEscalation({group_id: 'abcdef123456'});
  const enqueue = events.find(({name}) => name === 'enqueue').args;
  assert.equal(enqueue[2].manual_reanalysis, false);
  assert.equal(enqueue[2].requested_by, 'dashboard');
  assert.equal(enqueue[2].reason, 'Escalated from SOC Alerts for incident response');
  assert.equal(enqueue[2].related_limit, 250);
  assert.equal(enqueue[2].pcap_analysis_limit, 25);
  assert.deepEqual(enqueue[3], {priority: 1100, maxAttempts: 12});
  assert.match(events.at(-1).args[3].eventKey, /incident_response_analysis:automatic:/);
  assert.equal(result.case_id, 'ir-case');
});
