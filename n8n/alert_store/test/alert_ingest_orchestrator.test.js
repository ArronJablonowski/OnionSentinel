'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAlertIngestOrchestrator} = require('../services/alert_ingest_orchestrator');

function stored(overrides = {}) {
  return {
    ok: true, status: 'accepted', stored: true,
    alert: {alert_id: 'alert-1', triage_level: 'high', seen_count: 1,
      stable_group_id: 'group-1', stable_group_key: 'group-key'},
    filter: {status: 'accepted'},
    ...overrides,
  };
}

function owner(overrides = {}) {
  const events = [];
  const service = createAlertIngestOrchestrator({
    scoreAlert: () => ({level: 'high'}),
    withWriteGate: async (task) => {
      events.push('gate:start');
      const value = await task();
      events.push('gate:end');
      return value;
    },
    withTransaction: async (task) => {
      events.push('transaction:start');
      const value = await task();
      events.push('transaction:commit');
      return value;
    },
    storeUnlocked: async () => stored(),
    queueNotification: async () => { events.push('notification'); return {status: 'queued'}; },
    nowUtc: () => 'time',
    buildPostCommitPayload: () => ({report: true}),
    enqueueJob: async (type) => events.push(`job:${type}`),
    recordMetric: async (type, event) => events.push(`metric:${type}:${event}`),
    severityRank: {high: 3, informational: 0},
    postCommitMaxAttempts: 5,
    hasUsableExternalIntel: () => false,
    nestedField: () => '',
    enrichmentMaxAttempts: 4,
    groupKeyFromRow: () => 'derived-key',
    groupIdFromKey: () => 'derived-id',
    matchesAnalysis: () => true,
    signalAiWorkers: async () => events.push('wake:ai'),
    drainNotificationOutbox: async () => events.push('drain:notification'),
    drainEnrichmentJobs: async () => events.push('drain:enrichment'),
    drainPostCommitJobs: async () => events.push('drain:post-commit'),
    ...overrides,
  });
  return {events, service};
}

test('keeps notification, durable jobs, and metrics inside the ingest transaction', async () => {
  const {events, service} = owner();
  await service.store({alert_id: 'alert-1'});
  const commit = events.indexOf('transaction:commit');
  for (const name of ['notification', 'job:n8n_post_commit', 'job:public_enrichment',
    'job:ai_analysis', 'metric:alert_ingest:completed']) {
    assert(events.indexOf(name) > events.indexOf('transaction:start'));
    assert(events.indexOf(name) < commit);
  }
});

test('starts wake and all drains only after commit and write-gate release', async () => {
  const {events, service} = owner({hasUsableExternalIntel: () => true});
  await service.store({alert_id: 'alert-1'});
  const gateEnd = events.indexOf('gate:end');
  for (const name of ['wake:ai', 'drain:notification', 'drain:enrichment',
    'drain:post-commit']) assert(events.indexOf(name) > gateEnd);
});

test('failed persistence does not enqueue, wake, or drain downstream work', async () => {
  const {events, service} = owner({
    storeUnlocked: async () => ({ok: false, status: 'failed'}),
  });
  assert.deepEqual(await service.store({alert_id: 'alert-1'}), {ok: false, status: 'failed'});
  assert.deepEqual(events, ['gate:start', 'transaction:start', 'transaction:commit', 'gate:end']);
});

test('authorized campaign sample limit denies enrichment above its ordinal', async () => {
  const {events, service} = owner({storeUnlocked: async () => stored({
    campaign: {member_ordinal: 3, enrichment_sample_limit: 2},
  })});
  await service.store({alert_id: 'alert-1'});
  assert(!events.includes('job:public_enrichment'));
  assert(events.includes('job:ai_analysis'));
});

test('incident-response-only campaign suppresses duplicate SOC analysis', async () => {
  const {events, service} = owner({storeUnlocked: async () => stored({
    campaign: {member_ordinal: 1, enrichment_sample_limit: 2,
      investigation_mode: 'incident_response_only'},
  })});
  await service.store({alert_id: 'alert-1'});
  assert(events.includes('job:public_enrichment'));
  assert(!events.includes('job:ai_analysis'));
  assert(!events.includes('wake:ai'));
});

test('queued incident wakes AI even while enrichment owns the normal wake', async () => {
  const {events, service} = owner({storeUnlocked: async () => stored({
    incident: {status: 'queued'},
  })});
  await service.store({alert_id: 'alert-1'});
  assert(events.includes('job:public_enrichment'));
  assert(events.includes('wake:ai'));
});
