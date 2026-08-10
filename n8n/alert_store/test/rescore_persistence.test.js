'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createRescorePersistence} = require('../services/rescore_persistence');

function owner(overrides = {}) {
  const events = [];
  const updates = [];
  const rows = [
    {alert_id: 'alert-1', alert_json: JSON.stringify({source: {port: '123'},
      destination: {port: 443}, network: {iana_number: 6},
      security_onion: {raw_event: {event: 'raw'}}})},
    {alert_id: 'alert-invalid', alert_json: '{'},
  ];
  const service = createRescorePersistence({
    all: async () => { events.push('read'); return rows; },
    run: async (sql, params) => {
      events.push(`update:${params.$alert_id}`);
      updates.push({sql: sql.replace(/\s+/g, ' ').trim(), params});
    },
    scoreAlert: () => ({score: 80, level: 'high', routing: 'analyze',
      traffic_direction: 'outbound'}),
    nestedField: (value, path) => path.split('.').reduce((item, key) => item?.[key], value),
    integerField: (value) => Number.isFinite(Number(value)) ? Number(value) : null,
    jsonText: (value) => JSON.stringify(value ?? null),
    enrichmentRecord: () => ({provider: 'bounded'}),
    rebuildGroupSummaries: async () => { events.push('groups'); return {groups: 7}; },
    scoringRulesName: 'scoring_rules.json',
    ...overrides,
  });
  return {events, service, updates};
}

test('rescoring preserves the exact persistence projection and skips malformed rows', async () => {
  const {events, service, updates} = owner();
  assert.deepEqual(await service.rescore(), {ok: true, status: 'rescored',
    total_alerts: 2, rescored: 1, skipped: 1, group_summary_groups: 7,
    scoring_rules: 'scoring_rules.json'});
  assert.deepEqual(events, ['read', 'update:alert-1', 'groups']);
  assert.equal(updates.length, 1);
  assert(updates[0].sql.startsWith('UPDATE alerts SET source_port'));
  assert.deepEqual(updates[0].params, {$source_port: 123, $destination_port: 443,
    $network_protocol: undefined, $transport_protocol: 6,
    $traffic_direction: 'outbound', $triage_score: 80, $triage_level: 'high',
    $routing: 'analyze', $raw_event_json: '{"event":"raw"}',
    $enrichment_json: '{"provider":"bounded"}',
    $alert_json: '{"source":{"port":"123"},"destination":{"port":443},"network":{"iana_number":6},"security_onion":{"raw_event":{"event":"raw"}},"triage":{"score":80,"level":"high","routing":"analyze","traffic_direction":"outbound"}}',
    $alert_id: 'alert-1'});
});

test('an update failure is isolated and group summaries still rebuild afterward', async () => {
  const {events, service} = owner({run: async () => { events.push('update:failed');
    throw new Error('write failed'); }});
  const result = await service.rescore();
  assert.equal(result.rescored, 0);
  assert.equal(result.skipped, 2);
  assert.deepEqual(events, ['read', 'update:failed', 'groups']);
});

test('group rebuild failures propagate instead of reporting a partial success', async () => {
  const {service} = owner({rebuildGroupSummaries: async () => {
    throw new Error('group rebuild failed');
  }});
  await assert.rejects(service.rescore(), /group rebuild failed/);
});
