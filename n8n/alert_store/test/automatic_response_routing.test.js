'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAutomaticResponseRouting} = require('../services/automatic_response_routing');

function owner(overrides = {}) {
  const events = [];
  const service = createAutomaticResponseRouting({
    nestedField: (value, path) => path.split('.').reduce((item, key) => item?.[key], value),
    readPolicy: () => ({soc_analyst_pcap_min_severity: 'medium',
      soc_analyst_incident_min_severity: 'high'}),
    matchesPcap: () => true,
    matchesIncident: () => true,
    groupKeyFromRow: () => 'group-key',
    groupIdFromKey: () => 'group-id',
    get: async () => { events.push('get'); return null; },
    run: async (_sql, params) => { events.push({run: params}); },
    parseJsonObject: (value) => JSON.parse(value || '{}'),
    jsonText: (value) => JSON.stringify(value),
    nowUtc: () => 'now',
    createPcapRequest: async (payload) => {
      events.push({pcap: payload});
      return {request: {status: 'pending', request_id: 'pcap-1'}};
    },
    pcapRequestDefaultWindowSeconds: 300,
    queueIncidentResponseForGroup: async (payload) => {
      events.push({incident: payload});
      return {status: 'queued', case_id: 'ir-1'};
    },
    severityRank: {high: 3, critical: 4},
    ...overrides,
  });
  return {events, service};
}

const alert = {triage: {level: 'HIGH'}};
const row = {alert_id: 'alert-1', stable_group_id: 'stable-id',
  triage_level: 'medium', filter_status: 'accepted', last_seen: 'last'};

for (const [name, args, expected] of [
  ['duplicate', [false, {status: 'accepted'}], 'skipped_duplicate'],
  ['filter', [true, {status: 'accepted'}, {...row, filter_status: 'dropped'}], 'skipped_filter'],
  ['suppression', [true, {status: 'suppressed'}], 'skipped_suppression'],
]) {
  test(`${name} admission gate stops both automatic response owners`, async () => {
    const {events, service} = owner();
    const stored = args[2] || row;
    assert.equal((await service.queuePcap(alert, stored, args[0], args[1])).status, expected);
    assert.equal((await service.queueIncident(alert, stored, args[0], args[1])).status, expected);
    assert.deepEqual(events, []);
  });
}

test('configured severity gates preserve bounded projections', async () => {
  const {service} = owner({matchesPcap: () => false, matchesIncident: () => false});
  assert.deepEqual(await service.queuePcap(alert, row, true, {}),
    {status: 'skipped_level', triage_level: 'high', threshold: 'medium'});
  assert.deepEqual(await service.queueIncident(alert, row, true, {}),
    {status: 'skipped_level', triage_level: 'high', threshold: 'high'});
});

test('campaign sampling coalesces PCAP before persistence reads', async () => {
  const {events, service} = owner();
  const result = await service.queuePcap(alert, row, true, {}, {campaign_id: 'campaign-1',
    representative_group_id: 'representative', member_ordinal: 4, pcap_sample_limit: 3});
  assert.deepEqual(result, {status: 'coalesced_campaign', campaign_id: 'campaign-1',
    representative_group_id: 'representative', sample_limit: 3, member_ordinal: 4,
    triage_level: 'high', threshold: 'medium'});
  assert.deepEqual(events, []);
});

test('pending PCAP work is refreshed against stable group identity', async () => {
  const {events, service} = owner({get: async (_sql, params) => {
    events.push({get: params});
    return {request_id: 'pcap-existing', request_json: '{"alert_id":"old","last_seen":"old"}'};
  }});
  const result = await service.queuePcap(alert, row, true, {});
  assert.equal(result.status, 'coalesced');
  assert.deepEqual(events[0], {get: ['stable-id']});
  assert.deepEqual(events[1].run, ['alert-1', 'last',
    '{"alert_id":"alert-1","last_seen":"last"}',
    'Coalesced automatic PCAP request for high alert group', 'now', 'pcap-existing']);
});

test('new PCAP work preserves request ownership and bounded window', async () => {
  const {events, service} = owner();
  const result = await service.queuePcap(alert, row, true, {});
  assert.equal(result.request_id, 'pcap-1');
  assert.deepEqual(events[1].pcap, {group_id: 'group-id', alert_id: 'alert-1',
    requested_by: 'alert-store-auto-pcap', reason: 'Automatic PCAP request for high alert',
    max_window_seconds: 300});
});

test('PCAP failures remain bounded and do not abort alert persistence', async () => {
  const {service} = owner({get: async () => { throw new Error('pcap unavailable'); }});
  assert.deepEqual(await service.queuePcap(alert, row, true, {}),
    {status: 'failed', reason: 'pcap unavailable', triage_level: 'high', threshold: 'medium'});
});

test('non-representative incident campaign resolves the representative case', async () => {
  const {events, service} = owner({get: async (_sql, params) => {
    events.push({get: params}); return {case_id: 'ir-representative'};
  }});
  const result = await service.queueIncident(alert, row, true, {}, {campaign_id: 'campaign-1',
    member_count: 5, representative_group_id: 'representative',
    representative_alert_id: 'alert-representative', is_representative: false});
  assert.equal(result.status, 'coalesced_campaign');
  assert.equal(result.case_id, 'ir-representative');
  assert.deepEqual(events, [{get: ['representative']}]);
});

test('incident queue preserves identity, limits, event type, and priority', async () => {
  const {events, service} = owner();
  const result = await service.queueIncident(alert, row, true, {});
  assert.equal(result.status, 'queued');
  assert.deepEqual(events[0].incident, {dashboardGroupId: 'group-id', representative: row,
    requestedBy: 'alert-store-auto-incident',
    reason: 'Automatic incident response for high alert at configured high threshold',
    relatedLimit: 250, pcapAnalysisLimit: 25, manualReanalysis: false,
    eventType: 'auto_escalated', priority: 103});
});

test('incident failures retain or receive 503 and abort the ingest transaction', async () => {
  const unavailable = new Error('incident unavailable');
  const {service} = owner({queueIncidentResponseForGroup: async () => { throw unavailable; }});
  await assert.rejects(service.queueIncident(alert, row, true, {}), (error) =>
    error === unavailable && error.statusCode === 503);
  const conflict = new Error('conflict');
  conflict.statusCode = 409;
  const second = owner({queueIncidentResponseForGroup: async () => { throw conflict; }}).service;
  await assert.rejects(second.queueIncident(alert, row, true, {}), (error) =>
    error === conflict && error.statusCode === 409);
});
