'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createAuthorizedCampaignPersistence,
} = require('../services/authorized_campaign_persistence');

function matchedPolicy() {
  return {
    id: 'policy-1', enabled: true, campaign_id: 'campaign-1', campaign_key: 'key-1',
    bucket_start: '2026-08-10T00:00:00Z', bucket_end: '2026-08-10T01:00:00Z',
    investigation_mode: 'incident_response_only', window_seconds: 3600,
    pcap_sample_limit: 1, enrichment_sample_limit: 2,
    reconcile_existing_pending: true, authorization: {ticket: 'approved'},
    source_ips: [], destination_ips: [], rule_ids: [], source_ports: [],
    destination_ports: [], destination_port_ranges: [], transport_protocols: [],
    authorization_start: '2026-08-01T00:00:00Z',
    authorization_end: '2026-08-31T00:00:00Z',
  };
}

function owner(overrides = {}) {
  const events = [];
  const dependencies = {
    all: async () => [],
    get: async () => null,
    run: async (sql, params = []) => {
      events.push({type: 'run', sql: sql.replace(/\s+/g, ' ').trim(), params});
      return {changes: 0};
    },
    withImmediateTransaction: async (task) => {
      events.push({type: 'transaction:start'});
      const result = await task();
      events.push({type: 'transaction:end'});
      return result;
    },
    policy: {policies: []},
    matchAuthorizedActivity: () => null,
    parseJsonObject: (value) => typeof value === 'string' ? JSON.parse(value) : value || {},
    normalizeTimestampValue: (value) => value || '',
    nowUtc: () => '2026-08-10T00:00:00Z',
    jsonText: (value) => JSON.stringify(value),
    integerField: (value) => Number.isFinite(Number(value)) ? Number(value) : null,
    completePendingJobs: async () => 0,
    stableGroupKey: () => 'group-key',
    stableGroupId: () => 'group-id',
    buildAlertObservables: () => [],
    extractAlertIndicators: () => [],
    ...overrides,
  };
  const service = createAuthorizedCampaignPersistence(dependencies);
  return {events, service};
}

test('rejects ineligible or unmatched alerts without persistence reads or writes', async () => {
  let reads = 0;
  const {events, service} = owner({get: async () => { reads += 1; return null; }});
  assert.equal(await service.recordCampaign({}, {}, true), null);
  assert.equal(await service.recordCampaign({}, {alert_id: 'a', stable_group_id: 'g'}, true), null);
  assert.equal(reads, 0);
  assert.deepEqual(events, []);
});

test('existing membership is idempotent and returns its stable ordinal without writes', async () => {
  let read = 0;
  const existing = {
    campaign_id: 'campaign-1', policy_id: 'policy-1', observed_at: 'time',
    representative_alert_id: 'alert-1', representative_group_id: 'group-1',
    member_count: 3, distinct_target_count: 2,
    policy_json: JSON.stringify({investigation_mode: 'incident_response_only',
      pcap_sample_limit: 1, enrichment_sample_limit: 2}),
  };
  const {events, service} = owner({
    matchAuthorizedActivity: () => matchedPolicy(),
    get: async () => ++read === 1 ? existing : {count: 2},
  });
  const result = await service.recordCampaign({}, {
    alert_id: 'alert-1', stable_group_id: 'group-1',
  });
  assert.equal(result.member_ordinal, 2);
  assert.equal(result.is_representative, true);
  assert.equal(events.length, 0);
});

test('new membership writes campaign, member, and aggregate in order', async () => {
  let read = 0;
  const campaign = {...matchedPolicy(), representative_alert_id: 'alert-1',
    representative_group_id: 'group-1', member_count: 1, distinct_target_count: 1};
  const {events, service} = owner({
    matchAuthorizedActivity: () => matchedPolicy(),
    get: async () => {
      read += 1;
      if (read === 1) return null;
      if (read === 2) return campaign;
      return {count: 1};
    },
  });
  const result = await service.recordCampaign({timestamp: 'observed'}, {
    alert_id: 'alert-1', stable_group_id: 'group-1', destination_port: '443',
  });
  assert.equal(result.member_ordinal, 1);
  assert.deepEqual(events.map((event) => (
    event.sql.startsWith('INSERT OR IGNORE INTO authorized_activity_campaigns') ? 'campaign'
      : event.sql.startsWith('INSERT OR IGNORE INTO authorized_activity_campaign_members') ? 'member'
        : event.sql.startsWith('UPDATE authorized_activity_campaigns') ? 'aggregate' : 'unknown'
  )), ['campaign', 'member', 'aggregate']);
});

test('campaign backfill uses bounded rowid pages inside one transaction per page', async () => {
  let reads = 0;
  const row = {backfill_rowid: 7, alert_id: 'alert-1', stable_group_id: 'group-1',
    alert_json: '{}'};
  const {events, service} = owner({
    policy: {policies: [matchedPolicy()]},
    all: async (_sql, params) => {
      reads += 1;
      assert.equal(params[3], 128);
      return reads === 1 ? [row] : [];
    },
  });
  assert.equal(await service.backfillCampaigns(), 0);
  assert.deepEqual(events.map((event) => event.type), ['transaction:start', 'transaction:end']);
});

test('reconciliation never retires jobs without a replacement representative case', async () => {
  let completions = 0;
  const campaign = {campaign_id: 'c', representative_group_id: 'g',
    policy_json: JSON.stringify({investigation_mode: 'incident_response_only',
      reconcile_existing_pending: true})};
  const {service} = owner({
    all: async () => [campaign],
    get: async () => null,
    completePendingJobs: async () => { completions += 1; return 0; },
  });
  const result = await service.reconcileBacklog();
  assert.equal(result.campaigns, 0);
  assert.equal(completions, 0);
  assert.equal(service.reconciliationState().status, 'ok');
});

test('observable replacement deletes stale rows before inserting bounded evidence', async () => {
  const observables = [
    {observable_type: 'ip', observable_value: '10.0.0.1', role: 'source', source: 'alert'},
    {observable_type: 'domain', observable_value: 'example.test', role: 'target', source: 'alert'},
  ];
  const {events, service} = owner({buildAlertObservables: () => observables});
  assert.equal(await service.indexObservables({}, {
    alert_id: 'alert-1', first_seen: 'first', last_seen: 'last',
  }), 2);
  assert(events[0].sql.startsWith('DELETE FROM alert_observables'));
  assert(events[1].sql.startsWith('INSERT INTO alert_observables'));
  assert(events[2].sql.startsWith('INSERT INTO alert_observables'));
});

test('observable startup repair is one recoverable transaction', async () => {
  const {events, service} = owner({
    all: async () => [{alert_id: 'alert-1', alert_json: '{}'}],
  });
  assert.equal(await service.backfillObservables(), 1);
  assert.equal(events[0].type, 'transaction:start');
  assert(events[1].sql.startsWith('DELETE FROM alert_observables'));
  assert.equal(events.at(-1).type, 'transaction:end');
});
