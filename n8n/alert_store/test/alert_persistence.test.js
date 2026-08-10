'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAlertPersistence} = require('../services/alert_persistence');

function alert(overrides = {}) {
  return {alert_id: 'alert-1', rule_name: 'Rule', source: {ip: '10.0.0.1'},
    destination: {ip: '10.0.0.2', port: 443}, network: {transport: 'tcp'},
    triage: {score: 80, level: 'high', routing: 'analyze', reasons: []}, ...overrides};
}

function owner(overrides = {}) {
  const events = [];
  let insertChanges = 1;
  const row = {alert_id: 'alert-1', stable_group_key: '', stable_group_id: ''};
  const service = createAlertPersistence({
    currentGroupKey: async () => { events.push('current-group'); return ''; },
    nowUtc: () => 'time',
    findDropRule: () => null,
    nestedField: (value, path) => path.split('.').reduce((item, key) => item?.[key], value),
    ruleName: (rule) => rule.name,
    normalizeTimestampValue: (value) => value || '',
    integerField: (value) => Number.isFinite(Number(value)) ? Number(value) : null,
    jsonText: (value) => JSON.stringify(value ?? null),
    enrichmentRecord: () => ({}),
    run: async (sql) => {
      const normalized = sql.replace(/\s+/g, ' ').trim();
      if (normalized.startsWith('INSERT OR IGNORE INTO alerts')) {
        events.push('insert');
        return {changes: insertChanges};
      }
      events.push(normalized.includes('seen_count = seen_count + 1')
        ? 'update:duplicate' : 'update:suppression');
      return {changes: 1};
    },
    get: async () => { events.push('select'); return {...row}; },
    applySuppression: async () => { events.push('suppression'); return {status: 'accepted'}; },
    persistStableIdentity: async () => {
      events.push('identity');
      return {stable_group_key: 'next-key', stable_group_id: 'next-id'};
    },
    indexObservables: async () => events.push('observables'),
    recordCampaign: async (_alert, _row, inserted) => {
      events.push(`campaign:${inserted}`);
      return null;
    },
    groupKeyFromRow: () => 'next-key',
    refreshGroupSummary: async (key) => events.push(`group:${key}`),
    queueAutomaticPcap: async () => { events.push('pcap'); return {status: 'none'}; },
    queueAutomaticIncident: async () => { events.push('incident'); return {status: 'none'}; },
    ...overrides,
  });
  return {events, service, setInsertChanges: (value) => { insertChanges = value; }};
}

test('rejects a missing alert identity before reads or writes', async () => {
  const {events, service} = owner();
  assert.deepEqual(await service.store(alert({alert_id: ''})), {
    ok: false, status: 'rejected', reason: 'missing alert_id',
  });
  assert.deepEqual(events, []);
});

test('drop policy returns bounded projection without persisting evidence', async () => {
  const {events, service} = owner({findDropRule: () => ({name: 'drop-1', reason: 'test'})});
  const result = await service.store(alert());
  assert.equal(result.status, 'dropped');
  assert.equal(result.filter.rule, 'drop-1');
  assert.deepEqual(events, ['current-group']);
});

test('new accepted alert preserves identity and downstream side-effect order', async () => {
  const {events, service} = owner();
  const result = await service.store(alert());
  assert.equal(result.status, 'accepted');
  assert.deepEqual(events, ['current-group', 'insert', 'suppression', 'select', 'identity',
    'observables', 'campaign:true', 'group:next-key', 'pcap', 'incident']);
});

test('duplicate increments count without reapplying suppression or campaign membership', async () => {
  let suppressionCalls = 0;
  const {events, service, setInsertChanges} = owner({
    applySuppression: async () => { suppressionCalls += 1; return {status: 'accepted'}; },
  });
  setInsertChanges(0);
  const result = await service.store(alert());
  assert.equal(result.status, 'already_seen');
  assert.equal(suppressionCalls, 0);
  assert(events.includes('update:duplicate'));
  assert(events.includes('campaign:false'));
});

test('suppressed insert persists routed alert before stable identity and indexes', async () => {
  const {events, service} = owner({applySuppression: async () => {
    events.push('suppression');
    return {status: 'suppressed', rule: 'suppress-1', key: 'key', reason: 'noise'};
  }});
  const result = await service.store(alert());
  assert.equal(result.status, 'suppressed');
  assert(events.indexOf('update:suppression') < events.indexOf('identity'));
  assert.equal(result.triage.routing, 'suppressed');
});

test('stable identity migration refreshes previous summary before current summary', async () => {
  const {events, service} = owner({currentGroupKey: async () => {
    events.push('current-group');
    return 'previous-key';
  }});
  await service.store(alert());
  assert(events.indexOf('group:previous-key') < events.indexOf('group:next-key'));
});
