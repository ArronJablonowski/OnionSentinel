'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createStartupPersistenceCompatibility,
} = require('../composition/startup_persistence_compatibility');

function createCompatibility({columns = [], pending = []} = {}) {
  const writes = [];
  const transactions = [];
  const compatibility = createStartupPersistenceCompatibility({
    database: {
      db: {all: (sql, params, callback) => callback(null, columns.map((name) => ({name})))},
      run: async (...args) => { writes.push(args); },
      all: async () => pending,
      withTransaction: async (task) => {
        transactions.push('begin');
        await task();
        transactions.push('commit');
      },
    },
    identity: {
      stableGroupKey: (row) => `key:${row.rule_id}`,
      stableGroupId: (row) => `id:${row.rule_id}`,
    },
    serialization: {parseJsonObject: (value) => JSON.parse(value)},
  });
  return {compatibility, writes, transactions};
}

test('fails closed when a dependency section is absent', () => {
  assert.throws(
    () => createStartupPersistenceCompatibility({database: {}}),
    /identity startup persistence compatibility section is required/,
  );
});

test('adds only absent columns and preserves stable identity write shape', async () => {
  const existing = createCompatibility({columns: ['present']});
  await existing.compatibility.ensureColumn('alerts', 'present', 'TEXT');
  assert.equal(existing.writes.length, 0);

  const missing = createCompatibility();
  await missing.compatibility.ensureColumn('alerts', 'new_column', 'TEXT');
  await missing.compatibility.persistStableIdentity(
    'alert-1',
    {rule_id: 'old'},
    {rule_id: 'new'},
  );
  assert.deepEqual(missing.writes[0], [
    'ALTER TABLE alerts ADD COLUMN new_column TEXT',
  ]);
  assert.deepEqual(missing.writes[1][1], ['new', 'key:new', 'id:new', 'alert-1']);
});

test('backfill is one transaction and schema initialization retains order', async () => {
  const {compatibility, writes, transactions} = createCompatibility({
    pending: [
      {alert_id: 'a1', rule_id: 'old', alert_json: '{"rule_id":"r1"}'},
      {alert_id: 'a2', rule_id: 'old', alert_json: '{"rule_id":"r2"}'},
    ],
  });
  assert.equal(await compatibility.backfillStableGroupIdentity(), 2);
  assert.deepEqual(transactions, ['begin', 'commit']);
  assert.equal(writes.length, 2);

  const calls = [];
  const owner = (name, method = 'install') => ({
    [method]: async () => { calls.push(name); return false; },
  });
  const initDb = compatibility.createSchemaInitializer({
    alertStoreSchemaFoundation: {
      configureRuntime: async () => { calls.push('configure'); return false; },
      installFoundation: async () => { calls.push('foundation'); },
    },
    incidentAnalysisSchema: owner('incident'),
    aiReviewSchema: owner('review'),
    notificationEnrichmentSchema: owner('notification'),
    pcapSchema: owner('pcap'),
    startupPersistenceOrchestrator: owner('startup', 'initialize'),
  });
  await initDb();
  assert.deepEqual(calls, [
    'configure', 'foundation', 'incident', 'review', 'notification', 'pcap', 'startup',
  ]);
});
