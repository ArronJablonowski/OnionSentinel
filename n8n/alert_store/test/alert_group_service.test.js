'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createAlertGroupService} = require('../services/alert_group_service');

function createHarness({reads = [], rows = [], failInsert = false} = {}) {
  const getResults = [...reads];
  const allResults = [...rows];
  const statements = [];
  let gateCalls = 0;
  let transactionCalls = 0;
  const service = createAlertGroupService({
    all: async () => allResults.shift() || [],
    get: async () => getResults.shift() || null,
    run: async (sql, params = []) => {
      statements.push({sql: sql.trim(), params});
      if (failInsert && /INSERT INTO alert_group_summary/.test(sql)) {
        throw new Error('insert failed');
      }
    },
    withImmediateTransaction: async (task) => {
      transactionCalls += 1;
      return task();
    },
    withSqliteWriteGate: async (task) => {
      gateCalls += 1;
      return task();
    },
    nowUtc: () => '2026-08-09 22:20:00+00:00',
    normalizeTriageLevel: (value, fallback) => String(value || fallback || 'unknown').toLowerCase(),
    alertGroupId: (key) => `id:${key}`,
    alertGroupKeySql: 'GROUP_KEY_SQL',
  });
  return {
    service,
    statements,
    counts: () => ({gateCalls, transactionCalls}),
  };
}

test('preserves suppression identity precedence and legacy fallback fields', () => {
  const {service} = createHarness();
  assert.equal(service.alertGroupKeyFromRow(null), '');
  assert.equal(service.alertGroupKeyFromRow({suppression_key: 'pinned'}), 'pinned');
  assert.equal(service.alertGroupKeyFromRow({
    severity_label: 'HIGH', rule_name: 'Rule', source_ip: '1.1.1.1',
    destination_ip: '2.2.2.2', filter_status: 'suppressed',
  }), 'high|Rule|1.1.1.1|2.2.2.2|suppressed');
});

test('removes both summary and alias when a group becomes empty', async () => {
  const {service, statements} = createHarness({reads: [{raw_alert_count: 0}]});
  await service.refreshAlertGroupSummary('group-key');
  assert.deepEqual(
    statements.map((item) => item.sql),
    [
      'DELETE FROM alert_group_summary WHERE group_id = ?',
      'DELETE FROM alert_group_alias WHERE legacy_group_id = ?',
    ],
  );
});

test('refreshes one representative summary and its stable alias', async () => {
  const representative = {
    alert_id: 'alert-1', triage_level: 'HIGH', severity_label: 'medium',
  };
  const {service, statements} = createHarness({reads: [
    {raw_alert_count: 2, total_seen_count: 5, first_seen: 'first', last_seen: 'last'},
    representative,
    {stable_group_id: 'stable-id', stable_group_key: 'stable-key'},
  ]});
  await service.refreshAlertGroupSummary('group-key');
  assert.equal(statements.length, 2);
  assert.match(statements[0].sql, /INSERT INTO alert_group_summary/);
  assert.equal(statements[0].params[0], 'id:group-key');
  assert.equal(statements[0].params[5], 2);
  assert.equal(statements[0].params[6], 5);
  assert.equal(statements[0].params[20], 'high');
  assert.match(statements[1].sql, /INSERT INTO alert_group_alias/);
  assert.deepEqual(statements[1].params.slice(0, 3), [
    'id:group-key', 'stable-id', 'stable-key',
  ]);
});

test('rebuild uses one windowed scan, owns gate, and rolls back failures', async () => {
  const row = {group_key: 'one', alert_id: 'alert-1'};
  const success = createHarness({rows: [[row]]});
  assert.deepEqual(await success.service.rebuildAlertGroupSummaries(), {
    ok: true, status: 'group_summary_rebuilt', groups: 1,
  });
  assert.equal(success.counts().gateCalls, 1);
  assert.match(success.statements[0].sql, /BEGIN IMMEDIATE/);
  assert.match(success.statements.at(-1).sql, /COMMIT/);

  const failure = createHarness({rows: [[row]], failInsert: true});
  await assert.rejects(failure.service.rebuildAlertGroupSummaries(), /insert failed/);
  assert.match(failure.statements.at(-1).sql, /ROLLBACK/);
});

test('bulk alias refresh is one immediate transaction', async () => {
  const {service, statements, counts} = createHarness({rows: [[
    {legacy_group_id: 'old-1', stable_group_id: 'new-1', stable_group_key: 'key-1'},
    {legacy_group_id: 'old-2', stable_group_id: 'new-2', stable_group_key: 'key-2'},
  ]]});
  assert.equal(await service.refreshGroupAliases(), 2);
  assert.equal(counts().transactionCalls, 1);
  assert.equal(statements.length, 2);
});
