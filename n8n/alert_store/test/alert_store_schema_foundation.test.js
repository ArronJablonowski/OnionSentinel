'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createAlertStoreSchemaFoundation,
} = require('../services/alert_store_schema_foundation');

function owner(overrides = {}) {
  const events = [];
  const service = createAlertStoreSchemaFoundation({
    run: async (sql) => events.push({type: 'run', sql: sql.replace(/\s+/g, ' ').trim()}),
    ensureColumn: async (table, name, definition) => {
      events.push({type: 'column', table, name, definition});
    },
    assertControlledSchema: async () => events.push({type: 'assert'}),
    controlledEvaluationMode: false,
    sqliteBusyTimeoutMs: 5000,
    allowedJournalModes: new Set(['DELETE', 'WAL']),
    sqliteJournalMode: 'DELETE',
    allowedSynchronousModes: new Set(['FULL', 'NORMAL']),
    sqliteSynchronous: 'FULL',
    allowedTempStoreModes: new Set(['DEFAULT', 'MEMORY']),
    sqliteTempStore: 'DEFAULT',
    alertGroupKeySql: "COALESCE(stable_group_key, '')",
    ...overrides,
  });
  return {events, service};
}

test('controlled evaluation configures only timeout and validates the existing schema', async () => {
  const {events, service} = owner({controlledEvaluationMode: true});
  assert.equal(await service.configureRuntime(), true);
  assert.deepEqual(events, [
    {type: 'run', sql: 'PRAGMA busy_timeout = 5000'},
    {type: 'assert'},
  ]);
});

test('invalid SQLite settings preserve fail-safe fallback order', async () => {
  const {events, service} = owner({
    sqliteJournalMode: 'invalid',
    sqliteSynchronous: 'invalid',
    sqliteTempStore: 'invalid',
  });
  assert.equal(await service.configureRuntime(), false);
  assert.deepEqual(events.map((event) => event.sql), [
    'PRAGMA journal_mode = DELETE',
    'PRAGMA synchronous = FULL',
    'PRAGMA temp_store = DEFAULT',
    'PRAGMA busy_timeout = 5000',
  ]);
});

test('WAL configuration checkpoints only after the busy timeout', async () => {
  const {events, service} = owner({
    sqliteJournalMode: 'WAL',
    sqliteSynchronous: 'NORMAL',
    sqliteTempStore: 'MEMORY',
  });
  assert.equal(await service.configureRuntime(), false);
  assert.deepEqual(events.map((event) => event.sql), [
    'PRAGMA journal_mode = WAL',
    'PRAGMA synchronous = NORMAL',
    'PRAGMA temp_store = MEMORY',
    'PRAGMA busy_timeout = 5000',
    'PRAGMA wal_autocheckpoint = 1000',
  ]);
});

test('foundation installs alerts, groups, and campaigns in dependency order', async () => {
  const {events, service} = owner();
  await service.installFoundation();
  const statements = events.filter((event) => event.type === 'run').map((event) => event.sql);
  const alert = statements.findIndex((sql) => sql.includes('CREATE TABLE IF NOT EXISTS alerts'));
  const group = statements.findIndex((sql) => sql.includes('CREATE TABLE IF NOT EXISTS alert_group_summary'));
  const campaign = statements.findIndex((sql) => sql.includes('CREATE TABLE IF NOT EXISTS authorized_activity_campaigns'));
  const member = statements.findIndex((sql) => sql.includes('CREATE TABLE IF NOT EXISTS authorized_activity_campaign_members'));
  assert(alert >= 0 && alert < group && group < campaign && campaign < member);
  assert(statements.some((sql) => sql.includes('idx_alerts_group_key_expr_v2')
    && sql.includes("COALESCE(stable_group_key, '')")));
  assert.deepEqual(
    events.filter((event) => event.type === 'column').map((event) => event.name),
    ['traffic_direction', 'source_port', 'destination_port', 'network_protocol',
      'transport_protocol', 'triage_score', 'triage_level', 'routing', 'filter_status',
      'filter_reason', 'suppression_key', 'raw_event_json', 'enrichment_json', 'rule_id',
      'stable_group_key', 'stable_group_id'],
  );
});
