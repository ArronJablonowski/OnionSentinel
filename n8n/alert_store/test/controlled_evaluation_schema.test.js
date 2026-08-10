'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  REQUIRED_COLUMNS,
  createControlledEvaluationSchema,
} = require('../lib/controlled_evaluation_schema');

function owner({journal = 'delete', missing = '', validIndex = true} = {}) {
  const initialized = [];
  const service = createControlledEvaluationSchema({
    all: async (sql) => {
      const table = sql.match(/^PRAGMA table_info\(([^)]+)\)$/)?.[1];
      if (table) return REQUIRED_COLUMNS[table].filter((column) => column !== missing)
        .map((name) => ({name}));
      if (sql.includes('index_list')) return validIndex
        ? [{name: 'idx_incident_reanalysis_runs_controlled_dispatch', unique: 1, partial: 1}]
        : [];
      if (sql.includes('index_info')) return [{name: 'controlled_dispatch_id'}];
      return [];
    },
    get: async (sql) => (sql.includes('journal_mode')
      ? {journal_mode: journal}
      : {sql: `CREATE UNIQUE INDEX idx_incident_reanalysis_runs_controlled_dispatch
          ON incident_reanalysis_runs(controlled_dispatch_id)
          WHERE controlled_dispatch_id IS NOT NULL`}),
    initializeDurableJobs: () => initialized.push('jobs'),
    initializePipelineMetrics: () => initialized.push('metrics'),
  });
  return {initialized, service};
}

test('accepts the exact controlled evaluation schema and initializes owners', async () => {
  const {initialized, service} = owner();
  await service.assertSchema();
  assert.deepEqual(initialized, ['jobs', 'metrics']);
});

test('requires DELETE journal mode before any owner initialization', async () => {
  const {initialized, service} = owner({journal: 'wal'});
  await assert.rejects(service.assertSchema(), /requires SQLite DELETE journal mode/);
  assert.deepEqual(initialized, []);
});

test('fails closed on a missing required column', async () => {
  const {service} = owner({missing: 'lease_token'});
  await assert.rejects(service.assertSchema(), /missing durable_jobs columns/);
});

test('fails closed without partial unique controlled dispatch ownership', async () => {
  const {service} = owner({validIndex: false});
  await assert.rejects(service.assertSchema(), /dispatch uniqueness/);
});
