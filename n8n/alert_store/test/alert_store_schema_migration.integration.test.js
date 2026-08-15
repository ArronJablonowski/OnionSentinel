'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const sqlite3 = require('sqlite3');
const {
  createStartupPersistenceCompatibility,
} = require('../composition/startup_persistence_compatibility');
const {
  createAlertStoreSchemaVersion,
} = require('../services/alert_store_schema_version');
const {createSqliteRuntime} = require('../services/sqlite_runtime');

function close(database) {
  return new Promise((resolve, reject) => {
    database.close((error) => (error ? reject(error) : resolve()));
  });
}

function migrationHarness({fail = false} = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'alert-store-schema-'));
  const runtime = createSqliteRuntime({
    fs,
    path,
    processApi: process,
    sqlite3,
    dbPath: path.join(directory, 'alerts.sqlite3'),
    controlledEvaluationMode: false,
    busyTimeoutMs: 5000,
  });
  const compatibility = createStartupPersistenceCompatibility({
    database: {
      db: runtime.database,
      run: runtime.run,
      all: runtime.all,
      withTransaction: runtime.withImmediateTransaction,
    },
    identity: {stableGroupKey: () => 'key', stableGroupId: () => 'id'},
    serialization: {parseJsonObject: JSON.parse},
  });
  const version = createAlertStoreSchemaVersion({run: runtime.run, get: runtime.get});
  const initDb = compatibility.createSchemaInitializer({
    alertStoreSchemaVersion: version,
    alertStoreSchemaFoundation: {
      configureRuntime: async () => false,
      installFoundation: async () => runtime.run(
        'CREATE TABLE migrated_foundation (id INTEGER PRIMARY KEY)',
      ),
    },
    incidentAnalysisSchema: {
      install: async () => {
        await runtime.run('CREATE TABLE migrated_incident (id INTEGER PRIMARY KEY)');
        if (fail) throw new Error('injected migration failure');
      },
    },
    aiReviewSchema: {install: async () => undefined},
    notificationEnrichmentSchema: {install: async () => undefined},
    pcapSchema: {install: async () => undefined},
    startupPersistenceOrchestrator: {
      initialize: async () => runtime.withImmediateTransaction(
        () => runtime.run('CREATE TABLE nested_startup_owner (id INTEGER PRIMARY KEY)'),
      ),
    },
  });
  async function cleanup() {
    await close(runtime.database);
    fs.rmSync(directory, {recursive: true, force: true});
  }
  return {cleanup, initDb, runtime};
}

test('real SQLite migration commits schema, nested owner, and version together', async () => {
  const harness = migrationHarness();
  try {
    await harness.runtime.run('CREATE TABLE legacy_state (value TEXT NOT NULL)');
    await harness.runtime.run("INSERT INTO legacy_state VALUES ('preserved')");
    await harness.initDb();
    const version = await harness.runtime.get(
      "SELECT value FROM alert_store_metadata WHERE key='schema_version'",
    );
    const tables = await harness.runtime.all(
      `SELECT name FROM sqlite_master
       WHERE type='table'
         AND (name LIKE 'migrated_%' OR name='nested_startup_owner')
       ORDER BY name`,
    );
    const legacy = await harness.runtime.get('SELECT value FROM legacy_state');
    assert.equal(version.value, '1');
    assert.deepEqual(tables.map(({name}) => name), [
      'migrated_foundation', 'migrated_incident', 'nested_startup_owner',
    ]);
    assert.equal(legacy.value, 'preserved');
  } finally {
    await harness.cleanup();
  }
});

test('real SQLite migration failure rolls back every DDL owner and version record', async () => {
  const harness = migrationHarness({fail: true});
  try {
    await harness.runtime.run('CREATE TABLE legacy_state (value TEXT NOT NULL)');
    await harness.runtime.run("INSERT INTO legacy_state VALUES ('preserved')");
    await assert.rejects(harness.initDb(), /injected migration failure/);
    const migrated = await harness.runtime.all(
      `SELECT name FROM sqlite_master
       WHERE name IN ('alert_store_metadata', 'migrated_foundation', 'migrated_incident')`,
    );
    const legacy = await harness.runtime.get('SELECT value FROM legacy_state');
    assert.deepEqual(migrated, []);
    assert.equal(legacy.value, 'preserved');
  } finally {
    await harness.cleanup();
  }
});
