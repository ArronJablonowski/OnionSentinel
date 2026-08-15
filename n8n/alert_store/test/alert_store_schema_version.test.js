'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  ALERT_STORE_SCHEMA_VERSION,
  createAlertStoreSchemaVersion,
} = require('../services/alert_store_schema_version');

function owner({row = null} = {}) {
  const writes = [];
  const reads = [];
  const service = createAlertStoreSchemaVersion({
    run: async (...args) => writes.push(args),
    get: async (...args) => { reads.push(args); return row; },
  });
  return {reads, service, writes};
}

test('persists one exact aggregate schema version after admission', async () => {
  const {reads, service, writes} = owner();
  assert.equal(ALERT_STORE_SCHEMA_VERSION, 1);
  assert.deepEqual(await service.prepareMigration(), {from: null, to: 1});
  await service.persistCurrent();
  assert.match(writes[0][0], /CREATE TABLE IF NOT EXISTS alert_store_metadata/);
  assert.deepEqual(reads[0][1], ['schema_version']);
  assert.match(writes[1][0], /INSERT INTO alert_store_metadata/);
  assert.deepEqual(writes[1][1], ['schema_version', '1']);
});

test('rejects invalid and future versions before migration owners run', async () => {
  for (const value of ['invalid', '0', '2']) {
    const {service, writes} = owner({row: {value}});
    await assert.rejects(
      service.prepareMigration(),
      value === '2' ? /newer schema version 2/ : /schema version is invalid/,
    );
    assert.equal(writes.length, 1);
  }
});

test('controlled evaluation requires the exact persisted version without writes', async () => {
  const accepted = owner({row: {value: '1'}});
  await accepted.service.assertCurrent();
  assert.equal(accepted.writes.length, 0);

  const missing = owner();
  await assert.rejects(missing.service.assertCurrent(), /schema version is missing/);
  assert.equal(missing.writes.length, 0);
});
