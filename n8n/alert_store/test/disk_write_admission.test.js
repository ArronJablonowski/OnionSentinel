'use strict';

const assert = require('node:assert/strict');
const nodePath = require('node:path');
const test = require('node:test');
const {createDiskWriteAdmission} = require('../services/disk_write_admission');

function owner({blocks = 100, bavail = 30, bsize = 10, existing = ['/data'],
  start = 79, hard = 80, reserve = 100, maxRequest = 25} = {}) {
  const calls = [];
  const service = createDiskWriteAdmission({
    fs: {
      existsSync: (candidate) => existing.includes(candidate),
      statfsSync: (candidate) => {
        calls.push(candidate);
        return {blocks, bavail, bsize};
      },
    },
    path: nodePath,
    dbPath: '/data/missing/alerts.sqlite3',
    diskStartMaxUsedPercent: start,
    diskHardMaxUsedPercent: hard,
    diskMinFreeBytes: reserve,
    maxRequestBytes: maxRequest,
  });
  return {calls, service};
}

test('filesystem anchor climbs to the nearest existing parent', () => {
  const {service} = owner();
  assert.equal(service.existingFilesystemAnchor('/data/missing/nested'), '/data');
});

test('capacity snapshot preserves byte arithmetic, rounding, and schema', () => {
  const {calls, service} = owner();
  assert.deepEqual(service.diskCapacitySnapshot(25), {
    filesystem_anchor: '/data', total_bytes: 1000, used_bytes: 700, free_bytes: 300,
    additional_bytes: 25, free_after_bytes: 275, used_percent: 70,
    projected_used_percent: 72.5, start_max_used_percent: 79,
    hard_max_used_percent: 80, min_free_bytes: 100,
  });
  assert.deepEqual(calls, ['/data']);
});

test('capacity snapshot clamps negative and non-numeric additional bytes to zero', () => {
  const {service} = owner();
  assert.equal(service.diskCapacitySnapshot(-50).additional_bytes, 0);
  assert.equal(service.diskCapacitySnapshot('invalid').additional_bytes, 0);
});

function refusal(options, additionalBytes, expectedMessage) {
  const {service} = owner(options);
  assert.throws(
    () => service.assertDiskWriteAdmission('alert ingestion', additionalBytes),
    (error) => error.statusCode === 507 && error.message === expectedMessage,
  );
}

test('hard-used limit has first refusal precedence', () => {
  refusal({bavail: 20}, 25,
    'alert ingestion refused: disk is 80% used; hard limit is 80%');
});

test('start-used limit refuses new writes below the hard ceiling', () => {
  refusal({bavail: 21}, 0,
    'alert ingestion refused: disk is 79% used; new-write limit is 79%');
});

test('projected-used limit includes the requested write size', () => {
  refusal({bavail: 22}, 10,
    'alert ingestion refused: projected disk use is 79%; new-write limit is 79%');
});

test('minimum-free reserve is enforced after percentage limits', () => {
  refusal({bavail: 50, start: 90, hard: 95, reserve: 500}, 10,
    'alert ingestion refused: projected free space is 490 bytes; reserve is 500 bytes');
});

test('admitted writes return the capacity snapshot and default request size', () => {
  const {service} = owner({start: 90, hard: 95, reserve: 100, maxRequest: 25});
  const snapshot = service.assertDiskWriteAdmission('alert ingestion');
  assert.equal(snapshot.additional_bytes, 25);
  assert.equal(snapshot.free_after_bytes, 275);
});
