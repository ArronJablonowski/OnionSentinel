'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createHealthRepository} = require('../repositories/health_repository');

test('normalizes empty SLO clocks and computes SQLite bytes', async () => {
  const queries = [];
  const repository = createHealthRepository({
    get: async (sql) => {
      queries.push(sql);
      if (sql === 'PRAGMA page_count') return {page_count: 4};
      if (sql === 'PRAGMA page_size') return {page_size: 1024};
      return {};
    },
    all: async (sql) => {
      queries.push(sql);
      return [];
    },
  });
  const jobs = await repository.jobAges();
  const pcap = await repository.pcapStats();
  assert.equal(await repository.sqliteBytes(), 4096);
  assert.equal(jobs.oldestPendingSeconds, 0);
  assert.equal(pcap.oldestPendingSeconds, 0);
  assert.ok(queries.some((sql) => sql.includes("status = 'processing'")));
  assert.ok(queries.some((sql) => sql.includes("status = 'fulfilled'")));
});
