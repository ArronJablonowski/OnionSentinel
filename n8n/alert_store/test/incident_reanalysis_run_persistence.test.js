'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  createIncidentReanalysisRunPersistence,
} = require('../services/incident_reanalysis_run_persistence');

function fixture({runRows = [], countRows = [], allResults = null} = {}) {
  const calls = [];
  const gets = [...runRows];
  const counts = [...countRows];
  const allQueue = allResults ? [...allResults] : null;
  const service = createIncidentReanalysisRunPersistence({
    get: async (sql, params) => { calls.push({type: 'get', sql, params}); return gets.shift() ?? null; },
    all: async (sql, params) => {
      calls.push({type: 'all', sql, params});
      return allQueue ? (allQueue.shift() || []) : (counts.shift() || []);
    },
    run: async (sql, params) => { calls.push({type: 'run', sql, params}); },
    nowUtc: () => '2026-08-09  21:30:00-06:00',
  });
  return {calls, service};
}

test('snapshot returns null without querying case counts for an absent run', async () => {
  const {calls, service} = fixture();
  assert.equal(await service.snapshot('missing'), null);
  assert.deepEqual(calls.map(({type}) => type), ['get']);
  assert.deepEqual(calls[0].params, ['missing']);
});

test('snapshot normalizes total and known counts while ignoring unknown states', async () => {
  const row = {run_id: 'run-1', total_count: '7', status: 'queued'};
  const {service} = fixture({runRows: [row], countRows: [[
    {status: 'queued', count: '2'},
    {status: 'running', count: 1},
    {status: 'completed', count: null},
    {status: 'future-state', count: 99},
  ]]});
  assert.deepEqual(await service.snapshot('run-1'), {
    ...row,
    total_count: 7,
    counts: {queued: 2, running: 1, completed: 0, failed: 0, skipped: 0},
  });
});

test('refresh is read-only for empty and absent identities', async () => {
  const {calls, service} = fixture();
  assert.equal(await service.refresh(''), null);
  assert.equal(await service.refresh('missing'), null);
  assert.deepEqual(calls.map(({type}) => type), ['get']);
});

const refreshCases = [
  ['running takes precedence', 3, {running: 1, queued: 2}, 'running', null],
  ['queued precedes terminal counts', 3, {queued: 1, completed: 2}, 'queued', null],
  ['empty run completes', 0, {}, 'completed', '2026-08-09  21:30:00-06:00'],
  ['all failures fail', 2, {failed: 2}, 'failed', '2026-08-09  21:30:00-06:00'],
  ['mixed terminal outcomes are partial', 3, {completed: 2, skipped: 1}, 'partial', '2026-08-09  21:30:00-06:00'],
  ['all completed completes', 2, {completed: 2}, 'completed', '2026-08-09  21:30:00-06:00'],
  ['incomplete unknown census remains queued', 2, {}, 'queued', null],
];

for (const [name, total, values, expectedStatus, expectedCompletedAt] of refreshCases) {
  test(`refresh: ${name}`, async () => {
    const countProjection = Object.entries(values).map(([status, count]) => ({status, count}));
    const first = {run_id: 'run-2', total_count: total, status: 'old'};
    const second = {run_id: 'run-2', total_count: total, status: expectedStatus};
    const {calls, service} = fixture({
      runRows: [first, second],
      countRows: [countProjection, countProjection],
    });
    assert.equal((await service.refresh('run-2')).status, expectedStatus);
    const update = calls.find(({type}) => type === 'run');
    assert.match(update.sql, /UPDATE incident_reanalysis_runs/);
    assert.deepEqual(update.params, [
      expectedStatus,
      '2026-08-09  21:30:00-06:00',
      expectedCompletedAt,
      'run-2',
    ]);
  });
}

test('supersede is a no-op when no older queued run owns the case', async () => {
  const {calls, service} = fixture({allResults: [[]]});
  assert.equal(await service.supersedeCase('case-1', 'replacement', 'now'), undefined);
  assert.deepEqual(calls.map(({type}) => type), ['all']);
  assert.deepEqual(calls[0].params, ['case-1', 'replacement']);
});

test('supersede updates exact older queued memberships then refreshes each run in order', async () => {
  const runRows = [
    {run_id: 'old-a', total_count: 1}, {run_id: 'old-a', total_count: 1},
    {run_id: 'old-b', total_count: 1}, {run_id: 'old-b', total_count: 1},
  ];
  const {calls, service} = fixture({
    runRows,
    allResults: [
      [{run_id: 'old-a'}, {run_id: 'old-b'}],
      [{status: 'skipped', count: 1}], [{status: 'skipped', count: 1}],
      [{status: 'completed', count: 1}], [{status: 'completed', count: 1}],
    ],
  });
  await service.supersedeCase('case-1', 'new-run', '2026-08-09  21:29:00-06:00');
  const writes = calls.filter(({type}) => type === 'run');
  assert.match(writes[0].sql, /UPDATE incident_reanalysis_run_cases/);
  assert.deepEqual(writes[0].params, [
    'Superseded by newer reanalysis run new-run',
    '2026-08-09  21:29:00-06:00',
    '2026-08-09  21:29:00-06:00',
    'case-1',
    'new-run',
  ]);
  assert.deepEqual(writes.slice(1).map(({params}) => params.at(-1)), ['old-a', 'old-b']);
});
