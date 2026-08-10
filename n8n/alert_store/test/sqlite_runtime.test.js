'use strict';

const assert = require('node:assert/strict');
const nodePath = require('node:path');
const test = require('node:test');
const {createSqliteRuntime} = require('../services/sqlite_runtime');

class FakeDatabase {
  static instances = [];

  constructor(...args) {
    this.openArgs = args;
    this.calls = [];
    this.failSql = new Map();
    FakeDatabase.instances.push(this);
  }

  configure(...args) { this.calls.push({name: 'configure', args}); }

  run(sql, params, callback) {
    this.calls.push({name: 'run', sql, params});
    const error = this.failSql.get(sql) || null;
    callback.call({changes: 2, lastID: 7}, error);
  }

  get(sql, params, callback) {
    this.calls.push({name: 'get', sql, params});
    callback(this.failSql.get(sql) || null, {kind: 'row'});
  }

  all(sql, params, callback) {
    this.calls.push({name: 'all', sql, params});
    callback(this.failSql.get(sql) || null, [{kind: 'row'}]);
  }
}

function owner({controlled = false, dbPath = '/runtime/alerts.sqlite3', resolvePath,
  realPath, metadata = {}, uid = 501, sidecars = [], busyTimeoutMs = 30000} = {}) {
  FakeDatabase.instances = [];
  const calls = [];
  const fileMetadata = {
    uid: 501,
    mode: 0o100600,
    isFile: () => true,
    isSymbolicLink: () => false,
    ...metadata,
  };
  const fs = {
    mkdirSync: (...args) => calls.push({name: 'mkdirSync', args}),
    lstatSync: (target) => { calls.push({name: 'lstatSync', target}); return fileMetadata; },
    realpathSync: (target) => realPath ?? target,
    existsSync: (target) => sidecars.some((suffix) => target.endsWith(suffix)),
  };
  const path = {...nodePath, resolve: (target) => resolvePath ?? nodePath.resolve(target)};
  const runtime = createSqliteRuntime({
    fs, path, processApi: {getuid: () => uid},
    sqlite3: {Database: FakeDatabase, OPEN_READWRITE: 2}, dbPath,
    controlledEvaluationMode: controlled, busyTimeoutMs,
  });
  return {calls, database: FakeDatabase.instances[0], runtime};
}

test('production creates the parent, opens normally, and configures busy timeout', () => {
  const {calls, database} = owner({busyTimeoutMs: 4567});
  assert.deepEqual(calls, [{name: 'mkdirSync', args: ['/runtime', {recursive: true}]}]);
  assert.deepEqual(database.openArgs, ['/runtime/alerts.sqlite3']);
  assert.deepEqual(database.calls, [{name: 'configure', args: ['busyTimeout', 4567]}]);
});

test('controlled evaluation validates and opens the exact file read-write', () => {
  const {calls, database} = owner({controlled: true});
  assert.equal(calls[0].name, 'lstatSync');
  assert.deepEqual(database.openArgs, ['/runtime/alerts.sqlite3', 2]);
  assert.equal(calls.some(({name}) => name === 'mkdirSync'), false);
});

test('controlled evaluation rejects every unsafe file identity condition', () => {
  const cases = [
    {dbPath: 'relative.sqlite3'},
    {realPath: '/different/alerts.sqlite3'},
    {metadata: {isFile: () => false}},
    {metadata: {isSymbolicLink: () => true}},
    {metadata: {uid: 777}},
    {metadata: {mode: 0o100622}},
  ];
  for (const options of cases) {
    assert.throws(() => owner({controlled: true, ...options}),
      /controlled evaluation database must be an owner-controlled regular file/);
  }
});

test('controlled evaluation rejects every SQLite recovery sidecar', () => {
  for (const suffix of ['-journal', '-wal', '-shm']) {
    assert.throws(() => owner({controlled: true, sidecars: [suffix]}),
      new RegExp(`controlled evaluation refuses database recovery sidecar ${suffix}`));
  }
});

test('run/get/all preserve callback values, defaults, statement context, and errors', async () => {
  const {database, runtime} = owner();
  const statement = await runtime.run('UPDATE value');
  assert.deepEqual(statement, {changes: 2, lastID: 7});
  assert.deepEqual(await runtime.get('SELECT one'), {kind: 'row'});
  assert.deepEqual(await runtime.all('SELECT many'), [{kind: 'row'}]);
  assert.deepEqual(database.calls.slice(1).map(({name, params}) => [name, params]), [
    ['run', []], ['get', []], ['all', []],
  ]);
  const failure = new Error('sqlite failed');
  database.failSql.set('FAIL', failure);
  await assert.rejects(runtime.run('FAIL'), (error) => error === failure);
  await assert.rejects(runtime.get('FAIL'), (error) => error === failure);
  await assert.rejects(runtime.all('FAIL'), (error) => error === failure);
});

test('write gate is FIFO, reports one active owner, and never overlaps', async () => {
  const {runtime} = owner();
  const events = [];
  let releaseFirst;
  const firstWait = new Promise((resolve) => { releaseFirst = resolve; });
  const first = runtime.withWriteGate(async () => {
    events.push('first:start');
    assert.equal(runtime.activeWrites(), 1);
    await firstWait;
    events.push('first:end');
    return 'first-result';
  });
  const second = runtime.withWriteGate(async () => {
    events.push('second:start');
    assert.equal(runtime.activeWrites(), 1);
    events.push('second:end');
    return 'second-result';
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(events, ['first:start']);
  releaseFirst();
  assert.equal(await first, 'first-result');
  assert.equal(await second, 'second-result');
  assert.deepEqual(events, ['first:start', 'first:end', 'second:start', 'second:end']);
  assert.equal(runtime.activeWrites(), 0);
});

test('write gate continues after rejection and restores active count', async () => {
  const {runtime} = owner();
  const failure = new Error('workflow failed');
  const first = runtime.withWriteGate(async () => { throw failure; });
  const second = runtime.withWriteGate(async () => 'recovered');
  await assert.rejects(first, (error) => error === failure);
  assert.equal(await second, 'recovered');
  assert.equal(runtime.activeWrites(), 0);
});

test('waitForWrites observes the current queue through completion and rejection', async () => {
  const {runtime} = owner();
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const first = runtime.withWriteGate(async () => pending);
  const second = runtime.withWriteGate(async () => { throw new Error('expected rejection'); });
  let drained = false;
  const wait = runtime.waitForWrites().then(() => { drained = true; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(drained, false);
  release();
  await first;
  await assert.rejects(second, /expected rejection/);
  await wait;
  assert.equal(drained, true);
  assert.equal(runtime.activeWrites(), 0);
});

test('immediate transaction commits successful work in exact order', async () => {
  const {database, runtime} = owner();
  const result = await runtime.withImmediateTransaction(async () => {
    database.calls.push({name: 'task'});
    return 'committed';
  });
  assert.equal(result, 'committed');
  assert.deepEqual(database.calls.slice(1).map((call) => call.sql || call.name), [
    'BEGIN IMMEDIATE', 'task', 'COMMIT',
  ]);
});

test('immediate transaction rolls back and preserves original error even if rollback fails', async () => {
  for (const rollbackFails of [false, true]) {
    const {database, runtime} = owner();
    const failure = new Error('task failed');
    if (rollbackFails) database.failSql.set('ROLLBACK', new Error('rollback failed'));
    await assert.rejects(runtime.withImmediateTransaction(async () => { throw failure; }),
      (error) => error === failure);
    assert.deepEqual(database.calls.slice(1).map(({sql}) => sql), [
      'BEGIN IMMEDIATE', 'ROLLBACK',
    ]);
  }
});
