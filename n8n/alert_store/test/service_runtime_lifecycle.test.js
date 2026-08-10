'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createServiceRuntimeLifecycle} = require('../services/service_runtime_lifecycle');

function fixture(overrides = {}) {
  const events = [];
  const intervals = [];
  const signals = new Map();
  const exits = [];
  const logs = [];
  let requestListener;
  const server = {
    listen(port, host, callback) { events.push(`listen:${host}:${port}`); callback(); },
    close(callback) { events.push('server.close'); callback(); },
  };
  const task = (name, failure = null) => async () => {
    events.push(name);
    if (failure) throw failure;
  };
  const workers = {
    telegram: {enabled: true, intervalMs: 11, drain: task('telegram')},
    enrichment: {intervalMs: 12, drain: task('enrichment')},
    enrichmentCache: {intervalMs: 13, prune: task('cache')},
    n8nPostCommit: {intervalMs: 14, drain: task('postcommit')},
    durableRecovery: {intervalMs: 15, recover: task('recovery')},
    pipelineDisk: {intervalMs: 16, capture: task('disk')},
    postgresShadow: {intervalMs: 17, drain: task('shadow')},
    pipelineMetrics: {
      intervalMs: 3600000,
      prune: task('metrics.prune'),
      withWriteGate: async (callback) => { events.push('metrics.gate'); await callback(); },
    },
  };
  const options = {
    initDb: task('initDb'),
    initializePostgresAssetStore: task('asset'),
    initializePostgresSoftwareStore: task('software'),
    initializePostgresAcHunterStore: task('acHunter'),
    getPostgresStoreState: () => ({postgresAssetStore: {}, postgresSoftwareStore: null, postgresAcHunterStore: {}}),
    applicationLogger: {log: (...args) => logs.push(args)},
    databaseLogFields: {
      database_path: '/db.sqlite3', postgres_shadow_enabled: true,
      asset_postgres_enabled: true, software_postgres_enabled: true,
      ac_hunter_postgres_enabled: true,
    },
    httpCreateServer: (listener) => { requestListener = listener; return server; },
    configureHttpServer: (value, config) => { events.push(['configure', config]); return value; },
    dispatchRequest: async () => undefined,
    sendJson: (...args) => events.push(['sendJson', ...args]),
    httpConfiguration: {requestTimeoutMs: 101, headersTimeoutMs: 102},
    host: '127.0.0.1',
    port: 8787,
    dbPath: '/db.sqlite3',
    controlledEvaluationMode: false,
    processLike: {once: (name, callback) => signals.set(name, callback), exit: (code) => exits.push(code)},
    consoleLike: {log: (...args) => logs.push(args), error: (...args) => logs.push(args)},
    database: {close: (callback) => { events.push('db.close'); callback(); }},
    getSqliteWriteGate: () => Promise.resolve(),
    getActiveSqliteWrites: () => 0,
    setIntervalFn: (callback, milliseconds) => {
      const timer = {callback, milliseconds, unref: () => events.push(`unref:${milliseconds}`)};
      intervals.push(timer);
      return timer;
    },
    setTimeoutFn: (callback, milliseconds) => ({callback, milliseconds, unref: () => events.push(`timeout.unref:${milliseconds}`)}),
    workers,
    ...overrides,
  };
  return {events, exits, intervals, logs, options, requestListener: () => requestListener, server, signals, workers};
}

test('starts required stores in order before configuring and listening', async () => {
  const f = fixture();
  await createServiceRuntimeLifecycle(f.options).start();
  assert.deepEqual(f.events.slice(0, 6), [
    'initDb', 'asset', 'software', 'acHunter',
    ['configure', {requestTimeoutMs: 101, headersTimeoutMs: 102}],
    'listen:127.0.0.1:8787',
  ]);
  assert.deepEqual(f.logs[0], ['info', 'database.initialized', {
    database_path: '/db.sqlite3', postgres_shadow_enabled: true,
    asset_postgres_enabled: true, software_postgres_enabled: true,
    ac_hunter_postgres_enabled: true, asset_postgres_available: true,
    software_postgres_available: false, ac_hunter_postgres_available: true,
  }]);
  assert(f.logs.some((entry) => entry[1] === 'service.ready'));
});

test('starts each enabled worker immediately and installs exact intervals', async () => {
  const f = fixture();
  await createServiceRuntimeLifecycle(f.options).start();
  assert.deepEqual(f.intervals.map(({milliseconds}) => milliseconds), [11, 12, 13, 14, 15, 16, 17, 3600000]);
  for (const name of ['telegram', 'enrichment', 'cache', 'postcommit', 'recovery', 'disk', 'shadow']) {
    assert.equal(f.events.filter((event) => event === name).length, 1, name);
  }
  assert.equal(f.events.includes('metrics.prune'), false);
  await f.intervals.at(-1).callback();
  assert(f.events.includes('metrics.gate'));
  assert(f.events.includes('metrics.prune'));
});

test('controlled mode installs both signals and suppresses all workers', async () => {
  const f = fixture({controlledEvaluationMode: true});
  await createServiceRuntimeLifecycle(f.options).start();
  assert.deepEqual([...f.signals.keys()], ['SIGTERM', 'SIGINT']);
  assert.equal(f.intervals.length, 0);
  assert.equal(f.events.includes('telegram'), false);
});

test('controlled shutdown drains writes, closes the database, and exits zero once', async () => {
  const f = fixture({controlledEvaluationMode: true});
  const lifecycle = createServiceRuntimeLifecycle(f.options);
  await lifecycle.start();
  f.signals.get('SIGTERM')();
  f.signals.get('SIGINT')();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(lifecycle.isShutdownStarted(), true);
  assert.deepEqual(f.events.filter((event) => event === 'server.close'), ['server.close']);
  assert(f.events.includes('db.close'));
  assert.deepEqual(f.exits, [0]);
  assert(f.events.includes('timeout.unref:10000'));
});

test('controlled shutdown fails closed when active writes remain', async () => {
  const f = fixture({controlledEvaluationMode: true, getActiveSqliteWrites: () => 1});
  await createServiceRuntimeLifecycle(f.options).start();
  f.signals.get('SIGTERM')();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(f.exits, [1]);
  assert.equal(f.events.includes('db.close'), false);
  assert(f.logs.some((entry) => String(entry[0]).includes('retained active writes')));
});

test('request failures preserve bounded 500 and post-header destruction behavior', async () => {
  const failure = new Error('dispatch failed');
  const f = fixture({dispatchRequest: async () => { throw failure; }});
  await createServiceRuntimeLifecycle(f.options).start();
  const response = {headersSent: false, destroy: (error) => f.events.push(['destroy', error])};
  f.requestListener()({}, response);
  await new Promise((resolve) => setImmediate(resolve));
  assert(f.events.some((entry) => Array.isArray(entry) && entry[0] === 'sendJson' && entry[2] === 500));
  response.headersSent = true;
  f.requestListener()({}, response);
  await new Promise((resolve) => setImmediate(resolve));
  assert(f.events.some((entry) => Array.isArray(entry) && entry[0] === 'destroy' && entry[1] === failure));
});

test('run logs startup failures and exits one without listening', async () => {
  const failure = new TypeError('database unavailable');
  const f = fixture({initDb: async () => { throw failure; }});
  createServiceRuntimeLifecycle(f.options).run();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(f.exits, [1]);
  assert.equal(f.events.some((event) => String(event).startsWith('listen:')), false);
  assert(f.logs.some((entry) => entry[0] === 'critical' && entry[1] === 'service.start_failed'
    && entry[2].error_type === 'TypeError' && entry[2].error_message === 'database unavailable'));
});

test('optional Telegram and PostgreSQL shadow workers remain disabled', async () => {
  const f = fixture();
  f.workers.telegram.enabled = false;
  f.workers.postgresShadow = null;
  await createServiceRuntimeLifecycle(f.options).start();
  assert.equal(f.events.includes('telegram'), false);
  assert.equal(f.events.includes('shadow'), false);
  assert.deepEqual(f.intervals.map(({milliseconds}) => milliseconds), [12, 13, 14, 15, 16, 3600000]);
});
