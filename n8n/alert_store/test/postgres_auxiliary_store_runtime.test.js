'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {createPostgresAuxiliaryStoreRuntime} = require(
  '../services/postgres_auxiliary_store_runtime'
);

const completeEnv = {
  ALERT_STORE_POSTGRES_HOST: 'db.internal',
  ALERT_STORE_POSTGRES_PORT: '5434',
  ALERT_STORE_POSTGRES_DATABASE: 'sentinel',
  ALERT_STORE_POSTGRES_USER: 'runtime-user',
  ALERT_STORE_POSTGRES_PASSWORD: 'runtime-password',
};

function owner({controlled = false, asset = true, software = true, acHunter = true,
  env = completeEnv, failures = {}} = {}) {
  const events = [];
  const pools = [];
  function createPool(config) {
    const pool = {config, handlers: {}, on(name, handler) { this.handlers[name] = handler; }};
    pools.push(pool);
    events.push({name: 'pool', config});
    if (failures.pool) throw new Error(failures.pool);
    return pool;
  }
  function storeFactory(name) {
    return ({pool, schemaPath, logger}) => {
      const store = {name, poolSeen: pool, schemaPath, loggerSeen: logger,
        async initialize() {
          events.push({name: `${name}.initialize`});
          if (failures[name]) throw new Error(failures[name]);
        },
        async stats() { return {name}; }};
      events.push({name: `${name}.create`, schemaPath});
      return store;
    };
  }
  const logger = {log: (...args) => events.push({name: 'log', args})};
  const runtime = createPostgresAuxiliaryStoreRuntime({
    env, controlledEvaluationMode: controlled, assetPostgresEnabled: asset,
    softwarePostgresEnabled: software, acHunterPostgresEnabled: acHunter,
    assetSchemaPath: '/schema/asset.sql', softwareSchemaPath: '/schema/software.sql',
    acHunterSchemaPath: '/schema/ac.sql', createPool,
    createAssetStore: storeFactory('asset'),
    createSoftwareStore: storeFactory('software'),
    createAcHunterStore: storeFactory('acHunter'), logger,
  });
  return {events, pools, runtime};
}

test('all-disabled and controlled modes construct no pool or store', async () => {
  for (const options of [{asset: false, software: false, acHunter: false}, {controlled: true}]) {
    const {events, runtime} = owner(options);
    await runtime.initializeAssetStore();
    await runtime.initializeSoftwareStore();
    await runtime.initializeAcHunterStore();
    assert.deepEqual(events, []);
    assert.equal(runtime.state().postgresAssetStore, undefined);
  }
});

test('missing connection keys set one bounded unavailable reason for every store', async () => {
  const {events, runtime} = owner({env: {ALERT_STORE_POSTGRES_HOST: 'db'}});
  await runtime.initializeAssetStore();
  assert.deepEqual(events, []);
  const state = runtime.state();
  const expected = 'missing ALERT_STORE_POSTGRES_DATABASE, ALERT_STORE_POSTGRES_USER, ALERT_STORE_POSTGRES_PASSWORD';
  assert.equal(state.postgresAssetStoreError, expected);
  assert.equal(state.postgresSoftwareStoreError, expected);
  assert.equal(state.postgresAcHunterStoreError, expected);
  assert.throws(() => runtime.requireAssetStore(), (error) =>
    error.statusCode === 503 && error.message === `PostgreSQL asset inventory is unavailable: ${expected}`);
});

test('pool configuration preserves credentials, defaults, and clamps only at construction', async () => {
  const {events, pools, runtime} = owner({env: {...completeEnv,
    ASSET_POSTGRES_POOL_SIZE: '50', ASSET_POSTGRES_CONNECT_TIMEOUT_MS: '500'}});
  await runtime.initializeAssetStore();
  assert.deepEqual(pools[0].config, {
    host: 'db.internal', port: 5434, database: 'sentinel', user: 'runtime-user',
    password: 'runtime-password', max: 20, connectionTimeoutMillis: 1000,
    idleTimeoutMillis: 10000, application_name: 'onion-sentinel-postgres-store',
  });
  const state = runtime.state();
  assert.equal(Object.hasOwn(state, 'postgresAssetPool'), false);
  assert.equal(Object.hasOwn(state, 'password'), false);
  assert.equal(events.some(({name, args}) => name === 'log'
    && JSON.stringify(args).includes('runtime-password')), false);
});

test('all enabled stores initialize on one pool and preserve ready metadata', async () => {
  const {events, pools, runtime} = owner();
  await runtime.initializeAssetStore();
  await runtime.initializeSoftwareStore();
  await runtime.initializeAcHunterStore();
  const state = runtime.state();
  assert.equal(state.postgresAssetStore.poolSeen, pools[0]);
  assert.equal(state.postgresSoftwareStore.poolSeen, pools[0]);
  assert.equal(state.postgresAcHunterStore.poolSeen, pools[0]);
  assert.equal(runtime.requireAssetStore(), state.postgresAssetStore);
  assert.equal(runtime.requireSoftwareStore(), state.postgresSoftwareStore);
  assert.equal(runtime.requireAcHunterStore(), state.postgresAcHunterStore);
  assert.deepEqual(events.filter(({name}) => name === 'log').map(({args}) => args), [
    ['info', 'asset_store.ready', {backend: 'postgresql', schema_version: 1}],
    ['info', 'software_inventory_store.ready', {backend: 'postgresql', schema_version: 1}],
    ['info', 'ac_hunter_store.ready', {backend: 'postgresql', schema_version: 1,
      retention_seconds: 86400, scheduled_minute: 35}],
  ]);
});

test('idle pool error updates every store reason, bounds it, and logs once', async () => {
  const {events, pools, runtime} = owner();
  await runtime.initializeAssetStore();
  pools[0].handlers.error(new Error('x'.repeat(600)));
  const state = runtime.state();
  assert.equal(state.postgresAssetStoreError.length, 500);
  assert.equal(state.postgresSoftwareStoreError, state.postgresAssetStoreError);
  assert.equal(state.postgresAcHunterStoreError, state.postgresAssetStoreError);
  assert.deepEqual(events.at(-1), {name: 'log', args: [
    'error', 'asset_store.postgres_idle_error', {error_message: 'x'.repeat(500)},
  ]});
});

test('asset initialization failure is bounded and propagated to dependent states', async () => {
  const {events, runtime} = owner({failures: {asset: 'asset schema failed'}});
  await runtime.initializeAssetStore();
  const state = runtime.state();
  assert.equal(state.postgresAssetStore, null);
  assert.equal(state.postgresAssetStoreError, 'asset schema failed');
  assert.equal(state.postgresSoftwareStoreError, 'asset schema failed');
  assert.equal(state.postgresAcHunterStoreError, 'asset schema failed');
  assert.deepEqual(events.at(-1), {name: 'log', args: [
    'error', 'asset_store.initialization_failed', {error_message: 'asset schema failed'},
  ]});
});

test('dependent stores retain exact missing-shared-pool reasons', async () => {
  const softwareOnly = owner({asset: false, software: true, acHunter: false,
    env: {ALERT_STORE_POSTGRES_HOST: 'db'}}).runtime;
  await softwareOnly.initializeSoftwareStore();
  assert.equal(softwareOnly.state().postgresSoftwareStoreError,
    'shared PostgreSQL pool is unavailable; enable the PostgreSQL asset store');
  const acOnly = owner({asset: false, software: false, acHunter: true,
    env: {ALERT_STORE_POSTGRES_HOST: 'db'}}).runtime;
  await acOnly.initializeAcHunterStore();
  assert.equal(acOnly.state().postgresAcHunterStoreError,
    'shared PostgreSQL pool is unavailable');
});

test('dependent store failures remain isolated with exact log events', async () => {
  const {events, runtime} = owner({failures: {software: 'software failed',
    acHunter: 'ac failed'}});
  await runtime.initializeAssetStore();
  await runtime.initializeSoftwareStore();
  await runtime.initializeAcHunterStore();
  const state = runtime.state();
  assert.equal(state.postgresAssetStoreError, '');
  assert.equal(state.postgresSoftwareStore, null);
  assert.equal(state.postgresSoftwareStoreError, 'software failed');
  assert.equal(state.postgresAcHunterStore, null);
  assert.equal(state.postgresAcHunterStoreError, 'ac failed');
  const logs = events.filter(({name}) => name === 'log').map(({args}) => args[1]);
  assert.deepEqual(logs, ['asset_store.ready', 'software_inventory_store.initialization_failed',
    'ac_hunter_store.initialization_failed']);
});

test('require methods fail closed with exact disabled and unavailable 503 messages', () => {
  const disabled = owner({asset: false, software: false, acHunter: false}).runtime;
  for (const [method, message] of [
    ['requireAssetStore', 'PostgreSQL asset inventory is disabled'],
    ['requireSoftwareStore', 'PostgreSQL software inventory is disabled'],
    ['requireAcHunterStore', 'PostgreSQL AC Hunter cache is disabled'],
  ]) {
    assert.throws(() => disabled[method](), (error) =>
      error.statusCode === 503 && error.message === message);
  }
  const unavailable = owner().runtime;
  assert.throws(() => unavailable.requireAssetStore(), (error) =>
    error.statusCode === 503 && error.message === 'PostgreSQL asset inventory is unavailable');
});
