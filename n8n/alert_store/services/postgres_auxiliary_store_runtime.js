'use strict';

function createPostgresAuxiliaryStoreRuntime({
  env, controlledEvaluationMode, assetPostgresEnabled, softwarePostgresEnabled,
  acHunterPostgresEnabled, assetSchemaPath, softwareSchemaPath, acHunterSchemaPath,
  createPool, createAssetStore, createSoftwareStore, createAcHunterStore, logger,
}) {
  for (const [name, value] of Object.entries({
    createPool, createAssetStore, createSoftwareStore, createAcHunterStore,
  })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }
  if (!env || typeof env !== 'object') throw new TypeError('env must be an object');
  if (!logger || typeof logger.log !== 'function') {
    throw new TypeError('logger must provide log');
  }

  let postgresAssetPool;
  let postgresAssetStore;
  let postgresAssetStoreError = '';
  let postgresSoftwareStore;
  let postgresSoftwareStoreError = '';
  let postgresAcHunterStore;
  let postgresAcHunterStoreError = '';

  function state() {
    return {
      postgresAssetStore,
      assetPostgresEnabled,
      postgresAssetStoreError,
      postgresSoftwareStore,
      softwarePostgresEnabled,
      postgresSoftwareStoreError,
      postgresAcHunterStore,
      acHunterPostgresEnabled,
      postgresAcHunterStoreError,
    };
  }

  async function initializeAssetStore() {
    if (
      (!assetPostgresEnabled && !softwarePostgresEnabled && !acHunterPostgresEnabled)
      || controlledEvaluationMode
    ) return;
    const requiredKeys = [
      'ALERT_STORE_POSTGRES_HOST',
      'ALERT_STORE_POSTGRES_DATABASE',
      'ALERT_STORE_POSTGRES_USER',
      'ALERT_STORE_POSTGRES_PASSWORD',
    ];
    const missing = requiredKeys.filter((key) => !String(env[key] || '').trim());
    if (missing.length) {
      const error = `missing ${missing.join(', ')}`;
      postgresAssetStoreError = error;
      postgresSoftwareStoreError = error;
      postgresAcHunterStoreError = error;
      return;
    }
    try {
      postgresAssetPool = createPool({
        host: String(env.ALERT_STORE_POSTGRES_HOST),
        port: Number(env.ALERT_STORE_POSTGRES_PORT || 5433),
        database: String(env.ALERT_STORE_POSTGRES_DATABASE),
        user: String(env.ALERT_STORE_POSTGRES_USER),
        password: String(env.ALERT_STORE_POSTGRES_PASSWORD),
        max: Math.max(2, Math.min(20, Number(env.ASSET_POSTGRES_POOL_SIZE || 8))),
        connectionTimeoutMillis: Math.max(
          1000,
          Number(env.ASSET_POSTGRES_CONNECT_TIMEOUT_MS || 3000),
        ),
        idleTimeoutMillis: 10000,
        application_name: 'onion-sentinel-postgres-store',
      });
      postgresAssetPool.on('error', (error) => {
        postgresAssetStoreError = String(error.message || error).slice(0, 500);
        postgresSoftwareStoreError = postgresAssetStoreError;
        postgresAcHunterStoreError = postgresAssetStoreError;
        logger.log('error', 'asset_store.postgres_idle_error', {
          error_message: postgresAssetStoreError,
        });
      });
      if (assetPostgresEnabled) {
        postgresAssetStore = createAssetStore({
          pool: postgresAssetPool,
          schemaPath: assetSchemaPath,
          logger,
        });
        await postgresAssetStore.initialize();
        postgresAssetStoreError = '';
        logger.log('info', 'asset_store.ready', {
          backend: 'postgresql',
          schema_version: 1,
        });
      }
    } catch (error) {
      postgresAssetStore = null;
      postgresAssetStoreError = String(error.message || error).slice(0, 500);
      postgresSoftwareStoreError = postgresAssetStoreError;
      postgresAcHunterStoreError = postgresAssetStoreError;
      logger.log('error', 'asset_store.initialization_failed', {
        error_message: postgresAssetStoreError,
      });
    }
  }

  async function initializeAcHunterStore() {
    if (!acHunterPostgresEnabled || controlledEvaluationMode) return;
    if (!postgresAssetPool) {
      postgresAcHunterStoreError = 'shared PostgreSQL pool is unavailable';
      return;
    }
    try {
      postgresAcHunterStore = createAcHunterStore({
        pool: postgresAssetPool,
        schemaPath: acHunterSchemaPath,
        logger,
      });
      await postgresAcHunterStore.initialize();
      postgresAcHunterStoreError = '';
      logger.log('info', 'ac_hunter_store.ready', {
        backend: 'postgresql',
        schema_version: 1,
        retention_seconds: 86400,
        scheduled_minute: 35,
      });
    } catch (error) {
      postgresAcHunterStore = null;
      postgresAcHunterStoreError = String(error.message || error).slice(0, 500);
      logger.log('error', 'ac_hunter_store.initialization_failed', {
        error_message: postgresAcHunterStoreError,
      });
    }
  }

  async function initializeSoftwareStore() {
    if (!softwarePostgresEnabled || controlledEvaluationMode) return;
    if (!postgresAssetPool) {
      postgresSoftwareStoreError = (
        'shared PostgreSQL pool is unavailable; enable the PostgreSQL asset store'
      );
      return;
    }
    try {
      postgresSoftwareStore = createSoftwareStore({
        pool: postgresAssetPool,
        schemaPath: softwareSchemaPath,
        logger,
      });
      await postgresSoftwareStore.initialize();
      postgresSoftwareStoreError = '';
      logger.log('info', 'software_inventory_store.ready', {
        backend: 'postgresql',
        schema_version: 1,
      });
    } catch (error) {
      postgresSoftwareStore = null;
      postgresSoftwareStoreError = String(error.message || error).slice(0, 500);
      logger.log('error', 'software_inventory_store.initialization_failed', {
        error_message: postgresSoftwareStoreError,
      });
    }
  }

  function requireStore(enabled, store, storeError, disabledMessage, unavailableMessage) {
    if (!enabled) {
      const error = new Error(disabledMessage);
      error.statusCode = 503;
      throw error;
    }
    if (!store) {
      const error = new Error(`${unavailableMessage}${storeError ? `: ${storeError}` : ''}`);
      error.statusCode = 503;
      throw error;
    }
    return store;
  }

  function requireAssetStore() {
    return requireStore(assetPostgresEnabled, postgresAssetStore, postgresAssetStoreError,
      'PostgreSQL asset inventory is disabled', 'PostgreSQL asset inventory is unavailable');
  }

  function requireSoftwareStore() {
    return requireStore(softwarePostgresEnabled, postgresSoftwareStore,
      postgresSoftwareStoreError, 'PostgreSQL software inventory is disabled',
      'PostgreSQL software inventory is unavailable');
  }

  function requireAcHunterStore() {
    return requireStore(acHunterPostgresEnabled, postgresAcHunterStore,
      postgresAcHunterStoreError, 'PostgreSQL AC Hunter cache is disabled',
      'PostgreSQL AC Hunter cache is unavailable');
  }

  return {
    state,
    initializeAssetStore,
    initializeSoftwareStore,
    initializeAcHunterStore,
    requireAssetStore,
    requireSoftwareStore,
    requireAcHunterStore,
  };
}

module.exports = {createPostgresAuxiliaryStoreRuntime};
