'use strict';

function createServiceRuntimeLifecycle(options) {
  const {
    initDb,
    initializePostgresAssetStore,
    initializePostgresSoftwareStore,
    initializePostgresAcHunterStore,
    getPostgresStoreState,
    applicationLogger,
    databaseLogFields,
    httpCreateServer,
    configureHttpServer,
    dispatchRequest,
    sendJson,
    httpConfiguration,
    host,
    port,
    dbPath,
    controlledEvaluationMode,
    processLike,
    consoleLike,
    database,
    waitForSqliteWrites,
    getActiveSqliteWrites,
    setIntervalFn,
    setTimeoutFn,
    workers,
  } = options;

  let shutdownStarted = false;

  function isShutdownStarted() {
    return shutdownStarted;
  }

  function logWorkerError(prefix, error) {
    consoleLike.error(`${prefix}: ${error.message}`);
  }

  function invokeCatching(task, prefix) {
    void task().catch((error) => logWorkerError(prefix, error));
  }

  function scheduleCatching(task, intervalMs, recurringPrefix, initialPrefix) {
    setIntervalFn(() => invokeCatching(task, recurringPrefix), intervalMs).unref();
    invokeCatching(task, initialPrefix);
  }

  function startBackgroundWorkers() {
    if (workers.telegram.enabled) {
      setIntervalFn(() => void workers.telegram.drain(), workers.telegram.intervalMs).unref();
      void workers.telegram.drain();
    }
    setIntervalFn(() => void workers.enrichment.drain(), workers.enrichment.intervalMs).unref();
    void workers.enrichment.drain();
    scheduleCatching(
      workers.enrichmentCache.prune,
      workers.enrichmentCache.intervalMs,
      'enrichment cache retention failed',
      'initial enrichment cache retention failed',
    );
    setIntervalFn(() => void workers.n8nPostCommit.drain(), workers.n8nPostCommit.intervalMs).unref();
    void workers.n8nPostCommit.drain();
    scheduleCatching(
      workers.durableRecovery.recover,
      workers.durableRecovery.intervalMs,
      'durable job lease recovery failed',
      'initial durable job lease recovery failed',
    );
    scheduleCatching(
      workers.pipelineDisk.capture,
      workers.pipelineDisk.intervalMs,
      'pipeline disk sample failed',
      'initial pipeline disk sample failed',
    );
    if (workers.postgresShadow?.enabled()) {
      scheduleCatching(
        workers.postgresShadow.drain,
        workers.postgresShadow.intervalMs,
        'PostgreSQL shadow projection failed',
        'initial PostgreSQL shadow projection failed',
      );
    }
    setIntervalFn(() => {
      invokeCatching(
        () => workers.pipelineMetrics.withWriteGate(workers.pipelineMetrics.prune),
        'pipeline metric retention failed',
      );
    }, workers.pipelineMetrics.intervalMs).unref();
  }

  function installControlledEvaluationShutdown(server) {
    const shutdown = () => {
      if (shutdownStarted) return;
      shutdownStarted = true;
      const deadline = setTimeoutFn(() => processLike.exit(1), 10000);
      deadline.unref();
      server.close(async (serverError) => {
        if (serverError) {
          consoleLike.error(`controlled evaluation server shutdown failed: ${serverError.message}`);
          processLike.exit(1);
          return;
        }
        await waitForSqliteWrites();
        if (getActiveSqliteWrites() !== 0) {
          consoleLike.error('controlled evaluation shutdown retained active writes');
          processLike.exit(1);
          return;
        }
        database.close((databaseError) => {
          if (databaseError) {
            consoleLike.error(`controlled evaluation database shutdown failed: ${databaseError.message}`);
            processLike.exit(1);
            return;
          }
          processLike.exit(0);
        });
      });
    };
    processLike.once('SIGTERM', shutdown);
    processLike.once('SIGINT', shutdown);
  }

  async function start() {
    await initDb();
    await initializePostgresAssetStore();
    await initializePostgresSoftwareStore();
    await initializePostgresAcHunterStore();
    const postgresStoreState = getPostgresStoreState();
    applicationLogger.log('info', 'database.initialized', {
      ...databaseLogFields,
      asset_postgres_available: Boolean(postgresStoreState.postgresAssetStore),
      software_postgres_available: Boolean(postgresStoreState.postgresSoftwareStore),
      ac_hunter_postgres_available: Boolean(postgresStoreState.postgresAcHunterStore),
    });
    const server = configureHttpServer(httpCreateServer((request, response) => {
      void dispatchRequest(request, response).catch((error) => {
        consoleLike.error(`unhandled HTTP request failure: ${error.message}`);
        if (!response.headersSent) sendJson(response, 500, {ok: false, status: 'error'});
        else response.destroy(error);
      });
    }), httpConfiguration);
    server.listen(port, host, () => {
      consoleLike.log(`alert-store listening on ${host}:${port}, db=${dbPath}`);
      applicationLogger.log('info', 'service.ready', {
        listen_host: host,
        listen_port: port,
        database_path: dbPath,
      });
    });
    if (controlledEvaluationMode) installControlledEvaluationShutdown(server);
    else startBackgroundWorkers();
    return server;
  }

  function run() {
    void start().catch((error) => {
      applicationLogger.log('critical', 'service.start_failed', {
        error_type: error.name,
        error_message: error.message,
      });
      consoleLike.error(error);
      processLike.exit(1);
    });
  }

  return {isShutdownStarted, run, start};
}

module.exports = {createServiceRuntimeLifecycle};
