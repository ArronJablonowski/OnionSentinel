'use strict';

const {AsyncLocalStorage} = require('node:async_hooks');

function createSqliteRuntime({
  fs, path, processApi, sqlite3, dbPath, controlledEvaluationMode, busyTimeoutMs,
}) {
  if (!fs || typeof fs.mkdirSync !== 'function' || typeof fs.lstatSync !== 'function'
    || typeof fs.realpathSync !== 'function' || typeof fs.existsSync !== 'function') {
    throw new TypeError('fs must provide SQLite path admission operations');
  }
  if (!path || typeof path.resolve !== 'function' || typeof path.dirname !== 'function') {
    throw new TypeError('path must provide resolve and dirname');
  }
  if (!sqlite3 || typeof sqlite3.Database !== 'function') {
    throw new TypeError('sqlite3.Database is required');
  }

  if (controlledEvaluationMode) {
    const databasePath = path.resolve(dbPath);
    const databaseMetadata = fs.lstatSync(databasePath);
    const databaseOwner = typeof processApi.getuid === 'function'
      ? processApi.getuid()
      : databaseMetadata.uid;
    if (
      databasePath !== dbPath
      || fs.realpathSync(databasePath) !== databasePath
      || !databaseMetadata.isFile()
      || databaseMetadata.isSymbolicLink()
      || databaseMetadata.uid !== databaseOwner
      || (databaseMetadata.mode & 0o022) !== 0
    ) {
      throw new Error(
        'controlled evaluation database must be an owner-controlled regular file',
      );
    }
    const recoverySidecar = ['-journal', '-wal', '-shm'].find(
      (suffix) => fs.existsSync(`${databasePath}${suffix}`),
    );
    if (recoverySidecar) {
      throw new Error(
        `controlled evaluation refuses database recovery sidecar ${recoverySidecar}`,
      );
    }
  } else {
    fs.mkdirSync(path.dirname(dbPath), {recursive: true});
  }

  const database = controlledEvaluationMode
    ? new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE)
    : new sqlite3.Database(dbPath);
  database.configure('busyTimeout', busyTimeoutMs);

  function run(sql, params = []) {
    // Promise wrappers let owners use async/await with sqlite3.
    return new Promise((resolve, reject) => {
      database.run(sql, params, function onRun(error) {
        if (error) reject(error);
        else resolve(this);
      });
    });
  }

  function get(sql, params = []) {
    return new Promise((resolve, reject) => {
      database.get(sql, params, (error, row) => {
        if (error) reject(error);
        else resolve(row);
      });
    });
  }

  function all(sql, params = []) {
    return new Promise((resolve, reject) => {
      database.all(sql, params, (error, rows) => {
        if (error) reject(error);
        else resolve(rows);
      });
    });
  }

  let sqliteWriteGate = Promise.resolve();
  let activeSqliteWrites = 0;
  const transactionContext = new AsyncLocalStorage();

  function withWriteGate(task) {
    // sqlite3 serializes individual statements, but request handlers can still
    // interleave multi-statement workflows. Queue workflows so suppression,
    // raw alerts, and group summaries remain coherent during bursts.
    const next = sqliteWriteGate.catch(() => undefined).then(async () => {
      activeSqliteWrites += 1;
      try {
        return await task();
      } finally {
        activeSqliteWrites -= 1;
      }
    });
    sqliteWriteGate = next.catch(() => undefined);
    return next;
  }

  async function withImmediateTransaction(task) {
    const context = transactionContext.getStore();
    if (context) {
      context.nextSavepoint += 1;
      const savepoint = `onion_sentinel_nested_${context.nextSavepoint}`;
      await run(`SAVEPOINT ${savepoint}`);
      try {
        const result = await task();
        await run(`RELEASE SAVEPOINT ${savepoint}`);
        return result;
      } catch (error) {
        await run(`ROLLBACK TO SAVEPOINT ${savepoint}`).catch(() => undefined);
        await run(`RELEASE SAVEPOINT ${savepoint}`).catch(() => undefined);
        throw error;
      }
    }
    await run('BEGIN IMMEDIATE');
    try {
      return await transactionContext.run({nextSavepoint: 0}, async () => {
        const result = await task();
        await run('COMMIT');
        return result;
      });
    } catch (error) {
      await run('ROLLBACK').catch(() => undefined);
      throw error;
    }
  }

  function waitForWrites() {
    return sqliteWriteGate.catch(() => undefined);
  }

  return {
    database,
    run,
    get,
    all,
    withWriteGate,
    withImmediateTransaction,
    waitForWrites,
    activeWrites: () => activeSqliteWrites,
  };
}

module.exports = {createSqliteRuntime};
