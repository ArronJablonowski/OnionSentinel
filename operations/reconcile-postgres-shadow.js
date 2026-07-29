#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const sqlite3 = require('sqlite3');
const {Pool} = require('pg');

function parseArgs(argv) {
  const result = {};
  for (let index = 2; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith('--') || value === undefined) {
      throw new Error('usage: reconcile-postgres-shadow.js --env FILE --sqlite FILE');
    }
    result[key.slice(2)] = value;
  }
  if (!result.env || !result.sqlite) throw new Error('both --env and --sqlite are required');
  return result;
}

function readEnv(file) {
  const values = {};
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || !line.includes('=')) continue;
    const [key, ...parts] = line.split('=');
    values[key.trim()] = parts.join('=').trim();
  }
  return values;
}

function sqliteAll(database, sql) {
  return new Promise((resolve, reject) => {
    database.all(sql, [], (error, rows) => (error ? reject(error) : resolve(rows)));
  });
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]),
    );
  }
  return value;
}

function signature(row, postgres = false) {
  const payload = postgres ? row.payload_json : JSON.parse(row.payload_json || '{}');
  return JSON.stringify({
    id: Number(postgres ? row.sqlite_id : row.id),
    revision: Number(row.source_revision || row.revision),
    job_type: String(row.job_type),
    dedupe_key: String(row.dedupe_key),
    payload: canonicalJson(payload),
    status: String(row.status),
    priority: Number(row.priority),
    attempt_count: Number(row.attempt_count),
    max_attempts: Number(row.max_attempts),
    rerun_requested: postgres
      ? Boolean(row.rerun_requested)
      : Boolean(Number(row.rerun_requested)),
  });
}

async function main() {
  const args = parseArgs(process.argv);
  const env = readEnv(path.resolve(args.env));
  const required = [
    'ALERT_STORE_POSTGRES_HOST',
    'ALERT_STORE_POSTGRES_PORT',
    'ALERT_STORE_POSTGRES_DATABASE',
    'ALERT_STORE_POSTGRES_USER',
    'ALERT_STORE_POSTGRES_PASSWORD',
  ];
  const missing = required.filter((key) => !env[key]);
  if (missing.length) throw new Error(`missing PostgreSQL settings: ${missing.join(', ')}`);

  const database = new sqlite3.Database(
    `file:${path.resolve(args.sqlite)}?mode=ro`,
    sqlite3.OPEN_READONLY | sqlite3.OPEN_URI,
  );
  const pool = new Pool({
    host: env.ALERT_STORE_POSTGRES_HOST,
    port: Number(env.ALERT_STORE_POSTGRES_PORT),
    database: env.ALERT_STORE_POSTGRES_DATABASE,
    user: env.ALERT_STORE_POSTGRES_USER,
    password: env.ALERT_STORE_POSTGRES_PASSWORD,
    max: 1,
    connectionTimeoutMillis: 3000,
    statement_timeout: 15000,
    query_timeout: 20000,
    application_name: 'onion-sentinel-shadow-reconciler',
  });
  try {
    const sqliteRows = await sqliteAll(
      database,
      `SELECT job.*, outbox.revision, outbox.projected_revision,
              outbox.updated_at AS projection_updated_at
       FROM durable_jobs AS job
       JOIN postgres_shadow_outbox AS outbox
         ON outbox.entity_type = 'durable_job'
        AND outbox.entity_key = CAST(job.id AS TEXT)
       ORDER BY job.id`,
    );
    const postgresResult = await pool.query(
      `SELECT * FROM onion_sentinel_queue.shadow_durable_jobs
       ORDER BY sqlite_id`,
    );
    const sqliteMap = new Map(
      sqliteRows.map((row) => [Number(row.id), signature(row)]),
    );
    const postgresMap = new Map(
      postgresResult.rows.map((row) => [Number(row.sqlite_id), signature(row, true)]),
    );
    // Queue mutations and projection are intentionally separate transactions.
    // Exclude only currently dirty identities from an exact comparison, then
    // fail if any such projection has remained dirty beyond the bounded grace.
    const dirtyRows = sqliteRows.filter(
      (row) => Number(row.projected_revision) < Number(row.revision),
    );
    const dirtyIds = new Set(dirtyRows.map((row) => Number(row.id)));
    const oldestDirtyMs = dirtyRows.reduce((oldest, row) => {
      const parsed = Date.parse(String(row.projection_updated_at || '').replace('  ', 'T'));
      return Number.isFinite(parsed) ? Math.min(oldest, parsed) : oldest;
    }, Number.POSITIVE_INFINITY);
    const pendingProjectionAgeSeconds = Number.isFinite(oldestDirtyMs)
      ? Math.max(0, Math.floor((Date.now() - oldestDirtyMs) / 1000))
      : 0;
    const missingIds = [...sqliteMap.keys()].filter(
      (id) => !dirtyIds.has(id) && !postgresMap.has(id),
    );
    const extraIds = [...postgresMap.keys()].filter(
      (id) => !dirtyIds.has(id) && !sqliteMap.has(id),
    );
    const mismatchedIds = [...sqliteMap.keys()].filter(
      (id) => (
        !dirtyIds.has(id)
        && postgresMap.has(id)
        && sqliteMap.get(id) !== postgresMap.get(id)
      ),
    );
    const pendingProjectionStale = pendingProjectionAgeSeconds > 300;
    const result = {
      generated_at: new Date().toISOString(),
      ok: (
        missingIds.length === 0
        && extraIds.length === 0
        && mismatchedIds.length === 0
        && !pendingProjectionStale
      ),
      sqlite_rows: sqliteMap.size,
      postgres_rows: postgresMap.size,
      pending_projection_count: dirtyIds.size,
      pending_projection_age_seconds: pendingProjectionAgeSeconds,
      pending_projection_stale: pendingProjectionStale,
      missing_count: missingIds.length,
      extra_count: extraIds.length,
      mismatch_count: mismatchedIds.length,
      missing_sample: missingIds.slice(0, 10),
      extra_sample: extraIds.slice(0, 10),
      mismatch_sample: mismatchedIds.slice(0, 10),
    };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.ok) process.exitCode = 1;
  } finally {
    await pool.end();
    await new Promise((resolve) => database.close(() => resolve()));
  }
}

main().catch((error) => {
  process.stderr.write(`shadow reconciliation failed: ${error.message}\n`);
  process.exitCode = 1;
});
