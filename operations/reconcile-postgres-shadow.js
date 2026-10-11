#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

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

function sqliteAll(database, sql, parameters = []) {
  return new Promise((resolve, reject) => {
    database.all(sql, parameters, (error, rows) => (error ? reject(error) : resolve(rows)));
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

async function reconcilePages({sqlitePage, postgresPage, maximumId, pageSize = 500}) {
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 1000) {
    throw new Error('reconciliation page size must be between 1 and 1000');
  }
  const result = {generated_at: new Date().toISOString(), ok: true,
    sqlite_rows: 0, postgres_rows: 0, pending_projection_count: 0,
    pending_projection_age_seconds: 0, pending_projection_stale: false,
    missing_count: 0, extra_count: 0, mismatch_count: 0,
    missing_sample: [], extra_sample: [], mismatch_sample: []};
  let oldestDirtyMs = Infinity;
  const record = (kind, id) => {
    result[`${kind}_count`] += 1;
    if (result[`${kind}_sample`].length < 10) result[`${kind}_sample`].push(id);
  };
  // Match the same bounded identity range in both stores. No payload or complete
  // table remains resident across pages, including differences and samples.
  for (let lower = 0; lower < maximumId; lower += pageSize) {
    const upper = lower + pageSize;
    const rows = await sqlitePage(lower, upper);
    const projected = await postgresPage(lower, upper);
    result.sqlite_rows += rows.length;
    result.postgres_rows += projected.length;
    const local = new Map(rows.map(row => [Number(row.id), row]));
    const remote = new Map(projected.map(row => [Number(row.sqlite_id), row]));
    for (const [id, row] of local) {
      if (Number(row.projected_revision) < Number(row.revision)) {
        result.pending_projection_count += 1;
        const parsed = Date.parse(String(row.projection_updated_at || '').replace('  ', 'T'));
        if (Number.isFinite(parsed)) oldestDirtyMs = Math.min(oldestDirtyMs, parsed);
        continue;
      }
      if (!remote.has(id)) record('missing', id);
      else if (signature(row) !== signature(remote.get(id), true)) record('mismatch', id);
    }
    for (const id of remote.keys()) if (!local.has(id)) record('extra', id);
  }
  result.pending_projection_age_seconds = Number.isFinite(oldestDirtyMs)
    ? Math.max(0, Math.floor((Date.now() - oldestDirtyMs) / 1000)) : 0;
  result.pending_projection_stale = result.pending_projection_age_seconds > 300;
  result.ok = result.missing_count === 0 && result.extra_count === 0
    && result.mismatch_count === 0 && !result.pending_projection_stale;
  return result;
}

async function main() {
  const sqlite3 = require('sqlite3');
  const {Pool} = require('pg');
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
  database.configure('busyTimeout', 5000);
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
    const result = await reconcilePages({
      sqlitePage: (lower, upper) => sqliteAll(database,
        `SELECT job.*, outbox.revision, outbox.projected_revision,
                outbox.updated_at AS projection_updated_at
         FROM durable_jobs AS job JOIN postgres_shadow_outbox AS outbox
           ON outbox.entity_type = 'durable_job'
          AND outbox.entity_key = CAST(job.id AS TEXT)
         WHERE job.id > ? AND job.id <= ? ORDER BY job.id`, [lower, upper]),
      postgresPage: async (lower, upper) => (await pool.query(
        `SELECT * FROM onion_sentinel_queue.shadow_durable_jobs
         WHERE sqlite_id > $1 AND sqlite_id <= $2 ORDER BY sqlite_id`,
        [lower, upper],
      )).rows,
      maximumId: Math.max(
        Number((await sqliteAll(database, 'SELECT COALESCE(MAX(id), 0) AS maximum FROM durable_jobs'))[0].maximum),
        Number((await pool.query('SELECT COALESCE(MAX(sqlite_id), 0) AS maximum FROM onion_sentinel_queue.shadow_durable_jobs')).rows[0].maximum),
      ),
    });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!result.ok) process.exitCode = 1;
  } finally {
    await pool.end();
    await new Promise((resolve) => database.close(() => resolve()));
  }
}

module.exports = {reconcilePages, signature};

if (require.main === module) main().catch((error) => {
  process.stderr.write(`shadow reconciliation failed: ${error.message}\n`);
  process.exitCode = 1;
});
