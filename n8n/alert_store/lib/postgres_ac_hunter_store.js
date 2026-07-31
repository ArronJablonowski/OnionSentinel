'use strict';

const crypto = require('crypto');
const fs = require('fs');

const SCHEMA = 'onion-sentinel-ac-hunter-review-v1';
const DATASET = 'security-onion-rolling';
const RETENTION_SECONDS = 24 * 60 * 60;
const REFRESH_INTERVAL_SECONDS = 60 * 60;
const SCHEDULE_MINUTE = 35;
const MAX_PAYLOAD_BYTES = 8 * 1024 * 1024;
const FORBIDDEN_KEYS = new Set([
  'authorization', 'cookie', 'email', 'jwt', 'password', 'secret',
  'session', 'session_cookie', 'token',
]);

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function timestamp(value, field) {
  const raw = String(value || '').trim();
  const parsed = new Date(raw);
  if (!raw || !Number.isFinite(parsed.getTime()) || !/(?:Z|[+-]\d\d:\d\d)$/.test(raw)) {
    throw new Error(`${field} must be an offset-aware timestamp`);
  }
  return parsed.toISOString();
}

function inspectTree(value, depth = 0) {
  if (depth > 14) throw new Error('AC Hunter snapshot nesting is invalid');
  if (Array.isArray(value)) {
    if (value.length > 5000) throw new Error('AC Hunter snapshot list is too large');
    value.forEach((item) => inspectTree(item, depth + 1));
    return;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value);
    if (entries.length > 1000) throw new Error('AC Hunter snapshot object is too large');
    for (const [key, item] of entries) {
      if (typeof key !== 'string' || key.length > 128 || FORBIDDEN_KEYS.has(key.toLowerCase())) {
        throw new Error('AC Hunter snapshot contains prohibited material');
      }
      inspectTree(item, depth + 1);
    }
    return;
  }
  if (typeof value === 'string' && value.length > 8192) {
    throw new Error('AC Hunter snapshot text is too large');
  }
  if (value !== null && !['string', 'number', 'boolean', 'undefined'].includes(typeof value)) {
    throw new Error('AC Hunter snapshot value is invalid');
  }
}

function normalizeSnapshot(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('AC Hunter snapshot must be an object');
  }
  const encoded = JSON.stringify(value);
  if (Buffer.byteLength(encoded) > MAX_PAYLOAD_BYTES) {
    throw new Error('AC Hunter snapshot exceeds its size boundary');
  }
  const result = clone(value);
  inspectTree(result);
  if (
    result.schema !== SCHEMA
    || Number(result.version) !== 1
    || result.ok !== true
    || !result.modules
    || typeof result.modules !== 'object'
    || Array.isArray(result.modules)
  ) {
    throw new Error('AC Hunter snapshot schema is unsupported');
  }
  const dataset = result.dataset;
  if (!dataset || typeof dataset !== 'object' || dataset.name !== DATASET) {
    throw new Error('AC Hunter dataset is invalid');
  }
  result.last_pulled_at = timestamp(result.last_pulled_at, 'last_pulled_at');
  return result;
}

function datasetProjection(snapshot) {
  const value = normalizeSnapshot(snapshot);
  // Pull time, cache state, and transport health are observations about the
  // collection run. They must not create a new dataset version by themselves.
  // Everything rendered as AC Hunter evidence remains digest-authoritative.
  return {
    schema: value.schema,
    version: value.version,
    dataset: value.dataset,
    time_range: value.time_range,
    modules: value.modules,
    counts: value.counts || {},
    verdict_counts: value.verdict_counts || {},
    top_hosts: value.top_hosts || [],
    top_risky_internal_hosts: value.top_risky_internal_hosts || [],
    correlated_hosts: value.correlated_hosts || [],
    analyst_notes: value.analyst_notes || [],
    disclaimer: value.disclaimer || '',
  };
}

function datasetDigest(snapshot) {
  return crypto.createHash('sha256')
    .update(JSON.stringify(datasetProjection(snapshot)))
    .digest('hex');
}

function findingCount(snapshot) {
  return Object.values(snapshot.modules || {}).reduce((total, module) => (
    total + (Array.isArray(module?.findings) ? module.findings.length : 0)
  ), 0);
}

function publicSnapshot(row, historyCount, now = new Date()) {
  const payload = clone(row.payload);
  const checkedAt = new Date(row.last_checked_at);
  const ageSeconds = Math.max(0, Math.floor((now.getTime() - checkedAt.getTime()) / 1000));
  const stale = ageSeconds > (REFRESH_INTERVAL_SECONDS * 2);
  payload.last_pulled_at = checkedAt.toISOString();
  payload.metadata = {...(payload.metadata || {})};
  payload.metadata.last_pulled_at = checkedAt.toISOString();
  payload.metadata.stale = stale;
  payload.metadata.storage_backend = 'postgresql';
  payload.cache = {
    status: stale ? 'stale' : 'fresh',
    stale,
    refreshed_at: checkedAt.toISOString(),
    age_seconds: ageSeconds,
    ttl_seconds: RETENTION_SECONDS,
    retention_seconds: RETENTION_SECONDS,
    refresh_interval_seconds: REFRESH_INTERVAL_SECONDS,
    scheduled_minute: SCHEDULE_MINUTE,
    storage_backend: 'postgresql',
    dataset_digest: row.current_digest,
    last_changed_at: new Date(row.last_changed_at).toISOString(),
    last_pull_changed: row.last_pull_changed === true,
    history_count: Number(historyCount || 0),
    last_error: '',
  };
  return payload;
}

function createPostgresAcHunterStore({pool, schemaPath, logger = console, now = () => new Date()}) {
  if (!pool || typeof pool.query !== 'function') throw new Error('PostgreSQL pool is required');

  async function initialize() {
    await pool.query(fs.readFileSync(schemaPath, 'utf8'));
    const version = await pool.query(
      `SELECT version FROM onion_sentinel_ac_hunter.schema_version
       WHERE component = 'ac_hunter_cache'`,
    );
    if (Number(version.rows[0]?.version || 0) !== 1) {
      throw new Error('AC Hunter PostgreSQL schema version is unsupported');
    }
  }

  async function ingest(value) {
    const snapshot = normalizeSnapshot(value);
    const digest = datasetDigest(snapshot);
    const checkedAt = timestamp(snapshot.last_pulled_at, 'last_pulled_at');
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const stateResult = await client.query(
        `SELECT current_digest FROM onion_sentinel_ac_hunter.current_state
         WHERE singleton = 1 FOR UPDATE`,
      );
      const previousDigest = String(stateResult.rows[0]?.current_digest || '');
      const changed = previousDigest !== digest;
      if (changed) {
        await client.query(
          `INSERT INTO onion_sentinel_ac_hunter.snapshots
           (dataset_digest, dataset_name, collected_at, payload)
           VALUES ($1, $2, $3, $4::jsonb)
           ON CONFLICT (dataset_digest) DO NOTHING`,
          [digest, DATASET, checkedAt, JSON.stringify(snapshot)],
        );
      }
      await client.query(
        `UPDATE onion_sentinel_ac_hunter.current_state
         SET current_digest = $1,
             last_checked_at = $2,
             last_changed_at = CASE WHEN $3 THEN $2 ELSE last_changed_at END,
             last_pull_changed = $3,
             successful_pulls = successful_pulls + 1,
             unchanged_pulls = unchanged_pulls + CASE WHEN $3 THEN 0 ELSE 1 END,
             updated_at = clock_timestamp()
         WHERE singleton = 1`,
        [digest, checkedAt, changed],
      );
      await client.query(
        `INSERT INTO onion_sentinel_ac_hunter.pull_runs
         (checked_at, dataset_digest, changed, finding_count)
         VALUES ($1, $2, $3, $4)`,
        [checkedAt, digest, changed, findingCount(snapshot)],
      );
      await client.query(
        `DELETE FROM onion_sentinel_ac_hunter.pull_runs
         WHERE checked_at < $1::timestamptz - interval '24 hours'`,
        [checkedAt],
      );
      await client.query(
        `DELETE FROM onion_sentinel_ac_hunter.snapshots
         WHERE collected_at < $1::timestamptz - interval '24 hours'
           AND dataset_digest <> $2`,
        [checkedAt, digest],
      );
      await client.query('COMMIT');
      logger.log?.('info', 'ac_hunter.snapshot_ingested', {
        dataset_digest: digest,
        changed,
        finding_count: findingCount(snapshot),
      });
      return {ok: true, changed, dataset_digest: digest, checked_at: checkedAt};
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async function latest() {
    const result = await pool.query(
      `SELECT state.current_digest, state.last_checked_at,
              state.last_changed_at, state.last_pull_changed,
              snapshot.payload,
              (SELECT count(*) FROM onion_sentinel_ac_hunter.snapshots
               WHERE collected_at >= state.last_checked_at - interval '24 hours'
                  OR dataset_digest = state.current_digest) AS history_count
       FROM onion_sentinel_ac_hunter.current_state AS state
       JOIN onion_sentinel_ac_hunter.snapshots AS snapshot
         ON snapshot.dataset_digest = state.current_digest
       WHERE state.singleton = 1`,
    );
    if (!result.rowCount) return null;
    return publicSnapshot(result.rows[0], result.rows[0].history_count, now());
  }

  async function stats() {
    const result = await pool.query(
      `SELECT state.current_digest, state.last_checked_at,
              state.last_changed_at, state.last_pull_changed,
              state.successful_pulls, state.unchanged_pulls,
              (SELECT count(*) FROM onion_sentinel_ac_hunter.snapshots) AS snapshots,
              (SELECT count(*) FROM onion_sentinel_ac_hunter.pull_runs) AS pull_runs
       FROM onion_sentinel_ac_hunter.current_state AS state
       WHERE state.singleton = 1`,
    );
    const row = result.rows[0] || {};
    return {
      enabled: true,
      available: Boolean(row.current_digest),
      backend: 'postgresql',
      retention_seconds: RETENTION_SECONDS,
      refresh_interval_seconds: REFRESH_INTERVAL_SECONDS,
      scheduled_minute: SCHEDULE_MINUTE,
      current_digest: row.current_digest || '',
      last_checked_at: row.last_checked_at ? new Date(row.last_checked_at).toISOString() : '',
      last_changed_at: row.last_changed_at ? new Date(row.last_changed_at).toISOString() : '',
      last_pull_changed: row.last_pull_changed === true,
      successful_pulls: Number(row.successful_pulls || 0),
      unchanged_pulls: Number(row.unchanged_pulls || 0),
      snapshots: Number(row.snapshots || 0),
      pull_runs: Number(row.pull_runs || 0),
    };
  }

  return {initialize, ingest, latest, stats};
}

module.exports = {
  DATASET,
  REFRESH_INTERVAL_SECONDS,
  RETENTION_SECONDS,
  SCHEDULE_MINUTE,
  createPostgresAcHunterStore,
  datasetDigest,
  datasetProjection,
  normalizeSnapshot,
  publicSnapshot,
};
