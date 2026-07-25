'use strict';

const {randomUUID} = require('node:crypto');

// Small, storage-backed work queue shared by asynchronous alert-store jobs.
// The caller supplies DB helpers so this module stays independent of sqlite3's
// callback API and can be exercised with the same transaction gate as ingest.
function createDurableJobQueue({run, get, all, now, transitionLeaseSeconds = 900}) {
  const externalLeaseSeconds = Math.max(60, Number(transitionLeaseSeconds) || 900);

  async function recoverExpired() {
    const timestamp = now();
    const expired = await all(
      `SELECT * FROM durable_jobs
       WHERE status = 'processing'
         AND (lease_token IS NULL
           OR lease_expires_at IS NULL
           OR datetime(replace(lease_expires_at, '  ', 'T')) <= datetime(replace(?, '  ', 'T')))`,
      [timestamp],
    );
    const summary = {recovered: 0, failed: 0, job_types: {}};
    for (const job of expired) {
      const updated = await fail(job, job.last_error || 'worker lease expired before completion');
      if (!updated) continue;
      const terminal = Number(job.attempt_count || 0) >= Number(job.max_attempts || 8);
      summary[terminal ? 'failed' : 'recovered'] += 1;
      const jobType = String(job.job_type || 'unknown');
      summary.job_types[jobType] = (summary.job_types[jobType] || 0) + 1;
    }
    return summary;
  }

  async function install() {
    await run(`
      CREATE TABLE IF NOT EXISTS durable_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_type TEXT NOT NULL,
        dedupe_key TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK(status IN ('pending', 'processing', 'completed', 'failed')),
        priority INTEGER NOT NULL DEFAULT 0,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 8,
        next_attempt_at TEXT NOT NULL,
        lease_expires_at TEXT,
        lease_token TEXT,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        completed_at TEXT,
        last_completed_at TEXT,
        requested_at TEXT NOT NULL,
        processing_started_at TEXT,
        rerun_requested INTEGER NOT NULL DEFAULT 0,
        UNIQUE(job_type, dedupe_key)
      )
    `);
    const columns = new Set((await all('PRAGMA table_info(durable_jobs)')).map((row) => String(row.name || '')));
    if (!columns.has('last_completed_at')) {
      await run('ALTER TABLE durable_jobs ADD COLUMN last_completed_at TEXT');
    }
    if (!columns.has('requested_at')) {
      await run('ALTER TABLE durable_jobs ADD COLUMN requested_at TEXT');
    }
    if (!columns.has('processing_started_at')) {
      await run('ALTER TABLE durable_jobs ADD COLUMN processing_started_at TEXT');
    }
    if (!columns.has('rerun_requested')) {
      await run('ALTER TABLE durable_jobs ADD COLUMN rerun_requested INTEGER NOT NULL DEFAULT 0');
    }
    if (!columns.has('lease_token')) {
      await run('ALTER TABLE durable_jobs ADD COLUMN lease_token TEXT');
    }
    await run('UPDATE durable_jobs SET last_completed_at = completed_at WHERE last_completed_at IS NULL AND completed_at IS NOT NULL');
    await run('UPDATE durable_jobs SET requested_at = COALESCE(requested_at, created_at) WHERE requested_at IS NULL');
    await run("UPDATE durable_jobs SET processing_started_at = COALESCE(processing_started_at, updated_at) WHERE status = 'processing' AND processing_started_at IS NULL");
    await run('CREATE INDEX IF NOT EXISTS idx_durable_jobs_due ON durable_jobs(status, job_type, next_attempt_at, priority DESC, id)');
    await run('CREATE INDEX IF NOT EXISTS idx_durable_jobs_lease ON durable_jobs(status, lease_expires_at)');
    await recoverExpired();
  }

  async function enqueue(jobType, dedupeKey, payload, options = {}) {
    const timestamp = now();
    await run(
      `INSERT INTO durable_jobs (
         job_type, dedupe_key, payload_json, status, priority, max_attempts,
         next_attempt_at, created_at, updated_at, requested_at
       ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
       ON CONFLICT(job_type, dedupe_key) DO UPDATE SET
         payload_json = excluded.payload_json,
         priority = MAX(durable_jobs.priority, excluded.priority),
         max_attempts = excluded.max_attempts,
         status = CASE WHEN durable_jobs.status = 'processing' THEN 'processing' ELSE 'pending' END,
         next_attempt_at = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.next_attempt_at ELSE excluded.next_attempt_at END,
         attempt_count = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.attempt_count ELSE 0 END,
         completed_at = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.completed_at ELSE NULL END,
         last_error = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.last_error ELSE NULL END,
         requested_at = excluded.requested_at,
         processing_started_at = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.processing_started_at ELSE NULL END,
         rerun_requested = CASE WHEN durable_jobs.status = 'processing' THEN 1 ELSE 0 END,
         updated_at = excluded.updated_at`,
      [jobType, dedupeKey, JSON.stringify(payload || {}), Number(options.priority || 0),
        Math.max(1, Number(options.maxAttempts || 8)), timestamp, timestamp, timestamp, timestamp],
    );
  }

  async function claim(jobType, leaseSeconds = 300) {
    const timestamp = now();
    const candidate = await get(
      `SELECT * FROM durable_jobs
       WHERE job_type = ? AND status = 'pending'
         AND datetime(replace(next_attempt_at, '  ', 'T')) <= datetime(replace(?, '  ', 'T'))
         AND attempt_count < max_attempts
       ORDER BY priority DESC, next_attempt_at ASC, id ASC LIMIT 1`,
      [jobType, timestamp],
    );
    if (!candidate) return null;
    const lease = new Date(Date.now() + Math.max(30, Number(leaseSeconds)) * 1000).toISOString();
    const leaseToken = randomUUID();
    const result = await run(
      `UPDATE durable_jobs SET status = 'processing', attempt_count = attempt_count + 1,
         lease_expires_at = ?, lease_token = ?, processing_started_at = ?, rerun_requested = 0,
         updated_at = ? WHERE id = ? AND status = 'pending'`,
      [lease, leaseToken, timestamp, timestamp, candidate.id],
    );
    if (result.changes !== 1) return null;
    return {...candidate, attempt_count: Number(candidate.attempt_count || 0) + 1,
      processing_started_at: timestamp, lease_token: leaseToken,
      payload: JSON.parse(candidate.payload_json || '{}')};
  }

  async function complete(job) {
    const timestamp = now();
    const result = await run(
      `UPDATE durable_jobs SET
         status = CASE WHEN rerun_requested = 1 THEN 'pending' ELSE 'completed' END,
         next_attempt_at = CASE WHEN rerun_requested = 1 THEN ? ELSE next_attempt_at END,
         attempt_count = CASE WHEN rerun_requested = 1 THEN 0 ELSE attempt_count END,
         lease_expires_at = NULL,
         lease_token = NULL,
         last_error = NULL,
         completed_at = CASE WHEN rerun_requested = 1 THEN NULL ELSE ? END,
         last_completed_at = ?,
         processing_started_at = CASE WHEN rerun_requested = 1 THEN NULL ELSE processing_started_at END,
         rerun_requested = 0,
         updated_at = ?
       WHERE id = ? AND status = 'processing' AND lease_token IS ?`,
      [timestamp, timestamp, timestamp, timestamp, job.id, job.lease_token],
    );
    return Number(result.changes || 0) === 1;
  }

  async function completePendingByDedupeKeys(jobType, dedupeKeys) {
    const keys = [...new Set((dedupeKeys || []).map((value) => String(value || '').trim()).filter(Boolean))];
    if (!keys.length) return 0;
    const timestamp = now();
    let completed = 0;
    // Keep each statement below common SQLite parameter limits. The caller's
    // surrounding write transaction makes the full reconciliation atomic.
    for (let offset = 0; offset < keys.length; offset += 500) {
      const chunk = keys.slice(offset, offset + 500);
      const placeholders = chunk.map(() => '?').join(', ');
      const result = await run(
        `UPDATE durable_jobs SET status = 'completed', lease_expires_at = NULL,
           lease_token = NULL, last_error = NULL, completed_at = ?, last_completed_at = ?,
           processing_started_at = NULL, rerun_requested = 0, updated_at = ?
         WHERE job_type = ? AND status = 'pending'
           AND dedupe_key IN (${placeholders})`,
        [timestamp, timestamp, timestamp, jobType, ...chunk],
      );
      completed += Number(result.changes || 0);
    }
    return completed;
  }

  async function fail(job, error, baseRetrySeconds = 30, retryable = true) {
    const terminal = retryable === false
      || Number(job.attempt_count || 0) >= Number(job.max_attempts || 8);
    const delay = Math.min(3600, Math.max(5, Number(baseRetrySeconds)) * (2 ** Math.max(0, Number(job.attempt_count || 1) - 1)));
    const retryAt = new Date(Date.now() + delay * 1000).toISOString();
    const result = await run(
      `UPDATE durable_jobs SET status = ?, next_attempt_at = ?, lease_expires_at = NULL,
         lease_token = NULL, last_error = ?, updated_at = ?
       WHERE id = ? AND status = 'processing' AND lease_token IS ?`,
      [terminal ? 'failed' : 'pending', retryAt, String(error || 'job failed').slice(0, 1000),
        now(), job.id, job.lease_token],
    );
    return Number(result.changes || 0) === 1;
  }

  async function stats() {
    const rows = await all('SELECT job_type, status, COUNT(*) AS count FROM durable_jobs GROUP BY job_type, status');
    return rows;
  }

  async function transition(
    jobType,
    dedupeKey,
    status,
    error = '',
    suppliedLeaseToken = '',
    retryable = true,
  ) {
    if (!['pending', 'processing', 'completed', 'failed'].includes(status)) {
      throw new Error('invalid durable job status');
    }
    const timestamp = now();
    let result;
    let leaseToken = suppliedLeaseToken;
    if (status === 'processing') {
      const leaseExpiry = new Date(Date.now() + externalLeaseSeconds * 1000).toISOString();
      if (suppliedLeaseToken) {
        // A heartbeat may only extend the exact lease it owns. It must not
        // clear rerun_requested because evidence can arrive concurrently.
        result = await run(
          `UPDATE durable_jobs SET lease_expires_at = ?, updated_at = ?
           WHERE job_type = ? AND dedupe_key = ? AND status = 'processing'
             AND lease_token = ?`,
          [leaseExpiry, timestamp, jobType, dedupeKey, suppliedLeaseToken],
        );
      } else {
        leaseToken = randomUUID();
        result = await run(
          `UPDATE durable_jobs SET status = 'processing', attempt_count = attempt_count + 1,
             lease_expires_at = ?, lease_token = ?, processing_started_at = ?, rerun_requested = 0,
             last_error = NULL, updated_at = ?
           WHERE job_type = ? AND dedupe_key = ? AND status = 'pending'
             AND datetime(replace(next_attempt_at, '  ', 'T')) <= datetime(replace(?, '  ', 'T'))
             AND attempt_count < max_attempts`,
          [leaseExpiry, leaseToken, timestamp, timestamp, jobType, dedupeKey, timestamp],
        );
      }
    } else if (status === 'failed') {
      const job = await get(
        'SELECT * FROM durable_jobs WHERE job_type = ? AND dedupe_key = ?',
        [jobType, dedupeKey],
      );
      if (!job) return {updated: false, leaseToken: null};
      if (Number(job.rerun_requested || 0) === 1) {
        result = await run(
          `UPDATE durable_jobs SET status = 'pending', attempt_count = 0,
             next_attempt_at = ?, lease_expires_at = NULL, lease_token = NULL, last_error = NULL,
             processing_started_at = NULL, rerun_requested = 0, updated_at = ?
           WHERE id = ? AND status = 'processing' AND lease_token IS ?`,
          [timestamp, timestamp, job.id, suppliedLeaseToken],
        );
      } else {
        return {
          updated: await fail(
            {...job, lease_token: suppliedLeaseToken},
            error,
            30,
            retryable,
          ),
          leaseToken: null,
        };
      }
    } else if (status === 'completed') {
      result = await run(
        `UPDATE durable_jobs SET
           status = CASE WHEN rerun_requested = 1 THEN 'pending' ELSE ? END,
           next_attempt_at = CASE WHEN rerun_requested = 1 THEN ? ELSE next_attempt_at END,
           attempt_count = CASE WHEN rerun_requested = 1 THEN 0 ELSE attempt_count END,
           lease_expires_at = NULL,
           lease_token = NULL,
           last_error = CASE WHEN rerun_requested = 1 THEN NULL ELSE ? END,
           completed_at = CASE WHEN rerun_requested = 1 THEN NULL WHEN ? = 'completed' THEN ? ELSE NULL END,
           last_completed_at = CASE WHEN ? = 'completed' THEN ? ELSE last_completed_at END,
           processing_started_at = CASE WHEN rerun_requested = 1 THEN NULL ELSE processing_started_at END,
           rerun_requested = 0,
           updated_at = ?
         WHERE job_type = ? AND dedupe_key = ? AND status = 'processing' AND lease_token IS ?`,
        [status, timestamp, String(error || '').slice(0, 1000) || null,
          status, timestamp, status, timestamp, timestamp, jobType, dedupeKey, suppliedLeaseToken],
      );
    } else {
      result = await run(
        `UPDATE durable_jobs SET status = 'pending', attempt_count = 0,
           next_attempt_at = ?, lease_expires_at = NULL, lease_token = NULL, last_error = ?,
           processing_started_at = NULL, rerun_requested = 0, updated_at = ?
         WHERE job_type = ? AND dedupe_key = ? AND status = 'failed'`,
        [timestamp, String(error || '').slice(0, 1000) || null, timestamp, jobType, dedupeKey],
      );
    }
    return {updated: result.changes === 1, leaseToken: result.changes === 1 ? leaseToken : null};
  }

  return {install, enqueue, claim, complete, completePendingByDedupeKeys, fail, stats, transition, recoverExpired};
}

module.exports = {createDurableJobQueue};
