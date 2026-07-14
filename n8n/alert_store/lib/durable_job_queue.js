'use strict';

// Small, storage-backed work queue shared by asynchronous alert-store jobs.
// The caller supplies DB helpers so this module stays independent of sqlite3's
// callback API and can be exercised with the same transaction gate as ingest.
function createDurableJobQueue({run, get, all, now}) {
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
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        completed_at TEXT,
        UNIQUE(job_type, dedupe_key)
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_durable_jobs_due ON durable_jobs(status, job_type, next_attempt_at, priority DESC, id)');
    await run('CREATE INDEX IF NOT EXISTS idx_durable_jobs_lease ON durable_jobs(status, lease_expires_at)');
    await run(
      "UPDATE durable_jobs SET status = 'pending', lease_expires_at = NULL, updated_at = ? " +
      "WHERE status = 'processing' AND (lease_expires_at IS NULL OR datetime(replace(lease_expires_at, '  ', 'T')) <= datetime(replace(?, '  ', 'T')))",
      [now(), now()],
    );
  }

  async function enqueue(jobType, dedupeKey, payload, options = {}) {
    const timestamp = now();
    await run(
      `INSERT INTO durable_jobs (
         job_type, dedupe_key, payload_json, status, priority, max_attempts,
         next_attempt_at, created_at, updated_at
       ) VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)
       ON CONFLICT(job_type, dedupe_key) DO UPDATE SET
         payload_json = excluded.payload_json,
         priority = MAX(durable_jobs.priority, excluded.priority),
         max_attempts = excluded.max_attempts,
         status = CASE WHEN durable_jobs.status = 'processing' THEN 'processing' ELSE 'pending' END,
         next_attempt_at = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.next_attempt_at ELSE excluded.next_attempt_at END,
         completed_at = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.completed_at ELSE NULL END,
         last_error = CASE WHEN durable_jobs.status = 'processing' THEN durable_jobs.last_error ELSE NULL END,
         updated_at = excluded.updated_at`,
      [jobType, dedupeKey, JSON.stringify(payload || {}), Number(options.priority || 0),
        Math.max(1, Number(options.maxAttempts || 8)), timestamp, timestamp, timestamp],
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
    const result = await run(
      `UPDATE durable_jobs SET status = 'processing', attempt_count = attempt_count + 1,
         lease_expires_at = ?, updated_at = ? WHERE id = ? AND status = 'pending'`,
      [lease, timestamp, candidate.id],
    );
    if (result.changes !== 1) return null;
    return {...candidate, attempt_count: Number(candidate.attempt_count || 0) + 1,
      payload: JSON.parse(candidate.payload_json || '{}')};
  }

  async function complete(id) {
    const timestamp = now();
    await run(
      "UPDATE durable_jobs SET status = 'completed', lease_expires_at = NULL, last_error = NULL, completed_at = ?, updated_at = ? WHERE id = ?",
      [timestamp, timestamp, id],
    );
  }

  async function fail(job, error, baseRetrySeconds = 30) {
    const terminal = Number(job.attempt_count || 0) >= Number(job.max_attempts || 8);
    const delay = Math.min(3600, Math.max(5, Number(baseRetrySeconds)) * (2 ** Math.max(0, Number(job.attempt_count || 1) - 1)));
    const retryAt = new Date(Date.now() + delay * 1000).toISOString();
    await run(
      `UPDATE durable_jobs SET status = ?, next_attempt_at = ?, lease_expires_at = NULL,
         last_error = ?, updated_at = ? WHERE id = ?`,
      [terminal ? 'failed' : 'pending', retryAt, String(error || 'job failed').slice(0, 1000), now(), job.id],
    );
  }

  async function stats() {
    const rows = await all('SELECT job_type, status, COUNT(*) AS count FROM durable_jobs GROUP BY job_type, status');
    return rows;
  }

  async function transition(jobType, dedupeKey, status, error = '') {
    if (!['pending', 'processing', 'completed', 'failed'].includes(status)) {
      throw new Error('invalid durable job status');
    }
    const timestamp = now();
    const result = await run(
      `UPDATE durable_jobs SET status = ?,
         attempt_count = attempt_count + CASE WHEN ? = 'processing' THEN 1 ELSE 0 END,
         lease_expires_at = CASE WHEN ? = 'processing' THEN ? ELSE NULL END,
         last_error = ?, completed_at = CASE WHEN ? = 'completed' THEN ? ELSE NULL END,
         updated_at = ? WHERE job_type = ? AND dedupe_key = ?`,
      [status, status, status, new Date(Date.now() + 3600 * 1000).toISOString(),
        String(error || '').slice(0, 1000) || null, status, timestamp, timestamp, jobType, dedupeKey],
    );
    return result.changes === 1;
  }

  return {install, enqueue, claim, complete, fail, stats, transition};
}

module.exports = {createDurableJobQueue};
