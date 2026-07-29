'use strict';

// Transactional bridge from SQLite authority to a future PostgreSQL shadow.
//
// SQLite triggers maintain one dirty marker per durable job in the same
// transaction as the authoritative queue mutation. A projector can read the
// current durable_jobs snapshot, apply it idempotently to PostgreSQL, and then
// acknowledge the exact revision it observed. No network call occurs inside
// the SQLite transaction and no queue mutation can be committed without its
// projection intent.
function createPostgresShadowOutbox({run, get, all}) {
  async function install() {
    await run(`
      CREATE TABLE IF NOT EXISTS postgres_shadow_outbox (
        entity_type TEXT NOT NULL,
        entity_key TEXT NOT NULL,
        revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
        projected_revision INTEGER NOT NULL DEFAULT 0
          CHECK(projected_revision >= 0),
        attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
        next_attempt_at TEXT NOT NULL,
        last_error TEXT,
        updated_at TEXT NOT NULL,
        projected_at TEXT,
        PRIMARY KEY(entity_type, entity_key)
      )
    `);
    await run(`
      CREATE INDEX IF NOT EXISTS idx_postgres_shadow_outbox_due
      ON postgres_shadow_outbox(
        entity_type, next_attempt_at, updated_at, entity_key
      )
      WHERE projected_revision < revision
    `);
    await run(`
      CREATE TRIGGER IF NOT EXISTS trg_durable_jobs_shadow_insert
      AFTER INSERT ON durable_jobs
      BEGIN
        INSERT INTO postgres_shadow_outbox (
          entity_type, entity_key, revision, projected_revision,
          attempt_count, next_attempt_at, updated_at
        ) VALUES (
          'durable_job', CAST(NEW.id AS TEXT), 1, 0, 0,
          strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
          strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        )
        ON CONFLICT(entity_type, entity_key) DO UPDATE SET
          revision = postgres_shadow_outbox.revision + 1,
          attempt_count = 0,
          next_attempt_at = excluded.next_attempt_at,
          last_error = NULL,
          updated_at = excluded.updated_at;
      END
    `);
    await run(`
      CREATE TRIGGER IF NOT EXISTS trg_durable_jobs_shadow_update
      AFTER UPDATE ON durable_jobs
      BEGIN
        INSERT INTO postgres_shadow_outbox (
          entity_type, entity_key, revision, projected_revision,
          attempt_count, next_attempt_at, updated_at
        ) VALUES (
          'durable_job', CAST(NEW.id AS TEXT), 1, 0, 0,
          strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
          strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        )
        ON CONFLICT(entity_type, entity_key) DO UPDATE SET
          revision = postgres_shadow_outbox.revision + 1,
          attempt_count = 0,
          next_attempt_at = excluded.next_attempt_at,
          last_error = NULL,
          updated_at = excluded.updated_at;
      END
    `);
    // Seed pre-existing jobs exactly once. Subsequent startups leave clean
    // acknowledged revisions untouched.
    await run(`
      INSERT INTO postgres_shadow_outbox (
        entity_type, entity_key, revision, projected_revision,
        attempt_count, next_attempt_at, updated_at
      )
      SELECT
        'durable_job', CAST(id AS TEXT), 1, 0, 0,
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
      FROM durable_jobs
      WHERE 1
      ON CONFLICT(entity_type, entity_key) DO NOTHING
    `);
  }

  async function pending(limit = 100) {
    const boundedLimit = Math.max(1, Math.min(1000, Number(limit) || 100));
    return all(
      `SELECT
         outbox.entity_type,
         outbox.entity_key,
         outbox.revision,
         job.*
       FROM postgres_shadow_outbox AS outbox
       JOIN durable_jobs AS job
         ON outbox.entity_type = 'durable_job'
        AND CAST(job.id AS TEXT) = outbox.entity_key
       WHERE outbox.projected_revision < outbox.revision
         AND datetime(replace(outbox.next_attempt_at, '  ', 'T'))
           <= datetime('now')
       ORDER BY outbox.updated_at ASC, outbox.entity_key ASC
       LIMIT ?`,
      [boundedLimit],
    );
  }

  async function markProjected(entityKey, revision, projectedAt) {
    const result = await run(
      `UPDATE postgres_shadow_outbox
       SET projected_revision = ?,
           attempt_count = 0,
           last_error = NULL,
           projected_at = ?,
           updated_at = CASE WHEN revision = ? THEN ? ELSE updated_at END
       WHERE entity_type = 'durable_job'
         AND entity_key = ?
         AND projected_revision < ?
         AND revision >= ?`,
      [
        revision,
        projectedAt,
        revision,
        projectedAt,
        String(entityKey),
        revision,
        revision,
      ],
    );
    return Number(result.changes || 0) === 1;
  }

  async function markFailure(entityKey, revision, error, retryAt) {
    const result = await run(
      `UPDATE postgres_shadow_outbox
       SET attempt_count = attempt_count + 1,
           next_attempt_at = ?,
           last_error = ?
       WHERE entity_type = 'durable_job'
         AND entity_key = ?
         AND revision = ?
         AND projected_revision < revision`,
      [
        retryAt,
        String(error || 'PostgreSQL shadow projection failed').slice(0, 1000),
        String(entityKey),
        revision,
      ],
    );
    return Number(result.changes || 0) === 1;
  }

  async function stats() {
    const row = await get(`
      SELECT
        COUNT(*) AS tracked,
        SUM(CASE WHEN projected_revision < revision THEN 1 ELSE 0 END)
          AS pending,
        COALESCE(SUM(attempt_count), 0) AS attempts,
        MAX(CASE WHEN projected_revision < revision THEN updated_at END)
          AS newest_pending_at,
        MIN(CASE WHEN projected_revision < revision THEN updated_at END)
          AS oldest_pending_at
      FROM postgres_shadow_outbox
    `);
    return {
      tracked: Number(row?.tracked || 0),
      pending: Number(row?.pending || 0),
      attempts: Number(row?.attempts || 0),
      newest_pending_at: row?.newest_pending_at || null,
      oldest_pending_at: row?.oldest_pending_at || null,
    };
  }

  return {install, pending, markProjected, markFailure, stats};
}

module.exports = {createPostgresShadowOutbox};
