'use strict';

function nullableTimestamp(value) {
  const text = String(value || '').trim();
  return text || null;
}

function createPostgresShadowProjector({
  pool,
  outbox,
  withWriteGate,
  now,
  batchSize = 50,
  retrySeconds = 30,
}) {
  let active = false;
  const metrics = {
    runs: 0,
    projected: 0,
    stale: 0,
    failures: 0,
    last_success_at: null,
    last_error: null,
  };

  async function apply(row) {
    const values = [
      Number(row.id),
      Number(row.revision),
      String(row.job_type),
      String(row.dedupe_key),
      JSON.parse(row.payload_json || '{}'),
      String(row.status),
      Number(row.priority || 0),
      Number(row.attempt_count || 0),
      Number(row.max_attempts || 8),
      nullableTimestamp(row.next_attempt_at),
      nullableTimestamp(row.lease_expires_at),
      row.lease_token || null,
      row.last_error || null,
      nullableTimestamp(row.created_at),
      nullableTimestamp(row.updated_at),
      nullableTimestamp(row.completed_at),
      nullableTimestamp(row.last_completed_at),
      nullableTimestamp(row.requested_at),
      nullableTimestamp(row.processing_started_at),
      Boolean(Number(row.rerun_requested || 0)),
    ];
    const placeholders = values.map((_, index) => `$${index + 1}`).join(', ');
    const result = await pool.query(
      `SELECT onion_sentinel_queue.apply_shadow_durable_job(
         ${placeholders}
       ) AS applied`,
      values,
    );
    return result.rows?.[0]?.applied === true;
  }

  async function drain() {
    if (active) return {...metrics, skipped_active: true};
    active = true;
    metrics.runs += 1;
    try {
      const rows = await outbox.pending(batchSize);
      for (const row of rows) {
        try {
          const applied = await apply(row);
          await withWriteGate(() => outbox.markProjected(
            row.entity_key,
            Number(row.revision),
            now(),
          ));
          metrics[applied ? 'projected' : 'stale'] += 1;
          metrics.last_success_at = now();
          metrics.last_error = null;
        } catch (error) {
          const retryAt = new Date(
            Date.now() + Math.max(5, Number(retrySeconds) || 30) * 1000,
          ).toISOString();
          await withWriteGate(() => outbox.markFailure(
            row.entity_key,
            Number(row.revision),
            error.message,
            retryAt,
          ));
          metrics.failures += 1;
          metrics.last_error = String(error.message || error).slice(0, 500);
          // A database-level outage affects the batch. Stop here rather than
          // creating one failed attempt per queued row.
          break;
        }
      }
      return snapshot();
    } finally {
      active = false;
    }
  }

  function snapshot() {
    return {...metrics, active};
  }

  async function close() {
    await pool.end();
  }

  return {drain, snapshot, close};
}

module.exports = {createPostgresShadowProjector};
