'use strict';

function createIncidentDurableJobPersistence({get, run, conflict}) {
  if (typeof get !== 'function') throw new TypeError('get must be a function');
  if (typeof run !== 'function') throw new TypeError('run must be a function');
  if (typeof conflict !== 'function') throw new TypeError('conflict must be a function');

  function normalizedKeys(groupIds) {
    return [...new Set(
      (groupIds || [])
        .map((value) => (typeof value === 'string' ? value.trim().toLowerCase() : ''))
        .filter(Boolean),
    )];
  }

  async function rejectProcessing(jobType, groupIds) {
    const keys = normalizedKeys(groupIds);
    if (!keys.length) return;
    const placeholders = keys.map(() => '?').join(', ');
    const processing = await get(
      `SELECT id, dedupe_key FROM durable_jobs
       WHERE job_type = ? AND status = 'processing'
         AND dedupe_key IN (${placeholders})
       ORDER BY id ASC LIMIT 1`,
      [jobType, ...keys],
    );
    if (processing) {
      throw conflict(
        `controlled dispatch conflicts with processing ${jobType} job for ${processing.dedupe_key}`,
      );
    }
  }

  async function retirePendingIncident(groupIds, retiredAt) {
    const keys = normalizedKeys(groupIds);
    if (!keys.length) return 0;
    const placeholders = keys.map(() => '?').join(', ');
    const result = await run(
      `UPDATE durable_jobs
       SET status = 'completed', lease_expires_at = NULL, lease_token = NULL,
           last_error = NULL, completed_at = COALESCE(completed_at, ?),
           last_completed_at = COALESCE(last_completed_at, ?),
           processing_started_at = NULL, rerun_requested = 0, updated_at = ?
       WHERE job_type = 'incident_response_analysis'
         AND status = 'pending' AND dedupe_key IN (${placeholders})`,
      [retiredAt, retiredAt, retiredAt, ...keys],
    );
    return Number(result.changes || 0);
  }

  return {rejectProcessing, retirePendingIncident};
}

module.exports = {createIncidentDurableJobPersistence};
