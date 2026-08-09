'use strict';

function createHealthRepository({get, all}) {
  if (typeof get !== 'function' || typeof all !== 'function') {
    throw new TypeError('health repository requires get and all query ports');
  }

  async function jobAges() {
    const oldestJob = await get(`SELECT MAX(0, CAST((julianday('now') - julianday(replace(MIN(next_attempt_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
      FROM durable_jobs WHERE status = 'pending'`);
    const oldestPending = await all(`SELECT job_type,
        MAX(0, CAST((julianday('now') - julianday(replace(MIN(next_attempt_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
      FROM durable_jobs WHERE status = 'pending' GROUP BY job_type`);
    const latestCompleted = await all(`SELECT job_type,
        MAX(0, CAST((julianday('now') - julianday(replace(MAX(last_completed_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
      FROM durable_jobs WHERE last_completed_at IS NOT NULL GROUP BY job_type`);
    const oldestProcessing = await all(`SELECT job_type,
        MAX(0, CAST((julianday('now') - julianday(replace(MIN(updated_at), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
      FROM durable_jobs WHERE status = 'processing' GROUP BY job_type`);
    return {
      oldestPendingSeconds: Number(oldestJob?.seconds || 0),
      oldestPending,
      latestCompleted,
      oldestProcessing,
    };
  }

  async function pcapStats() {
    const status = await all(
      'SELECT status, analysis_status, COUNT(*) AS count FROM pcap_requests GROUP BY status, analysis_status',
    );
    const outcomes = await all(
      "SELECT COALESCE(outcome, 'unknown') AS outcome, COUNT(*) AS count FROM pcap_requests GROUP BY COALESCE(outcome, 'unknown')",
    );
    const storage = await get(`SELECT
        COUNT(*) AS fulfilled_count,
        COALESCE(SUM(artifact_size_bytes), 0) AS artifact_bytes_total,
        COALESCE(AVG(artifact_size_bytes), 0) AS artifact_bytes_average,
        COALESCE(MAX(artifact_size_bytes), 0) AS artifact_bytes_maximum,
        COALESCE(SUM(CASE WHEN datetime(replace(completed_at, '  ', 'T')) >= datetime('now', '-24 hours') THEN artifact_size_bytes ELSE 0 END), 0) AS artifact_bytes_24h,
        SUM(CASE WHEN datetime(replace(completed_at, '  ', 'T')) >= datetime('now', '-24 hours') THEN 1 ELSE 0 END) AS fulfilled_24h
      FROM pcap_requests WHERE status = 'fulfilled'`);
    const oldest = await get(`SELECT MAX(0, CAST((julianday('now') - julianday(replace(MIN(COALESCE(updated_at, created_at)), '  ', 'T'))) * 86400 AS INTEGER)) AS seconds
      FROM pcap_requests WHERE status = 'pending'`);
    return {
      status,
      outcomes,
      storage: storage || {},
      oldestPendingSeconds: Number(oldest?.seconds || 0),
    };
  }

  async function sqliteBytes() {
    const pageCount = await get('PRAGMA page_count');
    const pageSize = await get('PRAGMA page_size');
    return Number(pageCount?.page_count || 0) * Number(pageSize?.page_size || 0);
  }

  return {jobAges, pcapStats, sqliteBytes};
}

module.exports = {createHealthRepository};
