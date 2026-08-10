'use strict';

function createPcapSchema({run, ensureColumn, backfillOutcomes}) {
  for (const [name, value] of Object.entries({run, ensureColumn, backfillOutcomes})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function installTable() {
    await run(`
      CREATE TABLE IF NOT EXISTS pcap_requests (
        request_id TEXT PRIMARY KEY, status TEXT NOT NULL, alert_id TEXT,
        group_id TEXT, group_key TEXT, first_seen TEXT, last_seen TEXT,
        source_ip TEXT, source_port INTEGER, destination_ip TEXT,
        destination_port INTEGER, network_protocol TEXT, transport_protocol TEXT,
        community_id TEXT, requested_by TEXT, reason TEXT NOT NULL,
        max_window_seconds INTEGER NOT NULL, relay_host TEXT, artifact_path TEXT,
        artifact_sha256 TEXT, artifact_size_bytes INTEGER, error TEXT,
        diagnostics_json TEXT, request_json TEXT NOT NULL, created_at TEXT NOT NULL,
        claimed_at TEXT, completed_at TEXT, updated_at TEXT NOT NULL
      )
    `);
  }

  async function installCompatibilityColumns() {
    const columns = [
      ['claimed_at', 'TEXT'], ['completed_at', 'TEXT'], ['diagnostics_json', 'TEXT'],
      ['analysis_status', "TEXT NOT NULL DEFAULT 'not_ready'"],
      ['analysis_attempt_count', 'INTEGER NOT NULL DEFAULT 0'],
      ['analysis_error', 'TEXT'], ['analysis_started_at', 'TEXT'],
      ['analysis_completed_at', 'TEXT'], ['outcome', 'TEXT'], ['transfer_stage', 'TEXT'],
      ['transfer_bytes', 'INTEGER NOT NULL DEFAULT 0'],
      ['transfer_total_bytes', 'INTEGER NOT NULL DEFAULT 0'],
      ['transfer_progress_at', 'TEXT'], ['transfer_duration_seconds', 'INTEGER'],
      ['transfer_attempt_count', 'INTEGER NOT NULL DEFAULT 0'],
      ['transfer_retry_count', 'INTEGER NOT NULL DEFAULT 0'],
      ['transfer_last_error', 'TEXT'], ['transfer_last_failed_stage', 'TEXT'],
      ['next_attempt_at', 'TEXT'],
    ];
    for (const [name, definition] of columns) {
      await ensureColumn('pcap_requests', name, definition);
    }
  }

  async function runBackfills() {
    await run(`
      UPDATE pcap_requests
      SET transfer_duration_seconds = MAX(
        0,
        CAST(ROUND(
          (julianday(replace(completed_at, '  ', 'T')) -
           julianday(replace(claimed_at, '  ', 'T'))) * 86400
        ) AS INTEGER)
      )
      WHERE transfer_duration_seconds IS NULL
        AND claimed_at IS NOT NULL
        AND completed_at IS NOT NULL
    `);
    await backfillOutcomes();
  }

  async function installIndexes() {
    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_pcap_requests_status_created ON pcap_requests(status, created_at)',
      'CREATE INDEX IF NOT EXISTS idx_pcap_requests_status_next_attempt ON pcap_requests(status, next_attempt_at)',
      'CREATE INDEX IF NOT EXISTS idx_pcap_requests_completed_at ON pcap_requests(completed_at)',
      'CREATE INDEX IF NOT EXISTS idx_pcap_requests_alert_id ON pcap_requests(alert_id)',
      'CREATE INDEX IF NOT EXISTS idx_pcap_requests_group_id ON pcap_requests(group_id)',
    ];
    for (const sql of indexes) await run(sql);
  }

  async function install() {
    await installTable();
    await installCompatibilityColumns();
    await runBackfills();
    await installIndexes();
  }

  return {install};
}

module.exports = {createPcapSchema};
