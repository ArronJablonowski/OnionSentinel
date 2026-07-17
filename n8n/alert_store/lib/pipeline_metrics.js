'use strict';

const DEFAULT_WINDOWS = Object.freeze({
  '15m': 15 * 60,
  '1h': 60 * 60,
  '24h': 24 * 60 * 60,
});

function numeric(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function timestampMs(value) {
  const parsed = Date.parse(String(value || '').replace('  ', 'T'));
  return Number.isFinite(parsed) ? parsed : null;
}

function ageSeconds(value, nowMs) {
  const parsed = timestampMs(value);
  return parsed == null ? 0 : Math.max(0, Math.floor((nowMs - parsed) / 1000));
}

function ratePerSecond(count, windowSeconds) {
  return windowSeconds > 0 ? numeric(count) / windowSeconds : 0;
}

function etaSeconds(backlog, completionRate) {
  const amount = Math.max(0, numeric(backlog));
  const rate = Math.max(0, numeric(completionRate));
  if (!amount) return 0;
  if (!rate) return null;
  return Math.ceil(amount / rate);
}

function queuePressure(arrivalRate, completionRate) {
  const arrivals = Math.max(0, numeric(arrivalRate));
  const completions = Math.max(0, numeric(completionRate));
  if (!arrivals) return 0;
  if (!completions) return null;
  return Number((arrivals / completions).toFixed(3));
}

function windowRollups(events, nowMs, windows = DEFAULT_WINDOWS) {
  const rollups = {};
  for (const [label, seconds] of Object.entries(windows)) {
    const cutoff = nowMs - seconds * 1000;
    const current = events.filter((event) => (timestampMs(event.occurred_at) || 0) >= cutoff);
    const enqueued = current.filter((event) => event.event_type === 'enqueued').length;
    const completedRows = current.filter((event) => event.event_type === 'completed');
    const failed = current.filter((event) => event.event_type === 'failed').length;
    const completed = completedRows.length;
    const completedBytes = completedRows.reduce((total, event) => total + Math.max(0, numeric(event.size_bytes)), 0);
    const arrivalRate = ratePerSecond(enqueued, seconds);
    const completionRate = ratePerSecond(completed, seconds);
    rollups[label] = {
      window_seconds: seconds,
      enqueued,
      completed,
      failed,
      completed_bytes: completedBytes,
      arrival_rate_per_minute: Number((arrivalRate * 60).toFixed(3)),
      completion_rate_per_minute: Number((completionRate * 60).toFixed(3)),
      completed_bytes_per_second: Number(ratePerSecond(completedBytes, seconds).toFixed(3)),
      pressure_ratio: queuePressure(arrivalRate, completionRate),
    };
  }
  return rollups;
}

function preferredRate(rollups, field) {
  for (const label of ['15m', '1h', '24h']) {
    const value = numeric(rollups?.[label]?.[field]);
    if (value > 0) return value;
  }
  return 0;
}

function stageSnapshot(name, queue, events, nowMs) {
  const throughput = windowRollups(events, nowMs);
  const completionRate = preferredRate(throughput, 'completion_rate_per_minute') / 60;
  const byteRate = preferredRate(throughput, 'completed_bytes_per_second');
  const pending = Math.max(0, numeric(queue?.pending));
  const processing = Math.max(0, numeric(queue?.processing));
  const backlogBytes = Math.max(0, numeric(queue?.backlog_bytes_known));
  return {
    stage: name,
    pending,
    processing,
    failed: Math.max(0, numeric(queue?.failed)),
    oldest_pending_seconds: ageSeconds(queue?.oldest_pending_at, nowMs),
    oldest_processing_seconds: ageSeconds(queue?.oldest_processing_at, nowMs),
    backlog_bytes_known: backlogBytes,
    backlog_bytes_unknown_items: Math.max(0, numeric(queue?.backlog_bytes_unknown_items)),
    drain_eta_seconds: etaSeconds(pending + processing, completionRate),
    byte_drain_eta_seconds: etaSeconds(backlogBytes, byteRate),
    throughput,
  };
}

function diskProjection(disk, stages, samples, nowMs) {
  const totalBytes = Math.max(0, numeric(disk?.total_bytes));
  const usedBytes = Math.max(0, numeric(disk?.used_bytes));
  const startLimit = Math.min(80, Math.max(1, numeric(disk?.start_max_used_percent) || 75));
  const hardLimit = Math.min(80, Math.max(startLimit, numeric(disk?.hard_max_used_percent) || 80));
  const startCeilingBytes = totalBytes * startLimit / 100;
  const hardCeilingBytes = totalBytes * hardLimit / 100;
  const knownBacklogBytes = stages.reduce((total, stage) => total + numeric(stage.backlog_bytes_known), 0);
  const unknownBacklogItems = stages.reduce((total, stage) => total + numeric(stage.backlog_bytes_unknown_items), 0);

  const growth = {};
  for (const [label, seconds] of Object.entries({'1h': 3600, '24h': 86400})) {
    const cutoff = nowMs - seconds * 1000;
    const candidates = (samples || [])
      .filter((sample) => (timestampMs(sample.captured_at) || 0) <= cutoff)
      .sort((left, right) => (timestampMs(right.captured_at) || 0) - (timestampMs(left.captured_at) || 0));
    const baseline = candidates[0];
    const elapsed = baseline ? Math.max(1, (nowMs - timestampMs(baseline.captured_at)) / 1000) : 0;
    const bytesPerSecond = baseline && elapsed
      ? Math.max(0, (usedBytes - numeric(baseline.disk_used_bytes)) / elapsed)
      : 0;
    growth[label] = {
      bytes_per_second: Number(bytesPerSecond.toFixed(3)),
      eta_to_start_limit_seconds: etaSeconds(Math.max(0, startCeilingBytes - usedBytes), bytesPerSecond),
      eta_to_hard_limit_seconds: etaSeconds(Math.max(0, hardCeilingBytes - usedBytes), bytesPerSecond),
    };
  }

  return {
    ...disk,
    start_limit_headroom_bytes: Math.max(0, Math.floor(startCeilingBytes - usedBytes)),
    hard_limit_headroom_bytes: Math.max(0, Math.floor(hardCeilingBytes - usedBytes)),
    known_pipeline_backlog_bytes: knownBacklogBytes,
    unknown_pipeline_backlog_items: unknownBacklogItems,
    projected_used_percent_with_known_backlog: totalBytes
      ? Number(((usedBytes + knownBacklogBytes) / totalBytes * 100).toFixed(2))
      : 100,
    known_backlog_fits_before_start_limit: unknownBacklogItems === 0 && usedBytes + knownBacklogBytes < startCeilingBytes,
    net_growth: growth,
  };
}

function createPipelineMetrics({run, all, now, diskSnapshot, retentionHours = 168}) {
  const boundedRetentionHours = Math.min(24 * 30, Math.max(24, numeric(retentionHours) || 168));

  async function install() {
    await run(`
      CREATE TABLE IF NOT EXISTS pipeline_stage_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_key TEXT NOT NULL UNIQUE,
        stage TEXT NOT NULL,
        event_type TEXT NOT NULL,
        item_key TEXT,
        size_bytes INTEGER NOT NULL DEFAULT 0,
        occurred_at TEXT NOT NULL
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_pipeline_stage_events_time ON pipeline_stage_events(occurred_at)');
    await run('CREATE INDEX IF NOT EXISTS idx_pipeline_stage_events_stage_time ON pipeline_stage_events(stage, event_type, occurred_at)');
    await run(`
      CREATE TABLE IF NOT EXISTS pipeline_metric_samples (
        captured_at TEXT PRIMARY KEY,
        disk_used_bytes INTEGER NOT NULL,
        disk_free_bytes INTEGER NOT NULL,
        sqlite_bytes INTEGER NOT NULL DEFAULT 0
      )
    `);
    await prune();
    await bootstrapRecentEvents();
  }

  async function bootstrapRecentEvents() {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    await run(`
      INSERT OR IGNORE INTO pipeline_stage_events
        (event_key, stage, event_type, item_key, size_bytes, occurred_at)
      SELECT 'bootstrap:alert:' || alert_id, 'alert_ingest', 'completed', alert_id,
             length(COALESCE(alert_json, '')), last_seen
      FROM alerts
      WHERE datetime(replace(last_seen, '  ', 'T')) >= datetime(?)
    `, [cutoff]);
    await run(`
      INSERT OR IGNORE INTO pipeline_stage_events
        (event_key, stage, event_type, item_key, size_bytes, occurred_at)
      SELECT 'bootstrap:job:' || job_type || ':' || dedupe_key || ':' || COALESCE(last_completed_at, ''),
             job_type, 'completed', dedupe_key, 0, last_completed_at
      FROM durable_jobs
      WHERE last_completed_at IS NOT NULL
        AND datetime(replace(last_completed_at, '  ', 'T')) >= datetime(?)
    `, [cutoff]);
    await run(`
      INSERT OR IGNORE INTO pipeline_stage_events
        (event_key, stage, event_type, item_key, size_bytes, occurred_at)
      SELECT 'bootstrap:pcap-transfer:' || request_id || ':' || COALESCE(completed_at, ''),
             'pcap_transfer', 'completed', request_id, COALESCE(artifact_size_bytes, 0), completed_at
      FROM pcap_requests
      WHERE status = 'fulfilled' AND completed_at IS NOT NULL
        AND datetime(replace(completed_at, '  ', 'T')) >= datetime(?)
    `, [cutoff]);
    await run(`
      INSERT OR IGNORE INTO pipeline_stage_events
        (event_key, stage, event_type, item_key, size_bytes, occurred_at)
      SELECT 'bootstrap:pcap-analysis:' || request_id || ':' || COALESCE(analysis_completed_at, ''),
             'pcap_analysis', 'completed', request_id, COALESCE(artifact_size_bytes, 0), analysis_completed_at
      FROM pcap_requests
      WHERE analysis_status = 'completed' AND analysis_completed_at IS NOT NULL
        AND datetime(replace(analysis_completed_at, '  ', 'T')) >= datetime(?)
    `, [cutoff]);
  }

  async function prune() {
    const cutoff = new Date(Date.now() - boundedRetentionHours * 60 * 60 * 1000).toISOString();
    await run("DELETE FROM pipeline_stage_events WHERE datetime(replace(occurred_at, '  ', 'T')) < datetime(?)", [cutoff]);
    await run("DELETE FROM pipeline_metric_samples WHERE datetime(replace(captured_at, '  ', 'T')) < datetime(?)", [cutoff]);
  }

  async function record(stage, eventType, itemKey, options = {}) {
    const eventKey = String(options.eventKey || `${stage}:${eventType}:${itemKey}:${now()}`);
    await run(
      `INSERT OR IGNORE INTO pipeline_stage_events
       (event_key, stage, event_type, item_key, size_bytes, occurred_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [eventKey, String(stage), String(eventType), String(itemKey || ''),
        Math.max(0, Math.floor(numeric(options.sizeBytes))), now()],
    );
  }

  async function captureDiskSample(sqliteBytes = 0) {
    const disk = diskSnapshot();
    await run(
      `INSERT OR REPLACE INTO pipeline_metric_samples
       (captured_at, disk_used_bytes, disk_free_bytes, sqlite_bytes) VALUES (?, ?, ?, ?)`,
      [now(), numeric(disk.used_bytes), numeric(disk.free_bytes), Math.max(0, numeric(sqliteBytes))],
    );
    return disk;
  }

  async function snapshot() {
    const nowText = now();
    const nowMs = timestampMs(nowText) || Date.now();
    const cutoff = new Date(nowMs - 24 * 60 * 60 * 1000).toISOString();
    const [events, durableRows, pcapRows, samples] = await Promise.all([
      all("SELECT stage, event_type, size_bytes, occurred_at FROM pipeline_stage_events WHERE datetime(replace(occurred_at, '  ', 'T')) >= datetime(?)", [cutoff]),
      all(`SELECT job_type AS stage,
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
          SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) AS processing,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
          MIN(CASE WHEN status = 'pending' THEN updated_at END) AS oldest_pending_at,
          MIN(CASE WHEN status = 'processing' THEN updated_at END) AS oldest_processing_at
        FROM durable_jobs GROUP BY job_type`),
      all(`SELECT 'pcap_transfer' AS stage,
          SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending,
          SUM(CASE WHEN status = 'claimed' THEN 1 ELSE 0 END) AS processing,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
          MIN(CASE WHEN status = 'pending' THEN updated_at END) AS oldest_pending_at,
          MIN(CASE WHEN status = 'claimed' THEN COALESCE(transfer_progress_at, updated_at) END) AS oldest_processing_at,
          COALESCE(SUM(CASE WHEN status = 'claimed' AND transfer_total_bytes > 0
            THEN MAX(0, transfer_total_bytes - transfer_bytes) ELSE 0 END), 0) AS backlog_bytes_known,
          SUM(CASE WHEN status IN ('pending', 'claimed') AND transfer_total_bytes <= 0 THEN 1 ELSE 0 END) AS backlog_bytes_unknown_items
        FROM pcap_requests
        UNION ALL
        SELECT 'pcap_analysis' AS stage,
          SUM(CASE WHEN status = 'fulfilled' AND analysis_status = 'pending' THEN 1 ELSE 0 END) AS pending,
          SUM(CASE WHEN status = 'fulfilled' AND analysis_status = 'processing' THEN 1 ELSE 0 END) AS processing,
          SUM(CASE WHEN status = 'fulfilled' AND analysis_status = 'failed' THEN 1 ELSE 0 END) AS failed,
          MIN(CASE WHEN status = 'fulfilled' AND analysis_status = 'pending' THEN updated_at END) AS oldest_pending_at,
          MIN(CASE WHEN status = 'fulfilled' AND analysis_status = 'processing' THEN updated_at END) AS oldest_processing_at,
          COALESCE(SUM(CASE WHEN status = 'fulfilled' AND analysis_status IN ('pending', 'processing')
            THEN COALESCE(artifact_size_bytes, 0) ELSE 0 END), 0) AS backlog_bytes_known,
          SUM(CASE WHEN status = 'fulfilled' AND analysis_status IN ('pending', 'processing')
            AND COALESCE(artifact_size_bytes, 0) <= 0 THEN 1 ELSE 0 END) AS backlog_bytes_unknown_items
        FROM pcap_requests`),
      all('SELECT captured_at, disk_used_bytes FROM pipeline_metric_samples ORDER BY captured_at DESC'),
    ]);

    const queueRows = [...durableRows, ...pcapRows];
    const stageNames = [
      'alert_ingest',
      'n8n_post_commit',
      'public_enrichment',
      'pcap_transfer',
      'pcap_analysis',
      'ai_analysis',
    ];
    const stages = stageNames.map((stage) => stageSnapshot(
      stage,
      queueRows.find((row) => row.stage === stage) || {},
      events.filter((event) => event.stage === stage),
      nowMs,
    ));
    const disk = diskProjection(diskSnapshot(), stages, samples, nowMs);
    return {generated_at: nowText, stages, disk};
  }

  return {install, record, captureDiskSample, prune, snapshot};
}

module.exports = {
  DEFAULT_WINDOWS,
  ageSeconds,
  etaSeconds,
  queuePressure,
  windowRollups,
  stageSnapshot,
  diskProjection,
  createPipelineMetrics,
};
