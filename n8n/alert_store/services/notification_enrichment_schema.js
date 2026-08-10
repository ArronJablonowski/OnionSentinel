'use strict';

function createNotificationEnrichmentSchema({run, nowUtc, installEnrichmentCache}) {
  for (const [name, value] of Object.entries({run, nowUtc, installEnrichmentCache})) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be a function`);
  }

  async function installNotifications() {
    await run(`
      CREATE TABLE IF NOT EXISTS notification_log (
        notification_key TEXT PRIMARY KEY, last_sent TEXT NOT NULL,
        sent_count INTEGER NOT NULL DEFAULT 1, channel TEXT NOT NULL,
        alert_id TEXT, triage_level TEXT, rule_name TEXT,
        source_ip TEXT, destination_ip TEXT
      )
    `);
    await run(`
      CREATE TABLE IF NOT EXISTS notification_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT, notification_key TEXT NOT NULL,
        channel TEXT NOT NULL DEFAULT 'telegram', alert_id TEXT,
        triage_level TEXT, rule_name TEXT, source_ip TEXT, destination_ip TEXT,
        payload_json TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
        attempt_count INTEGER NOT NULL DEFAULT 0, next_attempt_at TEXT NOT NULL,
        last_error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
        sent_at TEXT
      )
    `);
    await run('CREATE INDEX IF NOT EXISTS idx_notification_outbox_due ON notification_outbox(status, next_attempt_at, id)');
    await run('CREATE INDEX IF NOT EXISTS idx_notification_outbox_key ON notification_outbox(notification_key, status)');
    // Claims are process-local. A restarted process must make interrupted
    // deliveries eligible again; notification_log still enforces cooldown.
    await run(
      "UPDATE notification_outbox SET status = 'pending', updated_at = ? WHERE status = 'delivering'",
      [nowUtc()],
    );
  }

  async function installSuppression() {
    await run(`
      CREATE TABLE IF NOT EXISTS suppression_log (
        suppression_key TEXT PRIMARY KEY, rule_name TEXT NOT NULL, reason TEXT,
        window_start TEXT NOT NULL, last_seen TEXT NOT NULL,
        seen_count INTEGER NOT NULL DEFAULT 1,
        suppressed_count INTEGER NOT NULL DEFAULT 0,
        escalated_count INTEGER NOT NULL DEFAULT 0, ttl_seconds INTEGER NOT NULL,
        escalation_threshold INTEGER NOT NULL
      )
    `);
  }

  async function installEnrichment() {
    await installEnrichmentCache();
    await run(`
      CREATE TABLE IF NOT EXISTS enrichment_rate_limit (
        source TEXT PRIMARY KEY,
        last_request_at TEXT NOT NULL
      )
    `);
  }

  async function install() {
    await installNotifications();
    await installSuppression();
    await installEnrichment();
  }

  return {install};
}

module.exports = {createNotificationEnrichmentSchema};
